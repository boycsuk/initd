//! The two hardening tiers, and what separates them.
//!
//! Split from the rest of the SSH module because these two tasks share a shape
//! nothing else here has: a table of directives, written wholesale, validated,
//! and rolled back together. `ssh.install` runs a package manager and
//! `ssh.change-port` edits one value; these rewrite a policy.
//!
//! The tiers are deliberately separate tasks rather than one with a flag. The
//! safe tier changes what sshd accepts from a client that can already speak to
//! it; the strict tier changes *whether* a client can speak to it at all, which
//! is the one thing here that can lock somebody out of a daemon that is running
//! and configured correctly. A flag would make the dangerous half reachable by
//! a keystroke meant for the safe one.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::error::{Error, Lockout, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::tasks::algorithms;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::Outcome;
use crate::tasks::sshd_config;
use crate::tasks::{Progress, Support, Task, supported_everywhere};

use super::{has_authorized_key, reload_ssh, report, revertible};

/// Directives the safe tier sets.
///
/// Every one either matches an OpenSSH default or tightens something no
/// ordinary client depends on, so none can strand a client that could connect
/// before. Anything that narrows what a client must speak — algorithms,
/// forwarding — belongs to the strict tier instead.
///
/// Keyboard-interactive authentication is absent deliberately: its keyword
/// differs by version and is probed rather than assumed. See
/// [`keyboard_interactive_keywords`].
pub(super) const SAFE_DIRECTIVES: [(&str, &str); 17] = [
    ("PermitRootLogin", "no"),
    ("PasswordAuthentication", "no"),
    ("PubkeyAuthentication", "yes"),
    // Six attempts is the default; three still admits a mistyped passphrase
    // while halving what a brute-force attempt gets per connection.
    ("MaxAuthTries", "3"),
    // The default of 120 seconds holds an unauthenticated slot open long
    // enough to be worth exhausting.
    ("LoginGraceTime", "30"),
    ("X11Forwarding", "no"),
    ("AllowAgentForwarding", "no"),
    ("PermitEmptyPasswords", "no"),
    ("HostbasedAuthentication", "no"),
    ("IgnoreRhosts", "yes"),
    ("StrictModes", "yes"),
    ("PermitUserEnvironment", "no"),
    // Verbose logging records the fingerprint each login used, which is what
    // makes an unexpected key visible after the fact.
    ("LogLevel", "VERBOSE"),
    ("ClientAliveInterval", "300"),
    ("ClientAliveCountMax", "2"),
    ("MaxSessions", "10"),
    ("PermitTunnel", "no"),
];

/// The keywords for keyboard-interactive authentication, newest first.
///
/// `KbdInteractiveAuthentication` is the current name and is unknown before
/// OpenSSH 6.9; `ChallengeResponseAuthentication` is a deprecated alias since
/// 8.7 and is on a removal path. No single keyword is safe across the range,
/// so both are probed and every one this sshd accepts is written. On a version
/// that knows both they are aliases holding the same value, which is what
/// stops the pair disagreeing.
const KEYBOARD_INTERACTIVE_KEYWORDS: [&str; 2] = [
    "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication",
];

/// Applies the SSH hardening that cannot strand a client.
///
/// Destructive: applied to a server the administrator reaches over SSH without
/// a working key, it locks them out. The task refuses to disable password
/// authentication when no authorised key exists.
pub struct HardenSsh;

impl Task for HardenSsh {
    fn id(&self) -> &'static str {
        "ssh.harden"
    }

    fn title(&self) -> &'static str {
        "Harden the SSH configuration"
    }

    fn description(&self) -> &'static str {
        "Disables root login, password authentication, agent and X11 \
         forwarding, tunnelling and user environments; limits authentication \
         attempts to 3 and the login grace period to 30 seconds; disconnects \
         idle sessions after 10 minutes; and turns on verbose logging so the \
         key each login used is recorded. None of these can stop a client that \
         could connect before from connecting, provided it holds a key. \
         Requires an authorised key for root, keeps a backup of the previous \
         configuration, and holds the change open until you confirm you can \
         still log in."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Disabling password authentication without a key in place is the
        // documented way administrators lock themselves out of a server.
        if !has_authorized_key(executor, backend, "root")? {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoKeyForRoot,
            });
        }

        report(
            progress,
            format!("Applying {} hardening directives...", SAFE_DIRECTIVES.len()),
        );

        let hardened = SAFE_DIRECTIVES
            .into_iter()
            .fold(contents, |acc, (directive, value)| {
                sshd_config::set_directive(&acc, directive, value)
            });

        let hardened = disable_keyboard_interactive(executor, &hardened, progress)?;

        let backup = sshd_config::write_validated(executor, backend, &hardened)?;

        if let Some(ref backup) = backup {
            report(
                progress,
                format!("Previous configuration saved to {}", backup.copy),
            );
        }

        reload_ssh(executor, backend, progress)?;

        // `sshd -t` proved the syntax and the reload proved the daemon
        // accepted it, but neither proves the administrator can still log in:
        // the key this task requires might not be the one their client offers.
        // So the change is offered back until they say otherwise.
        Ok(revertible(backup, backend))
    }
}

/// Directives the strict tier sets besides the algorithm lists.
///
/// `RequiredRSASize` may only ever be raised, and 3072 is the smallest size
/// current guidance accepts. `AllowTcpForwarding no` is the one directive here
/// an administrator is likely to want back: it stops port forwarding, which
/// tunnels and remote development tooling rely on.
const STRICT_DIRECTIVES: [(&str, &str); 2] =
    [("RequiredRSASize", "3072"), ("AllowTcpForwarding", "no")];

/// Narrows the algorithms and forwarding sshd will accept.
///
/// Destructive in a way the safe tier is not: a client too old to speak any
/// surviving algorithm can no longer connect at all.
pub struct HardenSshStrict;

impl Task for HardenSshStrict {
    fn id(&self) -> &'static str {
        "ssh.harden-strict"
    }

    fn title(&self) -> &'static str {
        "Harden the SSH cryptography"
    }

    fn description(&self) -> &'static str {
        "Restricts the key exchange, cipher, MAC and host key algorithms to a \
         modern set, requires RSA keys of at least 3072 bits, and disables TCP \
         forwarding, which stops tunnelling and remote development tools. Only \
         algorithms this OpenSSH reports it supports are written, and a list \
         that would be narrowed to fewer than two is left at the system \
         default and reported. Old clients may no longer be able to connect. \
         Requires an authorised key for root, keeps a backup, and holds the \
         change open until you confirm you can still log in."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn support(&self, family: Family) -> Support {
        match family {
            Family::Debian | Family::Arch | Family::Alpine => Support::Yes,
            Family::Rhel => Support::No(
                "the only task RHEL's `Include` costs anything. Its shipped \
                 `50-redhat.conf` is read before the main file and carries the \
                 crypto policies, which are exactly the ciphers, key exchanges \
                 and MACs this tier sets — measured against a daemon, not \
                 inferred: the value written was absent from `sshd -T` while \
                 `sshd -t` approved the file. A drop-in numbered below 50 does \
                 win, and is not used, because on RHEL that choice belongs to \
                 `update-crypto-policies` system-wide rather than to one \
                 application contradicting it",
            ),
        }
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Same guard as the safe tier. This task disables no password, but a
        // configuration that strands the administrator's client is just as
        // unrecoverable as one that refuses their password.
        if !has_authorized_key(executor, backend, "root")? {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoKeyForRoot,
            });
        }

        report(progress, "Narrowing the accepted algorithms...");

        let mut hardened = contents;

        for class in algorithms::ALL_CLASSES {
            match algorithms::hardened_for(executor, class) {
                Some(value) => {
                    report(progress, format!("{}: {value}", class.directive()));
                    hardened = sshd_config::set_directive(&hardened, class.directive(), &value);
                }
                // Skipping is the safe outcome, not a compromise: the
                // compiled-in default admits a reasonable range, while a list
                // narrowed too far refuses clients for no gain. Reported so
                // that a directive the administrator asked for is never
                // silently absent.
                None => progress(OutputLine {
                    stream: Stream::Stderr,
                    text: format!(
                        "warning: {} left at the system default — this OpenSSH supports too \
                         few of the hardened algorithms to narrow it safely",
                        class.directive()
                    ),
                }),
            }
        }

        let hardened = STRICT_DIRECTIVES
            .into_iter()
            .fold(hardened, |acc, (directive, value)| {
                sshd_config::set_directive(&acc, directive, value)
            });

        let backup = sshd_config::write_validated(executor, backend, &hardened)?;

        if let Some(ref backup) = backup {
            report(
                progress,
                format!("Previous configuration saved to {}", backup.copy),
            );
        }

        reload_ssh(executor, backend, progress)?;

        Ok(revertible(backup, backend))
    }
}

/// Turns off keyboard-interactive authentication under whichever keyword this
/// sshd recognises.
///
/// Writing a keyword the daemon does not know is not a warning: `sshd -t`
/// rejects the file, `write_validated` restores the backup, and every other
/// directive set alongside it is lost. So each candidate is probed first and
/// only the accepted ones are written. When none is accepted the setting is
/// left alone and said so — the sixteen directives that did apply are worth
/// more than the one that could not.
fn disable_keyboard_interactive(
    executor: &dyn Executor,
    contents: &str,
    progress: Progress<'_>,
) -> Result<String> {
    let mut updated = contents.to_owned();
    let mut applied = false;

    for keyword in KEYBOARD_INTERACTIVE_KEYWORDS {
        if sshd_config::accepts_directive(executor, keyword, "no")? {
            updated = sshd_config::set_directive(&updated, keyword, "no");
            applied = true;
        }
    }

    if !applied {
        progress(OutputLine {
            stream: Stream::Stderr,
            text: "warning: keyboard-interactive authentication left unchanged — this sshd \
                   recognises neither keyword for it"
                .to_owned(),
        });
    }

    Ok(updated)
}
