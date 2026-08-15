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
use crate::i18n::Msg;
use crate::tasks::algorithms;
use crate::tasks::consequence::{Requirement, program_check};
use crate::tasks::params::ParamValues;
use crate::tasks::revert::Outcome;
use crate::tasks::sshd_config;
use crate::tasks::{Confirmation, Progress, Support, Task, supported_everywhere};

use super::{accounts_keeping_ssh_access, keeps_access, reload_ssh, report, revertible};

/// Directives the safe tier sets.
///
/// Every one either matches an OpenSSH default or tightens something no
/// ordinary client depends on, so none can strand a client that could connect
/// before. Anything that narrows what a client must speak — algorithms,
/// forwarding — belongs to the strict tier instead.
///
/// Keyboard-interactive authentication is absent deliberately: its keyword
/// differs by version and is probed rather than assumed. See
/// [`KEYBOARD_INTERACTIVE_KEYWORDS`] and [`disable_keyboard_interactive`].
const SAFE_DIRECTIVES: [(&str, &str); 17] = [
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

impl HardenSsh {
    /// This task's id, named so the interface can recognise it.
    ///
    /// A constant rather than a literal at the match site, for the reason
    /// `LockRoot::ID` records: matching on a literal puts the id in two places
    /// with nothing tying them together, and a rename would leave the dialog
    /// silently falling back to the generic warning — which here is the one
    /// that does not list the accounts keeping access.
    pub const ID: &'static str = "ssh.harden";
}

impl Task for HardenSsh {
    fn id(&self) -> &'static str {
        Self::ID
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
         Requires at least one account that keeps SSH access afterwards — root \
         does not count, since this disables it — keeps a backup of the \
         previous configuration, and holds the change open until you confirm \
         you can still log in."
    }

    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    /// There is no configuration to harden without a daemon that reads one.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("sshd", "ssh.install")]
    }
    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        backend.ensure_config_present(executor, Capability::Ssh)?;

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Disabling password authentication with no key in place is the
        // documented way administrators lock themselves out of a server.
        //
        // Asked of every account rather than of root, and `true` because this
        // tier writes `PermitRootLogin no` a few lines below: a root key is
        // worthless the moment this task finishes, so counting it would approve
        // a lockout using the very route the task closes.
        let holders = accounts_keeping_ssh_access(executor, backend, &contents, true)?;

        if keeps_access(&holders).is_empty() {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoAccountKeepsSshAccess,
            });
        }

        report(
            progress,
            &Msg::TaskSshApplyingDirectives {
                count: SAFE_DIRECTIVES.len(),
            },
        );

        let hardened = SAFE_DIRECTIVES
            .into_iter()
            .fold(contents, |acc, (directive, value)| {
                sshd_config::set_directive(&acc, directive, value)
            });

        let hardened = disable_keyboard_interactive(executor, &hardened, progress)?;

        let backup =
            sshd_config::write_validated(executor, backend, self.id(), &hardened, progress)?;

        super::report_backup(backup.as_ref(), progress);

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

impl HardenSshStrict {
    /// This task's id, for the reason [`HardenSsh::ID`] records.
    pub const ID: &'static str = "ssh.harden-strict";
}

impl Task for HardenSshStrict {
    fn id(&self) -> &'static str {
        Self::ID
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
         Requires at least one account that this configuration still admits \
         and that holds a key, keeps a backup, and holds the change open until \
         you confirm you can still log in."
    }

    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    /// There is no configuration to harden without a daemon that reads one.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("sshd", "ssh.install")]
    }
    fn support(&self, family: Family) -> Support {
        match family {
            // openSUSE carries the same crypto-policies mechanism RHEL does —
            // `40-suse-crypto-policies.conf`, which Includes
            // `/etc/crypto-policies/back-ends/opensshserver.config` — and it
            // loses rather than wins, which is why this is `Yes` where RHEL is
            // `No`. The shipped `sshd_config` Includes `/etc/ssh/sshd_config.d`
            // on line 12 and its own `/usr/etc` drop-ins on line 18, and sshd
            // honours the first occurrence. Measured the way RHEL's refusal
            // was, against a daemon rather than inferred from the file:
            // `Ciphers aes256-ctr` written the way this task writes it came
            // back from `sshd -T` as the effective value.
            Family::Debian | Family::Arch | Family::Alpine | Family::Suse => Support::Yes,
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
        backend.ensure_config_present(executor, Capability::Ssh)?;

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Same guard as the safe tier. This task disables no password, but a
        // configuration that strands the administrator's client is just as
        // unrecoverable as one that refuses their password.
        //
        // `false` where the safe tier passes `true`: this tier writes no
        // `PermitRootLogin`, so whether root is a way in is a question for the
        // file rather than for the task, and the scan reads it there.
        let holders = accounts_keeping_ssh_access(executor, backend, &contents, false)?;

        if keeps_access(&holders).is_empty() {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoAccountKeepsSshAccess,
            });
        }

        report(progress, &Msg::TaskSshNarrowingAlgorithms);

        let mut hardened = contents;

        for class in algorithms::ALL_CLASSES {
            match algorithms::hardened_for(executor, class) {
                Some(value) => {
                    report(
                        progress,
                        &Msg::TaskSshAlgorithmClass {
                            directive: class.directive().to_owned(),
                            value: value.clone(),
                        },
                    );
                    hardened = sshd_config::set_directive(&hardened, class.directive(), &value);
                }
                // Skipping is the safe outcome, not a compromise: the
                // compiled-in default admits a reasonable range, while a list
                // narrowed too far refuses clients for no gain. Reported so
                // that a directive the administrator asked for is never
                // silently absent.
                None => progress(OutputLine::new(
                    Stream::Stderr,
                    format!(
                        "warning: {} left at the system default — this OpenSSH supports too \
                         few of the hardened algorithms to narrow it safely",
                        class.directive()
                    ),
                )),
            }
        }

        let hardened = STRICT_DIRECTIVES
            .into_iter()
            .fold(hardened, |acc, (directive, value)| {
                sshd_config::set_directive(&acc, directive, value)
            });

        let backup =
            sshd_config::write_validated(executor, backend, self.id(), &hardened, progress)?;

        super::report_backup(backup.as_ref(), progress);

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
/// left alone and said so — the seventeen directives that did apply are worth
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
        progress(OutputLine::new(
            Stream::Stderr,
            "warning: keyboard-interactive authentication left unchanged — this sshd \
                   recognises neither keyword for it"
                .to_owned(),
        ));
    }

    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::ssh::fixtures::{ROOT_PASSWD, TEST_KEY, no_values};

    /// A passwd file with root and one ordinary account.
    ///
    /// Both ranks are present deliberately: the scan orders by rank and filters
    /// by nothing, and a fixture holding only one rank could not tell the two
    /// apart. `Rank::Root` sorts before `Rank::Human`, so every scenario here
    /// answers root's lookup before alice's.
    const TWO_ACCOUNTS: &str = "root:x:0:0:root:/root:/bin/bash\n\
         alice:x:1000:1000::/home/alice:/bin/sh\n";

    /// The passwd entry `getent` returns for the ordinary account above.
    const ALICE_PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh";

    #[test]
    fn hardening_refuses_when_no_account_holds_a_key() {
        // The lockout guard: disabling passwords with no key anywhere on the
        // host strands the administrator outside the server.
        // Root is skipped without a lookup: this tier writes
        // `PermitRootLogin no`, so only alice is asked about.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::failure(1, ""),   // alice has no authorized_keys
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("hardening with no key anywhere must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoAccountKeepsSshAccess
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn hardening_proceeds_on_a_host_whose_root_is_locked() {
        // The regression this whole change exists for. Root holds no key and is
        // locked, which is the recommended posture; an ordinary account holds
        // one and is how the operator actually reaches the host. The old guard
        // asked root alone and refused, telling them to authorise a key for the
        // account this task is about to disable.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // alice's authorized_keys exists
            Reply::ok(TEST_KEY),     // and holds a valid key
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("an ordinary account with a key is a way back in");

        assert!(
            mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "the configuration must be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn hardening_refuses_when_only_root_holds_a_key() {
        // The subtle case a narrower fix gets wrong. Root's key satisfies the
        // old guard and is worthless the moment this tier writes
        // `PermitRootLogin no`, so counting it would approve a lockout using
        // the one route the task itself closes.
        //
        // Root sorts after alice — the scan orders human accounts first — so
        // alice is asked about before it.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::failure(1, ""),   // alice has no authorized_keys
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("a key held only by root is not a way back in");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoAccountKeepsSshAccess
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|c| c.contains("/root/.ssh/authorized_keys")),
            "root's key must not even be read: this tier disables the account. {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn hardening_refuses_a_key_held_by_an_account_allowusers_excludes() {
        // A real key held by an account the daemon already refuses is not a way
        // back in. The tiers ignored `AllowUsers` entirely before this.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\nAllowUsers bob\n"), // read sshd_config
            Reply::ok(TWO_ACCOUNTS),                // cat /etc/passwd
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("a key on an account AllowUsers excludes is not a way in");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoAccountKeepsSshAccess
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|c| c.contains("authorized_keys")),
            "no key file is worth reading when the directive excludes every account: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn the_scan_reaches_an_account_numbered_below_the_human_threshold() {
        // The uid threshold orders and never filters, which is the rule
        // `list_ranked` states. A site numbering a real account below it must
        // still be found, or the scan reports a host as stranded while somebody
        // is logged into it.
        const LOW_UID: &str = "root:x:0:0:root:/root:/bin/bash\n\
             ops:x:499:499::/home/ops:/bin/sh\n";

        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),                        // read sshd_config
            Reply::ok(LOW_UID),                            // cat /etc/passwd
            Reply::ok("ops:x:499:499::/home/ops:/bin/sh"), // getent passwd
            Reply::ok(""),                                 // authorized_keys exists
            Reply::ok(TEST_KEY),                           // and holds a valid key
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("an account below uid 1000 still keeps the host reachable");

        assert!(
            mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "the configuration must be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn hardening_sets_every_safe_directive() {
        // Iterates the table rather than listing directives again, so a pair
        // added there is covered here without this test being edited.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("hardening must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        for (directive, value) in SAFE_DIRECTIVES {
            assert!(
                written.contains(&format!("{directive} {value}")),
                "{directive} is missing from the written config"
            );
        }
    }

    #[test]
    fn hardening_sets_no_crypto_directives() {
        // The tier boundary: narrowing algorithms can strand a client that
        // could connect before, so it belongs to the strict task.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("runs");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        for directive in ["Ciphers", "KexAlgorithms", "MACs", "AllowTcpForwarding"] {
            assert!(
                !written.contains(directive),
                "{directive} belongs to the strict tier, got: {written}"
            );
        }
    }

    #[test]
    fn hardening_writes_the_keyword_this_sshd_understands() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            Reply::ok(""),           // probe: KbdInteractiveAuthentication accepted
            Reply::failure(
                1,
                "command-line: line 0: Bad configuration option: ChallengeResponseAuthentication",
            ),
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("runs");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(
            written.contains("KbdInteractiveAuthentication no"),
            "got: {written}"
        );
        assert!(
            !written.contains("ChallengeResponseAuthentication no"),
            "a keyword this sshd rejects must not be written, got: {written}"
        );
    }

    #[test]
    fn hardening_falls_back_to_the_legacy_keyword() {
        // OpenSSH before 6.9 does not know the current name. Writing it would
        // cost the whole change, not just this directive.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            Reply::failure(
                1,
                "command-line: line 0: Bad configuration option: KbdInteractiveAuthentication",
            ),
            Reply::ok(""), // probe: ChallengeResponseAuthentication accepted
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("runs");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(
            written.contains("ChallengeResponseAuthentication no"),
            "got: {written}"
        );
        assert!(
            !written.contains("KbdInteractiveAuthentication no"),
            "got: {written}"
        );
    }

    #[test]
    fn the_safe_tier_writes_the_number_of_directives_it_claims() {
        // The prose around this array said sixteen while the array held
        // seventeen, in two places, and `integration_shared.rs` said
        // seventeen — a number stated in three files and checked in none.
        // Tied to the array here so the next directive added is a failing
        // build rather than a comment that quietly stops being true.
        assert_eq!(
            SAFE_DIRECTIVES.len(),
            17,
            "update the seventeen named in this module's comments and in \
             tests/integration_shared.rs"
        );
    }

    #[test]
    fn hardening_skips_keyboard_interactive_when_neither_keyword_is_known() {
        // The property that makes probing worth its cost: one unusable keyword
        // must not take the other seventeen directives down with it.
        let bad_option = |keyword: &str| {
            Reply::failure(
                1,
                format!("command-line: line 0: Bad configuration option: {keyword}"),
            )
        };
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            bad_option("KbdInteractiveAuthentication"),
            bad_option("ChallengeResponseAuthentication"),
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            })
            .expect("the other directives must still apply");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must still be written");

        assert!(
            !written.contains("KbdInteractive") && !written.contains("ChallengeResponse"),
            "no unrecognised keyword may be written, got: {written}"
        );
        for (directive, value) in SAFE_DIRECTIVES {
            assert!(
                written.contains(&format!("{directive} {value}")),
                "{directive} must survive a failed probe"
            );
        }
        assert!(
            warnings.iter().any(|w| w.contains("keyboard-interactive")),
            "the skip must be reported, got: {warnings:?}"
        );
    }

    /// Scripts the four `ssh -Q` queries the strict tier makes, in order.
    fn query_replies(kex: &str, cipher: &str, mac: &str, host_key: &str) -> [Reply; 4] {
        [
            Reply::ok(kex),
            Reply::ok(cipher),
            Reply::ok(mac),
            Reply::ok(host_key),
        ]
    }

    #[test]
    fn strict_hardening_writes_only_supported_algorithms() {
        let mut replies = vec![
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            // The scan does not stop at the first account that passes, so
            // alice is asked about too before the algorithm queries begin.
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::failure(1, ""),   // alice has no authorized_keys
        ];
        replies.extend(query_replies(
            "curve25519-sha256\ndiffie-hellman-group16-sha512\n",
            // No chacha20 on this build: it must not reach the file.
            "aes256-gcm@openssh.com\naes256-ctr\n",
            "hmac-sha2-512-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\n",
            "ssh-ed25519\nrsa-sha2-512\n",
        ));
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(Family::Debian);

        HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("strict hardening must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(
            written.contains("Ciphers aes256-gcm@openssh.com,aes256-ctr"),
            "got: {written}"
        );
        assert!(
            !written.contains("chacha20"),
            "an algorithm this build lacks must not be written, got: {written}"
        );
        assert!(written.contains("RequiredRSASize 3072"), "got: {written}");
        assert!(written.contains("AllowTcpForwarding no"), "got: {written}");
    }

    #[test]
    fn strict_hardening_skips_a_directive_it_cannot_query() {
        // `ssh` absent, or a query name this release does not know. The task
        // still has other work to do and must finish it.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            Reply::failure(255, "Unsupported query"),
            Reply::failure(255, "Unsupported query"),
            Reply::failure(255, "Unsupported query"),
            Reply::failure(255, "Unsupported query"),
        ]);
        let backend = for_family(Family::Debian);

        HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("a failed query must not fail the task");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must still be written");

        for directive in ["Ciphers", "KexAlgorithms", "MACs", "HostKeyAlgorithms"] {
            assert!(
                !written.contains(directive),
                "{directive} must be left at the default, got: {written}"
            );
        }
        assert!(written.contains("RequiredRSASize 3072"), "got: {written}");
    }

    #[test]
    fn strict_hardening_warns_when_it_skips_a_directive() {
        // A directive the administrator asked for must never be silently
        // absent from the result.
        let mut replies = vec![
            Reply::ok("Port 22\n"),
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::ok(""),
            Reply::ok(TEST_KEY),
        ];
        replies.extend(query_replies(
            "curve25519-sha256\ndiffie-hellman-group16-sha512\n",
            // Only one hardened cipher survives: below the floor.
            "3des-cbc\naes256-ctr\n",
            "hmac-sha2-512-etm@openssh.com\nhmac-sha2-256-etm@openssh.com\n",
            "ssh-ed25519\nrsa-sha2-512\n",
        ));
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            })
            .expect("runs");

        assert!(
            warnings.iter().any(|w| w.contains("Ciphers")),
            "the skipped directive must be named, got: {warnings:?}"
        );
    }

    #[test]
    fn strict_hardening_refuses_when_no_account_holds_a_key() {
        // Root is asked about here and first: this tier writes no
        // `PermitRootLogin`, and the file does not deny it.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::failure(1, ""),   // root has no authorized_keys
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::failure(1, ""),   // alice has none either
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("strict hardening with no key anywhere must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoAccountKeepsSshAccess
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn strict_hardening_counts_root_where_the_file_still_admits_it() {
        // The tiers differ here and the difference is deliberate: this one
        // writes no `PermitRootLogin`, so whether root is a way in is a
        // question for the file rather than for the task. A configuration that
        // still admits root is one where root's key is a genuine way back in.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\nPermitRootLogin yes\n"), // read sshd_config
            Reply::ok(TWO_ACCOUNTS),                     // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),                      // getent passwd: root
            Reply::ok(""),                               // root's file exists
            Reply::ok(TEST_KEY),                         // and holds a key
            Reply::ok(ALICE_PASSWD),                     // getent passwd: alice
            Reply::failure(1, ""),                       // alice has no keys
        ]);
        let backend = for_family(Family::Debian);

        HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("root's key counts where the daemon still admits root");

        assert!(
            mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "the configuration must be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn strict_hardening_refuses_root_where_the_file_already_denies_it() {
        // The same tier, the opposite file. `ssh.harden` ran first and wrote
        // `PermitRootLogin no`, so root's key authorises nothing and this must
        // not count it — the scan reads the directive rather than assuming the
        // tier's own behaviour.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\nPermitRootLogin no\n"), // read sshd_config
            Reply::ok(TWO_ACCOUNTS),                    // cat /etc/passwd
            Reply::ok(ALICE_PASSWD),                    // getent passwd: alice
            Reply::failure(1, ""),                      // alice has no keys
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("root's key authorises nothing once the file denies root");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoAccountKeepsSshAccess
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn strict_hardening_reloads_rather_than_restarts() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::ok(""),
            Reply::ok(TEST_KEY),
        ]);
        let backend = for_family(Family::Debian);

        HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("runs");

        let commands = mock.recorded_lines();
        assert!(
            commands.iter().any(|c| c.contains("reload")),
            "got: {commands:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("restart")),
            "restarting drops the administrator's own session, got: {commands:?}"
        );
    }

    #[test]
    fn strict_hardening_offers_a_revert() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ROOT_PASSWD),  // getent passwd: root's home
            Reply::ok(""),
            Reply::ok(TEST_KEY),
        ]);
        let backend = for_family(Family::Debian);

        let outcome = HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("runs");

        assert!(
            outcome.is_revertible(),
            "narrowing algorithms can strand a client, so it must be undoable"
        );
    }

    #[test]
    fn hardening_disables_root_login_and_passwords() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // it contains a valid key
            Reply::ok(""),           // test -e for the write
            Reply::ok(""),           // cp backup
            Reply::ok(""),           // tee
            Reply::ok(""),           // sshd -t
            Reply::ok(""),           // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("hardening must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("PermitRootLogin no"));
        assert!(written.contains("PasswordAuthentication no"));
    }

    #[test]
    fn hardening_reloads_rather_than_restarts() {
        // Restarting would drop the administrator's own session.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(TWO_ACCOUNTS), // cat /etc/passwd
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),
            Reply::ok(TEST_KEY),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("hardening must succeed");

        let commands = mock.recorded_lines();
        assert!(commands.iter().any(|c| c.contains("systemctl reload")));
        assert!(!commands.iter().any(|c| c.contains("systemctl restart")));
    }
}
