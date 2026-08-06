//! SSH administration tasks.
//!
//! Not one of these tasks knows which distribution it runs on. Package names,
//! unit names and command syntax all arrive through the backend — that is the
//! property this whole design exists to provide.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::files::Backup;
use crate::domain::firewall::Protocol as FirewallProtocol;
use crate::error::{Error, Lockout, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::tasks::algorithms;
use crate::tasks::consequence::{Consequence, External, Protocol, Reason, firewall_check};
use crate::tasks::params::{MAX_PORT, Param, ParamKind, ParamValues};
use crate::tasks::revert::{Outcome, Revert};
use crate::tasks::sshd_config;
use crate::tasks::{Category, Node, Progress, Support, Task, supported_everywhere};

/// Where a user's authorised keys live, relative to their home directory.
const AUTHORIZED_KEYS_RELATIVE: &str = ".ssh/authorized_keys";

/// Mode SSH requires on `~/.ssh`; anything looser makes sshd ignore the keys.
const SSH_DIR_MODE: u32 = 0o700;

/// Mode SSH requires on `authorized_keys`.
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

/// Key types `initd` accepts in an `authorized_keys` entry.
const VALID_KEY_PREFIXES: [&str; 5] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// Default port offered when none is given.
const DEFAULT_SSH_PORT: u32 = 22;

/// Builds the SSH category, subdivided by what each task acts on.
///
/// The area owns its own subdivision so that `tasks::tree()` stays a flat list
/// of areas. Tasks appear here with no values at all: those they need are
/// declared through `params()` and collected when the task is run.
pub fn category() -> Category {
    Category::new(
        "SSH",
        vec![
            Node::Category(Category::new(
                "Service",
                vec![Node::Task(Box::new(InstallSsh))],
            )),
            Node::Category(Category::new(
                "Configuration",
                vec![
                    // Ordered as they would be applied: narrowing the
                    // algorithms of a server whose passwords are still
                    // enabled is a strange place to start.
                    Node::Task(Box::new(HardenSsh)),
                    Node::Task(Box::new(HardenSshStrict)),
                    Node::Task(Box::new(ChangePort)),
                ],
            )),
            Node::Category(Category::new(
                "Keys",
                vec![Node::Task(Box::new(AuthorizeKey))],
            )),
            // Who may log in, rather than how the daemon is tuned or which key
            // material exists — neither of the categories above fits it.
            Node::Category(Category::new(
                "Access",
                vec![Node::Task(Box::new(RestrictUsers))],
            )),
        ],
    )
}

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Installs the OpenSSH server and enables it at boot.
pub struct InstallSsh;

impl Task for InstallSsh {
    fn id(&self) -> &'static str {
        "ssh.install"
    }

    fn title(&self) -> &'static str {
        "Install and enable the SSH server"
    }

    fn description(&self) -> &'static str {
        "Installs the OpenSSH server package and enables its service so it \
         starts at boot."
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // The task asks for a capability; the backend knows the names.
        let package = backend.package_for(Capability::Ssh);
        let service = backend.service_for(Capability::Ssh);

        if backend.packages().is_installed(executor, package)? {
            report(progress, format!("{package} is already installed"));
        } else {
            report(progress, format!("Installing {package}..."));
            backend.packages().install(executor, package)?;
        }

        report(progress, format!("Enabling {service}..."));
        backend.services().enable_and_start(executor, service)?;

        let state = backend.services().state(executor, service)?;
        report(
            progress,
            format!(
                "{service}: {}, {}",
                if state.active { "active" } else { "inactive" },
                if state.enabled { "enabled" } else { "disabled" }
            ),
        );

        // Installing and enabling a service cannot cost the administrator
        // their way in, so there is nothing worth offering to undo.
        Ok(Outcome::Done)
    }
}

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

/// Wraps a configuration backup as the undo for a change already applied.
///
/// A change with no backup — a file that did not exist — has nothing to put
/// back, so it finishes rather than offering an undo that would delete it.
fn revertible(backup: Option<Backup>, backend: &dyn Backend) -> Outcome {
    backup.map_or(Outcome::Done, |backup| {
        Outcome::Revertible(Revert::ConfigFile {
            backup,
            service: backend.service_for(Capability::Ssh),
        })
    })
}

/// Adds a public key to a user's `authorized_keys`.
///
/// Fieldless: the user and the key are declared as parameters and collected
/// when the task is run, so the tree can offer it without inventing values.
pub struct AuthorizeKey;

impl AuthorizeKey {
    /// Name of the parameter holding the account to authorise the key for.
    pub const USER: &'static str = "user";
    /// Name of the parameter holding the key itself.
    pub const KEY: &'static str = "key";
}

impl Task for AuthorizeKey {
    fn id(&self) -> &'static str {
        "ssh.authorize-key"
    }

    fn title(&self) -> &'static str {
        "Authorise a public key"
    }

    fn description(&self) -> &'static str {
        "Appends a public key to the user's authorized_keys, creating ~/.ssh \
         with the strict permissions sshd requires."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // root is offered because it is the account that always exists,
            // not because it is the one to prefer.
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_initial("root")
                .with_hint("the account the key authorises"),
            Param::new(Self::KEY, "Public key", ParamKind::PublicKey)
                .with_hint("paste the contents of a .pub file"),
        ]
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();
        let key = values.get(Self::KEY)?.trim().to_owned();
        let key = key.as_str();

        is_valid_public_key(key)?;

        let files = backend.files();
        let home = home_dir(&user);
        let ssh_dir = format!("{home}/.ssh");
        let path = format!("{home}/{AUTHORIZED_KEYS_RELATIVE}");

        // sshd silently ignores authorized_keys when the directory or file is
        // group- or world-accessible, so the modes are part of the operation
        // rather than an afterthought.
        files.create_dir(executor, &ssh_dir, SSH_DIR_MODE)?;
        files.set_owner(executor, &ssh_dir, &user)?;

        let present = files.exists(executor, &path)?;

        let existing = if present {
            files.read(executor, &path)?
        } else {
            String::new()
        };

        if key_is_present(&existing, key) {
            report(progress, "The key is already authorised; nothing to do");
            return Ok(Outcome::Done);
        }

        report(progress, format!("Adding the key to {path}..."));

        // Append rather than replace: other keys in the file are other
        // people's access.
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(key);
        updated.push('\n');

        // A new file is created empty, restricted, and only then written. The
        // other order leaves the file world-readable for as long as the two
        // privileged commands take — brief, and long enough for any account on
        // the box to read it or, worse, to hold it open and influence which
        // keys sshd honours. An empty file discloses nothing, which is what
        // makes the ordering possible. Same lesson as `wg0.conf`.
        //
        // An existing file keeps its own mode: it was created this way, and
        // rewriting it is what the append below is for.
        if !present {
            files.write(executor, &path, "")?;
            files.set_mode(executor, &path, AUTHORIZED_KEYS_MODE)?;
            files.set_owner(executor, &path, &user)?;
        }

        files.write(executor, &path, &updated)?;

        // Re-stated for a file that already existed, since a file left by
        // something else may carry a mode sshd refuses to read.
        if present {
            files.set_mode(executor, &path, AUTHORIZED_KEYS_MODE)?;
            files.set_owner(executor, &path, &user)?;
        }

        report(progress, "Key authorised");

        // Authorising a key only ever grants access; undoing it is the
        // dangerous direction, so it is not offered here.
        Ok(Outcome::Done)
    }
}

/// Home directory of a user.
///
/// Root is the documented exception to `/home/<name>`.
fn home_dir(user: &str) -> String {
    if user == "root" {
        "/root".to_owned()
    } else {
        format!("/home/{user}")
    }
}

/// Whether the key is already present, comparing the type and body only.
///
/// The trailing comment is ignored: the same key added from two machines
/// carries two different comments but grants identical access.
fn key_is_present(contents: &str, key: &str) -> bool {
    let fingerprint = key_fingerprint(key);

    contents
        .lines()
        .any(|line| key_fingerprint(line.trim()) == fingerprint)
}

/// The identifying part of a key line: its type and body, without the comment.
fn key_fingerprint(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split_whitespace();

    Some((parts.next()?, parts.next()?))
}

/// Changes the port sshd listens on.
///
/// Fieldless: the port is declared as a parameter and collected when the task
/// is run, so the tree can offer it without inventing a value.
pub struct ChangePort;

impl ChangePort {
    /// Name of the parameter holding the port to move sshd to.
    pub const PORT: &'static str = "port";
}

impl Task for ChangePort {
    fn id(&self) -> &'static str {
        "ssh.change-port"
    }

    fn title(&self) -> &'static str {
        "Change the SSH port"
    }

    fn description(&self) -> &'static str {
        "Changes the port sshd listens on, keeping a backup and validating \
         before reloading. The new port may also need firewall or SELinux \
         configuration."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::PORT, "Port", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .with_hint("1-65535"),
        ]
    }

    supported_everywhere!();

    fn consequences(&self, backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(port) = values.port(Self::PORT) else {
            // The port failed to parse, so the task will not run and there is
            // nothing downstream to invalidate.
            return Vec::new();
        };

        // Moving to the port sshd already uses changes nothing, so it
        // invalidates nothing. Warning anyway would train the administrator to
        // dismiss these without reading them.
        if port == DEFAULT_SSH_PORT {
            return Vec::new();
        }

        vec![
            Consequence::Invalidates {
                task: "firewall.allow-port",
                reason: Reason::PortChanged {
                    from: DEFAULT_SSH_PORT.to_string(),
                    to: port.to_string(),
                },
                // Verifiable now that the firewall is modelled: the rule either
                // names the new port or it does not, and the ruleset is the
                // only honest answer. The front-end phrases the query, since
                // the one holding this host's ruleset is not the same on every
                // family — and the needle each returns is the whole rule rather
                // than the bare number, since `2222` also appears in `22220`.
                check: firewall_check(backend, port, FirewallProtocol::Tcp),
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port,
                    protocol: Protocol::Tcp,
                },
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let port = values.port(Self::PORT)?;

        // Checked again here rather than trusted from the interface: the CLI
        // reaches this same path without passing through a form.
        if port == 0 || port > MAX_PORT {
            return Err(Error::InvalidPort { port });
        }

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // An unset Port directive means sshd is on its default of 22.
        let current = sshd_config::directive_value(&contents, "Port")
            .unwrap_or_else(|| DEFAULT_SSH_PORT.to_string());

        if current == port.to_string() {
            report(
                progress,
                format!("The port is already {current}; nothing to do"),
            );
            return Ok(Outcome::Done);
        }

        let updated = sshd_config::set_directive(&contents, "Port", &port.to_string());

        report(
            progress,
            format!("Changing the port from {current} to {}...", port),
        );
        let backup = sshd_config::write_validated(executor, backend, &updated)?;

        // Debian ships ssh.socket alongside ssh.service. When it is active the
        // socket owns the listening port, so editing sshd_config alone changes
        // nothing. Detect and warn rather than silently reconfiguring units.
        warn_if_socket_activated(executor, backend, progress)?;

        // Before the reload, not after: SELinux confines which ports the
        // daemon's own domain may bind, so a reload onto an unlabelled port
        // leaves a daemon that will not start — from a file that is valid,
        // was written successfully, and that `sshd -t` approved. Labelling
        // afterwards would be labelling a port nothing is listening on.
        //
        // Asked of the host rather than of the family: RHEL ships SELinux
        // enabled and administrators disable it, and where nothing enforces
        // this costs one command that answers by exit code.
        if backend.selinux().is_enforcing(executor)? {
            report(progress, format!("Labelling port {port} for SELinux..."));

            backend.selinux().allow_ssh_port(
                executor,
                port,
                crate::domain::firewall::Protocol::Tcp,
            )?;
        }

        report(
            progress,
            format!(
                "Port set to {port}. If a firewall is active, the new port may \
                 need to be opened before it can be reached."
            ),
        );

        reload_ssh(executor, backend, progress)?;

        // The firewall and SELinux warnings above are exactly the reasons this
        // change can succeed and still leave the machine unreachable, which is
        // why the old port is kept available to go back to.
        Ok(revertible(backup, backend))
    }
}

/// Warns when socket activation would override the configured port.
fn warn_if_socket_activated(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    const SSH_SOCKET: &str = "ssh.socket";

    let state = backend.services().state(executor, SSH_SOCKET)?;

    if state.active || state.enabled {
        progress(OutputLine {
            stream: Stream::Stderr,
            text: format!(
                "warning: {SSH_SOCKET} is active and defines the listening port \
                 itself. The port in sshd_config will not take effect until the \
                 socket unit is reconfigured or disabled."
            ),
        });
    }

    Ok(())
}

/// Whether the named user has at least one authorised key.
///
/// Read through the file editor rather than `std::fs` so it works under
/// privilege escalation, and so a missing file is a plain `false`.
fn has_authorized_key(executor: &dyn Executor, backend: &dyn Backend, user: &str) -> Result<bool> {
    let path = format!("{}/{AUTHORIZED_KEYS_RELATIVE}", home_dir(user));

    if !backend.files().exists(executor, &path)? {
        return Ok(false);
    }

    let contents = backend.files().read(executor, &path)?;

    Ok(contents
        .lines()
        .any(|line| is_valid_public_key(line.trim()).is_ok()))
}

/// Reloads SSH so a new configuration takes effect.
///
/// Reload rather than restart: restarting drops the very session the
/// administrator is connected through.
fn reload_ssh(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    let service = backend.service_for(Capability::Ssh);

    report(progress, format!("Reloading {service}..."));
    backend.services().reload(executor, service)
}

/// Validates the shape of an `authorized_keys` entry.
///
/// Only structural validation: type prefix plus a base64-looking body. Full
/// cryptographic verification is `ssh-keygen`'s job, and a malformed key would
/// make sshd ignore the whole file.
pub fn is_valid_public_key(line: &str) -> Result<()> {
    let invalid = |reason: &str| Error::InvalidPublicKey {
        reason: reason.to_owned(),
    };

    // Before anything else: `split_whitespace` treats a line break like any
    // other separator, so a value carrying one would validate as a single key
    // and then be written verbatim as two entries in `authorized_keys` — the
    // second of them never approved. `AuthorizeKey` only trims the outer
    // whitespace, and the CLI hands its argument straight here without passing
    // through the interface's per-keystroke filter, so this is the barrier.
    if line.contains(['\n', '\r']) {
        return Err(invalid("a key cannot span more than one line"));
    }

    let mut parts = line.split_whitespace();
    let key_type = parts.next().ok_or_else(|| invalid("the line is empty"))?;

    if !VALID_KEY_PREFIXES.contains(&key_type) {
        return Err(invalid(&format!("unrecognised key type: {key_type}")));
    }

    let body = parts
        .next()
        .ok_or_else(|| invalid("the key has no body after its type"))?;

    if body.len() < 32 || !body.bytes().all(is_base64_byte) {
        return Err(invalid("the key body is not valid base64"));
    }

    Ok(())
}

/// Whether a byte may appear in base64 content.
const fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// Restricts SSH login to a named set of accounts.
///
/// Fieldless: the accounts are declared as a parameter and collected when the
/// task is run, so the tree can offer it without inventing a list.
pub struct RestrictUsers;

impl RestrictUsers {
    /// Name of the parameter holding the accounts permitted to log in.
    pub const USERS: &'static str = "users";
}

impl Task for RestrictUsers {
    fn id(&self) -> &'static str {
        "ssh.allow-users"
    }

    fn title(&self) -> &'static str {
        "Restrict SSH login to named users"
    }

    fn description(&self) -> &'static str {
        "Sets AllowUsers in /etc/ssh/sshd_config to the accounts you name. \
         Afterwards sshd refuses every other account, including root and \
         including accounts that hold a valid key. Each account is checked to \
         exist first, and at least one of them must already have an authorised \
         key, since password authentication may be disabled. A backup is kept \
         and the change is held open until you confirm you can still log in."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // No starting value: seeding "root" would suggest the root-only
            // configuration `ssh.harden` exists to disable.
            Param::new(Self::USERS, "Allowed users", ParamKind::UsernameList)
                .with_hint("space-separated; every other account is refused"),
        ]
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let users = values.get(Self::USERS)?.trim().to_owned();

        // Checked again here rather than trusted from the interface: nothing
        // escapes a directive's value when it is written, so a newline in this
        // string would append a directive of the caller's choosing to a file
        // edited as root.
        ParamKind::UsernameList
            .validate(&users)
            .map_err(|reason| Error::InvalidAllowUsers { reason })?;

        let named: Vec<&str> = users.split_whitespace().collect();

        // An account that does not exist yields a configuration `sshd -t`
        // accepts and that matches nobody, so every login is refused. A typo
        // is the likely cause, which is why the name is reported back.
        for user in &named {
            if !backend.accounts().exists(executor, user)? {
                return Err(Error::LockoutRisk {
                    kind: Lockout::UnknownUser {
                        user: (*user).to_owned(),
                    },
                });
            }
        }

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Holding a key is not the same as being able to log in. An account
        // the daemon already refuses cannot be the one way back in, and root
        // is the case that matters: `ssh.harden` sets PermitRootLogin no, so
        // `AllowUsers root` afterwards produces a file sshd accepts and that
        // admits nobody. Nothing rolls that back, because nothing is wrong
        // with it.
        let root_refused = sshd_config::directive_value(&contents, "PermitRootLogin")
            .is_some_and(|value| value.eq_ignore_ascii_case("no"));

        // At least one, not all: a service account that logs in by other means
        // is a legitimate member of the list. One account that can log in and
        // holds a key is one way back in.
        let mut with_keys = Vec::new();
        for user in &named {
            let refused_outright = root_refused && *user == "root";

            if !refused_outright && has_authorized_key(executor, backend, user)? {
                with_keys.push(*user);
            }
        }

        if with_keys.is_empty() {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoKeyForAllowedUsers {
                    users: users.clone(),
                },
            });
        }

        // Stated before the change lands rather than after: this is the point
        // where the administrator can still recognise a name they did not
        // intend. Which accounts hold a key is the part that decides whether
        // the list is reachable at all.
        progress(OutputLine {
            stream: Stream::Stderr,
            text: format!(
                "After this change only these accounts may log in over SSH: {users}. \
                 Of those, {} already hold an authorised key.",
                with_keys.join(", ")
            ),
        });

        report(progress, format!("Restricting SSH login to {users}..."));

        let updated = sshd_config::set_directive(&contents, "AllowUsers", &users);
        let backup = sshd_config::write_validated(executor, backend, &updated)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// For tasks that declare no parameters.
    fn no_values() -> ParamValues {
        ParamValues::new()
    }

    /// The values `AuthorizeKey` declares, as the interface would collect them.
    fn key_values(user: &str, key: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(AuthorizeKey::USER, user);
        values.set(AuthorizeKey::KEY, key);
        values
    }

    /// The value `ChangePort` declares.
    fn port_values(port: u32) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(ChangePort::PORT, port.to_string());
        values
    }

    /// Runs the task against a mock, returning the commands it issued.
    fn run_install(family: Family, replies: Vec<Reply>) -> Vec<String> {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);

        InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("install must succeed");

        mock.recorded_lines()
    }

    #[test]
    fn uses_debian_names_on_debian() {
        // First reply: package not installed, so an install follows.
        let commands = run_install(Family::Debian, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("apt-get install -y openssh-server")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now ssh.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn uses_arch_names_on_arch() {
        let commands = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("pacman -S") && c.contains("openssh")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now sshd.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn the_same_task_produces_different_commands_per_family() {
        // The core claim of the design: identical task code, distro-correct
        // commands, with the package and the unit diverging independently.
        let debian = run_install(Family::Debian, vec![Reply::failure(1, "")]);
        let arch = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert_ne!(debian, arch);
    }

    #[test]
    fn skips_installation_when_the_package_is_present() {
        // First reply reports the package as installed.
        let commands = run_install(Family::Debian, vec![Reply::ok("install ok installed")]);

        assert!(
            !commands.iter().any(|c| c.contains("apt-get install")),
            "an installed package must not be reinstalled: {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.contains("systemctl enable")),
            "the service must still be enabled: {commands:?}"
        );
    }

    #[test]
    fn a_failing_install_propagates() {
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""),
            Reply::failure(100, "E: Unable to locate package"),
        ]);
        let backend = for_family(Family::Debian);

        let err = InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("a failing install must surface");

        assert!(
            matches!(err, crate::error::Error::CommandFailed { code: 100, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn reports_progress_to_the_caller() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |line| {
                lines.push(line.text)
            })
            .expect("install must succeed");

        assert!(!lines.is_empty(), "the task must report what it is doing");
    }

    #[test]
    fn supports_both_families() {
        assert!(InstallSsh.supports(Family::Debian));
        assert!(InstallSsh.supports(Family::Arch));
    }

    /// A valid ed25519 key body, long enough to pass structural validation.
    const TEST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ user@host";

    #[test]
    fn accepts_well_formed_public_keys() {
        for key_type in ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"] {
            let key = format!("{key_type} AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH x");
            assert!(
                is_valid_public_key(&key).is_ok(),
                "{key_type} must be valid"
            );
        }
    }

    #[test]
    fn rejects_malformed_public_keys() {
        // A malformed key makes sshd ignore the entire authorized_keys file.
        for bad in [
            "",
            "not-a-key-type AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH",
            "ssh-ed25519",
            "ssh-ed25519 short",
            "ssh-ed25519 has spaces and!invalid$chars@@@@@@@@@@@@@@@@@@@@",
        ] {
            assert!(
                is_valid_public_key(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_key_smuggling_a_second_line() {
        // `split_whitespace` treats a newline like any other separator, so a
        // value carrying one reads as a single key while `authorized_keys`
        // receives two entries — the second one nobody approved. The CLI hands
        // its argument straight to this check, so it is the only barrier.
        let smuggled = format!(
            "{TEST_KEY}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH attacker"
        );

        assert!(
            is_valid_public_key(&smuggled).is_err(),
            "a value spanning two lines is two keys, not one"
        );
    }

    #[test]
    fn rejects_a_key_carrying_a_carriage_return() {
        // sshd splits on \r as well, so it smuggles an entry the same way.
        let smuggled = format!(
            "{TEST_KEY}\rssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH attacker"
        );

        assert!(is_valid_public_key(&smuggled).is_err());
    }

    #[test]
    fn hardening_refuses_without_an_authorised_key() {
        // The lockout guard: disabling passwords with no key stranded the
        // administrator outside the server.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::failure(1, ""),  // authorized_keys does not exist
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("hardening without a key must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForRoot
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
    fn hardening_sets_every_safe_directive() {
        // Iterates the table rather than listing directives again, so a pair
        // added there is covered here without this test being edited.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
            Reply::ok(""),          // probe: KbdInteractiveAuthentication accepted
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
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
    fn hardening_skips_keyboard_interactive_when_neither_keyword_is_known() {
        // The property that makes probing worth its cost: one unusable keyword
        // must not take the other sixteen directives down with it.
        let bad_option = |keyword: &str| {
            Reply::failure(
                1,
                format!("command-line: line 0: Bad configuration option: {keyword}"),
            )
        };
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
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
        let mut replies = vec![Reply::ok("Port 22\n"), Reply::ok(""), Reply::ok(TEST_KEY)];
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
    fn strict_hardening_refuses_without_an_authorised_key() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::failure(1, ""),  // authorized_keys does not exist
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSshStrict
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("strict hardening without a key must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForRoot
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
    fn strict_hardening_reloads_rather_than_restarts() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
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

    /// For the task that restricts login to named accounts.
    fn users_values(users: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(RestrictUsers::USERS, users);
        values
    }

    #[test]
    fn restricting_users_writes_the_allow_list() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok(""),          // getent bob
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // alice authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::ok(""),          // bob authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::ok(""),          // test -e for the write
            Reply::ok(""),          // cp backup
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice bob"),
                &mut |_| {},
            )
            .expect("restricting to existing users with keys must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("AllowUsers alice bob"), "got: {written}");
    }

    #[test]
    fn restricting_users_refuses_an_unknown_account() {
        // A typo yields a config sshd accepts and that matches nobody, so
        // every login is refused.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),         // getent alice
            Reply::failure(2, ""), // getent admn — no such account
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice admn"),
                &mut |_| {},
            )
            .expect_err("an unknown account must refuse");

        assert!(
            matches!(&err, Error::LockoutRisk { kind: Lockout::UnknownUser { user } } if user == "admn"),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn restricting_users_refuses_when_no_named_user_has_a_key() {
        // Hardening disables password authentication, so an allow-list where
        // nobody holds a key leaves no way to log in at all.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok(""),          // getent bob
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::failure(1, ""),  // alice has no authorized_keys
            Reply::failure(1, ""),  // nor does bob
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice bob"),
                &mut |_| {},
            )
            .expect_err("an allow-list with no keys must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForAllowedUsers { .. }
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
    fn restricting_users_accepts_when_one_of_several_holds_a_key() {
        // Deliberately "at least one", not "all": a service account that logs
        // in by other means is a legitimate member of the list.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok(""),          // getent deploy
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // alice authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::failure(1, ""),  // deploy has none
            Reply::ok(""),          // test -e for the write
            Reply::ok(""),          // cp backup
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice deploy"),
                &mut |_| {},
            )
            .expect("one account with a key is one way back in");
    }

    #[test]
    fn restricting_users_refuses_to_allow_only_an_account_sshd_already_rejects() {
        // The trap: root holds a key, so a check for key possession alone
        // passes, but `ssh.harden` already set PermitRootLogin no. The result
        // is a file sshd accepts and that admits nobody — and since nothing is
        // wrong with it, nothing rolls it back.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                     // getent root
            Reply::ok("PermitRootLogin no\n"), // read sshd_config
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("root"), &mut |_| {})
            .expect_err("an allow-list of accounts sshd refuses must be refused");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForAllowedUsers { .. }
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
    fn restricting_users_still_allows_root_where_root_may_log_in() {
        // The guard must not refuse a list naming root on a server that has
        // not disabled root login.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent root
            Reply::ok("Port 22\n"), // read sshd_config — root login untouched
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("root"), &mut |_| {})
            .expect("root may still be named where root may still log in");
    }

    #[test]
    fn restricting_users_rejects_a_value_that_would_inject_a_directive() {
        // Nothing escapes a directive's value when it is written, and the CLI
        // never passes through the keystroke filter, so this is the only
        // barrier between an argument and a file edited as root.
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice\nPermitRootLogin yes"),
                &mut |_| {},
            )
            .expect_err("a newline must be refused");

        assert!(matches!(err, Error::InvalidAllowUsers { .. }), "{err:?}");
        assert!(
            mock.recorded().is_empty(),
            "the value must be rejected before anything runs, got: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn restricting_users_names_who_will_still_be_able_to_log_in() {
        // The administrator's last chance to recognise a name they did not
        // intend is before the change lands, not after.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // alice authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice"),
                &mut |line| {
                    if line.stream == Stream::Stderr {
                        warnings.push(line.text);
                    }
                },
            )
            .expect("runs");

        assert!(
            warnings.iter().any(|w| w.contains("alice")),
            "got: {warnings:?}"
        );
    }

    #[test]
    fn restricting_users_offers_a_revert() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // holds a key
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        let outcome = RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("alice"), &mut |_| {})
            .expect("runs");

        assert!(
            outcome.is_revertible(),
            "the change must be held open for confirmation"
        );
    }

    #[test]
    fn the_key_guard_reads_the_named_users_own_file() {
        // Generalised from root: `ssh.allow-users` has to ask the same question
        // about an ordinary account, whose keys live under /home.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),       // authorized_keys exists
            Reply::ok(TEST_KEY), // and holds a valid key
        ]);
        let backend = for_family(Family::Debian);

        let found = has_authorized_key(&mock, backend.as_ref(), "alice")
            .expect("reading the file must succeed");

        assert!(found, "a valid key must be recognised");
        assert!(
            mock.recorded_lines()
                .iter()
                .any(|c| c.contains("/home/alice/.ssh/authorized_keys")),
            "got: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn hardening_disables_root_login_and_passwords() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
            Reply::ok(""),          // test -e for the write
            Reply::ok(""),          // cp backup
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // systemctl reload
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

    #[test]
    fn authorising_a_key_sets_the_permissions_sshd_requires() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),         // install -d
            Reply::ok(""),         // chown dir
            Reply::failure(1, ""), // authorized_keys absent
            Reply::ok(""),         // test -e inside write
            Reply::ok(""),         // tee
            Reply::ok(""),         // chmod
            Reply::ok(""),         // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let commands = mock.recorded_lines();
        assert!(
            commands.iter().any(|c| c == "install -d -m 700 /root/.ssh"),
            "~/.ssh must be 700: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "chmod 600 /root/.ssh/authorized_keys"),
            "authorized_keys must be 600: {commands:?}"
        );
    }

    #[test]
    fn a_new_authorized_keys_is_restricted_before_it_holds_a_key() {
        // The property, and the reason it is asserted on the order rather than
        // on the final mode: `tee` creates a file with the shell's umask, so
        // writing the key first leaves it world-readable until the chmod lands
        // one privileged command later. A local account can read it in that
        // window, or hold it open and influence which keys sshd honours. The
        // fix is the one `wg0.conf` already carries — create empty, restrict,
        // then write — and a test that only checks the mode at the end passes
        // against both orders.
        // Strict: the subject is the order, so a command appearing between the
        // chmod and the write must fail this rather than answer success from
        // nowhere.
        let mock = MockExecutor::with_exact_replies([
            Reply::ok(""),         // install -d
            Reply::ok(""),         // chown dir
            Reply::failure(1, ""), // test -e: authorized_keys absent
            Reply::ok(""),         // test -e, opening the empty write
            Reply::ok(""),         // cp -p: backup
            Reply::ok(""),         // tee: create it empty
            Reply::ok(""),         // chmod 600, before any key exists
            Reply::ok(""),         // chown file
            Reply::ok(""),         // test -e, opening the real write
            Reply::ok(""),         // cp -p: backup
            Reply::ok(""),         // tee: the key
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let commands = mock.recorded_lines();
        let chmod = commands
            .iter()
            .position(|c| c == "chmod 600 /root/.ssh/authorized_keys")
            .expect("the file must be restricted");
        let wrote_key = mock
            .recorded()
            .iter()
            .position(|c| {
                c.program == "tee"
                    && c.stdin
                        .as_deref()
                        .is_some_and(|data| data.contains(TEST_KEY))
            })
            .expect("the key must be written");

        assert!(
            chmod < wrote_key,
            "the mode must be set before the key is written: {commands:?}"
        );
    }

    #[test]
    fn an_existing_authorized_keys_keeps_the_keys_already_in_it() {
        // The other direction of the same change: a file that already exists
        // is appended to, never truncated first — the keys in it are other
        // people's access.
        const OTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther other@host";

        let mock = MockExecutor::with_replies([
            Reply::ok(""),        // install -d
            Reply::ok(""),        // chown dir
            Reply::ok(""),        // authorized_keys exists
            Reply::ok(OTHER_KEY), // holding somebody else's key
            Reply::ok(""),        // test -e inside write
            Reply::ok(""),        // tee
            Reply::ok(""),        // chmod
            Reply::ok(""),        // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let written = mock
            .recorded()
            .iter()
            .find_map(|c| (c.program == "tee").then(|| c.stdin.clone()).flatten())
            .expect("the file must be written");

        assert!(written.contains(OTHER_KEY), "{written:?}");
        assert!(written.contains(TEST_KEY), "{written:?}");
    }

    #[test]
    fn authorising_the_same_key_twice_does_not_duplicate_it() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),       // install -d
            Reply::ok(""),       // chown
            Reply::ok(""),       // authorized_keys exists
            Reply::ok(TEST_KEY), // and already holds the key
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("a duplicate key must be a no-op");

        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "an already-present key must not be written again"
        );
    }

    #[test]
    fn authorising_a_key_keeps_existing_ones() {
        let existing = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQfakebodyvaluehere someone@else";
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(existing),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the file must be written");

        assert!(
            written.contains(existing),
            "existing keys are other people's access"
        );
        assert!(written.contains(TEST_KEY));
    }

    #[test]
    fn authorising_rejects_an_invalid_key_before_touching_the_system() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        let err = AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", "definitely not a key"),
                &mut |_| {},
            )
            .expect_err("an invalid key must be rejected");

        assert!(matches!(err, Error::InvalidPublicKey { .. }), "{err:?}");
        assert!(
            mock.recorded().is_empty(),
            "validation must happen before any command runs"
        );
    }

    #[test]
    fn changing_the_port_writes_and_validates() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::failure(3, ""),  // ssh.socket is-active
            Reply::failure(1, ""),  // ssh.socket is-enabled
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("Port 2222"));
    }

    #[test]
    fn an_enforcing_host_gets_the_port_labelled_before_the_reload() {
        // The ordering is the whole point. SELinux confines which ports the
        // daemon may bind, so a reload onto an unlabelled port leaves a daemon
        // that will not start — from a file `sshd -t` approved.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::failure(3, ""),  // ssh.socket is-active
            Reply::failure(1, ""),  // ssh.socket is-enabled
            Reply::ok(""),          // selinuxenabled
            Reply::ok(""),          // semanage port -a
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Rhel);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let lines = mock.recorded_lines();
        let labelled = lines
            .iter()
            .position(|line| line.contains("semanage"))
            .expect("the port must be labelled: {lines:?}");
        let reloaded = lines
            .iter()
            .position(|line| line.contains("reload"))
            .expect("the daemon must be reloaded: {lines:?}");

        assert!(
            labelled < reloaded,
            "the label must precede the reload: {lines:?}"
        );
        assert!(
            lines[labelled].contains("2222") && lines[labelled].contains("ssh_port_t"),
            "the new port must be labelled for SSH: {lines:?}"
        );
    }

    #[test]
    fn a_host_that_does_not_enforce_is_not_asked_to_label_anything() {
        // `selinuxenabled` exits non-zero on a RHEL host whose administrator
        // turned SELinux off, and running `semanage` there would fail on a
        // policy that is not managed — reported as an error the administrator
        // would have to interpret, over a port that needed no label.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::failure(3, ""),  // ssh.socket is-active
            Reply::failure(1, ""),  // ssh.socket is-enabled
            Reply::failure(1, ""),  // selinuxenabled: disabled
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Rhel);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("semanage")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_family_without_selinux_runs_no_check_at_all() {
        // The three families that have no policy answer from a constant, so
        // the task's question costs them nothing — no command, no process.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::failure(3, ""),  // ssh.socket is-active
            Reply::failure(1, ""),  // ssh.socket is-enabled
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let lines = mock.recorded_lines();
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("selinuxenabled") || line.contains("semanage")),
            "{lines:?}"
        );
    }

    #[test]
    fn changing_the_port_rejects_out_of_range_values() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        for port in [0, 70_000] {
            let err = ChangePort
                .run(&mock, backend.as_ref(), &port_values(port), &mut |_| {})
                .expect_err("an out-of-range port must be rejected");

            assert!(matches!(err, Error::InvalidPort { .. }), "{err:?}");
        }
    }

    #[test]
    fn changing_the_port_warns_when_socket_activation_is_in_play() {
        // Debian's ssh.socket owns the port; editing sshd_config alone would
        // silently do nothing.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("active\n"), // ssh.socket is active
            Reply::ok("enabled\n"),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            })
            .expect("changing the port must succeed");

        assert!(
            warnings.iter().any(|w| w.contains("ssh.socket")),
            "socket activation must be reported: {warnings:?}"
        );
    }

    #[test]
    fn destructive_tasks_are_marked_as_such() {
        // The TUI gates these behind a confirmation prompt.
        assert!(HardenSsh.is_destructive());
        assert!(ChangePort.is_destructive());
        assert!(!InstallSsh.is_destructive());
    }

    #[test]
    fn moving_the_port_invalidates_the_firewall_rule() {
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let firewall = consequences
            .iter()
            .find(|c| c.task() == Some("firewall.allow-port"))
            .expect("changing the port must name the firewall");

        assert!(matches!(
            firewall,
            Consequence::Invalidates {
                reason: Reason::PortChanged { from, to },
                ..
            } if from == "22" && to == "2222"
        ));
    }

    #[test]
    fn the_firewall_warning_can_be_verified() {
        // The firewall is on this host, so the tool can settle this one rather
        // than only reporting it — unlike the provider's edge firewall.
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let firewall = consequences
            .iter()
            .find(|c| c.task() == Some("firewall.allow-port"))
            .expect("changing the port must name the firewall");

        let check = firewall
            .check()
            .expect("a rule on this host is answerable from it");

        // The whole rule, not the bare number: `2222` is also a substring of
        // `22220`, and this project has been bitten before by a needle that
        // matched the wrong answer.
        assert_eq!(check.resolved_when_stdout_contains, "tcp dport 2222 accept");
    }

    #[test]
    fn moving_the_port_warns_about_the_provider_firewall() {
        // The failure this exists for: a port opened locally that the provider
        // still blocks. Nothing on this host can observe that, so it is
        // reported as unverifiable rather than checked.
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let external: Vec<_> = consequences.iter().filter(|c| c.is_external()).collect();

        assert_eq!(external.len(), 1, "got: {consequences:?}");
        assert!(
            external[0].check().is_none(),
            "an external warning must not offer verification"
        );
    }

    #[test]
    fn keeping_the_current_port_invalidates_nothing() {
        // Re-running with 22 changes nothing, so it breaks nothing. Warning
        // anyway is how these get dismissed unread.
        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &port_values(22))
                .is_empty()
        );
    }

    #[test]
    fn a_port_that_does_not_parse_yields_no_consequences() {
        // The task will not run, so nothing downstream is affected. This must
        // not panic: `consequences` is called while rendering.
        let mut unparseable = ParamValues::new();
        unparseable.set(ChangePort::PORT, "not-a-port".to_owned());

        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &unparseable)
                .is_empty()
        );
        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
    }

    #[test]
    fn tasks_that_change_nothing_elsewhere_declare_nothing() {
        // The default is empty, so a task only speaks up when it has something
        // to say.
        assert!(
            InstallSsh
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
        assert!(
            HardenSsh
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
    }
}
