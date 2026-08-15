//! Domain error type.
//!
//! Every failure propagates as an `Error`; no production path panics. `initd`
//! runs as root on the server it administers, so a panic mid-operation can
//! leave the system half-configured.
//!
//! Variants carry structured data only — never display text. `Display` renders
//! them through [`crate::i18n`] in the locale resolved from the environment, so
//! translating an error never means touching the code that raises it.

use std::path::PathBuf;

use crate::i18n::{ErrorField, Lang, Msg};

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a change was refused for risking the administrator's own access.
///
/// A discriminant rather than a message: the wording belongs in the catalogue,
/// and each case names the accounts involved so the administrator is told
/// which one to fix rather than merely that something is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lockout {
    /// Hardening would leave no account able to log in over SSH.
    ///
    /// Asked of every account on the host, not of root. The check this replaced
    /// asked whether *root* held a key, which was wrong in both directions: any
    /// account with a key is a way in, and root is the account `ssh.harden`
    /// removes — it writes `PermitRootLogin no`, so a root key satisfied the
    /// check and was worthless a step later. A host with root locked, which is
    /// the recommended posture, could not run either tier at all.
    NoAccountKeepsSshAccess,
    /// An account named in `AllowUsers` does not exist on this host.
    ///
    /// A typo produces a configuration `sshd -t` accepts and that matches
    /// nobody, so every login is refused.
    UnknownUser { user: String },
    /// No account named in `AllowUsers` has an authorised key.
    NoKeyForAllowedUsers { users: String },
}

/// Everything this tool can fail at, as data rather than as a sentence.
///
/// Each variant carries what went wrong and nothing about how to say it: the
/// wording lives in [`crate::i18n`], which renders these through an exhaustive
/// match. That is what makes a missing translation a compile error instead of a
/// message that silently comes out in the wrong language — and what lets the
/// TUI and the CLI report the same failure differently without either of them
/// parsing a string the other wrote.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `/etc/os-release` could not be read.
    OsReleaseUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// `/etc/os-release` exists but declares no `ID`.
    OsReleaseMissingId { path: PathBuf },

    /// The distribution was identified but belongs to no supported family.
    UnsupportedDistro { id: String, id_like: Option<String> },

    /// A repository's signing key is not the one this build expects.
    ///
    /// Carries both fingerprints because the difference is the evidence: an
    /// administrator seeing only "key mismatch" cannot tell a compromised
    /// mirror from a project that rotated its key.
    RepositoryKeyMismatch {
        repository: String,
        expected: String,
        found: String,
    },

    /// A repository's signing key could not be fetched or read.
    ///
    /// Distinct from a mismatch: nothing was proven either way, so the
    /// repository is not registered and nothing is claimed about it.
    RepositoryKeyUnverifiable { repository: String },

    /// A path that has to be absolute was not.
    ///
    /// `safe.directory` is matched literally by git, so a relative path never
    /// matches anything: the setting would be written, reported as applied, and
    /// do nothing. Refused where it is typed rather than discovered later, when
    /// git refuses a repository the operator believes they trusted.
    PathNotAbsolute { path: String },

    /// An APT repository was reached without knowing which suite to fetch.
    ///
    /// Distinct from either key failure: the key may be perfectly good. APT
    /// expands `$(ARCH)` and nothing else, so unlike dnf's `$releasever` the
    /// suite cannot be deferred to the package manager — and a guessed one
    /// registers a repository that serves nothing, which then surfaces as the
    /// package being missing rather than as the suite being wrong. Raised when
    /// the host declares no `VERSION_CODENAME`.
    RepositoryUnknownSuite { repository: String },

    /// No inbound filtering front-end is present on this host.
    ///
    /// Carries nothing: which front-ends were tried is a property of the
    /// family, and naming them in the error would put a list here that the
    /// backend already owns.
    NoFirewallFrontEnd,

    /// The ruleset could not be read, so what this host admits is unknown.
    ///
    /// Distinct from [`NoFirewallFrontEnd`](Self::NoFirewallFrontEnd), which
    /// states a fact about the machine, and from
    /// [`FirewallNotEnabled`](Self::FirewallNotEnabled), which states a fact
    /// about its policy. This one states a fact about *this process*: listing a
    /// ruleset needs root, and the interface's reading threads may not raise a
    /// password prompt under a screen somebody is looking at.
    ///
    /// Its own variant because the alternative was returning an empty set,
    /// which reads as "this host admits nothing" — and the port table is
    /// declarative, so confirming that empty set would ask for every port to be
    /// closed. Reported from a live host: a firewall enabled as root showed no
    /// SSH row once the operator returned as an unprivileged admin.
    FirewallStateUnreadable,

    /// Whether an account is locked could not be read.
    ///
    /// The account database's counterpart to
    /// [`FirewallStateUnreadable`](Self::FirewallStateUnreadable), and raised
    /// for the same reason: `/etc/shadow` is mode `640`, so an unprivileged
    /// caller is refused rather than told "no such account". `grep` exits
    /// non-zero for both, and reading the refusal as "not locked" is the
    /// dangerous direction — it offers to lock a root that is already locked,
    /// which is recovered through the hosting provider's rescue console.
    AccountStateUnreadable { user: String },

    /// The executable is not in `PATH`.
    ProgramNotFound { program: String },

    /// The process ran but exited with a non-zero status.
    CommandFailed {
        command: String,
        code: i32,
        stderr: String,
    },

    /// The process died from a signal, leaving no exit code.
    CommandTerminatedBySignal { command: String },

    /// A command produced no output for long enough that waiting stopped.
    ///
    /// The child is left running rather than killed: tasks are not idempotent,
    /// so stopping one mid-step leaves half of it applied with no way to know
    /// which half — the same reasoning that has cancellation refuse the next
    /// command instead of interrupting the running one. What ends is the wait.
    ///
    /// It exists because cancellation cannot reach a command already running,
    /// so a child that neither exits nor speaks — blocked on a prompt inherited
    /// from a terminal nobody is looking at, or on an unreachable mount — left
    /// the task thread waiting forever while the interface reported it as
    /// running and the stop key did nothing.
    CommandSilent { command: String, seconds: u64 },

    /// I/O failure while spawning or reading the process.
    CommandIo {
        command: String,
        #[source]
        source: std::io::Error,
    },

    /// The operator asked the task to stop, and it stopped before this command.
    ///
    /// Raised between commands rather than by interrupting one: a task killed
    /// mid-command would leave the step it was performing half applied, and
    /// tasks are not idempotent. The command named here is the one that was
    /// *not* run, so the report says where the task stopped.
    Cancelled { before: String },

    /// The operation needs root and no escalation mechanism is available.
    NoPrivilegeEscalator,

    /// The operator declined the password prompt, or got it wrong.
    ///
    /// Separate from a failed command because the command never ran: nothing
    /// was changed, so this ends a task rather than leaving it half applied.
    AuthenticationRefused { mechanism: String },

    /// Nobody answered the request for the terminal.
    ///
    /// The interface is gone, or took longer than the deadline. Distinct from
    /// a refusal, which is an answer.
    AuthenticationUnavailable { mechanism: String },

    /// A prompt was coming and this caller has no terminal to draw it on.
    ///
    /// Distinct from both of the above, and the difference is what the operator
    /// should do. Those two mean a request was made and went unanswered; this
    /// one means no request could be made at all — the interface's own threads
    /// hold the alternate screen and cannot give it up, so a helper about to
    /// ask for a password is refused rather than allowed to prompt where the
    /// prompt is invisible and the keystrokes answering it are not echoed.
    ///
    /// The remedy is not to retry: it is to give the helper a live timestamp
    /// (`sudo -v`, or `doas` with `persist`) before the interface needs it, so
    /// the command names itself here rather than reporting a mechanism.
    NoTerminalForPrompt { command: String },

    /// `sshd -t` rejected the configuration over a genuine syntax error.
    InvalidSshdConfig { details: String },

    /// A task refused to run because applying it would leave no way back in.
    ///
    /// Distinct from [`Error::InvalidSshdConfig`], which means `sshd -t`
    /// rejected a file. Nothing is wrong with the configuration here — the
    /// tool is refusing to write one that would strand the administrator.
    LockoutRisk { kind: Lockout },

    /// The public key is not in a recognisable format.
    InvalidPublicKey { reason: String },

    /// The `AllowUsers` value could not name a set of accounts.
    ///
    /// Raised by the task rather than only by the form: a CLI argument reaches
    /// the same path without passing through a keystroke filter.
    InvalidAllowUsers { reason: String },

    /// Port outside the usable range.
    InvalidPort { port: u32 },

    /// A running task's thread ended without reporting an outcome.
    ///
    /// Only reachable if the thread itself died. Reported rather than ignored:
    /// a task that vanishes must not be left looking like one still running.
    TaskVanished { task: String },

    /// A task was run without a value it declared it needs.
    ///
    /// User input never reaches this: the interface refuses to submit an
    /// incomplete form. It exists so that a task whose parameters were
    /// collected wrongly fails outright rather than substituting a default and
    /// changing something nobody asked it to.
    MissingParameter { name: String },

    /// An account that was to be created already exists.
    ///
    /// Refused rather than treated as success: the existing account may have a
    /// password, a different shell or no administrative rights, and quietly
    /// adopting it would report a provisioning that never happened.
    AccountExists { user: String },

    /// An account a task needs does not exist.
    NoSuchAccount { user: String },

    /// A path root was about to write through turned out to be a symbolic link.
    ///
    /// Refused rather than followed. The tools this would go on to run —
    /// `install -d`, `chown`, `tee` — all act on a link's target, so a path
    /// inside a directory an unprivileged account owns is one that account can
    /// aim elsewhere. Measured on `debian:13`: replacing `~/.ssh` with a link
    /// to a directory owned by root had root hand its ownership to the account
    /// that planted the link, and then write a file inside it.
    ///
    /// Named as its own variant because the operator has to be told what to
    /// look at: the account is not necessarily hostile, and a link into shared
    /// storage is a thing administrators set up deliberately.
    UnsafeSymlink { path: String },

    /// Adding an account to a group appeared to succeed and did not.
    ///
    /// `usermod` exiting zero says the command ran, not that the membership
    /// took. Read back because this account is often about to become the only
    /// way onto the machine.
    GroupMembershipFailed { user: String, group: String },

    /// No account on this host can still get in once root is locked.
    ///
    /// A claim about the machine rather than about a name, which is what
    /// `users.lock-root` always meant to assert and could not while it checked
    /// one account an operator had typed. Carries how many were examined
    /// because the refusal would otherwise assert more than was measured — the
    /// per-account reasons reach the operator through the report, where there
    /// is room for them.
    ///
    /// Why each was set aside lives in
    /// [`crate::tasks::users::NotAWayIn`] rather than here: those describe one
    /// account among many and no longer abort anything, which is the difference
    /// between a diagnosis and an error.
    NoWayBackIn { examined: usize },

    /// A deletion named `root`.
    ///
    /// Refused in the code rather than warned about in a dialog, the same way
    /// `users.lock-root` refuses an administrator of `root`. Every other
    /// account this tool deletes is one it could also create; `root` is not,
    /// and a machine without it is not one an operator recovers by running
    /// this tool again. Locking root is offered — deliberately, with its own
    /// guard that another way in exists — and deleting it is not: the two are
    /// not the same operation, and only one is undone by a rescue console.
    CannotDeleteRoot,

    /// A deletion named the account this session escalated from.
    ///
    /// Refused rather than warned about, because it can now be known: the
    /// escalation helper says which account it acted for, and deleting that one
    /// ends the session mid-task along with whatever rule granted it root.
    ///
    /// Only raised where the escalation identifies itself. A direct root login
    /// and `run0` leave nothing to compare against, and those keep the warning
    /// the confirmation carries — a check that cannot be made is stated as
    /// such rather than faked.
    CannotDeleteOwnAccount { user: String },

    /// The file has changed since this tool wrote it.
    ///
    /// The refusal a cross-session revert exists to be able to make. Restoring
    /// over an edit somebody made by hand would discard their work and say
    /// nothing, which is the one outcome a revert must never produce — so it
    /// stops, and carries both digests because the difference *is* the
    /// evidence: an administrator told only "the file changed" cannot tell
    /// their own edit from a package upgrade replacing a conffile.
    FileChangedSinceBackup {
        path: String,
        expected: String,
        found: String,
    },

    /// The copy that would be restored is not the one that was recorded.
    ///
    /// A backup truncated by a full disk is a file that exists and is
    /// readable, and restoring it puts half a configuration over a working
    /// one. Distinct from the live file having changed: nothing is wrong with
    /// the machine here, the record is what cannot be trusted.
    BackupCorrupt { copy: String },

    /// Nothing could be hashed, so nothing can be proven either way.
    ///
    /// Neither a mismatch nor a match. Reported as its own case because "the
    /// file is different" and "I could not read the file" call for different
    /// actions, and reporting the second as the first sends an administrator
    /// looking for an edit nobody made.
    RevertUnverifiable { path: String },

    /// A login shell is not listed in `/etc/shells`.
    ///
    /// `chsh` refuses one that is absent, and some PAM configurations refuse a
    /// session for an account whose shell is not listed.
    ShellNotListed { shell: String },

    /// An account has no subordinate UID/GID range.
    ///
    /// A rootless engine maps container users onto that range, so an account
    /// without one cannot start a single container. Checked before installing
    /// rather than after, since the install would otherwise be wasted.
    NoSubordinateIds { user: String },

    /// The rootless setup was asked for on a host with no engine installed.
    ///
    /// Distinct from a failure of the setup script itself, which is what the
    /// operator would otherwise see: upstream's script reports its own absence
    /// or a missing daemon in terms that name neither this tool nor the task
    /// that should have run first. Named as a separate error so the message can
    /// say which task installs it.
    DockerEngineAbsent,

    /// A Caddy task was asked for on a host with no Caddy installed.
    ///
    /// The same shape as [`Self::DockerEngineAbsent`] and added for the same
    /// reason: without it the operator sees `ProgramNotFound`, which names the
    /// binary that is missing from `PATH` and not the task that installs it.
    /// Worse for `caddy.security-headers`, where the validation runs *after*
    /// the snippet is written — so the raw error arrived with the file already
    /// modified and nothing to say what had happened.
    CaddyAbsent,

    /// A task that edits `sshd_config` was asked for on a host with no sshd.
    ///
    /// The write is validated by running `sshd -t` over the result, which is
    /// also the only thing that would have noticed the daemon was missing — and
    /// it notices *after* the file has been written, by failing to start a
    /// program that is not there. `ProgramNotFound` then travelled past the
    /// branch that restores the backup, so the host was left holding an edited
    /// configuration that nothing had checked, for a daemon it does not have.
    SshdAbsent,

    /// Validation was asked for against a Caddyfile that is not there.
    ///
    /// Separate from [`Self::InvalidCaddyfile`] because the two call for
    /// different actions: one says to fix a file, the other says there is none
    /// to fix. Caddy reports the absence through the same channel as a syntax
    /// error — `open …: no such file` in its stderr — so left to it, an
    /// operator on a host where no configuration was ever written is sent to
    /// edit something that does not exist.
    CaddyfileAbsent { path: String },

    /// An account's own service manager cannot be reached.
    ///
    /// `systemctl --user` finds its bus through `XDG_RUNTIME_DIR`, which
    /// `pam_systemd` sets while establishing the session `runuser -l` opens.
    /// Debian lists that module as `-session optional`, so when it cannot
    /// create a session it fails without even logging: the shell starts, the
    /// environment is empty, and every user-service command after it addresses
    /// nothing.
    ///
    /// Distinct from [`ServiceDidNotStart`](Self::ServiceDidNotStart), which
    /// reports a service that was reached and did not come up. Here nothing was
    /// reached, and the two call for different actions — one is about the
    /// engine, the other about `systemd-logind`.
    NoUserSession { user: String },

    /// A port was opened on a host that is not filtering anything.
    ///
    /// Distinct from [`NoFirewallFrontEnd`](Self::NoFirewallFrontEnd), which is
    /// about the tool being absent: here `nft` is installed and working, and
    /// what is missing is the default-deny policy that gives an `accept` rule
    /// its meaning. Without it there is no table to add the rule to, and `nft`
    /// answers `No such file or directory` — naming a file for a table nobody
    /// created, which reads as a defect in the rule.
    FirewallNotEnabled,

    /// A user service was enabled and is not running.
    ///
    /// `enable --now` exiting zero says the command ran, not that the service
    /// came up: a rootless engine that cannot map its ids or reach its runtime
    /// directory fails after that point.
    ServiceDidNotStart { service: String, user: String },

    /// A downloaded archive did not match the digest this build carries.
    ///
    /// The one outcome of an install that means the artefact was not what was
    /// expected, rather than that a command failed.
    ChecksumMismatch { program: String, version: String },

    /// A release has no artefact for this machine's architecture.
    ///
    /// Refused rather than served another machine's binary, which is the same
    /// limit pinned digests impose on versions: what cannot be verified for
    /// *this* host is not installed on it.
    UnsupportedArchitecture {
        program: String,
        version: String,
        arch: String,
    },

    /// A version this build carries no digest for.
    ///
    /// The intended limit of pinned checksums: what cannot be verified cannot
    /// be installed.
    UnknownRelease { version: String, known: String },

    /// A timer the task depends on is not enabled.
    ///
    /// Writing a policy file does not start anything: the package ships a
    /// debconf question whose answer decides whether the timer runs at all, so
    /// a policy alone can sit on a host that never applies it.
    TimerNotEnabled { timer: String },

    /// The family has no mechanism for a capability the task needs.
    ///
    /// Distinct from a command failing: nothing was attempted, because there
    /// was nothing on this system to attempt it with. Reachable only if a task
    /// declares itself supported on a family whose backend offers no
    /// implementation — a disagreement between two declarations, which is why
    /// it names the capability rather than a command.
    CapabilityUnavailable { capability: &'static str },

    /// Caddy rejected its configuration.
    InvalidCaddyfile { details: String },

    /// WireGuard is already configured on this host.
    ///
    /// Refused rather than overwritten: a new server key silently invalidates
    /// every peer configured against the old one, and each of them stops
    /// connecting with no indication why.
    WireguardAlreadyConfigured { path: String },

    /// WireGuard has no configuration to read.
    WireguardNotConfigured,

    /// Another peer already holds this tunnel address.
    ///
    /// Two peers on one address is a tunnel where the second to connect takes
    /// the first one's traffic, and neither reports an error.
    WireguardAddressTaken { address: String },

    /// A subnet could not be parsed.
    InvalidSubnet { subnet: String },

    /// A WireGuard key is not one.
    ///
    /// Checked because a truncated key parses and never completes a handshake:
    /// the failure appears as a tunnel that silently does not work rather than
    /// as an error where it was introduced.
    InvalidWireguardKey { reason: String },

    /// A kernel parameter this system does not have.
    ///
    /// Named rather than reported as a generic command failure: the usual
    /// cause is a module that is not loaded, and the parameter is what says
    /// which one.
    UnknownSysctl { key: String },

    /// A group an account was to be added to does not exist.
    ///
    /// Raised rather than letting `usermod -aG` succeed against a group the
    /// system does not have: it exits zero and grants nothing, so the account
    /// looks provisioned and cannot escalate. The administrative group is
    /// `sudo` on Debian and `wheel` on Arch, which is exactly when this
    /// happens.
    MissingGroup { group: String },

    /// The task is not supported on the detected family.
    TaskUnsupported { task: String, family: String },

    /// Failure initialising or restoring the terminal.
    Terminal {
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Converts this error into the catalogue message describing it.
    ///
    /// Sources are rendered with `to_string()` because they come from
    /// `std::io`, whose messages `initd` does not control or translate.
    pub fn to_msg(&self) -> Msg {
        match self {
            Self::OsReleaseUnreadable { path, source } => Msg::OsReleaseUnreadable {
                path: path.display().to_string(),
                source: source.to_string(),
            },
            Self::OsReleaseMissingId { path } => Msg::OsReleaseMissingId {
                path: path.display().to_string(),
            },
            Self::UnsupportedDistro { id, id_like } => Msg::UnsupportedDistro {
                id: id.clone(),
                id_like: id_like.clone(),
            },
            Self::RepositoryKeyMismatch {
                repository,
                expected,
                found,
            } => Msg::RepositoryKeyMismatch {
                repository: repository.clone(),
                expected: expected.clone(),
                found: found.clone(),
            },
            Self::RepositoryKeyUnverifiable { repository } => Msg::RepositoryKeyUnverifiable {
                repository: repository.clone(),
            },
            Self::RepositoryUnknownSuite { repository } => Msg::RepositoryUnknownSuite {
                repository: repository.clone(),
            },
            Self::PathNotAbsolute { path } => Msg::PathNotAbsolute { path: path.clone() },
            Self::NoFirewallFrontEnd => Msg::NoFirewallFrontEnd,
            Self::FirewallStateUnreadable => Msg::FirewallStateUnreadable,
            Self::AccountStateUnreadable { user } => {
                Msg::AccountStateUnreadable { user: user.clone() }
            }
            Self::FirewallNotEnabled => Msg::FirewallNotEnabled,
            Self::ProgramNotFound { program } => Msg::ProgramNotFound {
                program: program.clone(),
            },
            Self::CommandFailed {
                command,
                code,
                stderr,
            } => Msg::CommandFailed {
                command: command.clone(),
                code: *code,
                stderr: stderr.clone(),
            },
            Self::CommandTerminatedBySignal { command } => Msg::CommandTerminatedBySignal {
                command: command.clone(),
            },
            Self::CommandSilent { command, seconds } => Msg::CommandSilent {
                command: command.clone(),
                seconds: *seconds,
            },
            Self::CommandIo { command, source } => Msg::CommandIo {
                command: command.clone(),
                source: source.to_string(),
            },
            Self::Cancelled { before } => Msg::Cancelled {
                before: before.clone(),
            },
            Self::NoPrivilegeEscalator => Msg::NoPrivilegeEscalator,
            Self::AuthenticationRefused { mechanism } => Msg::AuthenticationRefused {
                mechanism: mechanism.clone(),
            },
            Self::AuthenticationUnavailable { mechanism } => Msg::AuthenticationUnavailable {
                mechanism: mechanism.clone(),
            },
            Self::NoTerminalForPrompt { command } => Msg::NoTerminalForPrompt {
                command: command.clone(),
            },
            Self::InvalidSshdConfig { details } => Msg::InvalidSshdConfig {
                details: details.clone(),
            },
            Self::LockoutRisk { kind } => match kind {
                Lockout::NoAccountKeepsSshAccess => Msg::LockoutNoAccountKeepsSshAccess,
                Lockout::UnknownUser { user } => Msg::LockoutUnknownUser { user: user.clone() },
                Lockout::NoKeyForAllowedUsers { users } => Msg::LockoutNoKeyForAllowedUsers {
                    users: users.clone(),
                },
            },
            Self::InvalidPublicKey { reason } => Msg::InvalidPublicKey {
                reason: reason.clone(),
            },
            Self::InvalidAllowUsers { reason } => Msg::InvalidAllowUsers {
                reason: reason.clone(),
            },
            Self::InvalidPort { port } => Msg::InvalidPort { port: *port },
            Self::MissingParameter { name } => Msg::MissingParameter { name: name.clone() },
            Self::MissingGroup { group } => Msg::MissingGroup {
                group: group.clone(),
            },
            Self::UnknownSysctl { key } => Msg::UnknownSysctl { key: key.clone() },
            Self::InvalidWireguardKey { reason } => Msg::InvalidWireguardKey {
                reason: reason.clone(),
            },
            Self::WireguardAlreadyConfigured { path } => {
                Msg::WireguardAlreadyConfigured { path: path.clone() }
            }
            Self::WireguardNotConfigured => Msg::WireguardNotConfigured,
            Self::NoSubordinateIds { user } => Msg::NoSubordinateIds { user: user.clone() },
            Self::DockerEngineAbsent => Msg::DockerEngineAbsent,
            Self::CaddyAbsent => Msg::CaddyAbsent,
            Self::SshdAbsent => Msg::SshdAbsent,
            Self::NoUserSession { user } => Msg::NoUserSession { user: user.clone() },
            Self::ChecksumMismatch { program, version } => Msg::ChecksumMismatch {
                program: program.clone(),
                version: version.clone(),
            },
            Self::UnsupportedArchitecture {
                program,
                version,
                arch,
            } => Msg::UnsupportedArchitecture {
                program: program.clone(),
                version: version.clone(),
                arch: arch.clone(),
            },
            Self::UnknownRelease { version, known } => Msg::UnknownRelease {
                version: version.clone(),
                known: known.clone(),
            },
            Self::CapabilityUnavailable { capability } => Msg::CapabilityUnavailable {
                capability: (*capability).to_owned(),
            },
            Self::TimerNotEnabled { timer } => Msg::TimerNotEnabled {
                timer: timer.clone(),
            },
            Self::InvalidCaddyfile { details } => Msg::InvalidCaddyfile {
                details: details.clone(),
            },
            Self::CaddyfileAbsent { path } => Msg::CaddyfileAbsent { path: path.clone() },
            Self::ServiceDidNotStart { service, user } => Msg::ServiceDidNotStart {
                service: service.clone(),
                user: user.clone(),
            },
            Self::WireguardAddressTaken { address } => Msg::WireguardAddressTaken {
                address: address.clone(),
            },
            Self::InvalidSubnet { subnet } => Msg::InvalidSubnet {
                subnet: subnet.clone(),
            },
            Self::AccountExists { user } => Msg::AccountExists { user: user.clone() },
            Self::NoSuchAccount { user } => Msg::NoSuchAccount { user: user.clone() },
            Self::UnsafeSymlink { path } => Msg::UnsafeSymlink { path: path.clone() },
            Self::GroupMembershipFailed { user, group } => Msg::GroupMembershipFailed {
                user: user.clone(),
                group: group.clone(),
            },
            Self::NoWayBackIn { examined } => Msg::NoWayBackIn {
                examined: *examined,
            },
            Self::CannotDeleteRoot => Msg::CannotDeleteRoot,
            Self::CannotDeleteOwnAccount { user } => {
                Msg::CannotDeleteOwnAccount { user: user.clone() }
            }
            Self::FileChangedSinceBackup {
                path,
                expected,
                found,
            } => Msg::FileChangedSinceBackup {
                path: path.clone(),
                expected: expected.clone(),
                found: found.clone(),
            },
            Self::BackupCorrupt { copy } => Msg::BackupCorrupt { copy: copy.clone() },
            Self::RevertUnverifiable { path } => Msg::RevertUnverifiable { path: path.clone() },
            Self::ShellNotListed { shell } => Msg::ShellNotListed {
                shell: shell.clone(),
            },
            Self::TaskVanished { task } => Msg::TaskVanished { task: task.clone() },
            Self::TaskUnsupported { task, family } => Msg::TaskUnsupported {
                task: task.clone(),
                family: family.clone(),
            },
            Self::Terminal { source } => Msg::Terminal {
                source: source.to_string(),
            },
        }
    }

    /// Breaks this error into labelled fields, for the output pane to draw.
    ///
    /// The second seam to text, beside [`Self::to_msg`], and the reason both
    /// exist is that they answer different questions. `to_msg` renders one
    /// sentence — the right shape for a status row, a log line, or `Display`.
    /// This returns the same data as fields, which is what a `CommandFailed`
    /// needs: `command`, `code` and `stderr` are three values, and flattening
    /// them into a sentence puts a package manager's whole stderr on one line
    /// with the exit code buried in the middle of it.
    ///
    /// Exhaustive rather than defaulted, deliberately. A variant added without
    /// deciding what its fields are called fails to compile here, which is the
    /// same protection `Task::support` gets from returning `Support` — the
    /// alternative is a new error rendering as an empty block at the moment
    /// somebody needs it most.
    ///
    /// Returns fields in reading order: what was attempted, then what came
    /// back, then the underlying cause. A value whose meaning is the sentence
    /// around it rather than a label above it returns nothing here — the
    /// caller falls back to [`Self::to_msg`], which is why this may be empty.
    pub fn to_fields(&self) -> Vec<(ErrorField, String)> {
        match self {
            // The three-field case this exists for. `stderr` last because it
            // is the only one that wraps, so the two short values above it stay
            // aligned with their labels.
            Self::CommandFailed {
                command,
                code,
                stderr,
            } => vec![
                (ErrorField::Command, command.clone()),
                (ErrorField::ExitCode, code.to_string()),
                (ErrorField::Stderr, stderr.clone()),
            ],
            Self::CommandSilent { command, seconds } => vec![
                (ErrorField::Command, command.clone()),
                (ErrorField::Seconds, seconds.to_string()),
            ],
            Self::CommandIo { command, source } => vec![
                (ErrorField::Command, command.clone()),
                (ErrorField::Cause, source.to_string()),
            ],
            Self::CommandTerminatedBySignal { command }
            | Self::Cancelled { before: command }
            | Self::NoTerminalForPrompt { command } => {
                vec![(ErrorField::Command, command.clone())]
            }

            // Pairs where the difference is the evidence. Both halves always
            // appear together: either alone says "something changed" without
            // saying what, which is the report these variants were widened to
            // avoid in the first place.
            Self::FileChangedSinceBackup {
                path,
                expected,
                found,
            } => vec![
                (ErrorField::Path, path.clone()),
                (ErrorField::Expected, expected.clone()),
                (ErrorField::Found, found.clone()),
            ],
            Self::RepositoryKeyMismatch {
                repository,
                expected,
                found,
            } => vec![
                (ErrorField::Repository, repository.clone()),
                (ErrorField::Expected, expected.clone()),
                (ErrorField::Found, found.clone()),
            ],
            Self::UnknownRelease { version, known } => vec![
                (ErrorField::Version, version.clone()),
                (ErrorField::Expected, known.clone()),
            ],

            Self::OsReleaseUnreadable { path, source } => vec![
                (ErrorField::Path, path.display().to_string()),
                (ErrorField::Cause, source.to_string()),
            ],
            Self::OsReleaseMissingId { path } => {
                vec![(ErrorField::Path, path.display().to_string())]
            }
            Self::UnsupportedDistro { id, id_like } => {
                let mut fields = vec![(ErrorField::Distribution, id.clone())];

                // Absent on a distribution that declares no lineage, and an
                // empty row would read as one that declares an empty one.
                if let Some(like) = id_like {
                    fields.push((ErrorField::Kind, like.clone()));
                }

                fields
            }
            Self::UnsupportedArchitecture {
                program,
                version,
                arch,
            } => vec![
                (ErrorField::Program, program.clone()),
                (ErrorField::Version, version.clone()),
                (ErrorField::Architecture, arch.clone()),
            ],
            Self::ChecksumMismatch { program, version } => vec![
                (ErrorField::Program, program.clone()),
                (ErrorField::Version, version.clone()),
            ],
            Self::ProgramNotFound { program } => {
                vec![(ErrorField::Program, program.clone())]
            }

            Self::RepositoryKeyUnverifiable { repository } => {
                vec![(ErrorField::Repository, repository.clone())]
            }
            Self::RepositoryUnknownSuite { repository } => {
                vec![(ErrorField::Repository, repository.clone())]
            }
            Self::PathNotAbsolute { path } | Self::CaddyfileAbsent { path } => {
                vec![(ErrorField::Path, path.clone())]
            }
            Self::ServiceDidNotStart { service, user } => vec![
                (ErrorField::Service, service.clone()),
                (ErrorField::User, user.clone()),
            ],
            Self::GroupMembershipFailed { user, group } => vec![
                (ErrorField::User, user.clone()),
                (ErrorField::Group, group.clone()),
            ],
            Self::MissingGroup { group } => vec![(ErrorField::Group, group.clone())],
            Self::AccountExists { user }
            | Self::NoSuchAccount { user }
            | Self::CannotDeleteOwnAccount { user }
            | Self::NoSubordinateIds { user }
            | Self::NoUserSession { user }
            | Self::AccountStateUnreadable { user } => vec![(ErrorField::User, user.clone())],
            Self::NoWayBackIn { examined } => {
                vec![(ErrorField::Examined, examined.to_string())]
            }

            Self::BackupCorrupt { copy } => vec![(ErrorField::Path, copy.clone())],
            Self::RevertUnverifiable { path }
            | Self::UnsafeSymlink { path }
            | Self::WireguardAlreadyConfigured { path } => {
                vec![(ErrorField::Path, path.clone())]
            }

            Self::AuthenticationRefused { mechanism }
            | Self::AuthenticationUnavailable { mechanism } => {
                vec![(ErrorField::Program, mechanism.clone())]
            }

            // `details` is a tool's own diagnostic, which is the one thing on
            // screen that says which line of the file is wrong.
            Self::InvalidSshdConfig { details } | Self::InvalidCaddyfile { details } => {
                vec![(ErrorField::Cause, details.clone())]
            }
            Self::InvalidPublicKey { reason }
            | Self::InvalidAllowUsers { reason }
            | Self::InvalidWireguardKey { reason } => {
                vec![(ErrorField::Cause, reason.clone())]
            }
            Self::InvalidPort { port } => vec![(ErrorField::Port, port.to_string())],
            Self::InvalidSubnet { subnet } => vec![(ErrorField::Address, subnet.clone())],
            Self::WireguardAddressTaken { address } => {
                vec![(ErrorField::Address, address.clone())]
            }
            Self::UnknownSysctl { key } => vec![(ErrorField::Directive, key.clone())],
            Self::ShellNotListed { shell } => vec![(ErrorField::Shell, shell.clone())],
            Self::TimerNotEnabled { timer } => vec![(ErrorField::Service, timer.clone())],
            Self::MissingParameter { name } => vec![(ErrorField::Value, name.clone())],
            Self::CapabilityUnavailable { capability } => {
                vec![(ErrorField::Value, (*capability).to_owned())]
            }
            Self::TaskVanished { task } => vec![(ErrorField::Task, task.clone())],
            Self::TaskUnsupported { task, family } => vec![
                (ErrorField::Task, task.clone()),
                (ErrorField::Distribution, family.clone()),
            ],
            Self::Terminal { source } => vec![(ErrorField::Cause, source.to_string())],

            // Nothing to label. Each of these is a whole sentence with no value
            // in it — a field block would be a heading over an empty column,
            // and the caller renders `to_msg` instead. `LockoutRisk` belongs
            // here rather than above: `Lockout` is a discriminant the
            // catalogue turns into a paragraph naming a remedy, and `kind
            // NoOtherAdmin` says less than the sentence it replaces.
            Self::NoFirewallFrontEnd
            | Self::FirewallStateUnreadable
            | Self::FirewallNotEnabled
            | Self::NoPrivilegeEscalator
            | Self::CannotDeleteRoot
            | Self::WireguardNotConfigured
            // Carries no field worth labelling: the whole answer is the
            // sentence naming the task to run first.
            | Self::DockerEngineAbsent
            | Self::CaddyAbsent
            | Self::SshdAbsent
            | Self::LockoutRisk { .. } => Vec::new(),
        }
    }
}

impl std::fmt::Display for Error {
    /// Renders in the locale resolved from the environment.
    ///
    /// Callers that need a specific language should render `to_msg()` directly
    /// instead of relying on `Display`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Lang::from_env().render(&self.to_msg()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_renders_the_catalogue_message() {
        let err = Error::InvalidPort { port: 70_000 };
        assert_eq!(err.to_string(), Lang::En.render(&err.to_msg()));
    }

    #[test]
    fn unsupported_distro_reports_both_fields() {
        let err = Error::UnsupportedDistro {
            id: "gentoo".to_owned(),
            id_like: None,
        };
        let rendered = Lang::En.render(&err.to_msg());
        assert!(rendered.contains("gentoo"), "got: {rendered}");
    }

    #[test]
    fn source_chain_is_preserved() {
        use std::error::Error as _;

        // Any variant carrying `#[source]` proves the chain survives; this one
        // is raised in production, so the test cannot outlive its subject.
        let err = Error::OsReleaseUnreadable {
            path: PathBuf::from("/etc/os-release"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert!(err.source().is_some(), "the io::Error source must survive");
    }
}
