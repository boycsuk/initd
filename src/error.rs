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

use crate::i18n::{Lang, Msg};

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Why a change was refused for risking the administrator's own access.
///
/// A discriminant rather than a message: the wording belongs in the catalogue,
/// and each case names the accounts involved so the administrator is told
/// which one to fix rather than merely that something is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lockout {
    /// Passwords would be disabled while no key authorises root.
    NoKeyForRoot,
    /// An account named in `AllowUsers` does not exist on this host.
    ///
    /// A typo produces a configuration `sshd -t` accepts and that matches
    /// nobody, so every login is refused.
    UnknownUser { user: String },
    /// No account named in `AllowUsers` has an authorised key.
    NoKeyForAllowedUsers { users: String },
}

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

    /// I/O failure while spawning or reading the process.
    CommandIo {
        command: String,
        #[source]
        source: std::io::Error,
    },

    /// The operation needs root and no escalation mechanism is available.
    NoPrivilegeEscalator,

    /// I/O failure on a file of the administered system.
    FileIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

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
            Self::CommandIo { command, source } => Msg::CommandIo {
                command: command.clone(),
                source: source.to_string(),
            },
            Self::NoPrivilegeEscalator => Msg::NoPrivilegeEscalator,
            Self::FileIo { path, source } => Msg::FileIo {
                path: path.display().to_string(),
                source: source.to_string(),
            },
            Self::InvalidSshdConfig { details } => Msg::InvalidSshdConfig {
                details: details.clone(),
            },
            Self::LockoutRisk { kind } => match kind {
                Lockout::NoKeyForRoot => Msg::LockoutNoKeyForRoot,
                Lockout::UnknownUser { user } => Msg::LockoutUnknownUser { user: user.clone() },
                Lockout::NoKeyForAllowedUsers { users } => Msg::LockoutNoKeyForAllowedUsers {
                    users: users.clone(),
                },
            },
            Self::InvalidPublicKey { reason } => Msg::InvalidPublicKey {
                reason: reason.clone(),
            },
            Self::InvalidPort { port } => Msg::InvalidPort { port: *port },
            Self::MissingParameter { name } => Msg::MissingParameter { name: name.clone() },
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

        let err = Error::FileIo {
            path: PathBuf::from("/etc/ssh/sshd_config"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        assert!(err.source().is_some(), "the io::Error source must survive");
    }
}
