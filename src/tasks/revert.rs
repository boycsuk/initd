//! Undoing a change that has already been applied.
//!
//! Some changes can end the session that made them. `sshd -t` proves the new
//! configuration is *syntactically* valid and a reload proves the daemon
//! accepted it, but neither proves the administrator can still get in: a key
//! that turns out not to be in `authorized_keys`, a firewall that was never
//! opened on the new port, an SELinux label that does not exist.
//!
//! So for those changes the tool applies, then waits. The administrator proves
//! access from a second session and keeps the change; if they cannot, or if
//! they simply stop answering, the backup goes back on its own.
//!
//! The timer is the point. An administrator who has just locked themselves out
//! is, by definition, not able to press a key to undo it.

use crate::backend::Backend;
use crate::domain::files::Backup;
use crate::error::Result;
use crate::exec::Executor;

/// How to put back what a task changed.
///
/// Returned by a task that succeeded, describing the undo it makes available
/// rather than performing it. Whether to use it is the operator's decision,
/// taken after they have had a chance to test the result.
#[derive(Debug, Clone)]
pub enum Revert {
    /// Restore a configuration file and reload the service that reads it.
    ///
    /// The reload is part of the revert rather than a separate step: a
    /// restored file that the daemon has not re-read has changed nothing.
    ConfigFile {
        backup: Backup,
        /// The unit to reload once the file is back.
        service: &'static str,
    },
}

impl Revert {
    /// Puts the change back.
    pub fn apply(&self, executor: &dyn Executor, backend: &dyn Backend) -> Result<()> {
        match self {
            Self::ConfigFile { backup, service } => {
                backend.files().restore(executor, backup)?;
                // `reload`, never `restart`: a restart would drop the very
                // session this revert exists to protect.
                backend.services().reload(executor, service)
            }
        }
    }

    /// What the revert would put back, for the interface to state.
    pub fn describes(&self) -> &str {
        match self {
            Self::ConfigFile { backup, .. } => &backup.original,
        }
    }
}

/// What a task leaves behind when it succeeds.
///
/// Most tasks finish and are done; `Outcome::Done` says so. A task whose
/// change could sever the administrator's own access returns
/// `Outcome::Revertible`, which is what puts the interface into its
/// verification window.
#[derive(Debug)]
pub enum Outcome {
    /// Finished. Nothing to undo, or nothing worth offering to undo.
    Done,
    /// Applied, and undoable for as long as the operator has not committed.
    Revertible(Revert),
}

impl Outcome {
    /// The revert this outcome offers, if any.
    pub const fn revert(&self) -> Option<&Revert> {
        match self {
            Self::Done => None,
            Self::Revertible(revert) => Some(revert),
        }
    }

    /// Whether the change can still be undone.
    #[cfg(test)]
    pub const fn is_revertible(&self) -> bool {
        matches!(self, Self::Revertible(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    fn test_backup() -> Backup {
        Backup {
            original: "/etc/ssh/sshd_config".to_owned(),
            copy: "/etc/ssh/sshd_config.initd.20260803".to_owned(),
        }
    }

    #[test]
    fn a_finished_task_offers_nothing_to_undo() {
        let outcome = Outcome::Done;

        assert!(!outcome.is_revertible());
        assert!(outcome.revert().is_none());
    }

    #[test]
    fn a_revertible_outcome_names_what_it_would_restore() {
        let outcome = Outcome::Revertible(Revert::ConfigFile {
            backup: test_backup(),
            service: "ssh.service",
        });

        assert!(outcome.is_revertible());
        assert_eq!(
            outcome.revert().expect("a revert").describes(),
            "/etc/ssh/sshd_config"
        );
    }

    #[test]
    fn reverting_restores_the_file_and_reloads_the_service() {
        // A restored file the daemon has not re-read has changed nothing, so
        // the reload is part of the revert rather than a step after it.
        let mock = MockExecutor::with_replies(vec![Reply::ok(""), Reply::ok("")]);
        let backend = for_family(Family::Debian);

        Revert::ConfigFile {
            backup: test_backup(),
            service: "ssh.service",
        }
        .apply(&mock, backend.as_ref())
        .expect("reverting must succeed");

        let commands = mock.recorded_lines();

        assert!(
            commands
                .iter()
                .any(|line| line.contains("sshd_config.initd")),
            "the backup must be copied back: {commands:?}"
        );
        assert!(
            commands.iter().any(|line| line.contains("reload")),
            "the service must re-read the restored file: {commands:?}"
        );
        assert!(
            !commands.iter().any(|line| line.contains("restart")),
            "a restart would drop the session this protects: {commands:?}"
        );
    }
}
