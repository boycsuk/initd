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
use crate::backend::backup_index::{self, BackupRecord};
use crate::domain::files::Backup;
use crate::error::{Error, Result};
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

    /// Restore a file from a copy recorded in an earlier session.
    ///
    /// Distinct from [`ConfigFile`](Self::ConfigFile), which is the undo the
    /// verification window offers within the session that made the change: the
    /// copy is in hand, nothing else has touched the file, and the countdown is
    /// what bounds that.
    ///
    /// This one crosses sessions, and the assumption the other rests on does
    /// not survive the crossing. An administrator may have edited the file by
    /// hand yesterday; restoring over that would discard their work with no
    /// warning, which is the one outcome a revert must never produce. So the
    /// record carries what this tool wrote, the live file is hashed before
    /// anything is restored, and a file that has changed since refuses rather
    /// than merging or overwriting.
    #[allow(
        dead_code,
        reason = "constructed by the History area, which lands in a later commit"
    )]
    FromIndex { record: BackupRecord },
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
            Self::FromIndex { record } => {
                // The check this variant exists for, and it comes first: once
                // the copy is over the original there is nothing left to
                // compare against, so proving the file is what this tool left
                // has to happen while it is still true.
                let Some(live) = backup_index::digest_of(executor, &record.path) else {
                    return Err(Error::RevertUnverifiable {
                        path: record.path.clone(),
                    });
                };

                if live != record.sha256_after {
                    return Err(Error::FileChangedSinceBackup {
                        path: record.path.clone(),
                        expected: record.sha256_after.clone(),
                        found: live,
                    });
                }

                // The copy itself, checked too. A backup truncated by a full
                // disk is a file that exists, is readable, and would replace a
                // working configuration with half of one.
                let Some(copy) = backup_index::digest_of(executor, &record.copy) else {
                    return Err(Error::RevertUnverifiable {
                        path: record.copy.clone(),
                    });
                };

                if copy != record.sha256_before {
                    return Err(Error::BackupCorrupt {
                        copy: record.copy.clone(),
                    });
                }

                backend.files().restore(
                    executor,
                    &Backup {
                        original: record.path.clone(),
                        copy: record.copy.clone(),
                    },
                )?;

                // A capability with no unit — a sysctl, a shell registration —
                // records an empty service, and reloading "" would be asking
                // systemd about a unit nobody named.
                if record.service.is_empty() {
                    return Ok(());
                }

                backend.services().reload(executor, record.service)
            }
        }
    }

    /// What the revert would put back, for the interface to state.
    pub fn describes(&self) -> &str {
        match self {
            Self::ConfigFile { backup, .. } => &backup.original,
            Self::FromIndex { record } => &record.path,
        }
    }

    /// Where the copy it would restore from is kept.
    ///
    /// Stated by the command line, which has no verification window to offer
    /// and so hands over the path instead. [`describes`](Self::describes) names
    /// the file that changed, which is the wrong one to reach for: an operator
    /// told to "restore the previous sshd_config" needs the copy, not the live
    /// file they are locked out by.
    pub fn restores_from(&self) -> &str {
        match self {
            Self::ConfigFile { backup, .. } => &backup.copy,
            Self::FromIndex { record } => &record.copy,
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

    /// A record whose digests are stated, so a test can decide what the host
    /// appears to hold.
    fn recorded(after: &str) -> BackupRecord {
        BackupRecord {
            task: "ssh.harden",
            path: "/etc/ssh/sshd_config".to_owned(),
            copy: "/var/lib/initd/backups/etc-ssh-sshd_config.20260809T142203Z".to_owned(),
            at: "20260809T142203Z".to_owned(),
            sha256_before: "a".repeat(64),
            sha256_after: after.to_owned(),
            service: "ssh.service",
        }
    }

    #[test]
    fn a_file_edited_since_the_backup_is_refused_rather_than_overwritten() {
        // The whole reason a cross-session revert checks anything. Restoring
        // over an administrator's own edit would discard their work and report
        // success, which is the one outcome a revert must never produce.
        let live = "b".repeat(64);
        let edited_since = "c".repeat(64);

        let mock = MockExecutor::with_replies([Reply::ok(format!(
            "{edited_since}  /etc/ssh/sshd_config"
        ))]);

        let err = Revert::FromIndex {
            record: recorded(&live),
        }
        .apply(&mock, for_family(Family::Debian).as_ref())
        .expect_err("a changed file must be refused");

        match err {
            Error::FileChangedSinceBackup {
                expected, found, ..
            } => {
                assert_eq!(expected, live);
                assert_eq!(found, edited_since);
            }
            other => panic!("wrong error: {other:?}"),
        }

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "nothing may be restored after the refusal: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_truncated_copy_is_refused_even_when_the_live_file_matches() {
        // The other half. The file is exactly what this tool left, so the
        // revert is legitimate — but the copy it would restore was damaged
        // after being taken, and putting half a configuration over a working
        // one is worse than leaving the change in place.
        let live = "b".repeat(64);
        let damaged = "d".repeat(64);

        let mock = MockExecutor::with_replies([
            // The live file: matches what was recorded.
            Reply::ok(format!("{live}  /etc/ssh/sshd_config")),
            // The copy: does not.
            Reply::ok(format!("{damaged}  /var/lib/initd/backups/x")),
        ]);

        let err = Revert::FromIndex {
            record: recorded(&live),
        }
        .apply(&mock, for_family(Family::Debian).as_ref())
        .expect_err("a damaged copy must be refused");

        assert!(matches!(err, Error::BackupCorrupt { .. }));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_neither_a_match_nor_a_mismatch() {
        // Reported as its own case: "the file is different" and "I could not
        // read the file" call for different actions, and reporting the second
        // as the first sends somebody looking for an edit nobody made.
        let mock = MockExecutor::with_replies([Reply::failure(1, "Permission denied")]);

        let err = Revert::FromIndex {
            record: recorded(&"b".repeat(64)),
        }
        .apply(&mock, for_family(Family::Debian).as_ref())
        .expect_err("an unreadable file must not be reported as changed");

        assert!(matches!(err, Error::RevertUnverifiable { .. }));
    }

    #[test]
    fn an_untouched_file_is_restored_and_its_unit_reloaded() {
        let live = "b".repeat(64);

        let mock = MockExecutor::with_replies([
            Reply::ok(format!("{live}  /etc/ssh/sshd_config")),
            Reply::ok(format!("{}  /var/lib/initd/backups/x", "a".repeat(64))),
            // The restore itself, then the reload.
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Revert::FromIndex {
            record: recorded(&live),
        }
        .apply(&mock, for_family(Family::Debian).as_ref())
        .expect("an untouched file must be restorable");

        let commands = mock.recorded_lines();

        assert!(
            commands.iter().any(|line| line.contains("cp")),
            "{commands:?}"
        );
        assert!(
            commands.iter().any(|line| line.contains("reload")),
            "a restored file the daemon has not re-read has changed nothing: {commands:?}"
        );
        assert!(
            !commands.iter().any(|line| line.contains("restart")),
            "a restart would drop the session this exists to protect: {commands:?}"
        );
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
    fn the_copy_is_named_apart_from_the_file_it_would_replace() {
        // The command line prints both, having no verification window to
        // offer. It printed only `describes()`, which names the file that
        // changed — so an operator told to "restore the previous sshd_config"
        // was handed the path of the one locking them out rather than the path
        // of the copy that would let them back in.
        let revert = Revert::ConfigFile {
            backup: test_backup(),
            service: "ssh.service",
        };

        assert_eq!(revert.describes(), "/etc/ssh/sshd_config");
        assert_eq!(
            revert.restores_from(),
            "/etc/ssh/sshd_config.initd.20260803"
        );
        assert_ne!(
            revert.describes(),
            revert.restores_from(),
            "the two paths are what makes the message actionable"
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
