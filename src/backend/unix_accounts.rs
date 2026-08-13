//! POSIX implementation of [`AccountReader`].
//!
//! Shared by every family that ships a full `getent`. Alpine's busybox does
//! not, which is why this is a capability behind a trait rather than a call
//! inlined into the task — and that second implementation exists:
//! [`super::busybox_accounts::BusyboxAccounts`] reads `/etc/passwd` directly.
//! Nothing above this line changed when it arrived, which was the claim.

use crate::domain::accounts::{AccountReader, home_from_passwd_line};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Reads accounts using `getent`.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixAccounts;

impl UnixAccounts {
    pub const fn new() -> Self {
        Self
    }
}

impl AccountReader for UnixAccounts {
    fn exists(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // `getent passwd <user>` exits non-zero for "no such account", which
        // is an answer rather than a failure, so the exit code is read instead
        // of checked. Unprivileged: the passwd database is world-readable, and
        // a lookup that asked for root would spend an escalation on a question
        // any user may ask.
        let command = Command::new("getent").args(["passwd", user]);

        Ok(executor.run(&command)?.success())
    }

    fn home_dir(&self, executor: &dyn Executor, user: &str) -> Result<String> {
        // The same lookup `exists` runs, reading the field it discards.
        let command = Command::new("getent").args(["passwd", user]);
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::NoSuchAccount {
                user: user.to_owned(),
            });
        }

        home_from_passwd_line(&output.stdout, user).ok_or_else(|| Error::NoSuchAccount {
            user: user.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn an_existing_account_is_reported_present() {
        let mock =
            MockExecutor::with_replies([Reply::ok("alice:x:1000:1000::/home/alice:/bin/sh")]);

        assert!(
            UnixAccounts::new()
                .exists(&mock, "alice")
                .expect("the lookup must succeed")
        );
    }

    #[test]
    fn a_size_is_measured_in_bytes_whatever_the_host_defaults_to() {
        // `du -s` alone answers in kibibytes on some systems and 512-byte
        // blocks on others. A number whose unit depends on the host is worse
        // than none in a sentence an operator will read as gigabytes.
        let mock = MockExecutor::with_replies([Reply::ok("2576980378\t/home/deploy")]);

        assert_eq!(
            UnixAccounts::new()
                .size_of(&mock, "/home/deploy")
                .expect("the measurement must succeed"),
            Some(2_576_980_378)
        );
        assert!(mock.single_command().args.contains(&"-sB1".to_owned()));
    }

    #[test]
    fn a_path_that_cannot_be_measured_is_not_reported_as_empty() {
        // Zero and unmeasurable are different facts, and reporting "(0 B)" for
        // a directory nobody could read understates what is at stake by
        // exactly the amount that matters.
        let mock = MockExecutor::with_replies([Reply::failure(1, "du: /home/gone: No such file")]);

        assert_eq!(
            UnixAccounts::new()
                .size_of(&mock, "/home/gone")
                .expect("an unmeasurable path is an answer, not a failure"),
            None
        );
    }

    #[test]
    fn a_missing_account_is_an_answer_not_a_failure() {
        // `getent` exits 2 for "no such key". Treating that as an error would
        // make a typo in an allow-list look like a broken system.
        let mock = MockExecutor::with_replies([Reply::failure(2, "")]);

        let found = UnixAccounts::new()
            .exists(&mock, "admn")
            .expect("a missing account must not raise");

        assert!(!found);
    }

    #[test]
    fn the_lookup_is_unprivileged() {
        // The passwd database is world-readable; escalating for it would spend
        // a sudo timestamp on a question that does not need one.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        UnixAccounts::new().exists(&mock, "alice").expect("runs");

        assert!(!mock.any_privileged(), "got: {:?}", mock.recorded_lines());
    }
}
