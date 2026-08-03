//! POSIX implementation of [`AccountReader`].
//!
//! Shared by every family that ships a full `getent`. Alpine's busybox does
//! not, which is why this is a capability behind a trait rather than a call
//! inlined into the task: that family will need its own implementation
//! reading `/etc/passwd` directly, and nothing above this line has to change
//! when it arrives.

use crate::domain::accounts::AccountReader;
use crate::error::Result;
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
