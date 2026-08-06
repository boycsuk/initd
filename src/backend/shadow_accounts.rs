//! shadow-utils implementation of [`AccountWriter`].
//!
//! Shared by every family shipping the full shadow suite (`useradd`,
//! `usermod`, `chage`, `getent`). Alpine's busybox provides `adduser` with a
//! different interface and no `chage`, which is why this is behind a trait
//! rather than inlined into the tasks.
//!
//! `useradd` rather than `adduser`: the latter is a Perl wrapper on Debian, a
//! busybox applet on Alpine, and absent on Arch. `useradd` is the one the
//! shadow suite defines and behaves the same wherever the suite is installed.

use super::posix_accounts;
use super::systemd::run_checked;
use crate::domain::account_writer::{AccountWriter, LockMethod, PasswordPolicy};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Expiry date written to lock an account, in days since the epoch.
///
/// `1` rather than `0`: `shadow(5)` documents `0` as ambiguous, since it is
/// also how "no expiry" is represented in some implementations. `1` is
/// unambiguously 1970-01-02 — comfortably in the past — and every
/// implementation reads it the same way.
const EXPIRED: &str = "1";

/// Manages accounts through the shadow suite.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShadowAccounts;

impl ShadowAccounts {
    pub const fn new() -> Self {
        Self
    }
}

impl AccountWriter for ShadowAccounts {
    fn create(
        &self,
        executor: &dyn Executor,
        user: &str,
        shell: &str,
        password: PasswordPolicy,
    ) -> Result<()> {
        // `-m` creates the home directory, which `useradd` does not do by
        // default on every distribution: Debian's login.defs sets CREATE_HOME,
        // Arch's does not. Passing it explicitly removes the difference.
        let mut command = Command::new("useradd")
            .args(["-m", "-s", shell, user])
            .privileged();

        match password {
            // An account created without `-p` has `!` in the password field,
            // which is already "no password will ever match". Passing nothing
            // is what leaves it that way; there is no flag that means it more
            // strongly.
            PasswordPolicy::Locked => {}
        }

        command = command.privileged();

        run_checked(executor, &command)
    }

    fn add_to_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<()> {
        // Checked first because `usermod -aG` accepts a group the system does
        // not have and exits zero, granting nothing. On Arch, where the group
        // is `wheel`, asking for `sudo` fails exactly this way — an account
        // that looks provisioned and cannot escalate.
        if !self.group_exists(executor, group)? {
            return Err(Error::MissingGroup {
                group: group.to_owned(),
            });
        }

        // `-a` is what makes this additive. Without it, `-G` replaces every
        // supplementary group the account had.
        let command = Command::new("usermod")
            .args(["-aG", group, user])
            .privileged();

        run_checked(executor, &command)
    }

    fn group_exists(&self, executor: &dyn Executor, group: &str) -> Result<bool> {
        // Unprivileged: the group database is world-readable, and escalating
        // would spend a sudo timestamp on a question any user may ask.
        let command = Command::new("getent").args(["group", group]);

        Ok(executor.run(&command)?.success())
    }

    fn is_in_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<bool> {
        posix_accounts::is_in_group(executor, user, group)
    }

    fn set_shell(&self, executor: &dyn Executor, user: &str, shell: &str) -> Result<()> {
        let command = Command::new("usermod")
            .args(["-s", shell, user])
            .privileged();

        run_checked(executor, &command)
    }

    fn lock(&self, executor: &dyn Executor, user: &str, method: LockMethod) -> Result<()> {
        match method {
            // `--expiredate`, not `passwd -l`. The latter prefixes the password
            // hash with `!`, which PAM checks during authentication — and
            // public-key authentication never gets there, so root would go on
            // logging in with a key against an account reported as locked.
            LockMethod::Expire => {
                let command = Command::new("usermod")
                    .args(["--expiredate", EXPIRED, user])
                    .privileged();

                run_checked(executor, &command)
            }
        }
    }

    fn is_locked(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // `chage -l` prints the expiry in a human-readable form. The account is
        // locked when the date is in the past; `never` means it is not.
        let command = Command::new("chage").args(["-l", user]).privileged();
        let output = executor.run(&command)?;

        if !output.success() {
            return Ok(false);
        }

        let expiry = output
            .stdout
            .lines()
            .find(|line| line.starts_with("Account expires"))
            .and_then(|line| line.split(':').nth(1))
            .map(str::trim)
            .unwrap_or("never");

        Ok(expiry != "never")
    }

    fn valid_shells(&self, executor: &dyn Executor) -> Result<Vec<String>> {
        posix_accounts::valid_shells(executor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn creating_an_account_makes_its_home_directory() {
        // Debian's login.defs sets CREATE_HOME and Arch's does not, so the
        // flag is passed rather than relied upon. An account with no home has
        // nowhere to put authorized_keys.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ShadowAccounts::new()
            .create(&mock, "alice", "/bin/bash", PasswordPolicy::Locked)
            .expect("creation must succeed");

        let command = mock.single_command();

        assert!(command.args.contains(&"-m".to_owned()), "{command:?}");
        assert!(mock.any_privileged());
    }

    #[test]
    fn adding_to_a_missing_group_is_refused() {
        // The silent failure this guards: `usermod -aG sudo` on Arch exits
        // zero and grants nothing, because the group is `wheel` there. An
        // account that looks provisioned and cannot escalate is worse than one
        // that failed loudly.
        let mock = MockExecutor::with_replies([Reply::failure(2, "")]);

        let err = ShadowAccounts::new()
            .add_to_group(&mock, "alice", "sudo")
            .expect_err("a missing group must fail");

        assert!(matches!(err, Error::MissingGroup { .. }), "{err:?}");

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "usermod must not run once the group check has failed"
        );
    }

    #[test]
    fn adding_to_an_existing_group_is_additive() {
        // Without `-a`, `-G` replaces every supplementary group the account
        // had, which can remove the very access it was granted for.
        let mock = MockExecutor::with_replies([Reply::ok("sudo:x:27:"), Reply::ok("")]);

        ShadowAccounts::new()
            .add_to_group(&mock, "alice", "sudo")
            .expect("the group exists, so this must succeed");

        let commands = mock.recorded_lines();

        assert_eq!(commands.len(), 2, "{commands:?}");
        assert!(commands[1].contains("-aG"), "{commands:?}");
    }

    #[test]
    fn group_membership_matches_whole_names() {
        // `sudo` is a substring of `sudoers`; a substring check would report
        // an account as an administrator on the strength of an unrelated
        // group.
        let mock = MockExecutor::with_replies([Reply::ok("alice sudoers docker\n")]);

        let member = ShadowAccounts::new()
            .is_in_group(&mock, "alice", "sudo")
            .expect("the query must succeed");

        assert!(!member, "sudoers must not satisfy a check for sudo");
    }

    #[test]
    fn group_membership_finds_the_group() {
        let mock = MockExecutor::with_replies([Reply::ok("alice sudo docker\n")]);

        assert!(
            ShadowAccounts::new()
                .is_in_group(&mock, "alice", "sudo")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn locking_expires_the_account_rather_than_its_password() {
        // The finding this encodes: a `!`-locked password does not stop key
        // authentication, because sshd never calls pam_authenticate for a
        // public key. Only expiry refuses every method.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ShadowAccounts::new()
            .lock(&mock, "root", LockMethod::Expire)
            .expect("locking must succeed");

        let command = mock.single_command();

        assert!(
            command.args.contains(&"--expiredate".to_owned()),
            "{command:?}"
        );
        assert!(
            !mock.recorded_lines()[0].contains("passwd -l"),
            "passwd -l leaves key authentication working"
        );
    }

    #[test]
    fn the_expiry_date_is_unambiguous() {
        // shadow(5) documents 0 as ambiguous — it can also mean "no expiry".
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ShadowAccounts::new()
            .lock(&mock, "root", LockMethod::Expire)
            .expect("locking must succeed");

        assert!(
            mock.single_command().args.contains(&"1".to_owned()),
            "the expiry must be 1, not 0"
        );
    }

    #[test]
    fn an_account_that_never_expires_is_not_locked() {
        let mock = MockExecutor::with_replies([Reply::ok(
            "Last password change\t: Aug 04, 2026\nAccount expires\t: never\n",
        )]);

        assert!(
            !ShadowAccounts::new()
                .is_locked(&mock, "root")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn an_expired_account_is_locked() {
        let mock = MockExecutor::with_replies([Reply::ok(
            "Last password change\t: Aug 04, 2026\nAccount expires\t: Jan 02, 1970\n",
        )]);

        assert!(
            ShadowAccounts::new()
                .is_locked(&mock, "root")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn comments_are_not_offered_as_login_shells() {
        // A `#` line accepted by the form and refused by the system is a shell
        // change that reports success and strands the account.
        let mock = MockExecutor::with_replies([Reply::ok(
            "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n\n/usr/bin/fish\n",
        )]);

        let shells = ShadowAccounts::new()
            .valid_shells(&mock)
            .expect("the read must succeed");

        assert_eq!(shells, ["/bin/sh", "/bin/bash", "/usr/bin/fish"]);
    }

    #[test]
    fn reading_the_shells_needs_no_privilege() {
        // /etc/shells is world-readable.
        let mock = MockExecutor::with_replies([Reply::ok("/bin/sh\n")]);

        ShadowAccounts::new().valid_shells(&mock).expect("runs");

        assert!(!mock.any_privileged());
    }
}
