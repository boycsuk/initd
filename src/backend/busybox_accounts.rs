//! busybox implementations of the account capabilities.
//!
//! Alpine ships busybox rather than the shadow suite and GNU coreutils, which
//! is why account handling is behind traits at all. Three differences matter:
//!
//! - There is no `getent`, so the passwd database is read directly.
//! - `useradd` is absent; busybox provides `adduser`, whose flags are not the
//!   same ones spelled differently — `-D` means "no password" where shadow
//!   would take nothing at all, and `-G` takes one group rather than a list.
//! - There is neither `usermod` nor `chage` — verified in a container rather
//!   than assumed. busybox stops at creating accounts and joining groups, so
//!   changing a shell or expiring an account needs the `shadow` package, which
//!   this implementation installs when it first needs one of them. Expiry is
//!   still read back out of `/etc/shadow` directly, since `chage` is only
//!   worth pulling in for the write.

use super::posix_accounts;
use crate::domain::account_writer::{AccountWriter, LockMethod, PasswordPolicy};
use crate::domain::accounts::{AccountReader, home_from_passwd_line};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Where the account database lives.
const PASSWD: &str = "/etc/passwd";

/// Where password ageing is recorded.
const SHADOW: &str = "/etc/shadow";

/// Index of the expiry field in a shadow entry, counting from zero.
///
/// `shadow(5)` numbers the fields from one and names the expiry as the eighth,
/// so this is that minus one. Stated as an index rather than as a field number
/// because it addresses a slice here, and the off-by-one between the two
/// conventions is exactly the mistake worth naming.
const SHADOW_EXPIRY_INDEX: usize = 7;

/// Expiry written to lock an account, in days since the epoch.
///
/// `1` rather than `0` for the same reason as the shadow implementation:
/// `shadow(5)` documents 0 as ambiguous.
const EXPIRED: &str = "1";

/// Reads accounts from `/etc/passwd` directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct BusyboxAccounts;

impl BusyboxAccounts {
    pub const fn new() -> Self {
        Self
    }
}

impl AccountReader for BusyboxAccounts {
    fn exists(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // No `getent` here, so the file is read. Anchored to the start of the
        // line and terminated by the colon that ends the name field, or
        // `admin` would be satisfied by an entry for `administrator`.
        let command = Command::new("grep").args(["-q", &format!("^{user}:"), PASSWD]);

        Ok(executor.run(&command)?.success())
    }

    fn home_dir(&self, executor: &dyn Executor, user: &str) -> Result<String> {
        // Without `-q` this time, since the line itself is the answer. Same
        // anchoring: `admin` must not be satisfied by `administrator`.
        let command = Command::new("grep").args([&format!("^{user}:"), PASSWD]);
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

/// Manages accounts through busybox's applets.
#[derive(Debug, Clone, Copy, Default)]
pub struct BusyboxAccountWriter;

/// The package providing `usermod`, which busybox does not.
const SHADOW_PACKAGE: &str = "shadow";

impl BusyboxAccountWriter {
    pub const fn new() -> Self {
        Self
    }

    /// Makes `usermod` available, installing the shadow suite if it is not.
    ///
    /// busybox covers creating an account and joining a group but stops short
    /// of changing a shell or setting an expiry, and Alpine leaves those to an
    /// optional package. Installed on demand rather than as a prerequisite of
    /// the backend: a host that only ever creates accounts should not carry a
    /// package it never calls.
    fn ensure_usermod(&self, executor: &dyn Executor) -> Result<()> {
        let present = executor
            .run(&Command::new("sh").args(["-c", "command -v usermod"]))?
            .success();

        if present {
            return Ok(());
        }

        let install = Command::new("apk")
            .args(["add", "--no-cache", SHADOW_PACKAGE])
            .privileged();

        super::systemd::run_checked(executor, &install)
    }
}

impl AccountWriter for BusyboxAccountWriter {
    fn create(
        &self,
        executor: &dyn Executor,
        user: &str,
        shell: &str,
        password: PasswordPolicy,
    ) -> Result<()> {
        // `adduser`, not `useradd`, and the flags differ in meaning rather
        // than in spelling: `-D` here means "do not assign a password", where
        // the shadow suite achieves the same by being given no password flag.
        let mut args = vec!["-h", &format!("/home/{user}"), "-s", shell]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();

        match password {
            PasswordPolicy::Locked => args.push("-D".to_owned()),
        }

        args.push(user.to_owned());

        let command = Command::new("adduser")
            .args(args.iter().map(String::as_str))
            .privileged();

        super::systemd::run_checked(executor, &command)
    }

    fn add_to_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<()> {
        if !self.group_exists(executor, group)? {
            return Err(Error::MissingGroup {
                group: group.to_owned(),
            });
        }

        // `addgroup <user> <group>` here, which reads backwards compared to
        // `usermod -aG <group> <user>`. Additive by nature: busybox has no
        // equivalent of `-G` replacing the whole set, so there is no flag to
        // forget.
        let command = Command::new("addgroup").args([user, group]).privileged();

        super::systemd::run_checked(executor, &command)
    }

    fn group_exists(&self, executor: &dyn Executor, group: &str) -> Result<bool> {
        let command = Command::new("grep").args(["-q", &format!("^{group}:"), "/etc/group"]);

        Ok(executor.run(&command)?.success())
    }

    fn is_in_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<bool> {
        // busybox provides `id`, and its `-nG` output is the same
        // space-separated list, which is why this is the shared one.
        posix_accounts::is_in_group(executor, user, group)
    }

    fn set_shell(&self, executor: &dyn Executor, user: &str, shell: &str) -> Result<()> {
        self.ensure_usermod(executor)?;

        let command = Command::new("usermod")
            .args(["-s", shell, user])
            .privileged();

        super::systemd::run_checked(executor, &command)
    }

    fn lock(&self, executor: &dyn Executor, user: &str, method: LockMethod) -> Result<()> {
        match method {
            // Same reasoning as everywhere else: a locked password leaves key
            // authentication working, and only expiry refuses every method.
            LockMethod::Expire => {
                self.ensure_usermod(executor)?;

                let command = Command::new("usermod")
                    .args(["--expiredate", EXPIRED, user])
                    .privileged();

                super::systemd::run_checked(executor, &command)
            }
        }
    }

    fn is_locked(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // No `chage`, so the shadow entry is read directly. Fetched whole and
        // split here rather than piped through `cut` inside an `sh -c` string:
        // interpolating a username into a shell command works only for as long
        // as every caller validates it first, and this backend cannot see who
        // its callers will be. An argv element cannot be reinterpreted as
        // syntax, so the question stops depending on that.
        let command = Command::new("grep")
            .args([&format!("^{user}:"), SHADOW])
            .privileged();

        let output = executor.run(&command)?;

        if !output.success() {
            return Ok(false);
        }

        // The expiry is empty when the account never expires, which is what
        // distinguishes it from one expired at the epoch.
        let expiry = output
            .stdout
            .split(':')
            .nth(SHADOW_EXPIRY_INDEX)
            .unwrap_or("")
            .trim();

        Ok(!expiry.is_empty())
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
    fn an_account_is_read_from_the_file_rather_than_through_getent() {
        // busybox ships no `getent`, which is the difference that makes
        // account reading a capability rather than one shared implementation.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        BusyboxAccounts::new()
            .exists(&mock, "alice")
            .expect("the lookup must succeed");

        let line = mock.recorded_lines().remove(0);

        assert!(line.starts_with("grep"), "{line}");
        assert!(line.contains("/etc/passwd"), "{line}");
    }

    #[test]
    fn a_name_is_anchored_so_a_longer_one_does_not_satisfy_it() {
        // `admin` must not be answered by an entry for `administrator`.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        BusyboxAccounts::new().exists(&mock, "admin").expect("runs");

        assert!(
            mock.recorded_lines()[0].contains("^admin:"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn creating_an_account_uses_adduser_with_no_password() {
        // `-D` means "no password" here; the shadow suite means the same thing
        // by passing no password flag at all. Not a spelling difference.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        BusyboxAccountWriter::new()
            .create(&mock, "alice", "/bin/sh", PasswordPolicy::Locked)
            .expect("creation must succeed");

        let command = mock.single_command();

        assert_eq!(command.program, "adduser");
        assert!(command.args.contains(&"-D".to_owned()), "{command:?}");
    }

    #[test]
    fn a_group_is_joined_with_the_arguments_reversed() {
        // `addgroup <user> <group>` reads backwards compared to
        // `usermod -aG <group> <user>`, and getting it round the wrong way
        // creates a group named after the user.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        BusyboxAccountWriter::new()
            .add_to_group(&mock, "alice", "wheel")
            .expect("the group exists, so this must succeed");

        let line = mock.recorded_lines().remove(1);

        assert!(line.ends_with("addgroup alice wheel"), "{line}");
    }

    #[test]
    fn adding_to_a_missing_group_is_refused_here_too() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        let err = BusyboxAccountWriter::new()
            .add_to_group(&mock, "alice", "wheel")
            .expect_err("a missing group must fail");

        assert!(matches!(err, Error::MissingGroup { .. }), "{err:?}");
    }

    #[test]
    fn the_shadow_suite_is_installed_when_usermod_is_missing() {
        // Verified in a container rather than assumed: busybox ships neither
        // `usermod` nor `chage`, and Alpine leaves both to an optional
        // package. Without this the task fails with "not found" after having
        // already created the account.
        let mock = MockExecutor::with_replies([
            Reply::failure(127, "usermod: not found"),
            Reply::ok(""), // apk add shadow
            Reply::ok(""), // usermod
        ]);

        BusyboxAccountWriter::new()
            .lock(&mock, "root", LockMethod::Expire)
            .expect("locking must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.contains("apk add --no-cache shadow")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    /// A shadow entry, as `/etc/shadow` holds it.
    ///
    /// Nine colon-separated fields; the eighth is the expiry. Written out in
    /// full because the function now splits the line itself rather than
    /// letting `cut` do it, so a test feeding only the field would be
    /// exercising something the code no longer does.
    fn shadow_entry(expiry: &str) -> String {
        format!("root:!:19000:0:99999:7::{expiry}:\n")
    }

    #[test]
    fn expiry_is_read_out_of_the_shadow_entry() {
        // No `chage` here, so the field is read directly. An empty eighth
        // field means the account never expires.
        let mock = MockExecutor::with_replies([Reply::ok(shadow_entry("1"))]);

        assert!(
            BusyboxAccountWriter::new()
                .is_locked(&mock, "root")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn an_empty_expiry_field_means_the_account_never_expires() {
        let mock = MockExecutor::with_replies([Reply::ok(shadow_entry(""))]);

        assert!(
            !BusyboxAccountWriter::new()
                .is_locked(&mock, "root")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_username_never_reaches_a_shell() {
        // The reason this stopped piping through `cut` in an `sh -c` string:
        // interpolating a name into shell syntax is safe only while every
        // caller validates it, and a backend cannot see its future callers.
        let mock = MockExecutor::with_replies([Reply::ok(shadow_entry("1"))]);

        BusyboxAccountWriter::new()
            .is_locked(&mock, "root")
            .expect("the query must succeed");

        let command = mock.single_command();

        assert_eq!(command.program, "grep");
        assert!(
            !command.args.iter().any(|arg| arg.contains('|')),
            "no shell pipeline: {command:?}"
        );
    }

    #[test]
    fn locking_expires_rather_than_touching_the_password() {
        let mock = MockExecutor::with_replies([
            Reply::ok("/usr/sbin/usermod"), // already available
            Reply::ok(""),
        ]);

        BusyboxAccountWriter::new()
            .lock(&mock, "root", LockMethod::Expire)
            .expect("locking must succeed");

        let line = mock.recorded_lines().remove(1);

        assert!(line.contains("--expiredate 1"), "{line}");
        assert!(!line.contains("passwd -l"), "{line}");
    }
}
