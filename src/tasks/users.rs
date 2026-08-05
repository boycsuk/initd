//! Account administration.
//!
//! Ordered before everything else in the tree because the rest depends on
//! there being a safe way in. `users.lock-root` is the one operation in this
//! tool that cannot be undone from a keyboard: a wrong hardening choice is
//! recoverable through the verification window, while an administrator locked
//! out of a remote machine needs the provider's rescue console.

use crate::backend::Backend;
use crate::distro::Family;
use crate::domain::account_writer::{LockMethod, PasswordPolicy};
use crate::error::{Error, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Task};

/// Families these tasks support.
///
/// Every family, though not by the same tools: Debian, Arch and RHEL ship the
/// shadow suite, while Alpine drives busybox's `adduser` through an
/// `AccountWriter` of its own.
const SUPPORTED: &[Family] = &[Family::Debian, Family::Arch, Family::Alpine, Family::Rhel];

/// The account whose lock is dangerous enough to warrant its own guard.
const ROOT: &str = "root";

/// Default login shell for a newly created account.
///
/// `/bin/bash` rather than anything more opinionated: it is present on both
/// families out of the box, and changing it afterwards is what
/// [`SetShell`] is for.
const DEFAULT_SHELL: &str = "/bin/bash";

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Builds the account administration category.
pub fn category() -> Category {
    Category::new(
        "Users",
        vec![
            Node::Task(Box::new(CreateUser)),
            Node::Task(Box::new(SetShell)),
            Node::Task(Box::new(LockRoot)),
        ],
    )
}

/// Creates an administrative account.
pub struct CreateUser;

impl CreateUser {
    /// Name of the parameter holding the account to create.
    pub const USER: &'static str = "user";
}

impl Task for CreateUser {
    fn id(&self) -> &'static str {
        "users.create"
    }

    fn title(&self) -> &'static str {
        "Create an administrative user"
    }

    fn description(&self) -> &'static str {
        "Creates an account with a home directory, no password, and membership \
         of the group that grants sudo on this distribution. Authorise a key \
         for it before locking root."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account to create"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn consequences(&self, values: &ParamValues) -> Vec<Consequence> {
        let Ok(user) = values.get(Self::USER) else {
            return Vec::new();
        };

        // The account exists and can escalate, but cannot log in until a key
        // is authorised for it — it was created without a password precisely
        // so that it cannot be reached by one.
        vec![Consequence::Invalidates {
            task: "ssh.authorize-key",
            reason: Reason::AccountNotListed {
                user: user.to_owned(),
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();
        let accounts = backend.account_writer();
        let group = backend.admin_group();

        if backend.accounts().exists(executor, &user)? {
            return Err(Error::AccountExists { user });
        }

        report(progress, format!("creating {user}"));

        // No password, deliberately: an account reachable by password is one
        // more thing to guess. It escalates through the admin group and logs
        // in with a key.
        accounts.create(executor, &user, DEFAULT_SHELL, PasswordPolicy::Locked)?;

        report(progress, format!("adding {user} to {group}"));

        // Fails rather than reporting success when the group is absent, which
        // is what asking for `sudo` on Arch would do.
        accounts.add_to_group(executor, &user, group)?;

        // Membership is read back rather than assumed. `usermod` exiting zero
        // says the command ran, not that the account is in the group — and
        // this account is about to become the only way onto the machine.
        if !accounts.is_in_group(executor, &user, group)? {
            return Err(Error::GroupMembershipFailed {
                user,
                group: group.to_owned(),
            });
        }

        report(progress, format!("{user} is in {group}"));

        Ok(Outcome::Done)
    }
}

/// Changes a user's login shell.
pub struct SetShell;

impl SetShell {
    /// Name of the parameter holding the account whose shell changes.
    pub const USER: &'static str = "user";
    /// Name of the parameter holding the shell to set.
    pub const SHELL: &'static str = "shell";
}

impl Task for SetShell {
    fn id(&self) -> &'static str {
        "users.set-shell"
    }

    fn title(&self) -> &'static str {
        "Change a user's login shell"
    }

    fn description(&self) -> &'static str {
        "Sets the login shell for an account. The shell must be listed in \
         /etc/shells, which is checked before the change is made."
    }

    /// Changing a login shell to something unusable locks that account out of
    /// interactive sessions, so it is confirmed like any other lockout risk.
    fn is_destructive(&self) -> bool {
        true
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account whose shell changes"),
            Param::new(Self::SHELL, "Shell", ParamKind::Path)
                .with_initial(DEFAULT_SHELL.to_owned())
                .with_hint("must appear in /etc/shells"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();
        let shell = values.get(Self::SHELL)?.trim().to_owned();
        let accounts = backend.account_writer();

        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        // Checked against what the system will actually accept rather than
        // against a list compiled into this binary: fish lives at
        // `/usr/bin/fish` on Arch and `/usr/bin/fish` or `/bin/fish` depending
        // on the Debian release, and a shell absent from /etc/shells is
        // refused by chsh and by some PAM configurations.
        let valid = accounts.valid_shells(executor)?;

        if !valid.iter().any(|candidate| candidate == &shell) {
            return Err(Error::ShellNotListed { shell });
        }

        report(progress, format!("setting {user} shell to {shell}"));

        accounts.set_shell(executor, &user, &shell)?;

        Ok(Outcome::Done)
    }
}

/// Bars the root account from logging in.
pub struct LockRoot;

impl Task for LockRoot {
    fn id(&self) -> &'static str {
        "users.lock-root"
    }

    fn title(&self) -> &'static str {
        "Lock the root account"
    }

    fn description(&self) -> &'static str {
        "Expires the root account so no authentication method admits it. \
         Refuses to run unless another account can already log in with a key \
         and escalate, because this is the one change a keyboard cannot undo."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::ADMIN, "Administrative account", ParamKind::Username)
                .with_hint("the account that must still be able to get in"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let admin = values.get(Self::ADMIN)?.to_owned();

        // The hard prerequisite. Every other change in this tool is
        // recoverable — this one can require the provider's rescue console, so
        // it verifies rather than warns. A dismissible warning is no
        // protection against the only irreversible mistake here.
        self.verify_a_way_back_in(executor, backend, &admin, progress)?;

        // Idempotent: an already-locked root is the state this task exists to
        // reach, so reaching it twice is success rather than an error. Saying
        // so is the point — silence would read as having just done it.
        if backend.account_writer().is_locked(executor, ROOT)? {
            report(progress, "root is already locked".to_owned());

            return Ok(Outcome::Done);
        }

        // Read once more, immediately before the irreversible step. The checks
        // above ran several privileged commands ago, and each of those is a
        // moment in which the key could have been removed — by a second
        // administrator, by another session of this tool, or by an edit made
        // by hand. Every other task in this tree can afford that window;
        // this one cannot, because the recovery from getting it wrong is the
        // hosting provider's rescue console.
        if !has_authorized_key(executor, backend, &admin)? {
            return Err(Error::NoAuthorizedKey { user: admin });
        }

        report(progress, "locking root".to_owned());

        // Expiry, not `passwd -l`. A `!`-prefixed hash is checked by PAM's
        // auth phase, and public-key authentication never reaches it on a PAM
        // build, so `passwd -l root` would leave root logging in with a key
        // against an account the tool reported as locked.
        backend
            .account_writer()
            .lock(executor, ROOT, LockMethod::Expire)?;

        Ok(Outcome::Done)
    }
}

impl LockRoot {
    /// Name of the parameter holding the account that must remain usable.
    pub const ADMIN: &'static str = "admin";

    /// Refuses to continue unless another account can still administer the box.
    ///
    /// Each check answers a different way of being locked out, and all of them
    /// have to hold: an account that exists but holds no key cannot log in, one
    /// that logs in but is not in the admin group cannot escalate, and one that
    /// satisfies both is still stranded if sudo asks for root's password.
    fn verify_a_way_back_in(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        admin: &str,
        progress: Progress<'_>,
    ) -> Result<()> {
        if admin == ROOT {
            return Err(Error::AdminCannotBeRoot);
        }

        if !backend.accounts().exists(executor, admin)? {
            return Err(Error::NoSuchAccount {
                user: admin.to_owned(),
            });
        }

        report(progress, format!("{admin} exists"));

        let group = backend.admin_group();

        if !backend
            .account_writer()
            .is_in_group(executor, admin, group)?
        {
            return Err(Error::NotAnAdministrator {
                user: admin.to_owned(),
                group: group.to_owned(),
            });
        }

        report(progress, format!("{admin} is in {group}"));

        // An account that cannot authenticate is not a way back in, and this
        // one has no password by design.
        if !has_authorized_key(executor, backend, admin)? {
            return Err(Error::NoAuthorizedKey {
                user: admin.to_owned(),
            });
        }

        report(progress, format!("{admin} holds an authorised key"));

        Ok(())
    }
}

/// Whether an account has at least one entry in `authorized_keys`.
fn has_authorized_key(executor: &dyn Executor, backend: &dyn Backend, user: &str) -> Result<bool> {
    let path = format!("/home/{user}/.ssh/authorized_keys");
    let files = backend.files();

    if !files.exists(executor, &path)? {
        return Ok(false);
    }

    // A file that exists but holds only comments authorises nobody, so the
    // contents decide rather than the file's presence.
    Ok(files
        .read(executor, &path)?
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && !line.starts_with('#')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Values for a task taking a single named parameter.
    fn values(name: &'static str, value: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(name, value.to_owned());
        values
    }

    /// Runs a task against a mock, discarding progress output.
    fn run(
        task: &dyn Task,
        family: Family,
        replies: Vec<Reply>,
        values: &ParamValues,
    ) -> (Result<Outcome>, Vec<String>) {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);
        let outcome = task.run(&mock, backend.as_ref(), values, &mut |_| {});

        (outcome, mock.recorded_lines())
    }

    #[test]
    fn a_new_user_joins_the_group_its_distribution_uses() {
        // The divergence in one assertion: the same task, the same values, two
        // different groups. Hard-coding either name would leave the other
        // family with an account that cannot escalate.
        for (family, group) in [(Family::Debian, "sudo"), (Family::Arch, "wheel")] {
            let (outcome, commands) = run(
                &CreateUser,
                family,
                vec![
                    Reply::failure(2, ""),               // account does not exist
                    Reply::ok(""),                       // useradd
                    Reply::ok("group:x:27:"),            // group exists
                    Reply::ok(""),                       // usermod -aG
                    Reply::ok(format!("alice {group}")), // id -nG
                ],
                &values(CreateUser::USER, "alice"),
            );

            outcome.expect("creation must succeed");

            assert!(
                commands.iter().any(|c| c.contains(&format!("-aG {group}"))),
                "{family} must use {group}: {commands:?}"
            );
        }
    }

    #[test]
    fn creating_an_existing_account_is_refused() {
        // Adopting it silently would report a provisioning that never
        // happened: the existing account may have a password, another shell,
        // or no administrative rights at all.
        let (outcome, commands) = run(
            &CreateUser,
            Family::Debian,
            vec![Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash")],
            &values(CreateUser::USER, "alice"),
        );

        let err = outcome.expect_err("an existing account must be refused");

        assert!(matches!(err, Error::AccountExists { .. }), "{err:?}");
        assert_eq!(commands.len(), 1, "nothing must be created: {commands:?}");
    }

    #[test]
    fn a_membership_that_did_not_take_is_an_error() {
        // `usermod` exiting zero says the command ran, not that it worked.
        // This account is often about to become the only way in.
        let (outcome, _) = run(
            &CreateUser,
            Family::Debian,
            vec![
                Reply::failure(2, ""),   // account does not exist
                Reply::ok(""),           // useradd
                Reply::ok("sudo:x:27:"), // group exists
                Reply::ok(""),           // usermod -aG reports success
                Reply::ok("alice"),      // ...and the group is not there
            ],
            &values(CreateUser::USER, "alice"),
        );

        let err = outcome.expect_err("a membership that did not take must fail");

        assert!(
            matches!(err, Error::GroupMembershipFailed { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn locking_root_needs_an_account_that_is_not_root() {
        // Naming the account being locked as the reason it is safe to lock it
        // is circular, and would satisfy every other check.
        let (outcome, commands) = run(
            &LockRoot,
            Family::Debian,
            vec![],
            &values(LockRoot::ADMIN, "root"),
        );

        let err = outcome.expect_err("root cannot vouch for itself");

        assert!(matches!(err, Error::AdminCannotBeRoot), "{err:?}");
        assert!(commands.is_empty(), "nothing must run: {commands:?}");
    }

    #[test]
    fn locking_root_needs_an_administrator_that_can_escalate() {
        // An account that logs in but cannot escalate leaves nobody able to
        // administer the machine once root is gone.
        let (outcome, _) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // exists
                Reply::ok("alice users"),                              // not in sudo
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("a non-administrator must not vouch");

        assert!(matches!(err, Error::NotAnAdministrator { .. }), "{err:?}");
    }

    #[test]
    fn locking_root_needs_an_administrator_that_can_authenticate() {
        // The account is created without a password by design, so a key is the
        // only thing that can let it in. In the admin group and unable to log
        // in is still locked out.
        let (outcome, _) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // exists
                Reply::ok("alice sudo"),                               // can escalate
                Reply::failure(1, ""),                                 // no authorized_keys
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("an account with no key must not vouch");

        assert!(matches!(err, Error::NoAuthorizedKey { .. }), "{err:?}");
    }

    #[test]
    fn an_authorized_keys_holding_only_comments_authorises_nobody() {
        // The file exists, so a presence check would pass. Nothing in it can
        // authenticate anyone.
        let (outcome, _) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("alice sudo"),
                Reply::ok(""),                    // the file exists
                Reply::ok("# added by hand\n\n"), // and holds no key
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("a file of comments must not count as a key");

        assert!(matches!(err, Error::NoAuthorizedKey { .. }), "{err:?}");
    }

    #[test]
    fn locking_root_expires_the_account_rather_than_its_password() {
        // The finding that makes this task correct: `passwd -l` writes a `!`
        // that PAM checks during authentication, and public-key auth never
        // reaches that check. Only expiry refuses every method.
        let (outcome, commands) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("alice sudo"),
                Reply::ok(""),                               // file exists
                Reply::ok("ssh-ed25519 AAAAC3Nza key@host"), // holds a key
                Reply::ok("Account expires\t: never"),       // not yet locked
                Reply::ok(""),                               // re-check: exists
                Reply::ok("ssh-ed25519 AAAAC3Nza key@host"), // re-check: still there
                Reply::ok(""),                               // usermod
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        outcome.expect("every prerequisite is satisfied");

        assert!(
            commands.iter().any(|c| c.contains("--expiredate 1 root")),
            "root must be expired, not password-locked: {commands:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("passwd -l")),
            "passwd -l leaves key authentication working: {commands:?}"
        );
    }

    #[test]
    fn a_key_removed_between_the_check_and_the_lock_stops_it() {
        // The window this closes: several privileged commands separate the
        // prerequisite checks from the lock itself, and a second administrator
        // — or another session of this tool — could remove the key in between.
        // Every other task can afford that; recovery from this one is the
        // provider's rescue console.
        let (outcome, commands) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("alice sudo"),
                Reply::ok(""),                               // file exists
                Reply::ok("ssh-ed25519 AAAAC3Nza key@host"), // holds a key
                Reply::ok("Account expires\t: never"),       // not yet locked
                Reply::failure(1, ""),                       // re-check: gone
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("a key that vanished must stop the lock");

        assert!(matches!(err, Error::NoAuthorizedKey { .. }), "{err:?}");
        assert!(
            !commands.iter().any(|c| c.contains("--expiredate")),
            "root must not be locked: {commands:?}"
        );
    }

    #[test]
    fn locking_an_already_locked_root_is_success() {
        // The state this task exists to reach. Reaching it twice is not a
        // failure, and the interface says so rather than staying silent.
        let (outcome, commands) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("alice sudo"),
                Reply::ok(""),
                Reply::ok("ssh-ed25519 AAAAC3Nza key@host"),
                Reply::ok("Account expires\t: Jan 02, 1970"), // already locked
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        outcome.expect("an already-locked root is the desired state");

        assert!(
            !commands.iter().any(|c| c.contains("--expiredate")),
            "nothing to do: {commands:?}"
        );
    }

    #[test]
    fn a_shell_absent_from_etc_shells_is_refused() {
        // chsh refuses it, and some PAM configurations refuse a session for an
        // account whose shell is not listed. Writing it would strand the user.
        let mut params = ParamValues::new();
        params.set(SetShell::USER, "alice".to_owned());
        params.set(SetShell::SHELL, "/usr/bin/fish".to_owned());

        let (outcome, commands) = run(
            &SetShell,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("/bin/sh\n/bin/bash\n"), // fish is not installed
            ],
            &params,
        );

        let err = outcome.expect_err("an unlisted shell must be refused");

        assert!(matches!(err, Error::ShellNotListed { .. }), "{err:?}");
        assert!(
            !commands.iter().any(|c| c.contains("usermod -s")),
            "the shell must not be written: {commands:?}"
        );
    }

    #[test]
    fn a_listed_shell_is_set() {
        let mut params = ParamValues::new();
        params.set(SetShell::USER, "alice".to_owned());
        params.set(SetShell::SHELL, "/usr/bin/fish".to_owned());

        let (outcome, commands) = run(
            &SetShell,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                Reply::ok("/bin/sh\n/bin/bash\n/usr/bin/fish\n"),
                Reply::ok(""),
            ],
            &params,
        );

        outcome.expect("a listed shell must be accepted");

        assert!(
            commands
                .iter()
                .any(|c| c.contains("usermod -s /usr/bin/fish alice")),
            "{commands:?}"
        );
    }

    #[test]
    fn creating_a_user_points_at_authorising_a_key_for_it() {
        // The account has no password by design, so it cannot log in until a
        // key is authorised. Leaving that unsaid is how a machine ends up with
        // an administrator nobody can use.
        let consequences = CreateUser.consequences(&values(CreateUser::USER, "alice"));

        assert_eq!(
            consequences.len(),
            1,
            "exactly one follow-up: {consequences:?}"
        );
        assert_eq!(consequences[0].task(), Some("ssh.authorize-key"));
    }
}
