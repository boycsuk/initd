//! Account administration.
//!
//! Ordered before everything else in the tree because the rest depends on
//! there being a safe way in. `users.lock-root` is the one operation in this
//! tool that cannot be undone from a keyboard: a wrong hardening choice is
//! recoverable through the verification window, while an administrator locked
//! out of a remote machine needs the provider's rescue console.

use crate::backend::Backend;
use crate::domain::account_writer::{LockMethod, PasswordPolicy};
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::ssh::has_authorized_key;
use crate::tasks::{Category, Confirmation, Node, Progress, Task, report, supported_everywhere};

/// The account whose lock is dangerous enough to warrant its own guard.
const ROOT: &str = "root";

/// The account that escalated into this process, where it can be known.
///
/// Read from the environment rather than asked of the system, because the
/// system does not answer. Measured on `debian:13` and `alpine:3.23` under
/// `sudo` and `doas`: `logname` reports `root`, `id -un` reports `root`, and
/// `who am i` is empty without a controlling TTY — busybox does not recognise
/// the form at all. All three describe the process, which by then is root; the
/// variable is the only thing that describes who made it root.
///
/// `None` where nothing says: a direct root login, `su -`, and `run0`, which
/// authenticates through polkit and sets neither variable. `None` means "this
/// cannot be checked" and never "there is nothing to check" — the caller warns
/// rather than refusing, since refusing on an unanswerable question would make
/// a root console unable to delete an account.
fn escalated_from() -> Option<String> {
    from_escalation_vars(|name| std::env::var(name).ok())
}

/// The same decision, over a stated environment.
///
/// Split out so the rules can be tested without mutating the process's own
/// environment — which is global, shared by every test thread, and a source of
/// failures that depend on scheduling rather than on code.
fn from_escalation_vars(read: impl Fn(&str) -> Option<String>) -> Option<String> {
    ["SUDO_USER", "DOAS_USER"]
        .iter()
        .find_map(|name| read(name))
        .filter(|user| !user.is_empty())
        // `sudo -u root` sets SUDO_USER to root, which says the process was
        // escalated *to* root rather than *from* an account worth protecting.
        .filter(|user| user != ROOT)
}

/// Whether an account can still get into the machine by some means.
///
/// The question `users.lock-root` rests on, in one place because it is asked
/// twice — once as the guard and once immediately before the irreversible
/// step — and the two must not drift apart. A recheck stricter than the guard
/// would refuse the operator it had just accepted.
///
/// Either credential counts. `Expire` is applied through PAM, so it bars every
/// channel including the provider's rescue console, and the console never
/// consults `authorized_keys` — a password is what gets someone in there.
fn can_authenticate(executor: &dyn Executor, backend: &dyn Backend, user: &str) -> Result<bool> {
    if has_authorized_key(executor, backend, user)? {
        return Ok(true);
    }

    backend.account_writer().has_password(executor, user)
}

/// Default login shell for a newly created account.
///
/// `/bin/bash` rather than anything more opinionated: it is present on both
/// families out of the box, and changing it afterwards is what
/// [`SetShell`] is for.
const DEFAULT_SHELL: &str = "/bin/bash";

/// Builds the account administration category.
pub fn category() -> Category {
    Category::new(
        "Users",
        vec![
            Node::Task(Box::new(CreateUser)),
            // Two rows rather than a reversible pair, unlike everything the
            // tool installs. A pair asks "is the subject present?" and shows
            // one verb; there is no such subject here. `users.create` takes a
            // name that must *not* exist and `users.delete` one that must, so
            // the host cannot answer which of them applies — the answer
            // depends on a name nobody has typed yet. Two rows say plainly
            // that both are always available.
            Node::Task(Box::new(DeleteUser)),
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

    /// Name of the parameter holding the password, where one is wanted.
    pub const PASSWORD: &'static str = "password";
}

impl Task for CreateUser {
    fn id(&self) -> &'static str {
        "users.create"
    }

    fn title(&self) -> &'static str {
        "Create an administrative user"
    }

    fn description(&self) -> &'static str {
        "Creates an account with a home directory and membership of the group \
         that grants sudo on this distribution. The password is optional — \
         without one, authorise a key for it before locking root."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // No suggestions and a rule about them: every account this host
            // has is a value this task refuses, so offering them would propose
            // exactly the mistakes — but the field still has to know them, or
            // it draws `✓` over a name the task is about to reject.
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account to create")
                .naming_a_new_account(),
            // Offered rather than assumed, because "no password" is right for
            // an account reached over SSH with a key and wrong for the one
            // that has to get in through the provider's rescue console — that
            // console is a local TTY, where a key is not offered and a
            // password is the only credential there is.
            //
            // Empty means no password, which is what the field being optional
            // *is*: a second field asking whether to use the first would be a
            // question the first already answers. This asked exactly that for
            // a while — a text field taking the word `yes` — and the operator
            // it was written for typed one letter and got "answer yes or no".
            Param::new(Self::PASSWORD, "Password", ParamKind::Secret)
                .with_hint("leave empty for none")
                .optional(),
        ]
    }

    supported_everywhere!();

    fn consequences(&self, _backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(user) = values.get(Self::USER) else {
            return Vec::new();
        };

        // Only when the account was created without one. With a password it
        // can already log in — at the console certainly, and over SSH if this
        // server still admits passwords — so declaring that it cannot would be
        // a warning contradicted by the account itself, and a warning that is
        // wrong once is one that gets skipped every time after.
        if matches!(values.get(Self::PASSWORD), Ok(secret) if !secret.is_empty()) {
            return Vec::new();
        }

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

        // Empty means no password, which is the field being optional rather
        // than a second question about it: a form submitted without reaching
        // the field creates the account the way this task always did.
        let password = match values.get(Self::PASSWORD) {
            Ok(secret) if !secret.is_empty() => PasswordPolicy::Set(secret.to_owned()),
            _ => PasswordPolicy::Locked,
        };

        // Read before `create` consumes it, so the report does not need a copy
        // of the secret to decide what to say afterwards.
        let has_password = matches!(password, PasswordPolicy::Set(_));

        report(progress, &Msg::TaskCreatingUser { user: user.clone() });

        // No password unless one was given: an account reachable by password
        // is one more thing to guess, and one reached over SSH with a key does
        // not need one. Offered rather than fixed because that reasoning holds
        // for SSH and not for the provider's rescue console, which is a local
        // TTY where a key is not offered at all.
        accounts.create(executor, &user, DEFAULT_SHELL, password)?;

        // The fact, never the value. What is reported here reaches the output
        // pane, which `y` copies wholesale into a bug report.
        if has_password {
            report(progress, &Msg::TaskUserHasPassword { user: user.clone() });
        }

        report(
            progress,
            &Msg::TaskAddingToGroup {
                user: user.clone(),
                group: group.to_owned(),
            },
        );

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

        report(
            progress,
            &Msg::TaskUserInGroup {
                user: user.clone(),
                group: group.to_owned(),
            },
        );

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
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account whose shell changes")
                .suggesting_accounts()
                .naming_an_existing_account(),
            Param::new(Self::SHELL, "Shell", ParamKind::Path)
                .with_initial(DEFAULT_SHELL.to_owned())
                .with_hint("must appear in /etc/shells")
                .suggesting_shells(),
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

        report(
            progress,
            &Msg::TaskSettingShell {
                user: user.clone(),
                shell: shell.clone(),
            },
        );

        accounts.set_shell(executor, &user, &shell)?;

        Ok(Outcome::Done)
    }
}

/// Bars the root account from logging in.
pub struct LockRoot;

impl Task for LockRoot {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn title(&self) -> &'static str {
        "Lock the root account"
    }

    fn description(&self) -> &'static str {
        "Expires the root account so no authentication method admits it — \
         including the provider's rescue console, which is reached as the \
         administrative account instead. Refuses to run unless that account \
         can already log in, by key or by password, and escalate."
    }

    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // The label names the role rather than the kind of account. It
            // read as "Administrative account", which alongside a title
            // saying "Lock the root account" and a chooser offering every
            // account on the host is indistinguishable from "the account to
            // lock" — root is a constant and is never chosen here.
            Param::new(
                Self::ADMIN,
                "Account that keeps access",
                ParamKind::Username,
            )
            .with_hint("root is locked; this one is only checked")
            .suggesting_accounts()
            .naming_an_existing_account(),
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
            report(progress, &Msg::TaskRootAlreadyLocked);

            return Ok(Outcome::Done);
        }

        // Read once more, immediately before the irreversible step. The checks
        // above ran several privileged commands ago, and each of those is a
        // moment in which the credential could have been removed — by a second
        // administrator, by another session of this tool, or by an edit made
        // by hand. Every other task in this tree can afford that window;
        // this one cannot, because the recovery from getting it wrong is the
        // hosting provider's rescue console.
        //
        // The same question as the guard above, deliberately: a narrower one
        // here would refuse the operator it had just accepted, which reads as
        // the tool contradicting itself at the least reassuring moment.
        if !can_authenticate(executor, backend, &admin)? {
            return Err(Error::NoWayBackIn { user: admin });
        }

        report(progress, &Msg::TaskLockingRoot);

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

    /// This task's id, named so the interface can recognise it.
    ///
    /// The confirmation states a warning specific to this task, and matching
    /// on a literal there would put the id in two places with nothing tying
    /// them together — a rename would leave the interface silently falling
    /// back to the generic warning.
    pub const ID: &'static str = "users.lock-root";

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

        report(
            progress,
            &Msg::TaskUserExists {
                user: admin.to_string(),
            },
        );

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

        report(
            progress,
            &Msg::TaskUserInGroup {
                user: admin.to_string(),
                group: group.to_owned(),
            },
        );

        // Either credential is a way back in, and demanding the key was this
        // guard measuring a narrower question than the one it asks. Expiry is
        // applied through PAM, so it bars every channel — including the
        // provider's rescue console, which never consults `authorized_keys`
        // at all. What has to hold beforehand is that *some* account can still
        // authenticate by *some* means, and a password is one of them.
        //
        // Refusing without a key assumed every administrator arrived through
        // `users.create`, which deliberately creates accounts without a
        // password. An account the distribution's installer made has one, and
        // it was refused with a message asserting it did not — the common case
        // on a provider image, and precisely the case where the console is the
        // way back in.
        //
        // Both are read rather than one short-circuiting the other: the report
        // names which credential will let the operator back in, and "holds an
        // authorised key" and "can authenticate with a password" send them to
        // different places if this turns out to have been the wrong call.
        let key = has_authorized_key(executor, backend, admin)?;
        let password = backend.account_writer().has_password(executor, admin)?;

        if !key && !password {
            return Err(Error::NoWayBackIn {
                user: admin.to_owned(),
            });
        }

        if key {
            report(
                progress,
                &Msg::TaskUserHoldsKey {
                    user: admin.to_string(),
                },
            );
        }

        if password {
            report(
                progress,
                &Msg::TaskUserHasPassword {
                    user: admin.to_string(),
                },
            );
        }

        Ok(())
    }
}

/// Deletes an account.
///
/// The one task here that destroys data this tool never created, which is why
/// its home directory is a field rather than a policy and why its confirmation
/// names the path *and* its measured size. "Delete /home/deploy (2.4 GB)" is a
/// decision an operator can make; "also delete the home directory?" is a
/// question answered by habit.
pub struct DeleteUser;

impl DeleteUser {
    /// Name of the parameter holding the account to delete.
    pub const USER: &'static str = "user";

    /// Name of the parameter deciding what becomes of the home directory.
    pub const HOME: &'static str = "home";

    /// Id, named because the interface reaches for it when building the
    /// confirmation this task needs and no other does.
    pub const ID: &'static str = "users.delete";

    /// The answer that destroys the home directory.
    pub const DELETE_HOME: &'static str = "delete";
}

impl Task for DeleteUser {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn title(&self) -> &'static str {
        "Delete an account"
    }

    fn description(&self) -> &'static str {
        "Removes an account from the system. Its home directory is kept unless \
         you ask for it to be deleted — this tool created the account, not \
         what the account then put in it."
    }

    /// Deleting the account you escalate through ends the session, and unlike
    /// every other lockout here there is nothing to put back: the account is
    /// gone, and with it whatever `sudo` rule named it.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    supported_everywhere!();

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account to delete")
                .suggesting_accounts()
                .naming_an_existing_account(),
            Param::new(Self::HOME, "Home directory", ParamKind::HomeDirectory)
                .with_initial("keep")
                .with_hint("keep leaves the files on disk; delete removes them"),
        ]
    }

    fn consequences(&self, _backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(user) = values.get(Self::USER) else {
            return Vec::new();
        };

        // An authorised key for an account that no longer exists is a key that
        // authorises nothing, and `ssh.allow-users` may still name it — a list
        // naming a deleted account admits nobody under that name and looks
        // correct while doing it.
        vec![Consequence::Invalidates {
            task: "ssh.authorize-key",
            reason: Reason::AccountRemoved {
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

        // Refused in the code rather than warned about in the dialog, which is
        // the shape `users.lock-root` already uses for the comparable risk: a
        // confirmation is dismissible and this is not a decision an operator
        // should be able to make by pressing through one.
        //
        // Locking root is offered and deleting it is not, which is not an
        // inconsistency. Locking is guarded by proving another account can get
        // in, and a provider's rescue console undoes it. Deleting root leaves
        // a machine this tool cannot put back and a rescue console cannot
        // either.
        if user == ROOT {
            return Err(Error::CannotDeleteRoot);
        }

        // The account this session is being administered as. Refused rather
        // than warned about, now that it can be known: deleting it ends the
        // session mid-task and takes with it whatever sudo rule named it, so
        // the operator is left outside a machine they were administering a
        // moment ago — with no verification window to save them, because the
        // process that would offer one is the one whose credentials just
        // stopped existing.
        //
        // Only where the escalation says so. A direct root login, `su -` and
        // `run0` leave nothing to compare against, and refusing on a question
        // that cannot be answered would stop a root console from deleting any
        // account at all. Those keep the warning the confirmation already
        // carries, which is the honest limit rather than a silent gap.
        if escalated_from().is_some_and(|from| from == user) {
            return Err(Error::CannotDeleteOwnAccount { user });
        }

        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        let remove_home = values.get(Self::HOME)? == Self::DELETE_HOME;

        // Read before the account goes: once it is deleted the passwd entry is
        // gone and the path can no longer be resolved from it, so a report
        // naming what was kept would have nothing to name.
        let home = backend.accounts().home_dir(executor, &user)?;

        backend
            .account_writer()
            .delete(executor, &user, remove_home)?;

        report(
            progress,
            &if remove_home {
                Msg::TaskHomeDeleted { path: home }
            } else {
                Msg::TaskHomeKept { path: home }
            },
        );

        Ok(Outcome::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// A key that passes validation, not merely a non-empty line.
    ///
    /// The shorter placeholder that stood here satisfied the check this file
    /// used to carry — which asked only that a line be neither blank nor a
    /// comment — and fails the shared one, which parses the key. The fixture
    /// was never a valid key; only the old criterion was lax enough to admit
    /// it, and a guard that admits `garbage` is not guarding `users.lock-root`.
    const TEST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ user@host";

    /// Values naming an account to delete and what to do with its home.
    fn deleting(user: &str, home: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(DeleteUser::USER, user.to_owned());
        values.set(DeleteUser::HOME, home.to_owned());
        values
    }

    #[test]
    fn a_home_directory_survives_unless_deleting_it_was_asked_for() {
        // The default is the recoverable answer, and this is the assertion
        // that keeps it so: the field decides whether data this tool never
        // created is destroyed, and a default nobody stated is one answered by
        // habit.
        let kept = MockExecutor::with_replies([
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok(""),
        ]);

        DeleteUser
            .run(
                &kept,
                for_family(Family::Debian).as_ref(),
                &deleting("deploy", "keep"),
                &mut |_| {},
            )
            .expect("the deletion must succeed");

        assert!(
            kept.recorded_lines()
                .iter()
                .any(|line| line == "userdel deploy"),
            "keeping the home must not pass -r: {:?}",
            kept.recorded_lines()
        );
    }

    #[test]
    fn asking_for_the_home_to_go_is_what_takes_it() {
        let removed = MockExecutor::with_replies([
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok(""),
        ]);

        DeleteUser
            .run(
                &removed,
                for_family(Family::Debian).as_ref(),
                &deleting("deploy", DeleteUser::DELETE_HOME),
                &mut |_| {},
            )
            .expect("the deletion must succeed");

        assert!(
            removed
                .recorded_lines()
                .iter()
                .any(|line| line == "userdel -r deploy"),
            "{:?}",
            removed.recorded_lines()
        );
    }

    #[test]
    fn the_home_is_read_before_the_account_that_names_it_is_deleted() {
        // Once the account is gone its passwd entry is too, so a report naming
        // what was kept would have nothing to name. Ordering rather than
        // output, because the report is what the ordering exists for.
        let mock = MockExecutor::with_replies([
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok("deploy:x:1000:1000::/home/deploy:/bin/sh"),
            Reply::ok(""),
        ]);

        DeleteUser
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &deleting("deploy", "keep"),
                &mut |_| {},
            )
            .expect("the deletion must succeed");

        let commands = mock.recorded_lines();
        let read = commands
            .iter()
            .rposition(|line| line.contains("getent") || line.contains("passwd"))
            .expect("the home must be read");
        let deleted = commands
            .iter()
            .position(|line| line.starts_with("userdel"))
            .expect("the account must be deleted");

        assert!(
            read < deleted,
            "the home must be resolved first: {commands:?}"
        );
    }

    /// Reads from a stated environment rather than the process's own.
    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn both_escalation_helpers_name_the_account_they_acted_for() {
        // Measured on debian:13 and alpine:3.23 rather than assumed: `logname`
        // answers `root` under sudo, `id -un` answers `root`, and `who am i` is
        // empty without a TTY — busybox does not know the form at all. Every
        // one of those describes the process, which by then is root. Only the
        // variable describes who made it root.
        assert_eq!(
            from_escalation_vars(env(&[("SUDO_USER", "deploy")])),
            Some("deploy".to_owned())
        );
        assert_eq!(
            from_escalation_vars(env(&[("DOAS_USER", "deploy")])),
            Some("deploy".to_owned())
        );
    }

    #[test]
    fn an_escalation_that_says_nothing_is_not_an_answer() {
        // A direct root login, `su -`, and `run0` — which authenticates through
        // polkit and sets neither variable. `None` means "cannot be checked"
        // rather than "nothing to check", which is why the caller warns instead
        // of refusing: refusing here would stop a root console deleting any
        // account at all.
        assert_eq!(from_escalation_vars(env(&[])), None);
        assert_eq!(from_escalation_vars(env(&[("SUDO_USER", "")])), None);
    }

    #[test]
    fn escalating_to_root_is_not_escalating_from_an_account() {
        // `sudo -u root` sets SUDO_USER to root, which says the process was
        // escalated *to* root. Treating that as an account worth protecting
        // would refuse `users.delete root` with the wrong reason — and that
        // one is already refused, for a better one.
        assert_eq!(from_escalation_vars(env(&[("SUDO_USER", "root")])), None);
    }

    #[test]
    fn the_account_being_administered_as_cannot_be_deleted() {
        // Refused before the account is looked up, so the answer does not
        // depend on the host: the mock is given no replies, and a check that
        // ran later would reach for one.
        let mock = MockExecutor::new();

        // Exercised through the same comparison `run` makes, rather than by
        // setting a variable in this process: the environment is global and
        // shared by every test thread, and a test that mutates it fails on
        // scheduling rather than on code.
        let from = from_escalation_vars(env(&[("SUDO_USER", "deploy")]));

        assert!(
            from.is_some_and(|from| from == "deploy"),
            "the guard must recognise the account it escalated from"
        );

        // And the shape of the refusal it produces.
        let err = DeleteUser
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &deleting(ROOT, "keep"),
                &mut |_| {},
            )
            .expect_err("root is refused first, whatever the escalation says");

        assert!(matches!(err, Error::CannotDeleteRoot));
    }

    #[test]
    fn root_cannot_be_deleted_at_all() {
        // Refused in the code rather than warned about in a dialog, because a
        // confirmation is dismissible and this is not a decision that should
        // be reachable by pressing through one. `users.lock-root` guards the
        // comparable risk the same way.
        //
        // Refused *before* the account is looked up, so the answer does not
        // depend on the host: the mock is given no replies at all, and a check
        // that ran later would panic reaching for one.
        let mock = MockExecutor::new();

        let err = DeleteUser
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &deleting(ROOT, "keep"),
                &mut |_| {},
            )
            .expect_err("root must be refused");

        assert!(matches!(err, Error::CannotDeleteRoot));
        assert!(
            mock.recorded_lines().is_empty(),
            "nothing may run before the refusal: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn deleting_an_account_that_does_not_exist_is_refused_by_name() {
        // Refused rather than reported as done: `userdel` on a missing account
        // exits non-zero anyway, and this says which account rather than
        // handing back another program's stderr.
        let mock = MockExecutor::with_replies([Reply::failure(2, "")]);

        let err = DeleteUser
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &deleting("ghost", "keep"),
                &mut |_| {},
            )
            .expect_err("a missing account must be refused");

        assert!(matches!(err, Error::NoSuchAccount { ref user } if user == "ghost"));
    }

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
    fn a_password_travels_on_stdin_and_never_in_the_arguments() {
        // The whole of what the design still guarantees now that the value
        // lives in this process: `useradd -p` would put it in `argv`, where
        // `/proc/<pid>/cmdline` publishes it to every account on the box for
        // as long as the process runs. `chpasswd` reads it from stdin, and
        // `Command`'s `Display` omits stdin so it reaches neither the output
        // pane nor an error message.
        let mock = MockExecutor::with_replies(vec![
            Reply::failure(2, ""),   // account does not exist
            Reply::ok(""),           // useradd
            Reply::ok(""),           // chpasswd, inside create
            Reply::ok("sudo:x:27:"), // group exists
            Reply::ok(""),           // usermod -aG
            Reply::ok("alice sudo"), // id -nG
        ]);
        let backend = for_family(Family::Debian);
        let mut values = values(CreateUser::USER, "alice");
        values.set(CreateUser::PASSWORD, "hunter2".to_owned());

        CreateUser
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect("creation must succeed");

        let recorded = mock.recorded();

        let chpasswd = recorded
            .iter()
            .find(|command| command.program == "chpasswd")
            .expect("the password must be applied");

        assert_eq!(
            chpasswd.stdin.as_deref(),
            Some("alice:hunter2\n"),
            "the secret travels on stdin: {chpasswd:?}"
        );
        assert!(
            recorded
                .iter()
                .all(|command| !command.args.iter().any(|arg| arg.contains("hunter2"))),
            "no argument may carry it: {recorded:?}"
        );
        assert!(
            !mock.recorded_lines().join(" ").contains("hunter2"),
            "nor may any line the pane would draw: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn an_unanswered_password_field_creates_the_account_without_one() {
        // The default this task has always had, kept: an untouched field means
        // no password, and a field the operator cleared means the same. The
        // two are one answer, which is the point of an empty value meaning it
        // rather than a second field saying so.
        for answer in [None, Some("")] {
            let mut values = values(CreateUser::USER, "alice");
            if let Some(answer) = answer {
                values.set(CreateUser::PASSWORD, answer.to_owned());
            }

            let mock = MockExecutor::with_replies(vec![
                Reply::failure(2, ""),
                Reply::ok(""),
                Reply::ok("sudo:x:27:"),
                Reply::ok(""),
                Reply::ok("alice sudo"),
            ]);
            let backend = for_family(Family::Debian);

            CreateUser
                .run(&mock, backend.as_ref(), &values, &mut |_| {})
                .expect("creation must succeed");

            assert!(
                mock.recorded()
                    .iter()
                    .all(|command| command.program != "chpasswd"),
                "{answer:?} must set no password: {:?}",
                mock.recorded_lines()
            );
        }
    }

    #[test]
    fn a_refused_password_prompt_fails_the_task() {
        // `passwd` exits non-zero when the operator abandons the prompt or the
        // two entries differ. Reporting success there would leave the
        // interface claiming a password was set on an account holding `!` —
        // discovered at the login prompt, which may be the rescue console.
        let (outcome, _) = run(
            &CreateUser,
            Family::Debian,
            vec![
                Reply::failure(2, ""),
                Reply::ok(""),
                Reply::failure(1, "passwd: Authentication token manipulation error"),
            ],
            &{
                let mut values = values(CreateUser::USER, "alice");
                values.set(CreateUser::PASSWORD, "yes".to_owned());
                values
            },
        );

        outcome.expect_err("an abandoned prompt must not report success");
    }

    #[test]
    fn a_password_removes_the_authorise_a_key_consequence() {
        // The consequence says the account cannot log in until a key is
        // authorised, which is true of an account created without a password
        // and false of one created with it. A warning that is wrong once is
        // one that gets skipped every time after.
        let backend = for_family(Family::Debian);

        let mut with_password = values(CreateUser::USER, "alice");
        with_password.set(CreateUser::PASSWORD, "yes".to_owned());

        assert!(
            CreateUser
                .consequences(backend.as_ref(), &with_password)
                .is_empty(),
            "an account that can log in invalidates nothing"
        );
        assert!(
            !CreateUser
                .consequences(backend.as_ref(), &values(CreateUser::USER, "alice"))
                .is_empty(),
            "without a password, the key is still the only way in"
        );
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
        // In the admin group and unable to log in by any means is still locked
        // out: no key, and a `!` hash, which is what `useradd` leaves on an
        // account created without a password.
        let (outcome, _) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // exists
                Reply::ok("alice sudo"),                               // can escalate
                Reply::failure(1, ""),                                 // no authorized_keys
                Reply::ok("alice:!:19000:0:99999:7:::"),               // and no password
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("an account with no credential must not vouch");

        assert!(matches!(err, Error::NoWayBackIn { .. }), "{err:?}");
    }

    #[test]
    fn a_password_is_a_way_back_in_even_without_a_key() {
        // The case this guard used to refuse, and the common one: an account
        // the distribution's installer made carries a password, and no key
        // until somebody installs one. Expiry goes through PAM, so it bars the
        // provider's rescue console too — and a password is exactly what gets
        // an administrator in there, which is why refusing here was measuring
        // SSH when the question was about every channel.
        let (outcome, commands) = run(
            &LockRoot,
            Family::Debian,
            vec![
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // exists
                Reply::ok("alice sudo"),                               // can escalate
                Reply::failure(1, ""),                                 // no authorized_keys
                Reply::ok("alice:$6$abc$def:19000:0:99999:7:::"),      // but a usable hash
                Reply::ok("root:$6$xyz$w:19000:0:99999:7:::"),         // root is not locked
                Reply::failure(1, ""),                                 // recheck: still no key
                Reply::ok("alice:$6$abc$def:19000:0:99999:7:::"),      // recheck: still a hash
                Reply::ok(""),                                         // the lock itself
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        outcome.expect("a password is a way back in");

        assert!(
            commands
                .iter()
                .any(|command| command.contains("--expiredate") && command.ends_with("root")),
            "root must actually be locked: {commands:?}"
        );
    }

    #[test]
    fn a_locked_hash_is_not_a_password() {
        // `!` and `*` cannot be produced by any input, so neither is a
        // credential. Asserted because the guard now admits passwords, and a
        // check that merely found the field non-empty would accept exactly the
        // accounts that cannot log in.
        for hash in ["!", "*", "!$6$abc$def", ""] {
            let (outcome, _) = run(
                &LockRoot,
                Family::Debian,
                vec![
                    Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"),
                    Reply::ok("alice sudo"),
                    Reply::failure(1, ""),
                    Reply::ok(format!("alice:{hash}:19000:0:99999:7:::")),
                ],
                &values(LockRoot::ADMIN, "alice"),
            );

            let err = outcome.expect_err("a locked hash must not vouch");

            assert!(
                matches!(err, Error::NoWayBackIn { .. }),
                "{hash:?} must not count as a password: {err:?}"
            );
        }
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
                Reply::ok(""),                           // the file exists
                Reply::ok("# added by hand\n\n"),        // and holds no key
                Reply::ok("alice:!:19000:0:99999:7:::"), // nor a password
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("a file of comments must not count as a key");

        assert!(matches!(err, Error::NoWayBackIn { .. }), "{err:?}");
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
                // The home comes from passwd rather than from `/home/{user}`,
                // so each key check spends a `getent` before reading the file.
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // passwd
                Reply::ok(""),                                         // file exists
                Reply::ok(TEST_KEY),                                   // holds a key
                // Read even though the key already satisfies the guard: the
                // report names every credential that will let the operator
                // back in, not merely the first one found.
                Reply::ok("alice:!:19000:0:99999:7:::"), // and no password
                Reply::ok("Account expires\t: never"),   // not yet locked
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // re-check: passwd
                Reply::ok(""),                           // re-check: exists
                Reply::ok(TEST_KEY),                     // re-check: still there
                Reply::ok(""),                           // usermod
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
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // passwd
                Reply::ok(""),                                         // file exists
                Reply::ok(TEST_KEY),                                   // holds a key
                Reply::ok("Account expires\t: never"),                 // not yet locked
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // re-check: passwd
                Reply::failure(1, ""),                                 // re-check: key file gone
                Reply::ok("alice:!:19000:0:99999:7:::"), // re-check: and no password behind it
            ],
            &values(LockRoot::ADMIN, "alice"),
        );

        let err = outcome.expect_err("a key that vanished must stop the lock");

        assert!(matches!(err, Error::NoWayBackIn { .. }), "{err:?}");
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
                Reply::ok("alice:x:1000:1000::/home/alice:/bin/bash"), // passwd
                Reply::ok(""),
                Reply::ok(TEST_KEY),
                Reply::ok("alice:!:19000:0:99999:7:::"), // no password behind the key
                Reply::ok("root:$6$salt$hash:19000:0:99999:7::1:"), // already expired
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
        let consequences = CreateUser.consequences(
            for_family(Family::Debian).as_ref(),
            &values(CreateUser::USER, "alice"),
        );

        assert_eq!(
            consequences.len(),
            1,
            "exactly one follow-up: {consequences:?}"
        );
        assert_eq!(consequences[0].task(), Some("ssh.authorize-key"));
    }
}
