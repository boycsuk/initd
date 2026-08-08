//! Restricting login to a named set of accounts.
//!
//! `AllowUsers` naming an account that does not exist produces a configuration
//! `sshd -t` accepts and that matches nobody, so every login is refused. That
//! is why this task carries guards of its own rather than trusting validation,
//! and why it has no CLI form: the check that matters is a second session.

use crate::backend::{Backend, Capability};
use crate::error::{Error, Lockout, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::sshd_config;
use crate::tasks::{Confirmation, Progress, Task, report, supported_everywhere};

use super::{has_authorized_key, reload_ssh, revertible};

/// Restricts SSH login to a named set of accounts.
///
/// Fieldless: the accounts are declared as a parameter and collected when the
/// task is run, so the tree can offer it without inventing a list.
pub struct RestrictUsers;

impl RestrictUsers {
    /// Name of the parameter holding the accounts permitted to log in.
    pub const USERS: &'static str = "users";
}

impl Task for RestrictUsers {
    fn id(&self) -> &'static str {
        "ssh.allow-users"
    }

    fn title(&self) -> &'static str {
        "Restrict SSH login to named users"
    }

    fn description(&self) -> &'static str {
        "Sets AllowUsers in /etc/ssh/sshd_config to the accounts you name. \
         Afterwards sshd refuses every other account, including root and \
         including accounts that hold a valid key. Each account is checked to \
         exist first, and at least one of them must already have an authorised \
         key, since password authentication may be disabled. A backup is kept \
         and the change is held open until you confirm you can still log in."
    }

    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // No starting value: seeding "root" would suggest the root-only
            // configuration `ssh.harden` exists to disable.
            //
            // No suggestions either, though every name in it is an account
            // this host has. The field holds a space-separated *list*, and
            // taking a suggestion replaces the whole value — so offering
            // accounts here would delete the names already typed each time one
            // was chosen. Completing within a list is a different mechanism
            // from choosing a value, and this field needs the one that does
            // not exist yet rather than the one that does.
            Param::new(Self::USERS, "Allowed users", ParamKind::UsernameList)
                .with_hint("space-separated; every other account is refused"),
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
        let users = values.get(Self::USERS)?.trim().to_owned();

        // Checked again here rather than trusted from the interface: nothing
        // escapes a directive's value when it is written, so a newline in this
        // string would append a directive of the caller's choosing to a file
        // edited as root.
        ParamKind::UsernameList
            .validate(&users)
            .map_err(|reason| Error::InvalidAllowUsers { reason })?;

        let named: Vec<&str> = users.split_whitespace().collect();

        // An account that does not exist yields a configuration `sshd -t`
        // accepts and that matches nobody, so every login is refused. A typo
        // is the likely cause, which is why the name is reported back.
        for user in &named {
            if !backend.accounts().exists(executor, user)? {
                return Err(Error::LockoutRisk {
                    kind: Lockout::UnknownUser {
                        user: (*user).to_owned(),
                    },
                });
            }
        }

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // Holding a key is not the same as being able to log in. An account
        // the daemon already refuses cannot be the one way back in, and root
        // is the case that matters: `ssh.harden` sets PermitRootLogin no, so
        // `AllowUsers root` afterwards produces a file sshd accepts and that
        // admits nobody. Nothing rolls that back, because nothing is wrong
        // with it.
        let root_refused = sshd_config::directive_value(&contents, "PermitRootLogin")
            .is_some_and(|value| value.eq_ignore_ascii_case("no"));

        // At least one, not all: a service account that logs in by other means
        // is a legitimate member of the list. One account that can log in and
        // holds a key is one way back in.
        let mut with_keys = Vec::new();
        for user in &named {
            let refused_outright = root_refused && *user == "root";

            if !refused_outright && has_authorized_key(executor, backend, user)? {
                with_keys.push(*user);
            }
        }

        if with_keys.is_empty() {
            return Err(Error::LockoutRisk {
                kind: Lockout::NoKeyForAllowedUsers {
                    users: users.clone(),
                },
            });
        }

        // Stated before the change lands rather than after: this is the point
        // where the administrator can still recognise a name they did not
        // intend. Which accounts hold a key is the part that decides whether
        // the list is reachable at all.
        progress(OutputLine {
            stream: Stream::Stderr,
            text: format!(
                "After this change only these accounts may log in over SSH: {users}. \
                 Of those, {} already hold an authorised key.",
                with_keys.join(", ")
            ),
        });

        report(
            progress,
            &Msg::TaskSshAllowingUsers {
                users: users.clone(),
            },
        );

        let updated = sshd_config::set_directive(&contents, "AllowUsers", &users);
        let backup = sshd_config::write_validated(executor, backend, &updated, progress)?;

        if let Some(ref backup) = backup {
            report(
                progress,
                &Msg::TaskSshBackupSaved {
                    path: backup.copy.clone(),
                },
            );
        }

        reload_ssh(executor, backend, progress)?;

        Ok(revertible(backup, backend))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::ssh::fixtures::{ROOT_PASSWD, TEST_KEY};

    /// Passwd entries for the two ordinary accounts these tests name.
    const ALICE_PASSWD: &str = "alice:x:1000:1000::/home/alice:/bin/sh";
    const BOB_PASSWD: &str = "bob:x:1001:1001::/home/bob:/bin/sh";

    /// For the task that restricts login to named accounts.
    fn users_values(users: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(RestrictUsers::USERS, users);
        values
    }

    #[test]
    fn restricting_users_writes_the_allow_list() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),           // getent alice
            Reply::ok(""),           // getent bob
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // alice authorized_keys exists
            Reply::ok(TEST_KEY),     // and holds a key
            Reply::ok(BOB_PASSWD),   // getent passwd: bob's home
            Reply::ok(""),           // bob authorized_keys exists
            Reply::ok(TEST_KEY),     // and holds a key
            Reply::ok(""),           // test -e for the write
            Reply::ok(""),           // cp backup
            Reply::ok(""),           // tee
            Reply::ok(""),           // sshd -t
            Reply::ok(""),           // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice bob"),
                &mut |_| {},
            )
            .expect("restricting to existing users with keys must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("AllowUsers alice bob"), "got: {written}");
    }

    #[test]
    fn restricting_users_refuses_an_unknown_account() {
        // A typo yields a config sshd accepts and that matches nobody, so
        // every login is refused.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),         // getent alice
            Reply::failure(2, ""), // getent admn — no such account
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice admn"),
                &mut |_| {},
            )
            .expect_err("an unknown account must refuse");

        assert!(
            matches!(&err, Error::LockoutRisk { kind: Lockout::UnknownUser { user } } if user == "admn"),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn restricting_users_refuses_when_no_named_user_has_a_key() {
        // Hardening disables password authentication, so an allow-list where
        // nobody holds a key leaves no way to log in at all.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent alice
            Reply::ok(""),          // getent bob
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::failure(1, ""),  // alice has no authorized_keys
            Reply::failure(1, ""),  // nor does bob
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice bob"),
                &mut |_| {},
            )
            .expect_err("an allow-list with no keys must refuse");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForAllowedUsers { .. }
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn restricting_users_accepts_when_one_of_several_holds_a_key() {
        // Deliberately "at least one", not "all": a service account that logs
        // in by other means is a legitimate member of the list.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),           // getent alice
            Reply::ok(""),           // getent deploy
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // alice authorized_keys exists
            Reply::ok(TEST_KEY),     // and holds a key
            Reply::failure(1, ""),   // deploy has none
            Reply::ok(""),           // test -e for the write
            Reply::ok(""),           // cp backup
            Reply::ok(""),           // tee
            Reply::ok(""),           // sshd -t
            Reply::ok(""),           // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice deploy"),
                &mut |_| {},
            )
            .expect("one account with a key is one way back in");
    }

    #[test]
    fn restricting_users_refuses_to_allow_only_an_account_sshd_already_rejects() {
        // The trap: root holds a key, so a check for key possession alone
        // passes, but `ssh.harden` already set PermitRootLogin no. The result
        // is a file sshd accepts and that admits nobody — and since nothing is
        // wrong with it, nothing rolls it back.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                     // getent root
            Reply::ok("PermitRootLogin no\n"), // read sshd_config
        ]);
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("root"), &mut |_| {})
            .expect_err("an allow-list of accounts sshd refuses must be refused");

        assert!(
            matches!(
                err,
                Error::LockoutRisk {
                    kind: Lockout::NoKeyForAllowedUsers { .. }
                }
            ),
            "{err:?}"
        );
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn restricting_users_still_allows_root_where_root_may_log_in() {
        // The guard must not refuse a list naming root on a server that has
        // not disabled root login.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),          // getent root
            Reply::ok("Port 22\n"), // read sshd_config — root login untouched
            Reply::ok(ROOT_PASSWD), // getent passwd: root's home
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // and holds a key
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("root"), &mut |_| {})
            .expect("root may still be named where root may still log in");
    }

    #[test]
    fn restricting_users_rejects_a_value_that_would_inject_a_directive() {
        // Nothing escapes a directive's value when it is written, and the CLI
        // never passes through the keystroke filter, so this is the only
        // barrier between an argument and a file edited as root.
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        let err = RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice\nPermitRootLogin yes"),
                &mut |_| {},
            )
            .expect_err("a newline must be refused");

        assert!(matches!(err, Error::InvalidAllowUsers { .. }), "{err:?}");
        assert!(
            mock.recorded().is_empty(),
            "the value must be rejected before anything runs, got: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn restricting_users_names_who_will_still_be_able_to_log_in() {
        // The administrator's last chance to recognise a name they did not
        // intend is before the change lands, not after.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),           // getent alice
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // alice authorized_keys exists
            Reply::ok(TEST_KEY),     // and holds a key
            Reply::ok(""),           // test -e
            Reply::ok(""),           // cp
            Reply::ok(""),           // tee
            Reply::ok(""),           // sshd -t
            Reply::ok(""),           // reload
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        RestrictUsers
            .run(
                &mock,
                backend.as_ref(),
                &users_values("alice"),
                &mut |line| {
                    if line.stream == Stream::Stderr {
                        warnings.push(line.text);
                    }
                },
            )
            .expect("runs");

        assert!(
            warnings.iter().any(|w| w.contains("alice")),
            "got: {warnings:?}"
        );
    }

    #[test]
    fn restricting_users_offers_a_revert() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),           // getent alice
            Reply::ok("Port 22\n"),  // read sshd_config
            Reply::ok(ALICE_PASSWD), // getent passwd: alice's home
            Reply::ok(""),           // authorized_keys exists
            Reply::ok(TEST_KEY),     // holds a key
            Reply::ok(""),           // test -e
            Reply::ok(""),           // cp
            Reply::ok(""),           // tee
            Reply::ok(""),           // sshd -t
            Reply::ok(""),           // reload
        ]);
        let backend = for_family(Family::Debian);

        let outcome = RestrictUsers
            .run(&mock, backend.as_ref(), &users_values("alice"), &mut |_| {})
            .expect("runs");

        assert!(
            outcome.is_revertible(),
            "the change must be held open for confirmation"
        );
    }
}
