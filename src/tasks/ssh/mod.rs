//! SSH administration tasks.
//!
//! Not one of these tasks knows which distribution it runs on. Package names,
//! unit names and command syntax all arrive through the backend — that is the
//! property this whole design exists to provide.

pub mod allow_users;
#[cfg(test)]
pub mod fixtures;
pub mod harden;
pub mod install;
pub mod keys;
pub mod port;

pub use allow_users::RestrictUsers;
pub use harden::{HardenSsh, HardenSshStrict};
pub use install::{InstallSsh, UninstallSsh};
pub use keys::{AuthorizeKey, is_valid_public_key};
pub use port::ChangePort;

use crate::backend::{Backend, Capability};
use crate::domain::files::Backup;
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::revert::{Outcome, Revert};
use crate::tasks::users::ROOT;
use crate::tasks::{Category, Node, Progress, report};

/// Where a user's authorised keys live, relative to their home directory.
const AUTHORIZED_KEYS_RELATIVE: &str = ".ssh/authorized_keys";

/// Mode SSH requires on `~/.ssh`; anything looser makes sshd ignore the keys.
const SSH_DIR_MODE: u32 = 0o700;

/// Mode SSH requires on `authorized_keys`.
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

/// Key types `initd` accepts in an `authorized_keys` entry.
const VALID_KEY_PREFIXES: [&str; 5] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// Default port offered when none is given.
///
/// The last resort rather than the first: `sshd_config::effective_port` asks
/// the daemon what it is actually listening on, and this is what answers when
/// neither the daemon nor its file can say. Offering it unconditionally is how
/// a firewall admits 22 on a host whose SSH moved to 2222 — and that firewall
/// ends the session it was run from.
pub(crate) const DEFAULT_SSH_PORT: u32 = 22;

/// Builds the SSH category, subdivided by what each task acts on.
///
/// The area owns its own subdivision so that `tasks::tree()` stays a flat list
/// of areas. Tasks appear here with no values at all: those they need are
/// declared through `params()` and collected when the task is run.
pub fn category() -> Category {
    Category::new(
        "SSH",
        vec![
            Node::Category(Category::new(
                "Service",
                // A pair rather than a lone task, so the row reports what this
                // host already has. The inverse is the most dangerous operation
                // in the tree — see `UninstallSsh` — and it is reached only
                // once the probe has confirmed a server is actually installed.
                vec![Node::Reversible {
                    forward: Box::new(InstallSsh),
                    inverse: Box::new(UninstallSsh),
                }],
            )),
            Node::Category(Category::new(
                "Configuration",
                vec![
                    // Ordered as they would be applied: narrowing the
                    // algorithms of a server whose passwords are still
                    // enabled is a strange place to start.
                    Node::Task(Box::new(HardenSsh)),
                    Node::Task(Box::new(HardenSshStrict)),
                    Node::Task(Box::new(ChangePort)),
                ],
            )),
            Node::Category(Category::new(
                "Keys",
                vec![Node::Task(Box::new(AuthorizeKey))],
            )),
            // Who may log in, rather than how the daemon is tuned or which key
            // material exists — neither of the categories above fits it.
            Node::Category(Category::new(
                "Access",
                vec![Node::Task(Box::new(RestrictUsers))],
            )),
        ],
    )
}

/// Wraps a configuration backup as the undo for a change already applied.
///
/// A change with no backup — a file that did not exist — has nothing to put
/// back, so it finishes rather than offering an undo that would delete it.
fn revertible(backup: Option<Backup>, backend: &dyn Backend) -> Outcome {
    backup.map_or(Outcome::Done, |backup| {
        Outcome::Revertible(Revert::ConfigFile {
            backup,
            service: backend.service_for(Capability::Ssh),
        })
    })
}

/// Names the copy a change left behind, as soon as the change is written.
///
/// Called immediately after `write_validated` and before anything else, which
/// is a constraint rather than a preference: the file is already modified by
/// that point, and every step that follows can fail — a reload, a socket check,
/// an SELinux probe. A task that ends in an error returns no `Outcome`, so the
/// backup never reaches the operator through [`revertible`], and the changes
/// documented as able to cost an administrator their own way in would report a
/// failed command over a modified `sshd_config` without naming what to restore.
///
/// A function because that ordering was previously held by a comment in
/// `port.rs` and by imitation in the three tasks beside it. The one that
/// forgets is the one nobody notices, and what it costs is the recovery path
/// for the tasks most likely to need one.
fn report_backup(backup: Option<&Backup>, progress: Progress<'_>) {
    if let Some(backup) = backup {
        report(
            progress,
            &Msg::TaskSshBackupSaved {
                path: backup.copy.clone(),
            },
        );
    }
}

/// Whether the named user has at least one authorised key.
///
/// Read through the file editor rather than `std::fs` so it works under
/// privilege escalation, and so a missing file is a plain `false`.
///
/// `pub(crate)` because `users.lock-root` asks the same question before it
/// removes the last password on the box, and asking it a second way is how the
/// two answers drift: the copy that lived there resolved the home as
/// `/home/{user}`, which is the assumption this function exists to avoid.
pub(crate) fn has_authorized_key(
    executor: &dyn Executor,
    backend: &dyn Backend,
    user: &str,
) -> Result<bool> {
    // An account that does not exist holds no key, which is an answer rather
    // than a failure: this runs over the accounts named in `AllowUsers`, and
    // one of them being absent is exactly what the caller is checking for.
    let Ok(home) = backend.accounts().home_dir(executor, user) else {
        return Ok(false);
    };

    let path = format!("{home}/{AUTHORIZED_KEYS_RELATIVE}");

    if !backend.files().exists(executor, &path)? {
        return Ok(false);
    }

    let contents = backend.files().read(executor, &path)?;

    Ok(contents
        .lines()
        .any(|line| is_valid_public_key(line.trim()).is_ok()))
}

/// One account, and why it is or is not a way back in over SSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyHolder {
    /// The account, as `/etc/passwd` names it.
    pub user: String,
    /// Whether it keeps SSH access once the hardening is applied.
    pub keeps_access: bool,
}

/// Every account that still gets in over SSH once hardening is applied.
///
/// The question both tiers rest on, asked of the machine rather than of one
/// name. It replaces a guard that asked whether **root** held a key, which was
/// wrong twice over: any account with a key is a way in, and root is the one
/// account [`harden::HardenSsh`] takes away — it writes `PermitRootLogin no`,
/// so a root key satisfied the old check and was worthless a step later. On a
/// host with root locked by default, the recommended posture, both tasks were
/// unreachable while an ordinary account could log in perfectly well.
///
/// Three conditions, all of which must hold:
///
/// - the account has a key [`has_authorized_key`] recognises;
/// - `PermitRootLogin` does not refuse it, which only ever excludes root;
/// - `AllowUsers`, where the file sets it, names it. A key held by an account
///   the daemon already refuses is not a way back in, and this is the condition
///   the tiers ignored entirely.
///
/// Read from the configuration rather than assumed, so the strict tier — which
/// writes neither directive — judges by what the file actually says while the
/// safe tier is judged by what it is about to write. The caller passes
/// `refuses_root` accordingly.
///
/// Ordered by rank so human accounts come first and **filtered by nothing**,
/// the rule [`crate::domain::accounts::AccountReader::list_ranked`] states: the
/// uid threshold is a convention of the five families rather than a rule, so a
/// site numbering a real account below it still finds it here.
///
/// It does not stop at the first account that passes. The confirmation lists
/// every one so the operator can check that *theirs* is among them, and a scan
/// that returned early would leave them looking at a list of one and cancelling
/// — the rule `users.lock-root`'s own scan already follows.
///
/// The cost is one passwd lookup and one file read per account, cheaper than
/// that scan, which also spends an `id -nG`, a shadow read and a `sudo -l`.
pub(crate) fn accounts_keeping_ssh_access(
    executor: &dyn Executor,
    backend: &dyn Backend,
    contents: &str,
    refuses_root: bool,
) -> Result<Vec<KeyHolder>> {
    let root_refused = refuses_root
        || crate::tasks::sshd_config::directive_value(contents, "PermitRootLogin")
            .is_some_and(|value| value.eq_ignore_ascii_case("no"));

    // Absent means every account is permitted, which is not the same as an
    // empty list and is why this stays an `Option` rather than defaulting to
    // one. A file that sets it names the only accounts sshd will consider.
    let allowed: Option<Vec<String>> =
        crate::tasks::sshd_config::directive_value(contents, "AllowUsers")
            .map(|value| value.split_whitespace().map(str::to_owned).collect());

    backend
        .accounts()
        .list_ranked(executor)?
        .into_iter()
        .map(|account| {
            let refused_outright = (root_refused && account.name == ROOT)
                || allowed
                    .as_ref()
                    .is_some_and(|names| !names.contains(&account.name));

            let keeps_access =
                !refused_outright && has_authorized_key(executor, backend, &account.name)?;

            Ok(KeyHolder {
                user: account.name,
                keeps_access,
            })
        })
        .collect()
}

/// The accounts from a scan that keep access, by name.
///
/// Both the guard and the confirmation need exactly this, and deriving it twice
/// is how the dialog comes to promise what the task then refuses.
pub(crate) fn keeps_access(holders: &[KeyHolder]) -> Vec<String> {
    holders
        .iter()
        .filter(|holder| holder.keeps_access)
        .map(|holder| holder.user.clone())
        .collect()
}

/// Reloads SSH so a new configuration takes effect.
///
/// Reload rather than restart: restarting drops the very session the
/// administrator is connected through.
fn reload_ssh(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    let service = backend.service_for(Capability::Ssh);

    report(
        progress,
        &Msg::TaskSshReloading {
            unit: service.to_owned(),
        },
    );
    backend.services().reload(executor, service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::Confirmation;
    use crate::tasks::Task;
    use crate::tasks::params::ParamValues;

    use super::fixtures::TEST_KEY;

    #[test]
    fn the_key_guard_reads_the_named_users_own_file() {
        // Generalised from root: `ssh.allow-users` has to ask the same question
        // about an ordinary account, whose keys live under /home.
        // The home comes from the passwd database, so this one is deliberately
        // not `/home/alice`: an account whose home was moved is exactly the
        // case the old guess got wrong, and a fixture that agreed with the
        // guess would not have noticed.
        let mock = MockExecutor::with_replies([
            Reply::ok("alice:x:1000:1000::/srv/alice:/bin/sh"),
            Reply::ok(""),       // authorized_keys exists
            Reply::ok(TEST_KEY), // and holds a valid key
        ]);
        let backend = for_family(Family::Debian);

        let found = has_authorized_key(&mock, backend.as_ref(), "alice")
            .expect("reading the file must succeed");

        assert!(found, "a valid key must be recognised");
        assert!(
            mock.recorded_lines()
                .iter()
                .any(|c| c.contains("/srv/alice/.ssh/authorized_keys")),
            "the key must be looked for where passwd says the home is: {:?}",
            mock.recorded_lines()
        );
    }

    /// Root plus two ordinary accounts, so a scan can be seen not to stop.
    const THREE_ACCOUNTS: &str = "root:x:0:0:root:/root:/bin/bash\n\
         alice:x:1000:1000::/home/alice:/bin/sh\n\
         bob:x:1001:1001::/home/bob:/bin/sh\n";

    #[test]
    fn the_scan_reports_every_account_that_keeps_access() {
        // Not just the first. The confirmation lists them so the operator can
        // check that theirs is among them, and a scan that returned after the
        // first would leave them looking at a list of one and cancelling.
        let mock = MockExecutor::with_replies([
            Reply::ok(THREE_ACCOUNTS), // cat /etc/passwd
            Reply::ok("alice:x:1000:1000::/home/alice:/bin/sh"),
            Reply::ok(""),       // alice's authorized_keys exists
            Reply::ok(TEST_KEY), // and holds a valid key
            Reply::ok("bob:x:1001:1001::/home/bob:/bin/sh"),
            Reply::ok(""),       // bob's exists too
            Reply::ok(TEST_KEY), // and holds a key as well
        ]);
        let backend = for_family(Family::Debian);

        let holders = accounts_keeping_ssh_access(&mock, backend.as_ref(), "Port 22\n", true)
            .expect("the scan must succeed");

        assert_eq!(
            keeps_access(&holders),
            vec!["alice".to_owned(), "bob".to_owned()],
            "both accounts hold a key and both must be reported"
        );
    }

    #[test]
    fn the_scan_reports_an_account_that_holds_no_key() {
        // Reported rather than dropped: `keeps_access` filters, and a scan that
        // filtered too would leave the two indistinguishable from a host whose
        // passwd file could not be read.
        let mock = MockExecutor::with_replies([
            Reply::ok(THREE_ACCOUNTS), // cat /etc/passwd
            Reply::ok("alice:x:1000:1000::/home/alice:/bin/sh"),
            Reply::failure(1, ""), // alice has no authorized_keys
            Reply::ok("bob:x:1001:1001::/home/bob:/bin/sh"),
            Reply::ok(""),       // bob's exists
            Reply::ok(TEST_KEY), // and holds a key
        ]);
        let backend = for_family(Family::Debian);

        let holders = accounts_keeping_ssh_access(&mock, backend.as_ref(), "Port 22\n", true)
            .expect("the scan must succeed");

        assert_eq!(
            holders.len(),
            3,
            "every account is reported, whether or not it passed: {holders:?}"
        );
        assert_eq!(keeps_access(&holders), vec!["bob".to_owned()]);
    }

    #[test]
    fn an_allowusers_list_narrows_the_scan_to_what_it_names() {
        // A real key held by an account the daemon already refuses is not a way
        // back in. Only bob is named, so alice is never even looked up.
        let mock = MockExecutor::with_replies([
            Reply::ok(THREE_ACCOUNTS), // cat /etc/passwd
            Reply::ok("bob:x:1001:1001::/home/bob:/bin/sh"),
            Reply::ok(""),       // bob's authorized_keys exists
            Reply::ok(TEST_KEY), // and holds a valid key
        ]);
        let backend = for_family(Family::Debian);

        let holders =
            accounts_keeping_ssh_access(&mock, backend.as_ref(), "Port 22\nAllowUsers bob\n", true)
                .expect("the scan must succeed");

        assert_eq!(keeps_access(&holders), vec!["bob".to_owned()]);
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|c| c.contains("/home/alice")),
            "an account the directive excludes is not worth a lookup: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn destructive_tasks_are_marked_as_such() {
        // The TUI gates these behind a confirmation prompt.
        assert!(HardenSsh.confirmation() == Confirmation::Lockout);
        assert!(ChangePort.confirmation() == Confirmation::Lockout);
        assert!(InstallSsh.confirmation() == Confirmation::Change);
    }

    #[test]
    fn tasks_that_change_nothing_elsewhere_declare_nothing() {
        // The default is empty, so a task only speaks up when it has something
        // to say.
        assert!(
            InstallSsh
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
        assert!(
            HardenSsh
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
    }
}
