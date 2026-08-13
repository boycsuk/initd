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
