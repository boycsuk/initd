//! The fish shell, and registering it as a login shell.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Support, Task, report};

/// Installs the fish shell.
pub struct InstallFish;
impl Task for InstallFish {
    fn id(&self) -> &'static str {
        "fish.install"
    }

    fn title(&self) -> &'static str {
        "Install the fish shell"
    }

    fn description(&self) -> &'static str {
        "Installs fish and registers it in /etc/shells so an account may adopt \
         it. Set it for a user with users.set-shell."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fish)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fish.install"]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // openSUSE packages fish in its own repositories, on both
            // Tumbleweed and Leap 16.0 — which is the same Build Service the
            // refusal below sends RHEL users to, reached here as a first-party
            // package rather than a third-party one.
            Family::Debian | Family::Arch | Family::Alpine | Family::Suse => Support::Yes,
            Family::Rhel => Support::No(
                "EPEL-only, and unlike Caddy there is no verifiable \
                 alternative — fish publishes source rather than static \
                 binaries, and its own documentation points RHEL users at the \
                 openSUSE Build Service rather than at EPEL",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Installing a shell gives nobody that shell. Said plainly because the
        // two read as one action and are not.
        vec![Consequence::Invalidates {
            task: "users.set-shell",
            reason: Reason::RequiresSetting {
                setting: "a login shell, which no account has adopted yet",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        backend
            .packages()
            .install(executor, &[backend.package_for(Capability::Fish)])?;

        // Registered in /etc/shells, without which `chsh` refuses it and some
        // PAM configurations refuse a session for an account that uses it.
        // Read back from the system rather than assumed: the path differs
        // between distributions and releases.
        let path = resolve_program(executor, "fish")?;

        register_shell(executor, backend, &path)?;

        report(progress, &Msg::TaskFishInstalledAt { path: path.clone() });
        report(progress, &Msg::TaskFishNotForRoot);

        Ok(Outcome::Done)
    }
}
/// The absolute path of a program, as the system resolves it.
///
/// Read from the host rather than assumed: fish lives at `/usr/bin/fish` on
/// Arch and at either `/usr/bin/fish` or `/bin/fish` on Debian depending on
/// the release, and a path that does not match what is installed produces a
/// login shell nobody can use.
fn resolve_program(executor: &dyn Executor, program: &'static str) -> Result<String> {
    let output = executor.run(&Command::locating(program))?;

    if !output.success() {
        return Err(Error::ProgramNotFound {
            program: program.to_owned(),
        });
    }

    Ok(output.stdout.trim().to_owned())
}
/// Adds a shell to `/etc/shells` if it is not already listed.
fn register_shell(executor: &dyn Executor, backend: &dyn Backend, path: &str) -> Result<()> {
    const SHELLS: &str = "/etc/shells";

    let files = backend.files();
    let existing = files.read(executor, SHELLS)?;

    // Compared line by line rather than as a substring: `/bin/fish` is a
    // substring of `/usr/bin/fish`, so a careless check would decide the wrong
    // one was already registered.
    if existing.lines().any(|line| line.trim() == path) {
        return Ok(());
    }

    let backup = files.write(executor, SHELLS, &format!("{existing}{path}\n"))?;

    // No unit to reload: `/etc/shells` is consulted by `chsh` and by PAM at
    // the next login, so nothing is holding a stale copy. Recorded all the
    // same — this is a file the distribution owns and this tool appended to,
    // which makes it exactly the kind of edit somebody may want undone.
    if let Some(ref backup) = backup {
        crate::backend::backup_index::record_existing(executor, files, "fish.install", backup, "");
    }

    Ok(())
}
/// Removes the fish shell.
pub struct UninstallFish;
impl Task for UninstallFish {
    fn id(&self) -> &'static str {
        "fish.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the fish shell"
    }

    fn description(&self) -> &'static str {
        "Removes fish. Its entry in /etc/shells is left in place: an account \
         still set to it would otherwise have a login shell no file admits, \
         and the entry alone is harmless."
    }

    /// The same families the install runs on, for the same measured reasons.
    ///
    /// Written out rather than inherited: a task that offered to remove what
    /// it could never have installed would be a row promising an operation
    /// with nothing to operate on.
    fn support(&self, family: Family) -> Support {
        InstallFish.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fish)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fish.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Fish)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // An account whose login shell is about to stop existing cannot log
        // in. The mirror of what installing says, and the more urgent of the
        // two: the forward direction leaves an account working.
        vec![Consequence::Invalidates {
            task: "users.set-shell",
            reason: Reason::RequiresSetting {
                setting: "a login shell that still exists, for any account set to fish",
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
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Fish,
            "fish",
        )
    }
}
