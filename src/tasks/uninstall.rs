//! What every inverse task does, written once.
//!
//! Ten tasks undo an install, and they differ in three things: which
//! capability, which program name a release-installed one carries, and whether
//! a unit has to be stopped first. Everything else is identical — which is
//! exactly the shape that produces ten near-copies where the one that drifts
//! is the one nobody notices.
//!
//! The order is the mirror of installing. A unit is stopped and disabled
//! *before* the package goes, because the reverse leaves a moment where the
//! unit file has been deleted and the running service has not been told; and
//! `disable_and_stop` treats a unit that no longer exists as the state it was
//! asked for, so removing a package that took its unit with it does not then
//! fail at the last step having done everything.
//!
//! Always [`Outcome::Done`], never `Revertible`. The verification window
//! exists for a change that can sever the session applying it, and its undo is
//! cheap and local: restore a file, reload a unit. Undoing an uninstall means
//! reinstalling from the network, which fails outright on a host with no
//! egress or a stale package cache. A countdown promising an undo that cannot
//! run is worse than no countdown.

use crate::backend::{Backend, Capability};
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, report};

/// Name of the parameter choosing how thoroughly a package is removed.
pub const REMOVAL: &str = "removal";

/// The value that keeps configuration behind.
pub const KEEP_CONFIGURATION: &str = "remove";

/// The value that takes configuration with it.
pub const WITH_CONFIGURATION: &str = "purge";

/// The removal-depth field, for a task whose subject is a package.
///
/// Defaults to keeping configuration, which is the recoverable answer: a
/// reinstall finds what was there, and an operator who wanted it gone can say
/// so. The reverse default would destroy a hand-edited `jail.local` on the
/// strength of a field nobody read.
pub fn removal_param() -> Param {
    Param::new(REMOVAL, "Configuration", ParamKind::Removal)
        .with_initial(KEEP_CONFIGURATION)
        .with_hint("remove keeps configuration files; purge deletes them")
}

/// Undoes an install, whichever way the capability was installed.
///
/// Mirrors the branch the forward task took rather than assuming one: a family
/// that packages Caddy installed it with the package manager and a family that
/// does not downloaded a binary, so asking `has_package_for` again — in the
/// same order — is what keeps a released binary from being handed to `apt-get
/// remove` and a packaged one from having `/usr/local/bin` searched for it.
///
/// `program` is the executable a release-installed capability leaves behind,
/// and `&'static str` all the way down: it reaches `Command::locating`, which
/// builds a `sh -c` around it, so nothing from a form can arrive here.
pub fn undo(
    executor: &dyn Executor,
    backend: &dyn Backend,
    values: &ParamValues,
    progress: Progress<'_>,
    capability: Capability,
    program: &'static str,
) -> Result<Outcome> {
    let unit = backend.service_for(capability);

    if backend.has_package_for(capability) {
        let package = backend.package_for(capability);

        if !backend.packages().is_installed(executor, package)? {
            report(
                progress,
                &Msg::TaskNotInstalled {
                    what: package.to_owned(),
                },
            );

            return Ok(Outcome::Done);
        }

        // Before the package, not after: removing it first would delete the
        // unit file while the service was still running, leaving a daemon
        // nothing can now stop by name.
        if !unit.is_empty() {
            report(
                progress,
                &Msg::TaskDisabling {
                    unit: unit.to_owned(),
                },
            );

            backend.services().disable_and_stop(executor, unit)?;
        }

        let purging = values.get(REMOVAL).unwrap_or(KEEP_CONFIGURATION) == WITH_CONFIGURATION;

        report(
            progress,
            &if purging {
                Msg::TaskPurging {
                    what: package.to_owned(),
                }
            } else {
                Msg::TaskRemoving {
                    what: package.to_owned(),
                }
            },
        );

        if purging {
            backend.packages().purge(executor, package)?;
        } else {
            backend.packages().remove(executor, package)?;
        }

        return Ok(Outcome::Done);
    }

    // No package on this family, so the forward task downloaded a binary and
    // this one deletes the copy it wrote — never whatever the shell resolves.
    if !backend.binaries().is_installed_here(executor, program)? {
        // Present, but somewhere this tool never wrote. Named rather than
        // reported as absent: the operator can see the program works and would
        // read "not installed" as the tool being confused.
        if let Some(found_at) = backend.binaries().location_of(executor, program)? {
            report(
                progress,
                &Msg::TaskInstalledElsewhere {
                    what: program.to_owned(),
                    at: found_at,
                },
            );
        } else {
            report(
                progress,
                &Msg::TaskNotInstalled {
                    what: program.to_owned(),
                },
            );
        }

        return Ok(Outcome::Done);
    }

    report(
        progress,
        &Msg::TaskRemoving {
            what: program.to_owned(),
        },
    );

    backend.binaries().remove(executor, program)?;

    report(
        progress,
        &Msg::TaskBinaryRemoved {
            path: format!("/usr/local/bin/{program}"),
        },
    );

    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Values naming a removal depth, as a form would collect them.
    fn asking_for(depth: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(REMOVAL, depth);
        values
    }

    #[test]
    fn a_packaged_capability_is_disabled_before_it_is_removed() {
        // Removing the package first deletes the unit file while the service
        // is still running, leaving a daemon nothing can stop by name.
        let mock = MockExecutor::with_replies([
            Reply::ok("install ok installed"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        undo(
            &mock,
            for_family(Family::Debian).as_ref(),
            &asking_for(KEEP_CONFIGURATION),
            &mut |_| {},
            Capability::Caddy,
            "caddy",
        )
        .expect("the removal must succeed");

        let commands = mock.recorded_lines();

        let disabled = commands
            .iter()
            .position(|line| line.contains("disable"))
            .expect("the unit must be disabled");
        let removed = commands
            .iter()
            .position(|line| line.contains("apt-get remove"))
            .expect("the package must be removed");

        assert!(
            disabled < removed,
            "the unit must stop before the package goes: {commands:?}"
        );
    }

    #[test]
    fn the_operators_choice_decides_whether_configuration_survives() {
        for (depth, expected) in [
            (KEEP_CONFIGURATION, "apt-get remove"),
            (WITH_CONFIGURATION, "apt-get purge"),
        ] {
            let mock = MockExecutor::with_replies([
                Reply::ok("install ok installed"),
                Reply::ok(""),
                Reply::ok(""),
            ]);

            undo(
                &mock,
                for_family(Family::Debian).as_ref(),
                &asking_for(depth),
                &mut |_| {},
                Capability::Fail2ban,
                "fail2ban",
            )
            .expect("the removal must succeed");

            assert!(
                mock.recorded_lines()
                    .iter()
                    .any(|line| line.contains(expected)),
                "{depth} must issue {expected}: {:?}",
                mock.recorded_lines()
            );
        }
    }

    #[test]
    fn a_missing_value_keeps_the_configuration() {
        // The CLI can invoke a task without every optional value, and the
        // absent answer must be the recoverable one rather than the thorough
        // one. A reinstall finding its configuration is a smaller surprise
        // than an edited file having been deleted.
        let mock = MockExecutor::with_replies([
            Reply::ok("install ok installed"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        undo(
            &mock,
            for_family(Family::Debian).as_ref(),
            &ParamValues::new(),
            &mut |_| {},
            Capability::Fail2ban,
            "fail2ban",
        )
        .expect("the removal must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.contains("apt-get remove")),
            "an unanswered field must keep configuration: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn nothing_is_removed_when_nothing_is_installed() {
        // Reports and stops rather than running a removal that would exit
        // non-zero and be reported as a failed task.
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        undo(
            &mock,
            for_family(Family::Debian).as_ref(),
            &asking_for(KEEP_CONFIGURATION),
            &mut |_| {},
            Capability::Fail2ban,
            "fail2ban",
        )
        .expect("an absent package is not a failure");

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "only the query should run: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_binary_somebody_else_installed_is_left_where_it_is() {
        // The defect this whole distinction exists for. Debian packages no
        // zellij, so the question falls to the binary installer; a copy in
        // ~/.cargo/bin is not this tool's to delete.
        let mock = MockExecutor::with_replies([
            // `test -f /usr/local/bin/zellij` — nothing there.
            Reply::failure(1, ""),
            // `command -v zellij` — but the shell finds one.
            Reply::ok("/home/op/.cargo/bin/zellij\n"),
        ]);

        undo(
            &mock,
            for_family(Family::Debian).as_ref(),
            &ParamValues::new(),
            &mut |_| {},
            Capability::Zellij,
            "zellij",
        )
        .expect("a foreign copy is not a failure");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("rm ")),
            "a binary this tool did not install must not be deleted: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn this_tools_own_binary_is_deleted_from_where_it_was_written() {
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        undo(
            &mock,
            for_family(Family::Debian).as_ref(),
            &ParamValues::new(),
            &mut |_| {},
            Capability::Zellij,
            "zellij",
        )
        .expect("the removal must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line == "rm -f /usr/local/bin/zellij"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_family_that_packages_the_capability_never_touches_the_binary_path() {
        // Arch packages zellij. Asking the binary installer there would look
        // for /usr/local/bin/zellij, find nothing, and report "not installed"
        // about a program the package manager put in /usr/bin.
        let mock = MockExecutor::with_replies([Reply::ok("zellij 0.44.0-1"), Reply::ok("")]);

        undo(
            &mock,
            for_family(Family::Arch).as_ref(),
            &asking_for(KEEP_CONFIGURATION),
            &mut |_| {},
            Capability::Zellij,
            "zellij",
        )
        .expect("the removal must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.starts_with("pacman -R")),
            "{:?}",
            mock.recorded_lines()
        );
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("/usr/local/bin")),
            "{:?}",
            mock.recorded_lines()
        );
    }
}
