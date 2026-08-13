//! `systemd` implementation of [`ServiceManager`].
//!
//! Shared by every systemd-based family: only the unit names differ, and those
//! come from the backend, not from here. Alpine's OpenRC would be a sibling
//! implementation of the same trait — which is why this is not folded into a
//! specific family's module.

use crate::domain::{ServiceManager, ServiceState};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, Output};

/// Manages services through `systemctl`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemdServices;

impl SystemdServices {
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for SystemdServices {
    fn enable_and_start(&self, executor: &dyn Executor, service: &str) -> Result<()> {
        // `--now` enables at boot and starts immediately in one call, which
        // keeps the two from drifting apart if the second one fails.
        let command = Command::new("systemctl")
            .args(["enable", "--now", service])
            .privileged();

        run_checked(executor, &command)
    }

    fn reload(&self, executor: &dyn Executor, service: &str) -> Result<()> {
        let command = Command::new("systemctl")
            .args(["reload", service])
            .privileged();

        run_checked(executor, &command)
    }

    fn disable_and_stop(&self, executor: &dyn Executor, service: &str) -> Result<()> {
        // `--now` stops and disables in one call, the mirror of how the unit
        // was enabled: leaving one half undone is a service that reports itself
        // stopped and is running again after a reboot.
        let command = Command::new("systemctl")
            .args(["disable", "--now", service])
            .privileged();

        let output = executor.run(&command)?;

        if output.success() {
            return Ok(());
        }

        // A unit that does not exist is the state being asked for, not a
        // failure. Removing a package takes its unit with it, so a caller that
        // stops the service after removing the package would otherwise fail at
        // the last step having done everything it was asked. Matched on
        // systemd's own wording because it has no distinct exit code for it —
        // `disable` answers 1 both for a missing unit and for a refusal.
        if unit_is_absent(&output.stderr) {
            return Ok(());
        }

        Err(Error::CommandFailed {
            command: command.to_string(),
            code: output.code,
            stderr: output.stderr,
        })
    }

    fn state(&self, executor: &dyn Executor, service: &str) -> Result<ServiceState> {
        // `is-active` and `is-enabled` exit non-zero when the answer is "no",
        // so a failing exit code here is information, not an error.
        let active = executor.run(&Command::new("systemctl").args(["is-active", service]))?;
        let enabled = executor.run(&Command::new("systemctl").args(["is-enabled", service]))?;

        Ok(ServiceState {
            active: active.stdout.trim() == "active",
            enabled: enabled.stdout.trim() == "enabled",
        })
    }
}

/// Runs a command and turns a non-zero exit into an error.
/// Whether systemd is reporting a unit it does not have.
///
/// Matching another program's user-facing text, which this codebase avoids
/// where it can. It cannot here: `systemctl disable` exits 1 both for a unit
/// that does not exist and for one it refuses to touch, and those two need
/// opposite answers — the first is the state an uninstall wanted, the second is
/// a failure worth reporting.
///
/// Both spellings are matched because systemd has used both: "not loaded" is
/// what a running system says of an absent unit, "does not exist" is what
/// `disable` says when no unit file is found. Lowercased before comparing
/// rather than matched case-sensitively, since the message begins a sentence
/// in some versions and a clause in others.
pub(super) fn unit_is_absent(stderr: &str) -> bool {
    let stderr = stderr.to_lowercase();

    stderr.contains("does not exist") || stderr.contains("not loaded")
}

pub fn run_checked(executor: &dyn Executor, command: &Command) -> Result<()> {
    run_capturing(executor, command)?;

    Ok(())
}

/// Runs a command, returning its stdout, and turns a failure into an error.
///
/// What [`run_checked`] does, for the callers that need what the command said.
/// Eight of them wrote the same nine lines out by hand — `unix_files`,
/// `posix_accounts` twice over, `nftables`, `wg_tools`, `release_installer` —
/// because the checked helper beside them discards stdout and there was no
/// other. Each copy built `Error::CommandFailed` from the same three fields,
/// which is the shape that stays identical until one of them learns something
/// the others do not.
///
/// Returns the whole [`Output`] rather than the string: `wg_tools` wants stdout
/// trimmed, `nftables` wants it parsed, and a helper that trimmed for everyone
/// would be wrong for the caller that cares about a trailing newline.
pub fn run_capturing(executor: &dyn Executor, command: &Command) -> Result<Output> {
    let output = executor.run(command)?;

    if output.success() {
        return Ok(output);
    }

    Err(Error::CommandFailed {
        command: command.to_string(),
        code: output.code,
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn enable_and_start_uses_the_given_unit_name() {
        let mock = MockExecutor::new();

        SystemdServices::new()
            .enable_and_start(&mock, "ssh.service")
            .expect("enabling must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["systemctl enable --now ssh.service"]
        );
        assert!(mock.any_privileged(), "enabling a unit requires root");
    }

    #[test]
    fn disabling_also_stops_so_a_reboot_does_not_undo_it() {
        // Both halves in one call. A unit stopped but left enabled reports
        // itself stopped and is running again after a reboot — the mistake the
        // firewall made by writing rules the boot never replayed.
        let mock = MockExecutor::new();

        SystemdServices::new()
            .disable_and_stop(&mock, "caddy.service")
            .expect("disabling must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["systemctl disable --now caddy.service"]
        );
        assert!(mock.any_privileged(), "disabling a unit requires root");
    }

    #[test]
    fn a_unit_that_does_not_exist_is_the_state_that_was_wanted() {
        // Removing a package takes its unit with it, so stopping the service
        // after removing the package must not fail at the last step having done
        // everything it was asked.
        for stderr in [
            "Failed to disable unit: Unit file caddy.service does not exist.",
            "Failed to stop caddy.service: Unit caddy.service not loaded.",
        ] {
            let mock = MockExecutor::with_replies([Reply::failure(1, stderr)]);

            SystemdServices::new()
                .disable_and_stop(&mock, "caddy.service")
                .expect("an absent unit is not a failure");
        }
    }

    #[test]
    fn a_refusal_is_still_reported_as_one() {
        // The other half of the exit code systemd overloads: 1 means both "no
        // such unit" and "I will not", and only the first is success.
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "Failed to disable unit: Unit caddy.service is masked.",
        )]);

        SystemdServices::new()
            .disable_and_stop(&mock, "caddy.service")
            .expect_err("a refusal must not be reported as success");
    }

    #[test]
    fn reload_is_used_rather_than_restart() {
        // Restarting sshd would drop the administrator's own session.
        let mock = MockExecutor::new();

        SystemdServices::new()
            .reload(&mock, "sshd.service")
            .expect("reloading must succeed");

        let command = mock.single_command();
        assert_eq!(command.args[0], "reload");
        assert!(!command.args.contains(&"restart".to_owned()));
    }

    #[test]
    fn state_reports_active_and_enabled() {
        let mock = MockExecutor::with_replies([Reply::ok("active\n"), Reply::ok("enabled\n")]);

        let state = SystemdServices::new()
            .state(&mock, "ssh.service")
            .expect("querying state must succeed");

        assert_eq!(
            state,
            ServiceState {
                active: true,
                enabled: true
            }
        );
    }

    #[test]
    fn inactive_service_is_not_an_error() {
        // `is-active` exits 3 for an inactive unit; that is an answer, not a
        // failure.
        let mock = MockExecutor::with_replies([Reply::failure(3, ""), Reply::failure(1, "")]);

        let state = SystemdServices::new()
            .state(&mock, "ssh.service")
            .expect("an inactive service must not be an error");

        assert!(!state.active);
        assert!(!state.enabled);
    }

    #[test]
    fn a_failing_command_becomes_an_error() {
        let mock = MockExecutor::with_replies([Reply::failure(5, "Unit not found.")]);

        let err = SystemdServices::new()
            .enable_and_start(&mock, "nope.service")
            .expect_err("a failing systemctl must surface");

        assert!(
            matches!(err, Error::CommandFailed { code: 5, .. }),
            "{err:?}"
        );
    }
}
