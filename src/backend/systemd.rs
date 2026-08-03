//! `systemd` implementation of [`ServiceManager`].
//!
//! Shared by every systemd-based family: only the unit names differ, and those
//! come from the backend, not from here. Alpine's OpenRC would be a sibling
//! implementation of the same trait — which is why this is not folded into a
//! specific family's module.

use crate::domain::{ServiceManager, ServiceState};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

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
pub fn run_checked(executor: &dyn Executor, command: &Command) -> Result<()> {
    let output = executor.run(command)?;

    if output.success() {
        return Ok(());
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
