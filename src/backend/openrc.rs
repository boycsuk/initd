//! OpenRC implementation of [`ServiceManager`].
//!
//! The reason the service manager is a trait at all. systemd and OpenRC do not
//! merely spell the same commands differently: OpenRC splits "start it now"
//! from "start it at boot" across two programs — `rc-service` and
//! `rc-update` — where systemd folds both into `systemctl enable --now`.
//!
//! It also has no notion of a unit's *name* beyond the script in
//! `/etc/init.d`, so what the backend resolves for a capability is a script
//! name rather than a unit. `sshd` there, against `ssh.service` on Debian and
//! `sshd.service` on Arch — three spellings of one idea.

use crate::domain::{ServiceManager, ServiceState};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The runlevel a service is added to so it starts at boot.
///
/// `default` rather than `boot`: `boot` is for the services that bring the
/// system up before networking, and a daemon added there starts too early to
/// reach anything.
const RUNLEVEL: &str = "default";

/// Manages services through OpenRC.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenRcServices;

impl OpenRcServices {
    pub const fn new() -> Self {
        Self
    }
}

impl ServiceManager for OpenRcServices {
    fn enable_and_start(&self, executor: &dyn Executor, service: &str) -> Result<()> {
        // Two commands, because OpenRC has no single one that does both. The
        // order matters: adding to the runlevel first means a failure to start
        // still leaves the service configured to come up at the next boot,
        // which is the recoverable half of the pair.
        let enable = Command::new("rc-update")
            .args(["add", service, RUNLEVEL])
            .privileged();

        super::systemd::run_checked(executor, &enable)?;

        let start = Command::new("rc-service")
            .args([service, "start"])
            .privileged();

        super::systemd::run_checked(executor, &start)
    }

    fn reload(&self, executor: &dyn Executor, service: &str) -> Result<()> {
        // `reload` where the script defines it, which OpenRC reports as an
        // unknown command otherwise. sshd's script does, and that is the one
        // reload this tool performs — a restart would drop the session
        // applying the change.
        let command = Command::new("rc-service")
            .args([service, "reload"])
            .privileged();

        super::systemd::run_checked(executor, &command)
    }

    fn state(&self, executor: &dyn Executor, service: &str) -> Result<ServiceState> {
        // `rc-service <name> status` exits non-zero when the service is
        // stopped, which is an answer rather than a failure.
        let active = executor
            .run(&Command::new("rc-service").args([service, "status"]))?
            .success();

        // `rc-update show` lists what runs at each runlevel. Matched on the
        // service name as a whole word: `sshd` is a substring of `sshdgenkeys`
        // on some systems, and a substring check would report a service as
        // enabled on the strength of an unrelated one.
        let listed = executor.run(&Command::new("rc-update").arg("show"))?;

        let enabled = listed.stdout.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|name| name == service)
        });

        Ok(ServiceState { active, enabled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn enabling_uses_two_programs_because_openrc_has_no_single_one() {
        // systemd folds both halves into `systemctl enable --now`; OpenRC does
        // not, which is the divergence that makes this a trait rather than a
        // difference in spelling.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        OpenRcServices::new()
            .enable_and_start(&mock, "sshd")
            .expect("enabling must succeed");

        let commands = mock.recorded_lines();

        assert_eq!(commands.len(), 2, "{commands:?}");
        assert!(commands[0].starts_with("rc-update add"), "{commands:?}");
        assert!(
            commands[1].starts_with("rc-service sshd start"),
            "{commands:?}"
        );
    }

    #[test]
    fn a_service_is_added_to_the_runlevel_before_it_is_started() {
        // A failure to start then leaves it configured to come up at the next
        // boot, which is the recoverable half.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::failure(1, "failed")]);

        let result = OpenRcServices::new().enable_and_start(&mock, "sshd");

        assert!(result.is_err(), "a failed start must be reported");
        assert!(
            mock.recorded_lines()[0].contains("rc-update add"),
            "the runlevel entry must already exist: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_service_joins_the_default_runlevel_rather_than_boot() {
        // `boot` runs before networking, so a daemon added there starts too
        // early to reach anything.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        OpenRcServices::new()
            .enable_and_start(&mock, "sshd")
            .expect("enabling must succeed");

        assert!(
            mock.recorded_lines()[0].ends_with("default"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_stopped_service_is_an_answer_not_a_failure() {
        let mock = MockExecutor::with_replies([
            Reply::failure(3, "status: stopped"),
            Reply::ok("sshd | default"),
        ]);

        let state = OpenRcServices::new()
            .state(&mock, "sshd")
            .expect("a stopped service must not raise");

        assert!(!state.active);
        assert!(state.enabled, "stopped and enabled are independent");
    }

    #[test]
    fn enablement_matches_the_service_as_a_whole_word() {
        // `sshd` is a substring of `sshdgenkeys`. A substring check would
        // report a service as enabled on the strength of an unrelated one.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("sshdgenkeys | default")]);

        let state = OpenRcServices::new()
            .state(&mock, "sshd")
            .expect("the query must succeed");

        assert!(
            !state.enabled,
            "sshdgenkeys must not satisfy a check for sshd"
        );
    }

    #[test]
    fn a_running_and_enabled_service_reports_both() {
        let mock = MockExecutor::with_replies([
            Reply::ok("status: started"),
            Reply::ok("sshd | default\nchronyd | default"),
        ]);

        let state = OpenRcServices::new()
            .state(&mock, "sshd")
            .expect("the query must succeed");

        assert!(state.active);
        assert!(state.enabled);
    }
}
