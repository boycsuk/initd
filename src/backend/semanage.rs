//! `semanage` implementation of [`SelinuxManager`].
//!
//! The tools SELinux is administered with are packaged separately from the
//! policy they administer: a RHEL host can be enforcing while `semanage` is not
//! installed, which is the common case on a minimal install. So the port label
//! is applied through `semanage` where it exists and the absence is reported
//! rather than worked around — a task that silently skipped the labelling would
//! write a port the daemon cannot bind and call it done.

use super::systemd::run_checked;
use crate::domain::firewall::Protocol;
use crate::domain::selinux::SelinuxManager;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// The SELinux type that lets a process listen for SSH.
///
/// `ssh_port_t` is what the shipped policy labels 22 with, so a moved port
/// needs the same type rather than a new one: the daemon's own domain is
/// already permitted to bind it.
const SSH_PORT_TYPE: &str = "ssh_port_t";

/// Applies port labels through `semanage`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Semanage;

impl Semanage {
    pub const fn new() -> Self {
        Self
    }
}

impl SelinuxManager for Semanage {
    fn is_enforcing(&self, executor: &dyn Executor) -> Result<bool> {
        // `selinuxenabled` rather than `getenforce`: it answers by exit code,
        // where `getenforce` prints one of three words that would have to be
        // matched. Exit 1 means not enabled, which is an answer rather than a
        // failure — a container reports it, and so does a host whose
        // administrator turned SELinux off.
        let command = Command::new("selinuxenabled");

        match executor.run(&command) {
            Ok(output) => Ok(output.success()),
            // The tool itself is absent on a host without the policy installed.
            // Nothing is enforcing there, which is the same answer.
            Err(Error::ProgramNotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn allow_ssh_port(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()> {
        // Add first, fall through to modify. The reasoning originally written
        // here was that `-a` fails on a port already labelled and `-m` fails on
        // one that is not, so neither is idempotent alone — which turned out to
        // be wrong about the first half. Measured against policycoreutils on
        // Rocky 9: a second `-a` prints "already defined, modifying instead"
        // and exits 0, doing the fallback itself.
        //
        // The sequence stays because the outcome is right either way and the
        // premise is not one this project controls: an older or a differently
        // built policycoreutils may well fail where this one recovers, and the
        // fallback costs nothing when it is never reached.
        // `tests/integration_backends.rs` pins both paths, so whichever one a
        // host takes is one that has been observed.
        let add = Command::new("semanage")
            .args([
                "port",
                "-a",
                "-t",
                SSH_PORT_TYPE,
                "-p",
                protocol.as_str(),
                &port.to_string(),
            ])
            .privileged();

        if executor.run(&add)?.success() {
            return Ok(());
        }

        let modify = Command::new("semanage")
            .args([
                "port",
                "-m",
                "-t",
                SSH_PORT_TYPE,
                "-p",
                protocol.as_str(),
                &port.to_string(),
            ])
            .privileged();

        run_checked(executor, &modify)
    }
}

/// The answer for families with no mandatory access control layer.
///
/// A distinct type rather than an `Option` on the backend: every family answers
/// the question, and three of them answer that nothing is enforcing. That keeps
/// the task free of a branch it would otherwise have to write, which is the
/// same reason the firewall front-ends are resolved rather than matched on.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSelinux;

impl NoSelinux {
    pub const fn new() -> Self {
        Self
    }
}

impl SelinuxManager for NoSelinux {
    fn is_enforcing(&self, _executor: &dyn Executor) -> Result<bool> {
        Ok(false)
    }

    fn allow_ssh_port(
        &self,
        _executor: &dyn Executor,
        _port: u32,
        _protocol: Protocol,
    ) -> Result<()> {
        // Unreachable through the tasks, which ask `is_enforcing` first. Doing
        // nothing rather than erroring keeps that ordering a property of the
        // caller instead of a trap for the next one.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn an_enabled_policy_reports_enforcing() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        assert!(
            Semanage::new()
                .is_enforcing(&mock)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_disabled_policy_is_an_answer_rather_than_an_error() {
        // `selinuxenabled` exits 1 where SELinux is off, which is the state of
        // every container and of any host whose administrator disabled it.
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        let enforcing = Semanage::new()
            .is_enforcing(&mock)
            .expect("a disabled policy must not raise");

        assert!(!enforcing);
    }

    #[test]
    fn the_check_runs_without_privilege() {
        // Asked before the tool knows it will need any, so it must not prompt.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Semanage::new().is_enforcing(&mock).expect("runs");

        assert!(!mock.any_privileged());
    }

    #[test]
    fn labelling_a_new_port_adds_it() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Semanage::new()
            .allow_ssh_port(&mock, 2222, Protocol::Tcp)
            .expect("labelling must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["semanage port -a -t ssh_port_t -p tcp 2222"]
        );
        assert!(mock.any_privileged());
    }

    #[test]
    fn labelling_a_port_that_already_has_a_label_modifies_it() {
        // `-a` fails on a port that is already labelled, which is what
        // re-running the task looks like. The modify is what makes it
        // idempotent rather than an error the administrator has to interpret.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, "ValueError: Port tcp/2222 already defined"),
            Reply::ok(""),
        ]);

        Semanage::new()
            .allow_ssh_port(&mock, 2222, Protocol::Tcp)
            .expect("a second run must succeed");

        let lines = mock.recorded_lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[1].contains("-m"), "the retry must modify: {lines:?}");
    }

    #[test]
    fn a_label_that_can_neither_be_added_nor_modified_is_an_error() {
        // The case that must not pass quietly: the port stays unlabelled, so a
        // daemon told to use it will not start.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, "already defined"),
            Reply::failure(1, "SELinux policy is not managed"),
        ]);

        let result = Semanage::new().allow_ssh_port(&mock, 2222, Protocol::Tcp);

        assert!(result.is_err(), "an unlabelled port must be reported");
    }

    #[test]
    fn a_family_without_selinux_reports_nothing_enforcing() {
        // Without running anything: there is no tool to ask on a host that has
        // no policy at all.
        let mock = MockExecutor::new();

        let enforcing = NoSelinux::new()
            .is_enforcing(&mock)
            .expect("the query must succeed");

        assert!(!enforcing);
        assert!(
            mock.recorded_lines().is_empty(),
            "nothing should have been run: {:?}",
            mock.recorded_lines()
        );
    }
}
