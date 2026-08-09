//! Installing the SSH server itself.
//!
//! The one task in this area that cannot cost the administrator their way in:
//! it adds a daemon rather than changing how an existing one admits people.

use crate::backend::{Backend, Capability};
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Task, report, supported_everywhere};

/// Installs the OpenSSH server and enables it at boot.
pub struct InstallSsh;

impl Task for InstallSsh {
    fn id(&self) -> &'static str {
        "ssh.install"
    }

    fn title(&self) -> &'static str {
        "Install and enable the SSH server"
    }

    fn description(&self) -> &'static str {
        "Installs the OpenSSH server package and enables its service so it \
         starts at boot."
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // The task asks for a capability; the backend knows the names.
        let package = backend.package_for(Capability::Ssh);
        let service = backend.service_for(Capability::Ssh);

        if backend.packages().is_installed(executor, package)? {
            report(
                progress,
                &Msg::TaskAlreadyInstalled {
                    what: package.to_owned(),
                },
            );
        } else {
            report(
                progress,
                &Msg::TaskInstalling {
                    what: package.to_owned(),
                },
            );
            backend.packages().install(executor, package)?;
        }

        report(
            progress,
            &Msg::TaskEnabling {
                unit: service.to_owned(),
            },
        );
        backend.services().enable_and_start(executor, service)?;

        let state = backend.services().state(executor, service)?;
        report(
            progress,
            &Msg::TaskUnitState {
                unit: service.to_owned(),
                active: state.active,
                enabled: state.enabled,
            },
        );

        // Installing and enabling a service cannot cost the administrator
        // their way in, so there is nothing worth offering to undo.
        Ok(Outcome::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::ssh::fixtures::no_values;

    /// Runs the task against a mock, returning the commands it issued.
    fn run_install(family: Family, replies: Vec<Reply>) -> Vec<String> {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);

        InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect("install must succeed");

        mock.recorded_lines()
    }

    #[test]
    fn uses_debian_names_on_debian() {
        // First reply: package not installed, so an install follows.
        let commands = run_install(Family::Debian, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("apt-get install -y openssh-server")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now ssh.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn uses_arch_names_on_arch() {
        let commands = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("pacman -S") && c.contains("openssh")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now sshd.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn the_same_task_produces_different_commands_per_family() {
        // The core claim of the design: identical task code, distro-correct
        // commands, with the package and the unit diverging independently.
        let debian = run_install(Family::Debian, vec![Reply::failure(1, "")]);
        let arch = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert_ne!(debian, arch);
    }

    #[test]
    fn skips_installation_when_the_package_is_present() {
        // First reply reports the package as installed.
        let commands = run_install(Family::Debian, vec![Reply::ok("install ok installed")]);

        assert!(
            !commands.iter().any(|c| c.contains("apt-get install")),
            "an installed package must not be reinstalled: {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.contains("systemctl enable")),
            "the service must still be enabled: {commands:?}"
        );
    }

    #[test]
    fn a_failing_install_propagates() {
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""),
            Reply::failure(100, "E: Unable to locate package"),
        ]);
        let backend = for_family(Family::Debian);

        let err = InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |_| {})
            .expect_err("a failing install must surface");

        assert!(
            matches!(err, crate::error::Error::CommandFailed { code: 100, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn reports_progress_to_the_caller() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |line| {
                lines.push(line.text)
            })
            .expect("install must succeed");

        assert!(!lines.is_empty(), "the task must report what it is doing");
    }

    #[test]
    fn supports_both_families() {
        assert!(InstallSsh.supports(Family::Debian));
        assert!(InstallSsh.supports(Family::Arch));
    }
}
