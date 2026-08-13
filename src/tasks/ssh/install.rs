//! Installing the SSH server itself.
//!
//! The one task in this area that cannot cost the administrator their way in:
//! it adds a daemon rather than changing how an existing one admits people.

use crate::backend::{Backend, Capability};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Confirmation, Progress, Task, report, supported_everywhere};

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

    /// The package whose presence the row reports.
    ///
    /// Declared even though this task has no inverse, which is what the probe
    /// was originally built to choose between. A row with one verb still has
    /// something worth saying: reported as not detecting an SSH server that was
    /// already installed, because the tree asked the host nothing about it and
    /// the answer only arrived once the task had been run.
    fn subject(&self) -> Option<Capability> {
        Some(Capability::Ssh)
    }

    /// The row this task's success changes — its own.
    ///
    /// Missing until a guard went looking, because this was a lone task until
    /// it gained an inverse: a row with one verb never changed what it offered,
    /// so nothing re-measured it and nothing needed to. Pairing it made the
    /// omission matter without making it visible.
    fn affects(&self) -> &'static [&'static str] {
        &["ssh.install"]
    }

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

        // Which OpenSSH this host runs, reported whether it was just installed
        // or was already here — the second is the case that asked for it, since
        // "already installed" says nothing about *what* is installed, and the
        // version decides which hardening tier is safe: `ssh.harden-strict`
        // insists on algorithms an older client may never have learned.
        if let Some(version) = sshd_version(executor)? {
            report(progress, &Msg::TaskSshVersion { version });
        }

        // Installing and enabling a service cannot cost the administrator
        // their way in, so there is nothing worth offering to undo.
        Ok(Outcome::Done)
    }
}

/// Removes the OpenSSH server.
///
/// **The one task in this tool that can leave a machine unreachable with no way
/// back.** Every other lockout risk has a route out: `ssh.harden` can be
/// reverted inside its verification window, a firewall that closed the wrong
/// port can be undone from a console. This cannot. Removing the daemon over its
/// own connection ends the session mid-operation, and the mechanism that would
/// undo it dies with that session — reinstalling needs a package manager, which
/// needs a network path, which was the connection that just closed.
///
/// It was deliberately absent for exactly that reason, and is present now
/// because it was asked for. What that changes is what the tool refuses to do,
/// not what is true about the operation: the confirmation says so in the
/// strongest terms the interface has, and `docs/user-stories.md` records the
/// reversal rather than quietly dropping the old promise.
pub struct UninstallSsh;

impl Task for UninstallSsh {
    fn id(&self) -> &'static str {
        "ssh.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the SSH server"
    }

    fn description(&self) -> &'static str {
        "Removes the OpenSSH server. If you are connected over SSH, this ends \
         that connection and nothing can restore it: putting the package back \
         needs a way in, and this was it. Only run it from a console, or on a \
         host you can reach another way."
    }

    /// The strongest the interface has, and it understates this one: a lockout
    /// warning elsewhere means "you may lose the session". Here it means the
    /// machine may need the provider's console to be reachable again.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Ssh)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["ssh.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Ssh)
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
            Capability::Ssh,
            "the SSH server",
        )
    }
}

/// What OpenSSH this host runs, as its own daemon reports it.
///
/// `sshd -V` rather than `ssh -V`: Rocky's `openssh-server` package installs no
/// client at all, so asking the client answers `command not found` on a host
/// with a perfectly good daemon — measured on `rockylinux:9`.
///
/// Read from **stderr**, which is where all three implementations print it
/// while leaving stdout empty and exiting 0 — measured on `debian:13`,
/// `alpine:3.23` and `rockylinux:9`. This project has already paid for that
/// once: two helpers in the container suite read `ssh -V` from stdout, so the
/// two versions a scenario existed to compare were always blank.
///
/// A version that cannot be read is `None` rather than an error. This is a line
/// of narration at the end of a task that has already installed and started the
/// daemon; failing there would report a failure over work that succeeded.
fn sshd_version(executor: &dyn Executor) -> Result<Option<String>> {
    let command = Command::new("sshd").arg("-V");

    let output = match executor.run(&command) {
        Ok(output) => output,
        // An absent binary is not a failure of this task: the package installed
        // and the unit is running, and the daemon may simply not be on `PATH`
        // for an unprivileged lookup.
        Err(Error::ProgramNotFound { .. }) => return Ok(None),
        Err(other) => return Err(other),
    };

    // The banner is `OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 ...`. Only
    // the first field is kept: the rest names the distribution's patch level
    // and a second library's version, neither of which answers "which OpenSSH
    // is this".
    Ok(output
        .stderr
        .split_whitespace()
        .next()
        .filter(|version| !version.is_empty())
        .map(str::to_owned))
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

    /// Runs the task and returns what it said, rather than what it ran.
    fn narration_of(family: Family, replies: Vec<Reply>) -> String {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);
        let mut lines = Vec::new();

        InstallSsh
            .run(&mock, backend.as_ref(), &no_values(), &mut |line| {
                lines.push(line.text)
            })
            .expect("install must succeed");

        lines.join("\n")
    }

    #[test]
    fn the_version_running_here_is_reported() {
        // Asked for because "already installed" says nothing about *what* is
        // installed, and the version decides which hardening tier is safe:
        // `ssh.harden-strict` insists on algorithms an older client may never
        // have learned.
        let said = narration_of(
            Family::Debian,
            vec![
                Reply::ok("install ok installed"), // already installed
                Reply::ok(""),                     // enable --now
                Reply::ok("active"),
                Reply::ok("enabled"),
                // `sshd -V` prints to stderr and leaves stdout empty.
                Reply::failure(
                    0,
                    "OpenSSH_10.0p2 Debian-7+deb13u4, OpenSSL 3.5.6 7 Apr 2026",
                ),
            ],
        );

        assert!(
            said.contains("OpenSSH_10.0p2"),
            "the version must be reported: {said}"
        );
        // The distribution's patch level and OpenSSL's version answer a
        // different question, and a line carrying all three is one nobody reads.
        assert!(
            !said.contains("OpenSSL"),
            "only the OpenSSH field belongs on that line: {said}"
        );
    }

    #[test]
    fn the_version_is_read_from_stderr_where_sshd_prints_it() {
        // The defect this is written against, which this project has already
        // paid for once: two helpers in the container suite read `ssh -V` from
        // stdout, so the two versions a scenario existed to compare were always
        // blank. Measured on debian:13, alpine:3.23 and rockylinux:9 — all
        // three print to stderr, leave stdout empty, and exit 0.
        let said = narration_of(
            Family::Debian,
            vec![
                Reply::ok("install ok installed"),
                Reply::ok(""),
                Reply::ok("active"),
                Reply::ok("enabled"),
                // Everything on stdout, nothing on stderr: a reader looking at
                // the wrong stream would find this and report it.
                Reply::ok("OpenSSH_9.9p1, OpenSSL 3.5.5"),
            ],
        );

        assert!(
            !said.contains("OpenSSH_9.9p1"),
            "stdout is not where sshd prints its version: {said}"
        );
    }

    #[test]
    fn an_unreadable_version_is_left_out_rather_than_failing_the_task() {
        // A line of narration at the end of a task that has already installed
        // and started the daemon. Failing there would report a failure over
        // work that succeeded.
        let said = narration_of(
            Family::Debian,
            vec![
                Reply::ok("install ok installed"),
                Reply::ok(""),
                Reply::ok("active"),
                Reply::ok("enabled"),
                Reply::NotFound, // no `sshd` on PATH for this lookup
            ],
        );

        assert!(
            said.contains("ssh.service"),
            "the rest of the report must survive: {said}"
        );
        assert!(
            !said.contains("running"),
            "and must not claim a version it could not read: {said}"
        );
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
