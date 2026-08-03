//! Debian, Ubuntu and derivatives.
//!
//! Package names and unit names live here and nowhere else. Note that Debian
//! also ships `ssh.socket` alongside `ssh.service`, which matters when
//! changing the port — see the SSH port task.

use super::systemd::{SystemdServices, run_checked};
use super::unix_files::UnixFiles;
use super::{Backend, Capability};
use crate::distro::Family;
use crate::domain::{FileEditor, PackageManager, ServiceManager};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The OpenSSH server package on Debian.
const SSH_PACKAGE: &str = "openssh-server";

/// The SSH unit on Debian — note it is `ssh`, not `sshd` as on Arch.
const SSH_SERVICE: &str = "ssh.service";

/// Backend for the Debian family.
pub struct DebianBackend {
    packages: AptPackages,
    services: SystemdServices,
    files: UnixFiles,
}

impl DebianBackend {
    pub const fn new() -> Self {
        Self {
            packages: AptPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
        }
    }
}

impl Backend for DebianBackend {
    fn family(&self) -> Family {
        Family::Debian
    }

    fn package_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_PACKAGE,
        }
    }

    fn service_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_SERVICE,
        }
    }

    fn packages(&self) -> &dyn PackageManager {
        &self.packages
    }

    fn services(&self) -> &dyn ServiceManager {
        &self.services
    }

    fn files(&self) -> &dyn FileEditor {
        &self.files
    }
}

/// Package management through `apt-get`.
///
/// `apt-get` rather than `apt`, which warns that it has no stable CLI
/// interface for scripts.
#[derive(Debug, Clone, Copy)]
pub struct AptPackages;

impl PackageManager for AptPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // DEBIAN_FRONTEND is set through `env` rather than the executor so the
        // variable applies to this call only: an interactive debconf prompt
        // would hang a TUI that has handed the terminal over.
        let command = Command::new("env")
            .args([
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                package,
            ])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // `dpkg-query` exits non-zero for an unknown package, and prints the
        // status for a known one; only "install ok installed" means present,
        // since a removed-but-not-purged package still has an entry.
        let command = Command::new("dpkg-query").args(["-W", "-f=${Status}", package]);
        let output = executor.run(&command)?;

        Ok(output.success() && output.stdout.trim() == "install ok installed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn installs_the_debian_ssh_package_name() {
        let mock = MockExecutor::new();

        AptPackages
            .install(&mock, DebianBackend::new().package_for(Capability::Ssh))
            .expect("install must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["env DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server"]
        );
        assert!(mock.any_privileged());
    }

    #[test]
    fn install_runs_noninteractively() {
        // An interactive debconf prompt would hang the TUI.
        let mock = MockExecutor::new();

        AptPackages.install(&mock, "openssh-server").expect("runs");

        assert!(
            mock.single_command()
                .args
                .contains(&"DEBIAN_FRONTEND=noninteractive".to_owned())
        );
    }

    #[test]
    fn reports_an_installed_package() {
        let mock = MockExecutor::with_replies([Reply::ok("install ok installed")]);

        assert!(
            AptPackages
                .is_installed(&mock, "openssh-server")
                .expect("query must succeed")
        );
    }

    #[test]
    fn reports_a_missing_package() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "no packages found")]);

        assert!(
            !AptPackages
                .is_installed(&mock, "openssh-server")
                .expect("query must succeed")
        );
    }

    #[test]
    fn a_removed_but_unpurged_package_is_not_installed() {
        // dpkg keeps an entry for removed packages; only the full status line
        // means the package is actually present.
        let mock = MockExecutor::with_replies([Reply::ok("deinstall ok config-files")]);

        assert!(
            !AptPackages
                .is_installed(&mock, "openssh-server")
                .expect("query must succeed")
        );
    }
}
