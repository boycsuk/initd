//! Arch and derivatives.
//!
//! Package and unit names live here and nowhere else. Both differ from Debian,
//! and they differ independently: the package drops the `-server` suffix while
//! the unit gains a `d`.

use super::systemd::{SystemdServices, run_checked};
use super::unix_files::UnixFiles;
use super::{Backend, Capability};
use crate::distro::Family;
use crate::domain::{FileEditor, PackageManager, ServiceManager};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The OpenSSH package on Arch — server and client ship together.
const SSH_PACKAGE: &str = "openssh";

/// The SSH unit on Arch — `sshd`, unlike Debian's `ssh`.
const SSH_SERVICE: &str = "sshd.service";

/// Backend for the Arch family.
pub struct ArchBackend {
    packages: PacmanPackages,
    services: SystemdServices,
    files: UnixFiles,
}

impl ArchBackend {
    pub const fn new() -> Self {
        Self {
            packages: PacmanPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
        }
    }
}

impl Backend for ArchBackend {
    fn family(&self) -> Family {
        Family::Arch
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

/// Package management through `pacman`.
#[derive(Debug, Clone, Copy)]
pub struct PacmanPackages;

impl PackageManager for PacmanPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `--needed` skips reinstalling an up-to-date package, making the
        // operation idempotent; `--noconfirm` avoids a prompt that would hang
        // the TUI.
        let command = Command::new("pacman")
            .args(["-S", "--needed", "--noconfirm", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // `pacman -Q` exits non-zero when the package is not installed, so the
        // exit code alone answers the question.
        let command = Command::new("pacman").args(["-Q", package]);

        Ok(executor.run(&command)?.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn installs_the_arch_ssh_package_name() {
        let mock = MockExecutor::new();

        PacmanPackages
            .install(&mock, ArchBackend::new().package_for(Capability::Ssh))
            .expect("install must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["pacman -S --needed --noconfirm openssh"]
        );
        assert!(mock.any_privileged());
    }

    #[test]
    fn install_is_idempotent_and_noninteractive() {
        let mock = MockExecutor::new();

        PacmanPackages.install(&mock, "openssh").expect("runs");

        let args = mock.single_command().args;
        assert!(args.contains(&"--needed".to_owned()), "must not reinstall");
        assert!(args.contains(&"--noconfirm".to_owned()), "must not prompt");
    }

    #[test]
    fn reports_an_installed_package() {
        let mock = MockExecutor::with_replies([Reply::ok("openssh 10.1p1-1")]);

        assert!(
            PacmanPackages
                .is_installed(&mock, "openssh")
                .expect("query must succeed")
        );
    }

    #[test]
    fn reports_a_missing_package() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "error: package not found")]);

        assert!(
            !PacmanPackages
                .is_installed(&mock, "openssh")
                .expect("query must succeed")
        );
    }
}
