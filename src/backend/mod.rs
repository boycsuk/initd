//! Per-family backends.
//!
//! A backend bundles the capability implementations for one distribution
//! family *and* translates logical names into real ones. Adding a distribution
//! means adding one module here — never editing a task.

pub mod arch;
pub mod debian;
pub mod systemd;
pub mod unix_files;

use crate::distro::Family;
use crate::domain::{FileEditor, PackageManager, ServiceManager};

/// A capability that tasks request by name, without knowing what it is called
/// on the running system.
///
/// This indirection is the whole point of the design: `Ssh` is `openssh-server`
/// plus `ssh.service` on Debian, and `openssh` plus `sshd.service` on Arch, and
/// the two diverge independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// The OpenSSH server.
    Ssh,
}

/// Everything a task needs from the distribution it runs on.
pub trait Backend {
    /// The family this backend serves.
    fn family(&self) -> Family;

    /// The package providing a capability on this distribution.
    fn package_for(&self, capability: Capability) -> &'static str;

    /// The service unit providing a capability on this distribution.
    fn service_for(&self, capability: Capability) -> &'static str;

    fn packages(&self) -> &dyn PackageManager;
    fn services(&self) -> &dyn ServiceManager;
    fn files(&self) -> &dyn FileEditor;
}

/// Builds the backend for a detected family.
pub fn for_family(family: Family) -> Box<dyn Backend> {
    match family {
        Family::Debian => Box::new(debian::DebianBackend::new()),
        Family::Arch => Box::new(arch::ArchBackend::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_family_resolves_to_its_own_backend() {
        for family in [Family::Debian, Family::Arch] {
            assert_eq!(for_family(family).family(), family);
        }
    }

    #[test]
    fn ssh_package_and_unit_diverge_independently_across_families() {
        // The reason two families are implemented: neither name matches, and
        // they differ for unrelated reasons. A single family would prove
        // nothing about the abstraction.
        let debian = for_family(Family::Debian);
        let arch = for_family(Family::Arch);

        assert_eq!(debian.package_for(Capability::Ssh), "openssh-server");
        assert_eq!(arch.package_for(Capability::Ssh), "openssh");

        assert_eq!(debian.service_for(Capability::Ssh), "ssh.service");
        assert_eq!(arch.service_for(Capability::Ssh), "sshd.service");
    }
}
