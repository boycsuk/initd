//! Per-family backends.
//!
//! A backend bundles the capability implementations for one distribution
//! family *and* translates logical names into real ones. Adding a distribution
//! means adding one module here — never editing a task.

pub mod arch;
pub mod debian;
pub mod nftables;
pub mod procfs_sysctl;
pub mod shadow_accounts;
pub mod systemd;
pub mod systemd_user;
pub mod unix_accounts;
pub mod unix_files;
pub mod wg_tools;

use crate::distro::Family;
use crate::domain::{
    AccountReader, AccountWriter, FileEditor, FirewallManager, PackageManager, ServiceManager,
    SysctlManager, UserServiceManager, WireguardTools,
};

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
    /// WireGuard, whose tools and kernel module ship together on both families
    /// implemented today but under different package names.
    Wireguard,
    /// The rootless Docker engine.
    DockerRootless,
    /// The Caddy web server.
    Caddy,
}

/// Everything a task needs from the distribution it runs on.
pub trait Backend {
    /// The family this backend serves.
    ///
    /// Nothing in the interface asks for it today — the header names the
    /// distribution, not its family — but it is what proves a backend was
    /// resolved for the family that was detected, which is the one mistake
    /// this indirection could silently make.
    #[cfg_attr(not(test), allow(dead_code))]
    fn family(&self) -> Family;

    /// The package providing a capability on this distribution.
    fn package_for(&self, capability: Capability) -> &'static str;

    /// The service unit providing a capability on this distribution.
    fn service_for(&self, capability: Capability) -> &'static str;

    /// The configuration file a capability reads on this distribution.
    ///
    /// Both families implemented today agree on `/etc/ssh/sshd_config`, so
    /// this method looks redundant. It is not: the agreement is a fact about
    /// these two distributions rather than a property of the capability, and a
    /// path held in a task is a path no backend can correct. Package and unit
    /// names already resolve here; paths were the one system-specific name
    /// still living above this layer.
    fn path_for(&self, capability: Capability) -> &'static str;

    /// The group that grants administrative rights on this distribution.
    ///
    /// `sudo` on Debian, `wheel` on Arch and RHEL. The divergence matters more
    /// than most: `usermod -aG sudo` on Arch exits zero and grants nothing,
    /// leaving an account that looks provisioned and cannot escalate.
    fn admin_group(&self) -> &'static str;

    fn packages(&self) -> &dyn PackageManager;
    fn services(&self) -> &dyn ServiceManager;
    fn files(&self) -> &dyn FileEditor;
    fn accounts(&self) -> &dyn AccountReader;
    fn account_writer(&self) -> &dyn AccountWriter;

    /// Inbound packet filtering.
    ///
    /// One implementation today. `ufw` is deliberately absent: it wraps
    /// whichever backend is installed, so driving both it and `nft` on one host
    /// is how a rule becomes invisible to the tool that did not write it.
    fn firewall(&self) -> &dyn FirewallManager;

    /// Kernel parameters.
    fn sysctl(&self) -> &dyn SysctlManager;

    /// WireGuard key material and interface state.
    fn wireguard(&self) -> &dyn WireguardTools;

    /// Services belonging to one account rather than to the system.
    ///
    /// Separate from [`Backend::services`] because the two managers cannot see
    /// each other: a rootless engine runs under the account's own manager, and
    /// the system one has no view of it.
    fn user_services(&self) -> &dyn UserServiceManager;
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

    #[test]
    fn the_administrative_group_differs_by_family() {
        // The divergence that makes this a backend concern rather than a
        // constant in a task: asking for the wrong one costs nothing at the
        // time. `usermod -aG sudo` on Arch exits zero and grants nothing, so
        // the account looks provisioned right up until it needs to escalate.
        assert_eq!(for_family(Family::Debian).admin_group(), "sudo");
        assert_eq!(for_family(Family::Arch).admin_group(), "wheel");
    }

    #[test]
    fn every_family_resolves_a_config_path() {
        // The two families agree on this path today, so asserting the literal
        // would only restate the constant. What must hold is that the question
        // is answerable per family: a backend that returned an empty path
        // would have every file operation silently address the wrong file.
        for family in [Family::Debian, Family::Arch] {
            let path = for_family(family).path_for(Capability::Ssh);

            assert!(
                path.starts_with('/'),
                "{family} resolved a non-absolute config path: {path:?}"
            );
        }
    }
}
