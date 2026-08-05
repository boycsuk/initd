//! Per-family backends.
//!
//! A backend bundles the capability implementations for one distribution
//! family *and* translates logical names into real ones. Adding a distribution
//! means adding one module here — never editing a task.

pub mod alpine;
pub mod arch;
pub mod busybox_accounts;
pub mod debian;
pub mod firewalld;
pub mod nftables;
pub mod openrc;
pub mod procfs_sysctl;
pub mod release_installer;
pub mod rhel;
pub mod shadow_accounts;
pub mod systemd;
pub mod systemd_user;
pub mod unix_accounts;
pub mod unix_files;
pub mod wg_tools;

use crate::distro::Family;
use crate::domain::{
    AccountReader, AccountWriter, BinaryInstaller, FileEditor, FirewallManager, PackageManager,
    ServiceManager, SysctlManager, UserServiceManager, WireguardTools,
};
use crate::error::Result;
use crate::exec::Executor;

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
    /// The nftables front-end, which the firewall drives.
    Nftables,
    /// The fish shell.
    Fish,
    /// The Zellij multiplexer.
    Zellij,
    /// The mise version manager.
    Mise,
    /// The Rust toolchain.
    Rust,
    /// The fail2ban log-parsing banner.
    Fail2ban,
    /// The CrowdSec reputation-network banner.
    Crowdsec,
    /// Debian's unattended-upgrades.
    UnattendedUpgrades,
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
    ///
    /// Empty when the distribution has no package for it, which
    /// [`Backend::has_package_for`] is the readable way to ask.
    fn package_for(&self, capability: Capability) -> &'static str;

    /// Whether this distribution packages a capability at all.
    ///
    /// Zellij is the case: Arch packages it and no Debian or Ubuntu suite does,
    /// so one family installs from its repository and the other from a verified
    /// release. A task asks this rather than asking which distribution it is on.
    fn has_package_for(&self, capability: Capability) -> bool {
        !self.package_for(capability).is_empty()
    }

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

    /// The inbound filtering front-ends this family may present, in the order
    /// they should be tried.
    ///
    /// A list rather than one implementation, because which front-end holds a
    /// host's ruleset is a property of the host and not of the family. RHEL
    /// installs and runs firewalld by default, and an administrator is free to
    /// remove it and drive `nft` directly; both are ordinary states of the same
    /// distribution.
    ///
    /// They are alternatives and never layers. nftables evaluates every chain
    /// registered on a hook, and while `accept` passes a packet to the next
    /// chain, `drop` takes effect at once — so this tool's own table with a drop
    /// policy would override whatever firewalld admits, and a port opened with
    /// `firewall-cmd` would report success and stay closed. [`firewall_for`]
    /// picks exactly one.
    ///
    /// `ufw` is deliberately absent for the same reason it always was: it wraps
    /// whichever backend is installed, so driving both it and `nft` on one host
    /// is how a rule becomes invisible to the tool that did not write it.
    fn firewalls(&self) -> &[&dyn FirewallManager];

    /// Kernel parameters.
    fn sysctl(&self) -> &dyn SysctlManager;

    /// WireGuard key material and interface state.
    fn wireguard(&self) -> &dyn WireguardTools;

    /// Binaries installed from a verified release rather than from a package.
    ///
    /// The gap this covers is a different installation *mechanism*, not a
    /// different package name: Zellij is `pacman -S zellij` on Arch and has no
    /// package at all in any Debian or Ubuntu suite.
    fn binaries(&self) -> &dyn BinaryInstaller;

    /// Services belonging to one account rather than to the system.
    ///
    /// Separate from [`Backend::services`] because the two managers cannot see
    /// each other: a rootless engine runs under the account's own manager, and
    /// the system one has no view of it.
    fn user_services(&self) -> &dyn UserServiceManager;
}

/// Resolves which filtering front-end holds this host's ruleset.
///
/// Asks each candidate the family offers, in order, and returns the first that
/// reports itself present. The question is put to the host rather than answered
/// from the family because both answers are ordinary states of the same
/// distribution: a RHEL server runs firewalld out of the box, and one where the
/// administrator removed it drives `nft` directly.
///
/// Returns `None` when no candidate is available, which the caller reports
/// rather than working around — a firewall task on a host with no front-end has
/// nothing to drive, and picking one anyway would mean issuing commands to a
/// program that is not installed.
pub fn firewall_for<'a>(
    backend: &'a dyn Backend,
    executor: &dyn Executor,
) -> Result<Option<&'a dyn FirewallManager>> {
    for firewall in backend.firewalls() {
        if firewall.is_available(executor)? {
            return Ok(Some(*firewall));
        }
    }

    Ok(None)
}

/// Builds the backend for a detected family.
pub fn for_family(family: Family) -> Box<dyn Backend> {
    match family {
        Family::Debian => Box::new(debian::DebianBackend::new()),
        Family::Arch => Box::new(arch::ArchBackend::new()),
        Family::Alpine => Box::new(alpine::AlpineBackend::new()),
        Family::Rhel => Box::new(rhel::RhelBackend::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn each_family_resolves_to_its_own_backend() {
        // Iterating `ALL` rather than naming families: the mistake this guards
        // against is a dispatch arm pointing at the wrong backend, and a
        // hand-written list is one a new family is added without. Alpine went
        // untested here for exactly that reason.
        for &family in Family::ALL {
            assert_eq!(for_family(family).family(), family);
        }
    }

    #[test]
    fn rhel_prefers_firewalld_over_driving_nft_itself() {
        // The order is what keeps the two from being layered. A stock RHEL host
        // runs firewalld, and a table of this tool's own with a drop policy
        // would override it — leaving `firewall-cmd` reporting success on a
        // port that stays closed.
        let backend = for_family(Family::Rhel);
        let mock = MockExecutor::with_replies([Reply::ok("running")]);

        let firewall = firewall_for(backend.as_ref(), &mock)
            .expect("resolution must succeed")
            .expect("a running firewalld must be chosen");

        assert_eq!(firewall.name(), "firewalld");
    }

    #[test]
    fn rhel_falls_back_to_nftables_where_firewalld_is_not_running() {
        // An ordinary state of the same distribution, not a broken one: an
        // administrator is free to remove firewalld and drive `nft` directly.
        let mock = MockExecutor::with_replies([
            Reply::failure(252, "not running"),
            Reply::ok("nftables v1.0.9"),
        ]);
        let backend = for_family(Family::Rhel);

        let firewall = firewall_for(backend.as_ref(), &mock)
            .expect("resolution must succeed")
            .expect("nftables must answer where firewalld does not");

        assert_eq!(firewall.name(), "nftables");
    }

    #[test]
    fn a_host_with_no_front_end_resolves_to_none() {
        // Reported rather than worked around: picking one anyway would mean
        // issuing commands to a program that is not installed.
        let mock = MockExecutor::with_replies([
            Reply::failure(252, "not running"),
            Reply::failure(127, "nft: command not found"),
        ]);
        let backend = for_family(Family::Rhel);

        let firewall = firewall_for(backend.as_ref(), &mock).expect("resolution must succeed");

        assert!(firewall.is_none());
    }

    #[test]
    fn every_family_offers_at_least_one_front_end() {
        // A family offering none would make every firewall task unreachable
        // there, which is a gap `firewalls()` can express and nothing else
        // would catch.
        for &family in Family::ALL {
            assert!(
                !for_family(family).firewalls().is_empty(),
                "{family} offers no filtering front-end"
            );
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
        for &family in Family::ALL {
            let path = for_family(family).path_for(Capability::Ssh);

            assert!(
                path.starts_with('/'),
                "{family} resolved a non-absolute config path: {path:?}"
            );
        }
    }
}
