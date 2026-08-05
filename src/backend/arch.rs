//! Arch and derivatives.
//!
//! Package and unit names live here and nowhere else. Both differ from Debian,
//! and they differ independently: the package drops the `-server` suffix while
//! the unit gains a `d`.

use super::nftables::Nftables;
use super::procfs_sysctl::ProcfsSysctl;
use super::release_installer::ReleaseInstaller;
use super::semanage::NoSelinux;
use super::shadow_accounts::ShadowAccounts;
use super::systemd::{SystemdServices, run_checked};
use super::systemd_user::SystemdUserServices;
use super::unix_accounts::UnixAccounts;
use super::unix_files::UnixFiles;
use super::wg_tools::WgTools;
use super::{Backend, Capability};
use crate::distro::Family;
use crate::domain::{
    AccountReader, AccountWriter, BinaryInstaller, FileEditor, FirewallManager, PackageManager,
    SelinuxManager, ServiceManager, SysctlManager, UserServiceManager, WireguardTools,
};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The OpenSSH package on Arch — server and client ship together.
const SSH_PACKAGE: &str = "openssh";

/// The SSH unit on Arch — `sshd`, unlike Debian's `ssh`.
const SSH_SERVICE: &str = "sshd.service";

/// Where the OpenSSH server reads its configuration on Arch.
const SSH_CONFIG: &str = "/etc/ssh/sshd_config";

/// The WireGuard tools on Arch.
///
/// Same name as Debian's, which is coincidence rather than a rule: Arch never
/// shipped a `wireguard` metapackage at all, having only ever supported
/// kernels with the module built in.
const WIREGUARD_PACKAGE: &str = "wireguard-tools";

/// The unit template that brings an interface up.
const WIREGUARD_SERVICE: &str = "wg-quick@";

/// Where WireGuard keeps its configuration.
const WIREGUARD_CONFIG: &str = "/etc/wireguard";

/// The rootless Docker extras on Arch.
///
/// `docker` carries `dockerd-rootless-setuptool.sh` itself here — there is no
/// separate extras package, which is exactly the kind of divergence the
/// capability indirection exists for.
const DOCKER_ROOTLESS_PACKAGE: &str = "docker";

/// The rootless engine's user unit.
const DOCKER_USER_UNIT: &str = "docker.service";

/// Where the rootless engine keeps its daemon configuration.
const DOCKER_CONFIG: &str = ".config/docker/daemon.json";

/// The Caddy package on Arch.
const CADDY_PACKAGE: &str = "caddy";

/// The Caddy unit on Arch.
const CADDY_SERVICE: &str = "caddy.service";

/// Where Caddy reads its configuration on Arch.
///
/// `/etc/caddy/Caddyfile` on both families today, unlike the package that
/// provides the rootless engine.
const CADDY_CONFIG: &str = "/etc/caddy/Caddyfile";

/// The fish shell package on Arch.
const FISH_PACKAGE: &str = "fish";

/// Zellij on Arch, which packages it in `extra` — unlike Debian, which has no
/// package for it in any suite.
const ZELLIJ_PACKAGE: &str = "zellij";

/// The mise package on Arch.
const MISE_PACKAGE: &str = "mise";

/// The Rust toolchain installer on Arch.
const RUST_PACKAGE: &str = "rustup";

/// The nftables front-end on Arch.
const NFTABLES_PACKAGE: &str = "nftables";

/// The fail2ban package on Arch.
const FAIL2BAN_PACKAGE: &str = "fail2ban";

/// The fail2ban unit on Arch.
const FAIL2BAN_SERVICE: &str = "fail2ban.service";

/// The CrowdSec package on Arch.
const CROWDSEC_PACKAGE: &str = "crowdsec";

/// The CrowdSec unit on Arch.
const CROWDSEC_SERVICE: &str = "crowdsec.service";

/// Arch has no unattended-upgrades equivalent.
///
/// A rolling release upgrades everything or nothing, so applying updates
/// unattended means pulling whatever landed today — including changes that
/// need manual intervention. The task declares Debian only rather than
/// inventing a different operation under the same name.
const UNATTENDED_PACKAGE: &str = "";

/// The group granting sudo on Arch — `sudo` on Debian.
///
/// Asking for `sudo` here is the silent failure the capability exists to
/// prevent: the group is absent, `usermod -aG` still exits zero, and the
/// account ends up unable to escalate while appearing provisioned.
const ADMIN_GROUP: &str = "wheel";

/// Backend for the Arch family.
pub struct ArchBackend {
    packages: PacmanPackages,
    services: SystemdServices,
    files: UnixFiles,
    accounts: UnixAccounts,
    account_writer: ShadowAccounts,
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
}

impl ArchBackend {
    pub const fn new() -> Self {
        Self {
            packages: PacmanPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
            accounts: UnixAccounts::new(),
            account_writer: ShadowAccounts::new(),
            sysctl: ProcfsSysctl::new(),
            wireguard: WgTools::new(),
            user_services: SystemdUserServices::new(),
            binaries: ReleaseInstaller::new(),
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
            Capability::Wireguard => WIREGUARD_PACKAGE,
            Capability::DockerRootless => DOCKER_ROOTLESS_PACKAGE,
            Capability::Caddy => CADDY_PACKAGE,
            Capability::Fish => FISH_PACKAGE,
            Capability::Zellij => ZELLIJ_PACKAGE,
            Capability::Mise => MISE_PACKAGE,
            Capability::Rust => RUST_PACKAGE,
            Capability::Nftables => NFTABLES_PACKAGE,
            Capability::Fail2ban => FAIL2BAN_PACKAGE,
            Capability::Crowdsec => CROWDSEC_PACKAGE,
            Capability::UnattendedUpgrades => UNATTENDED_PACKAGE,
        }
    }

    fn service_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_SERVICE,
            Capability::Wireguard => WIREGUARD_SERVICE,
            Capability::DockerRootless => DOCKER_USER_UNIT,
            Capability::Caddy => CADDY_SERVICE,
            Capability::Fish | Capability::Zellij | Capability::Mise | Capability::Rust => "",
            // A front-end rather than a daemon: the ruleset lives in the
            // kernel and `nft` only speaks to it.
            Capability::Nftables => "",
            Capability::Fail2ban => FAIL2BAN_SERVICE,
            Capability::Crowdsec => CROWDSEC_SERVICE,
            Capability::UnattendedUpgrades => "",
        }
    }

    fn path_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_CONFIG,
            Capability::Wireguard => WIREGUARD_CONFIG,
            Capability::DockerRootless => DOCKER_CONFIG,
            Capability::Caddy => CADDY_CONFIG,
            Capability::Fish => "/etc/fish/config.fish",
            Capability::Zellij => "",
            Capability::Mise => "/etc/mise/config.toml",
            Capability::Rust => "",
            Capability::Nftables => "",
            Capability::Fail2ban => "/etc/fail2ban/jail.d",
            Capability::Crowdsec => "/etc/crowdsec",
            Capability::UnattendedUpgrades => "",
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

    fn admin_group(&self) -> &'static str {
        ADMIN_GROUP
    }

    fn accounts(&self) -> &dyn AccountReader {
        &self.accounts
    }

    fn account_writer(&self) -> &dyn AccountWriter {
        &self.account_writer
    }

    fn firewalls(&self) -> &[&dyn FirewallManager] {
        const FIREWALLS: &[&dyn FirewallManager] = &[&Nftables::new()];

        FIREWALLS
    }

    fn sysctl(&self) -> &dyn SysctlManager {
        &self.sysctl
    }

    fn selinux(&self) -> &dyn SelinuxManager {
        // Nothing enforces here, so the answer is a constant rather than a
        // question put to the host. Tasks still ask, which is what keeps the
        // check out of them.
        const SELINUX: &NoSelinux = &NoSelinux::new();

        SELINUX
    }

    fn wireguard(&self) -> &dyn WireguardTools {
        &self.wireguard
    }

    fn user_services(&self) -> &dyn UserServiceManager {
        &self.user_services
    }

    fn binaries(&self) -> &dyn BinaryInstaller {
        &self.binaries
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
