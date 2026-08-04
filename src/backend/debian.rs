//! Debian, Ubuntu and derivatives.
//!
//! Package names and unit names live here and nowhere else. Note that Debian
//! also ships `ssh.socket` alongside `ssh.service`, which matters when
//! changing the port — see the SSH port task.

use super::nftables::Nftables;
use super::procfs_sysctl::ProcfsSysctl;
use super::release_installer::ReleaseInstaller;
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
    ServiceManager, SysctlManager, UserServiceManager, WireguardTools,
};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The OpenSSH server package on Debian.
const SSH_PACKAGE: &str = "openssh-server";

/// The SSH unit on Debian — note it is `ssh`, not `sshd` as on Arch.
const SSH_SERVICE: &str = "ssh.service";

/// Where the OpenSSH server reads its configuration on Debian.
const SSH_CONFIG: &str = "/etc/ssh/sshd_config";

/// The WireGuard tools on Debian.
///
/// `wireguard-tools` rather than `wireguard`: the latter is a metapackage that
/// also pulls the DKMS module, which is dead weight on any kernel since 5.6
/// where WireGuard is built in.
const WIREGUARD_PACKAGE: &str = "wireguard-tools";

/// The unit template that brings an interface up.
///
/// Instantiated per interface — `wg-quick@wg0.service` — which is why the
/// interface name is appended by the task rather than baked in here.
const WIREGUARD_SERVICE: &str = "wg-quick@";

/// Where WireGuard keeps its configuration.
const WIREGUARD_CONFIG: &str = "/etc/wireguard";

/// The rootless Docker extras on Debian.
///
/// `docker-ce-rootless-extras` rather than `docker.io`: the distribution
/// package does not carry `dockerd-rootless-setuptool.sh` at all, so the
/// rootless install has nothing to run.
const DOCKER_ROOTLESS_PACKAGE: &str = "docker-ce-rootless-extras";

/// The rootless engine's user unit.
const DOCKER_USER_UNIT: &str = "docker.service";

/// Where the rootless engine keeps its daemon configuration, under the
/// account's own home rather than in /etc.
const DOCKER_CONFIG: &str = ".config/docker/daemon.json";

/// The Caddy package on Debian.
const CADDY_PACKAGE: &str = "caddy";

/// The Caddy unit on Debian.
const CADDY_SERVICE: &str = "caddy.service";

/// Where Caddy reads its configuration on Debian.
const CADDY_CONFIG: &str = "/etc/caddy/Caddyfile";

/// The fish shell package on Debian.
const FISH_PACKAGE: &str = "fish";

/// Zellij on Debian: there is none.
///
/// Verified against the package databases of every current Debian and Ubuntu
/// suite. Blog posts claiming `apt install zellij` works are wrong, which is
/// why the empty string here is a deliberate answer rather than an omission —
/// it routes the task to the verified-release installer.
const ZELLIJ_PACKAGE: &str = "";

/// The mise package on Debian.
const MISE_PACKAGE: &str = "mise";

/// The Rust toolchain installer on Debian.
///
/// `rustup` rather than `rustc`: the distribution package pins whatever version
/// the release froze, and a toolchain that cannot be updated is not one a build
/// can rely on.
const RUST_PACKAGE: &str = "rustup";

/// The fail2ban package on Debian.
const FAIL2BAN_PACKAGE: &str = "fail2ban";

/// The fail2ban unit on Debian.
const FAIL2BAN_SERVICE: &str = "fail2ban.service";

/// The CrowdSec package on Debian.
const CROWDSEC_PACKAGE: &str = "crowdsec";

/// The CrowdSec unit on Debian.
const CROWDSEC_SERVICE: &str = "crowdsec.service";

/// Debian's unattended upgrades.
const UNATTENDED_PACKAGE: &str = "unattended-upgrades";

/// The group granting sudo on Debian — `wheel` on Arch and RHEL.
const ADMIN_GROUP: &str = "sudo";

/// Backend for the Debian family.
pub struct DebianBackend {
    packages: AptPackages,
    services: SystemdServices,
    files: UnixFiles,
    accounts: UnixAccounts,
    account_writer: ShadowAccounts,
    firewall: Nftables,
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
}

impl DebianBackend {
    pub const fn new() -> Self {
        Self {
            packages: AptPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
            accounts: UnixAccounts::new(),
            account_writer: ShadowAccounts::new(),
            firewall: Nftables::new(),
            sysctl: ProcfsSysctl::new(),
            wireguard: WgTools::new(),
            user_services: SystemdUserServices::new(),
            binaries: ReleaseInstaller::new(),
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
            Capability::Wireguard => WIREGUARD_PACKAGE,
            Capability::DockerRootless => DOCKER_ROOTLESS_PACKAGE,
            Capability::Caddy => CADDY_PACKAGE,
            Capability::Fish => FISH_PACKAGE,
            Capability::Zellij => ZELLIJ_PACKAGE,
            Capability::Mise => MISE_PACKAGE,
            Capability::Rust => RUST_PACKAGE,
            Capability::Fail2ban => FAIL2BAN_PACKAGE,
            Capability::Crowdsec => CROWDSEC_PACKAGE,
            Capability::UnattendedUpgrades => UNATTENDED_PACKAGE,
        }
    }

    fn service_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_SERVICE,
            Capability::Wireguard => WIREGUARD_SERVICE,
            // The rootless engine is a user unit, addressed through
            // `user_services` rather than by name here.
            Capability::DockerRootless => DOCKER_USER_UNIT,
            Capability::Caddy => CADDY_SERVICE,
            // None of these is a service.
            Capability::Fish | Capability::Zellij | Capability::Mise | Capability::Rust => "",
            Capability::Fail2ban => FAIL2BAN_SERVICE,
            Capability::Crowdsec => CROWDSEC_SERVICE,
            // Driven by a timer the package ships, not by a unit of its own.
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
            Capability::Fail2ban => "/etc/fail2ban/jail.d",
            Capability::Crowdsec => "/etc/crowdsec",
            Capability::UnattendedUpgrades => "/etc/apt/apt.conf.d",
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

    fn firewall(&self) -> &dyn FirewallManager {
        &self.firewall
    }

    fn sysctl(&self) -> &dyn SysctlManager {
        &self.sysctl
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
