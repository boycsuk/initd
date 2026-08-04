//! Alpine and derivatives.
//!
//! The family that proves the abstraction, because it diverges in more than
//! names: no systemd, no shadow suite, no GNU coreutils. Where Debian and Arch
//! differ over whether a unit is called `ssh` or `sshd`, Alpine differs over
//! whether there are units at all.
//!
//! Several capabilities are therefore genuinely absent rather than spelled
//! differently, and this backend answers with an empty name for them. That is
//! what makes `has_package_for` a question worth asking: a task that finds no
//! package here is offered the honest answer instead of being handed a name
//! `apk` would reject.

use super::busybox_accounts::{BusyboxAccountWriter, BusyboxAccounts};
use super::nftables::Nftables;
use super::openrc::OpenRcServices;
use super::procfs_sysctl::ProcfsSysctl;
use super::release_installer::ReleaseInstaller;
use super::systemd_user::SystemdUserServices;
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

/// The OpenSSH server package on Alpine.
const SSH_PACKAGE: &str = "openssh";

/// The OpenSSH init script on Alpine.
///
/// A script name rather than a unit: OpenRC has no units, so what the backend
/// resolves here is the file in `/etc/init.d`.
const SSH_SERVICE: &str = "sshd";

/// Where the OpenSSH server reads its configuration on Alpine.
const SSH_CONFIG: &str = "/etc/ssh/sshd_config";

/// The group granting doas on Alpine.
///
/// `wheel`, as on Arch — Alpine ships `doas` rather than `sudo` by default,
/// and its default configuration grants the wheel group.
const ADMIN_GROUP: &str = "wheel";

/// The WireGuard tools on Alpine.
const WIREGUARD_PACKAGE: &str = "wireguard-tools";

/// The WireGuard init script on Alpine.
///
/// `wg-quick` here takes the interface as an argument to the script rather
/// than as a systemd template instance, so the name carries no `@`.
const WIREGUARD_SERVICE: &str = "wg-quick";

/// Where WireGuard keeps its configuration.
const WIREGUARD_CONFIG: &str = "/etc/wireguard";

/// The nftables package on Alpine.
const NFTABLES_PACKAGE: &str = "nftables";

/// The fish shell package on Alpine.
const FISH_PACKAGE: &str = "fish";

/// Zellij on Alpine, which packages it in `community`.
const ZELLIJ_PACKAGE: &str = "zellij";

/// The fail2ban package on Alpine.
const FAIL2BAN_PACKAGE: &str = "fail2ban";

/// The fail2ban init script on Alpine.
const FAIL2BAN_SERVICE: &str = "fail2ban";

/// The Caddy package on Alpine.
const CADDY_PACKAGE: &str = "caddy";

/// The Caddy init script on Alpine.
const CADDY_SERVICE: &str = "caddy";

/// Where Caddy reads its configuration on Alpine.
const CADDY_CONFIG: &str = "/etc/caddy/Caddyfile";

/// Backend for the Alpine family.
pub struct AlpineBackend {
    packages: ApkPackages,
    services: OpenRcServices,
    files: UnixFiles,
    accounts: BusyboxAccounts,
    account_writer: BusyboxAccountWriter,
    firewall: Nftables,
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
}

impl AlpineBackend {
    pub const fn new() -> Self {
        Self {
            packages: ApkPackages,
            services: OpenRcServices::new(),
            files: UnixFiles::new(),
            accounts: BusyboxAccounts::new(),
            account_writer: BusyboxAccountWriter::new(),
            firewall: Nftables::new(),
            sysctl: ProcfsSysctl::new(),
            wireguard: WgTools::new(),
            // Alpine has no per-user service manager at all. The
            // implementation is carried so the trait is satisfiable; the
            // rootless-container task declares the families it supports and
            // Alpine is not among them, so nothing reaches it.
            user_services: SystemdUserServices::new(),
            binaries: ReleaseInstaller::new(),
        }
    }
}

impl Backend for AlpineBackend {
    fn family(&self) -> Family {
        Family::Alpine
    }

    fn package_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_PACKAGE,
            Capability::Wireguard => WIREGUARD_PACKAGE,
            Capability::Nftables => NFTABLES_PACKAGE,
            Capability::Fish => FISH_PACKAGE,
            Capability::Zellij => ZELLIJ_PACKAGE,
            Capability::Fail2ban => FAIL2BAN_PACKAGE,
            Capability::Caddy => CADDY_PACKAGE,
            // Genuinely absent rather than named differently. Alpine has no
            // rootless Docker extras, no mise, no rustup and no unattended
            // upgrades — an empty name is the honest answer, and the tasks
            // that need them declare Alpine unsupported.
            Capability::DockerRootless
            | Capability::Mise
            | Capability::Rust
            | Capability::Crowdsec
            | Capability::UnattendedUpgrades => "",
        }
    }

    fn service_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_SERVICE,
            Capability::Wireguard => WIREGUARD_SERVICE,
            Capability::Fail2ban => FAIL2BAN_SERVICE,
            Capability::Caddy => CADDY_SERVICE,
            Capability::Nftables
            | Capability::DockerRootless
            | Capability::Fish
            | Capability::Zellij
            | Capability::Mise
            | Capability::Rust
            | Capability::Crowdsec
            | Capability::UnattendedUpgrades => "",
        }
    }

    fn path_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_CONFIG,
            Capability::Wireguard => WIREGUARD_CONFIG,
            Capability::Caddy => CADDY_CONFIG,
            Capability::Fish => "/etc/fish/config.fish",
            Capability::Fail2ban => "/etc/fail2ban/jail.d",
            Capability::Nftables
            | Capability::DockerRootless
            | Capability::Zellij
            | Capability::Mise
            | Capability::Rust
            | Capability::Crowdsec
            | Capability::UnattendedUpgrades => "",
        }
    }

    fn admin_group(&self) -> &'static str {
        ADMIN_GROUP
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

/// Package management through `apk`.
#[derive(Debug, Clone, Copy)]
pub struct ApkPackages;

impl PackageManager for ApkPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `--no-cache` rather than a separate `apk update`: it fetches the
        // index for this call and keeps none of it, which is what Alpine's own
        // documentation recommends and what keeps a container image small.
        let command = Command::new("apk")
            .args(["add", "--no-cache", package])
            .privileged();

        super::systemd::run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // `apk info -e` prints the package when installed and exits non-zero
        // otherwise, so the exit code alone answers the question.
        let command = Command::new("apk").args(["info", "-e", package]);

        Ok(executor.run(&command)?.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn installing_fetches_the_index_without_keeping_it() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ApkPackages
            .install(&mock, "openssh")
            .expect("install must succeed");

        assert_eq!(mock.recorded_lines(), ["apk add --no-cache openssh"]);
        assert!(mock.any_privileged());
    }

    #[test]
    fn a_missing_package_is_reported_by_its_exit_code() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        assert!(
            !ApkPackages
                .is_installed(&mock, "openssh")
                .expect("query must succeed")
        );
    }

    #[test]
    fn the_ssh_service_is_a_script_name_rather_than_a_unit() {
        // OpenRC has no units, so what the backend resolves is the file in
        // /etc/init.d — a third spelling beside `ssh.service` and
        // `sshd.service`.
        let backend = AlpineBackend::new();

        assert_eq!(backend.service_for(Capability::Ssh), "sshd");
        assert!(
            !backend.service_for(Capability::Ssh).contains(".service"),
            "OpenRC names no units"
        );
    }

    #[test]
    fn capabilities_alpine_lacks_answer_with_no_package() {
        // The honest answer, and what `has_package_for` exists to ask. A name
        // invented here would be one `apk` rejects at install time, long after
        // the task decided it could proceed.
        let backend = AlpineBackend::new();

        for absent in [
            Capability::DockerRootless,
            Capability::Mise,
            Capability::Rust,
            Capability::UnattendedUpgrades,
        ] {
            assert!(
                !backend.has_package_for(absent),
                "{absent:?} must report as unpackaged"
            );
        }
    }

    #[test]
    fn the_wireguard_script_takes_no_systemd_template_suffix() {
        // `wg-quick@wg0.service` is a systemd instance; OpenRC's script takes
        // the interface differently, so the trailing `@` must not be there.
        assert!(
            !AlpineBackend::new()
                .service_for(Capability::Wireguard)
                .contains('@'),
            "OpenRC has no template units"
        );
    }
}
