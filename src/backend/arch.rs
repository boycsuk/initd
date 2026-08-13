//! Arch and derivatives.
//!
//! Package and unit names live here and nowhere else. Both differ from Debian,
//! and they differ independently: the package drops the `-server` suffix while
//! the unit gains a `d`.

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
    AccountReader, AccountWriter, BinaryInstaller, FileEditor, PackageManager, ServiceManager,
    SysctlManager, UserServiceManager, WireguardTools,
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

/// Git, in `extra` rather than `core`.
const GIT_PACKAGE: &str = "git";

/// The GitHub CLI on Arch: `github-cli`, not `gh`.
///
/// The name splits on family rather than on packaging system — `gh` on Debian,
/// Ubuntu and openSUSE, `github-cli` here and on Alpine — which is exactly the
/// substitution this indirection exists for. `gh` is the *binary* everywhere;
/// only the package differs.
const GITHUB_CLI_PACKAGE: &str = "github-cli";

/// The nftables front-end on Arch.
const NFTABLES_PACKAGE: &str = "nftables";

/// What owns `sysctl` here.
///
/// Measured on `archlinux:latest`: `pacman -Qo` answers `procps-ng`, not
/// Debian's `procps`.
const SYSCTL_PACKAGE: &str = "procps-ng";

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
            Capability::Sysctl => SYSCTL_PACKAGE,
            Capability::Fail2ban => FAIL2BAN_PACKAGE,
            Capability::Crowdsec => CROWDSEC_PACKAGE,
            Capability::Git => GIT_PACKAGE,
            Capability::GithubCli => GITHUB_CLI_PACKAGE,
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
            Capability::Sysctl => "",
            Capability::Fail2ban => FAIL2BAN_SERVICE,
            Capability::Crowdsec => CROWDSEC_SERVICE,
            // Neither is a service: both are commands somebody runs.
            Capability::Git | Capability::GithubCli => "",
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
            Capability::Sysctl => "",
            Capability::Fail2ban => "/etc/fail2ban/jail.d",
            Capability::Crowdsec => "/etc/crowdsec",
            // Git's system-wide file, which `git config --system` writes.
            // The per-account one is `~/.gitconfig`, which depends on whose
            // account is being configured and so cannot be named here.
            Capability::Git => "/etc/gitconfig",
            // Configured per account under `$XDG_CONFIG_HOME` or
            // `~/.config`, so there is no system path to name.
            Capability::GithubCli => "",
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

/// Package management through `pacman`.
#[derive(Debug, Clone, Copy)]
pub struct PacmanPackages;

impl PackageManager for PacmanPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `--needed` skips reinstalling an up-to-date package, making the
        // operation idempotent; `--noconfirm` avoids a prompt that would hang
        // the TUI.
        //
        // `-Sy` rather than `-S`, because pacman resolves a name against a
        // local database it never refreshes on its own: on a host whose
        // databases have not been synced it warns `database file for 'core'
        // does not exist (use '-Sy' to download)` and then fails with `target
        // not found`, which reads as this backend having the package name
        // wrong. Measured on `archlinux:latest`, where the databases ship
        // empty; a sync with them already fresh costs 274 ms.
        //
        // The known objection is that `-Sy` without `-u` is a partial upgrade,
        // which Arch documents as unsupported: a package pulled from a newer
        // database can link against a library the installed system has not
        // updated to. This accepts that narrowly rather than dismissing it. The
        // alternative is `-Syu`, and a tool asked to install `nftables` must
        // not decide on its own to upgrade the kernel and every library on a
        // production server — a full upgrade is an operation with its own
        // reboot, its own timing, and its own confirmation, none of which this
        // task has. Between refusing to install at all and a sync scoped to one
        // package, the sync is the smaller risk, and the packages this backend
        // names are base-repository ones that rarely move independently.
        let command = Command::new("pacman")
            .args(["-Sy", "--needed", "--noconfirm", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // `pacman -Q` exits non-zero when the package is not installed, so the
        // exit code alone answers the question.
        let command = Command::new("pacman").args(["-Q", package]);

        Ok(executor.run(&command)?.success())
    }

    fn remove(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `-R` alone: it removes this package and refuses if something else
        // depends on it, which is the refusal an operator wants rather than a
        // cascade they did not ask for. `--noconfirm` avoids a prompt that
        // would hang a TUI that has handed the terminal over.
        let command = Command::new("pacman")
            .args(["-R", "--noconfirm", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn purge(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `-n` adds the configuration files pacman itself saved as `.pacsave`;
        // `-s` is deliberately absent, though it is what most guides pair with
        // it. `-s` removes dependencies now left orphaned, which reaches
        // outside the package the operator named and is a different operation.
        // Purging means "this package and its configuration", not "this
        // package and whatever else stopped being needed".
        let command = Command::new("pacman")
            .args(["-Rn", "--noconfirm", package])
            .privileged();

        run_checked(executor, &command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn the_databases_are_synced_in_the_same_operation() {
        // Measured on `archlinux:latest`, whose image ships its databases
        // empty: `pacman -S --needed --noconfirm procps-ng` warns `database
        // file for 'core' does not exist (use '-Sy' to download)` and then
        // fails with `target not found` over a name that is perfectly correct.
        //
        // One command rather than the two Debian needs, because pacman syncs
        // and installs together — and `-Syu` is deliberately not used: a task
        // asked to install one package must not upgrade the whole system on a
        // production server.
        let mock = MockExecutor::new();

        PacmanPackages.install(&mock, "procps-ng").expect("runs");

        let commands = mock.recorded_lines();

        assert_eq!(commands.len(), 1, "one operation: {commands:?}");
        assert!(
            commands[0].starts_with("pacman -Sy "),
            "the databases must be synced with it: {commands:?}"
        );
        assert!(
            !commands[0].contains("-Syu"),
            "and a full system upgrade is not this task's to make: {commands:?}"
        );
    }

    #[test]
    fn installs_the_arch_ssh_package_name() {
        let mock = MockExecutor::new();

        PacmanPackages
            .install(&mock, ArchBackend::new().package_for(Capability::Ssh))
            .expect("install must succeed");

        // `-Sy`, not `-S`: pacman never refreshes its databases on its own, so
        // on a host whose databases have not been synced the install fails with
        // `target not found` over a package name that is perfectly correct.
        // One command rather than two, since pacman syncs and installs in the
        // same operation.
        assert_eq!(
            mock.recorded_lines(),
            ["pacman -Sy --needed --noconfirm openssh"]
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
    fn removing_keeps_the_configuration_and_purging_does_not() {
        let removed = MockExecutor::new();
        PacmanPackages
            .remove(&removed, "fail2ban")
            .expect("removes");

        let purged = MockExecutor::new();
        PacmanPackages.purge(&purged, "fail2ban").expect("purges");

        assert_eq!(removed.recorded_lines(), ["pacman -R --noconfirm fail2ban"]);
        assert_eq!(purged.recorded_lines(), ["pacman -Rn --noconfirm fail2ban"]);
        assert!(removed.any_privileged());
        assert!(purged.any_privileged());
    }

    #[test]
    fn removal_never_cascades_into_orphaned_dependencies() {
        // `-s` is what most guides pair with `-Rn`, and it reaches outside the
        // package the operator named. Pinned rather than trusted to the reading
        // of a flag string: `-Rns` and `-Rn` differ by one character.
        let mock = MockExecutor::new();

        PacmanPackages.remove(&mock, "caddy").expect("removes");
        PacmanPackages.purge(&mock, "caddy").expect("purges");

        for line in mock.recorded_lines() {
            assert!(!line.contains("-Rs"), "removal must not cascade: {line}");
            assert!(!line.contains("-Rns"), "removal must not cascade: {line}");
        }
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
