//! RHEL and derivatives: Rocky, AlmaLinux, CentOS Stream, Fedora.
//!
//! Structurally the closest family to Arch — systemd, `wheel`, the shadow
//! suite, glibc — so almost every shared implementation applies unchanged. What
//! diverges is where software comes from: Red Hat's repositories are narrower
//! than Debian's or Arch's, and several capabilities the other families install
//! from a package have no package here at all.
//!
//! That gap is answered by mechanism rather than by name. Where a project
//! publishes a verifiable release, the empty package name routes the task to
//! [`ReleaseInstaller`], exactly as Debian already does for Zellij. Where it
//! does not, the capability is declared absent rather than pointed at a
//! third-party repository the tool cannot vouch for — EPEL is the case, and the
//! reasoning is recorded on each constant below.

use super::firewalld::Firewalld;
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

/// The OpenSSH server package, in BaseOS.
///
/// Same name as Debian's and the unit is Arch's — the two divergences the other
/// families are built around land on opposite sides here.
const SSH_PACKAGE: &str = "openssh-server";

/// The SSH unit — `sshd`, as on Arch.
const SSH_SERVICE: &str = "sshd.service";

/// Where the OpenSSH server reads its configuration.
///
/// RHEL 9 and later open this file with `Include /etc/ssh/sshd_config.d/*.conf`
/// and sshd honours the *first* occurrence of a directive, so a shipped drop-in
/// is read before anything appended below it. What that costs was measured
/// against a real daemon rather than reasoned about, because `sshd -t` validates
/// either way and the failure is silent:
///
/// - `50-redhat.conf` names only `SyslogFacility`, `UsePAM`, GSSAPI, X11
///   forwarding, `PrintMotd`, and — through a nested include of
///   `/etc/crypto-policies/back-ends/opensshserver.config` — the ciphers, key
///   exchanges and MACs.
/// - Everything it does not name takes effect from the main file.
///   `PermitRootLogin`, `PasswordAuthentication`, `Port` and `AllowUsers` were
///   each written there and read back from `sshd -T` as the daemon's effective
///   value.
///
/// So this path is right for every task except `ssh.harden-strict`, whose whole
/// subject is the three directives the crypto policies own.
const SSH_CONFIG: &str = "/etc/ssh/sshd_config";

/// The WireGuard tools, in AppStream rather than EPEL.
///
/// Contrary to how it is usually assumed to work: EPEL carried this for 7 and 8
/// only, before it entered the base repositories. Red Hat documents it as a
/// Technology Preview, which speaks to their support commitment rather than to
/// availability — the package installs without enabling any third-party
/// repository.
const WIREGUARD_PACKAGE: &str = "wireguard-tools";

/// The unit template that brings an interface up.
const WIREGUARD_SERVICE: &str = "wg-quick@";

/// Where WireGuard keeps its configuration.
const WIREGUARD_CONFIG: &str = "/etc/wireguard";

/// Rootless Docker has no package in any Red Hat repository.
///
/// Red Hat ships Podman instead and does not package Docker at all. Docker Inc
/// publishes a repository covering RHEL 8, 9 and 10, and it is verifiable —
/// the RPM signing key's fingerprint is published on `docs.docker.com` and on
/// two independent keyservers, so it can be pinned and checked rather than
/// trusted on arrival. Registering a repository is a capability this tool does
/// not have yet, so the task declares itself unsupported until it does.
const DOCKER_ROOTLESS_PACKAGE: &str = "";

/// The rootless engine's user unit, once a mechanism exists to install it.
const DOCKER_USER_UNIT: &str = "docker.service";

/// Where the rootless engine keeps its daemon configuration.
const DOCKER_CONFIG: &str = ".config/docker/daemon.json";

/// Caddy has no package outside third-party repositories.
///
/// EPEL carries it, and the project itself documents a COPR as official — but
/// neither can be verified: the COPR's signing key lives on the same host that
/// serves the packages, is absent from every keyserver, and `dnf` prints that
/// its contents are "not held to any quality or security level". The empty name
/// routes this to the release installer instead, which is the mechanism the
/// project already uses where a package is missing.
const CADDY_PACKAGE: &str = "";

/// The Caddy unit, once installed.
const CADDY_SERVICE: &str = "caddy.service";

/// Where Caddy reads its configuration.
const CADDY_CONFIG: &str = "/etc/caddy/Caddyfile";

/// fish is packaged only in EPEL.
///
/// Unlike Caddy and Zellij there is no verifiable alternative: fish publishes
/// no static binaries, only source, and its own documentation points RHEL users
/// at the openSUSE Build Service rather than at EPEL. With no official route
/// this tool can verify, the capability is declared absent.
const FISH_PACKAGE: &str = "";

/// Zellij is unpackaged everywhere in the Red Hat ecosystem.
///
/// Not merely missing from the base repositories: it returns no results across
/// Fedora and every EPEL branch. It publishes musl static releases with
/// per-file checksums, and being musl the artefact is the same one Debian
/// already installs — so this resolves to the release installer without the
/// table needing a Red Hat entry of its own.
const ZELLIJ_PACKAGE: &str = "";

/// mise is likewise unpackaged, and likewise published as a musl release.
///
/// It does offer an RPM repository of its own, which this declines: its
/// `baseurl` carries neither `$basearch` nor an EL version, so one flat path
/// serves every architecture and release. The musl tarball is the same artefact
/// Debian installs and is checksummed in a published manifest.
const MISE_PACKAGE: &str = "";

/// The Rust toolchain has no `rustup` package outside Fedora.
///
/// AppStream carries `rust-toolset`, which is a compiler and Cargo rather than
/// a toolchain manager — a different capability under a similar name, which is
/// the substitution this indirection exists to prevent. `rustup-init` is
/// published with a checksum per architecture and would resolve here, but only
/// from the archive path that pins a version: the current-release path serves a
/// new binary on every release, so a digest compiled into this build would
/// break itself. Until a version is pinned, the capability is absent.
const RUST_PACKAGE: &str = "";

/// The nftables front-end, in BaseOS.
///
/// Packaged rather than preinstalled — a Rocky 9 base image ships neither `nft`
/// nor `firewall-cmd`, which is why the enable task installs before it filters.
/// firewalld is the front-end Red Hat supports and it owns its own nftables
/// tables, so the two are resolved as alternatives rather than driven together:
/// that is the hazard [`Nftables`] already documents for `ufw`.
const NFTABLES_PACKAGE: &str = "nftables";

/// fail2ban is packaged only in EPEL.
///
/// It has never been in a base repository, in any release. Being Python there
/// is no static binary to verify either, and its own documentation offers no
/// RHEL-specific route. `sshguard` is no escape: it is EPEL-only too, and RHEL
/// ships no log-scanning tool of its own.
const FAIL2BAN_PACKAGE: &str = "";

/// The fail2ban unit, were it installed.
const FAIL2BAN_SERVICE: &str = "fail2ban.service";

/// CrowdSec publishes no verifiable artefact.
///
/// Its releases carry no checksum files, and its documented installation is a
/// script piped into a shell that registers a repository — the pattern this
/// project rejects by design in its own installer. Declared absent rather than
/// installed by a mechanism the tool refuses to use elsewhere.
const CROWDSEC_PACKAGE: &str = "";

/// The CrowdSec unit, were it installed.
const CROWDSEC_SERVICE: &str = "crowdsec.service";

/// Unattended upgrades are packaged, but under a name that moved.
///
/// RHEL 9 ships `dnf-automatic`; RHEL 10 renamed it `dnf5-plugin-automatic` and
/// replaced its four timers with one. The backend resolves a family rather than
/// a release, so it cannot name both — and naming either would be wrong on the
/// other half of the family. Declared absent until the version reaches this
/// layer.
const UNATTENDED_PACKAGE: &str = "";

/// The group granting sudo — `wheel`, as on Arch.
const ADMIN_GROUP: &str = "wheel";

/// Backend for the RHEL family.
pub struct RhelBackend {
    packages: DnfPackages,
    services: SystemdServices,
    files: UnixFiles,
    accounts: UnixAccounts,
    account_writer: ShadowAccounts,
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
}

impl RhelBackend {
    pub const fn new() -> Self {
        Self {
            packages: DnfPackages,
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

impl Backend for RhelBackend {
    fn family(&self) -> Family {
        Family::Rhel
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
            // kernel and `nft` only speaks to it. The `nftables.service` RHEL
            // ships restores a saved ruleset at boot; it is not what a rule is
            // applied through.
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
        // The only family offering two, and the order matters: firewalld is
        // installed and running on a stock RHEL host, so it is what holds the
        // ruleset and must be asked first. nftables is the fallback for a host
        // where the administrator removed firewalld to drive `nft` directly —
        // an ordinary state of the same distribution, not a broken one.
        //
        // They are never both driven. A table of this tool's own with a drop
        // policy would override what firewalld admits, leaving `firewall-cmd`
        // reporting success on a port that stays closed.
        const FIREWALLS: &[&dyn FirewallManager] = &[&Firewalld::new(), &Nftables::new()];

        FIREWALLS
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

/// Package management through `dnf`.
#[derive(Debug, Clone, Copy)]
pub struct DnfPackages;

impl PackageManager for DnfPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `-y` answers the prompts that would otherwise hang the TUI, including
        // the one asking whether to trust a repository's signing key. The
        // operation is idempotent on its own: `dnf install` on an installed
        // package exits zero having done nothing.
        let command = Command::new("dnf")
            .args(["install", "-y", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // `rpm -q` rather than `dnf list installed`: it reads the local
        // database, so it neither touches the network nor depends on repository
        // metadata being cached, and its exit code answers for one package
        // without parsing. Red Hat also documents `dnf` reporting success for
        // an install that did not happen, which makes querying the database
        // afterwards the reliable answer rather than a redundant one.
        let command = Command::new("rpm").args(["-q", package]);

        Ok(executor.run(&command)?.success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn installs_the_rhel_ssh_package_name() {
        let mock = MockExecutor::new();

        DnfPackages
            .install(&mock, RhelBackend::new().package_for(Capability::Ssh))
            .expect("install must succeed");

        assert_eq!(mock.recorded_lines(), ["dnf install -y openssh-server"]);
        assert!(mock.any_privileged());
    }

    #[test]
    fn install_is_noninteractive() {
        let mock = MockExecutor::new();

        DnfPackages.install(&mock, "openssh-server").expect("runs");

        let args = mock.single_command().args;
        assert!(args.contains(&"-y".to_owned()), "must not prompt");
    }

    #[test]
    fn reports_an_installed_package() {
        let mock = MockExecutor::with_replies([Reply::ok("openssh-server-9.9p1-8.el10.x86_64")]);

        assert!(
            DnfPackages
                .is_installed(&mock, "openssh-server")
                .expect("query must succeed")
        );
    }

    #[test]
    fn reports_a_missing_package() {
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "package openssh-server is not installed",
        )]);

        assert!(
            !DnfPackages
                .is_installed(&mock, "openssh-server")
                .expect("query must succeed")
        );
    }

    #[test]
    fn the_installed_query_reads_the_local_database() {
        // `rpm -q` rather than `dnf list installed`, and unprivileged: reading
        // which packages are present needs no rights, and a query that escalated
        // would prompt for a password to answer a question.
        let mock = MockExecutor::with_replies([Reply::ok("openssh-server-9.9p1-8.el10.x86_64")]);

        DnfPackages
            .is_installed(&mock, "openssh-server")
            .expect("query must succeed");

        assert_eq!(mock.recorded_lines(), ["rpm -q openssh-server"]);
        assert!(!mock.any_privileged(), "a query must not escalate");
    }

    #[test]
    fn the_administrative_group_is_wheel_not_sudo() {
        // The divergence that costs nothing at the time it is got wrong:
        // `usermod -aG sudo` exits zero here and grants nothing, leaving an
        // account that looks provisioned and cannot escalate.
        assert_eq!(RhelBackend::new().admin_group(), "wheel");
    }

    #[test]
    fn ssh_takes_debians_package_name_and_archs_unit_name() {
        // Neither of the two divergences the other families are built around
        // lands the same way here, which is what makes this a third set of
        // names rather than a copy of either.
        let backend = RhelBackend::new();

        assert_eq!(backend.package_for(Capability::Ssh), "openssh-server");
        assert_eq!(backend.service_for(Capability::Ssh), "sshd.service");
    }

    #[test]
    fn capabilities_without_a_verifiable_source_report_no_package() {
        // The empty name is an answer, not an oversight: `has_package_for` is
        // how a task asks, and these are the capabilities Red Hat's own
        // repositories do not carry.
        let backend = RhelBackend::new();

        for capability in [
            Capability::Caddy,
            Capability::Fish,
            Capability::Zellij,
            Capability::Mise,
            Capability::Rust,
            Capability::Fail2ban,
            Capability::Crowdsec,
            Capability::DockerRootless,
            Capability::UnattendedUpgrades,
        ] {
            assert!(
                !backend.has_package_for(capability),
                "{capability:?} must report no package on RHEL"
            );
        }
    }

    #[test]
    fn the_capabilities_red_hat_does_ship_resolve_to_a_package() {
        // The other half: declaring everything absent would pass the test above
        // and leave a backend that installs nothing.
        let backend = RhelBackend::new();

        for capability in [Capability::Ssh, Capability::Wireguard, Capability::Nftables] {
            assert!(
                backend.has_package_for(capability),
                "{capability:?} is in a base repository and must resolve"
            );
        }
    }
}
