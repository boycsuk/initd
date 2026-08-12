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
use super::rpm_packages;
use super::rpm_repositories::RpmRepositories;
use super::semanage::Semanage;
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
    Repository, RepositoryManager, SelinuxManager, ServiceManager, SysctlManager,
    UserServiceManager, WireguardTools,
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

/// The rootless Docker extras, from Docker's own repository.
///
/// Red Hat ships Podman and packages no Docker at all, so unlike every other
/// name here this one is not in a repository the host already has — see
/// [`Backend::repository_for`], which is how the task learns it must register
/// one first. The name matches Debian's because it is the same upstream
/// packaging: `docker-ce` carries the daemon and this carries the rootless
/// setup script, which is the part the task actually runs.
const DOCKER_ROOTLESS_PACKAGE: &str = "docker-ce-rootless-extras";

/// Where Docker serves packages for Red Hat Enterprise Linux itself.
const DOCKER_REPO_RHEL: &str = "https://download.docker.com/linux/rhel";

/// Where it serves the rebuilds — Rocky, AlmaLinux, CentOS Stream.
///
/// Not interchangeable with the path above: Docker builds one set of packages
/// for the rebuilds and another for Red Hat's own, and pointing a host at the
/// wrong one yields a repository whose `$releasever` resolves to nothing it
/// carries.
const DOCKER_REPO_CENTOS: &str = "https://download.docker.com/linux/centos";

/// Where each path serves its signing key.
///
/// Two URLs and one key: both were fetched and hash identically, which is why a
/// single fingerprint below covers either. The URL follows whichever repository
/// this host uses rather than deciding anything.
const DOCKER_KEY_RHEL: &str = "https://download.docker.com/linux/rhel/gpg";
const DOCKER_KEY_CENTOS: &str = "https://download.docker.com/linux/centos/gpg";

/// The fingerprint of the key Docker signs its RPMs with.
///
/// Published on `docs.docker.com` and on `keys.openpgp.org` and
/// `keyserver.ubuntu.com` — three hosts with different operators, none of them
/// the one serving the key. That is what makes this worth compiling in: an
/// attacker who can replace the key on the CDN cannot also replace this value,
/// so the comparison has something independent to fail against.
///
/// Note it is *not* the fingerprint in Docker's Debian documentation. The
/// `.deb` and `.rpm` archives are signed by different keys with different UIDs,
/// and using the Debian one here would refuse every legitimate key.
const DOCKER_RPM_FINGERPRINT: &str = "060A61C51B558A7F742B77AAC52FEB6B621E9F35";

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

/// Git, in AppStream rather than BaseOS.
const GIT_PACKAGE: &str = "git";

/// The GitHub CLI is in no Red Hat repository.
///
/// Absent from BaseOS, AppStream and Extras alike — measured against Rocky 9's
/// package listings, where `Extras` has no `g/` directory at all. The one
/// family of the five that packages it nowhere.
///
/// EPEL carries `gh` 2.97.0, and that is declined for the reason fail2ban and
/// CrowdSec are: EPEL is a third-party repository, and this project reaches for
/// one only when the alternative is nothing. Here the alternative is better
/// than the package — GitHub publishes per-architecture tarballs with a
/// checksums file, so the release installer answers with an artefact this build
/// verified rather than one a repository vouches for.
///
/// **GitHub's own RPM repository was considered and declined**, and the reason
/// is timing rather than principle. Its signing key was rotated: the
/// certificate this project would have pinned
/// (`2C6106201985B60E6C7AC87323F3D4EA75716059`) **expires 2026-09-05**, and its
/// replacement (`7F38BBB59D064DBCB3D84D725612B36462313325`) appears on
/// `keyserver.ubuntu.com` and *not* on `keys.openpgp.org` — and that keyserver
/// accepts unverified uploads, so its copy corroborates nothing. A fingerprint
/// with no independent publication is a value this build would be trusting the
/// serving host to have told it, which is the whole thing
/// [`crate::domain::repositories`] exists to refuse.
const GITHUB_CLI_PACKAGE: &str = "";

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
    selinux: Semanage,
    repositories: RpmRepositories,
    /// Which of Docker's per-distribution paths serves this host.
    ///
    /// The one thing in this backend that varies within the family rather than
    /// between families.
    docker_repo_path: &'static str,
    /// Where that path serves its signing key.
    docker_key_path: &'static str,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
}

impl RhelBackend {
    /// Builds a backend for a named distribution in this family.
    ///
    /// The `ID` decides one thing and only one: which of Docker's per-
    /// distribution repositories serves this host. Red Hat's own is
    /// `linux/rhel`; the rebuilds are served by `linux/centos`, which Docker
    /// documents and which is not interchangeable — a `$releasever` that the
    /// wrong path does not carry yields a repository with no packages in it.
    pub fn for_distribution(id: &str) -> Self {
        let (repo, key) = match id.to_ascii_lowercase().as_str() {
            "rhel" => (DOCKER_REPO_RHEL, DOCKER_KEY_RHEL),
            // Rocky, AlmaLinux, CentOS Stream and anything else reaching this
            // family through `ID_LIKE`. Docker builds one set of packages for
            // the rebuilds and serves them from here.
            _ => (DOCKER_REPO_CENTOS, DOCKER_KEY_CENTOS),
        };

        Self {
            docker_repo_path: repo,
            docker_key_path: key,
            ..Self::new()
        }
    }

    pub const fn new() -> Self {
        Self {
            // The rebuilds' paths are the default because they are the common
            // case: `for_distribution` narrows to Red Hat's own when the `ID`
            // says so.
            docker_repo_path: DOCKER_REPO_CENTOS,
            docker_key_path: DOCKER_KEY_CENTOS,
            packages: DnfPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
            accounts: UnixAccounts::new(),
            account_writer: ShadowAccounts::new(),
            sysctl: ProcfsSysctl::new(),
            selinux: Semanage::new(),
            repositories: RpmRepositories::new(),
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

    /// The one family that cannot purge.
    ///
    /// rpm does not track configuration as separately removable, so a file the
    /// administrator edited survives removal as `.rpmsave` whatever is asked of
    /// it. Answering false is what stops the interface offering a choice with
    /// one real outcome.
    fn has_purge_for(&self) -> bool {
        false
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
            // kernel and `nft` only speaks to it. The `nftables.service` RHEL
            // ships restores a saved ruleset at boot; it is not what a rule is
            // applied through.
            Capability::Nftables => "",
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

    fn repositories(&self) -> Option<&dyn RepositoryManager> {
        Some(&self.repositories)
    }

    fn repository_for(&self, capability: Capability) -> Option<Repository> {
        match capability {
            // The one capability Red Hat's repositories do not carry and whose
            // upstream can nonetheless be verified: Docker publishes the
            // fingerprint of its RPM signing key on its own documentation and
            // on two keyservers, so the key that arrives can be checked against
            // a value this build did not learn from the same host.
            Capability::DockerRootless => Some(Repository {
                name: "docker-ce",
                base_url: self.docker_repo_path,
                // Served beside the packages it signs, on whichever path this
                // host uses. Both paths serve the same key — the fingerprint
                // below was read from `linux/rhel` and matches what Docker
                // documents for every RPM distribution — so this follows the
                // repository rather than deciding which key is expected.
                key_url: self.docker_key_path,
                fingerprint: DOCKER_RPM_FINGERPRINT,
                // dnf expands `$releasever` from the running system, so the
                // release never has to reach this layer. APT has no equivalent
                // and Debian's entry carries a codename for that reason.
                suite: None,
            }),
            _ => None,
        }
    }

    fn selinux(&self) -> &dyn SelinuxManager {
        // The one family that has one. Whether it is enforcing is still asked
        // of the host: RHEL ships it enabled, administrators disable it, and a
        // container reports it disabled whatever the image.
        &self.selinux
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
        // Shared with SUSE: the question is about rpm's database rather than
        // about dnf, and both families were answering it with the same command
        // under the same reasoning, written out twice.
        rpm_packages::is_installed(executor, package)
    }

    fn remove(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `dnf remove` takes the dependencies the package pulled in and nothing
        // else needs. Unlike apt and pacman there is no flag to decline that,
        // so the note the other three carry — "no cascade" — cannot be made
        // here, and Alpine's `apk del` cannot make it either.
        let command = Command::new("dnf")
            .args(["remove", "-y", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn purge(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // The same command as `remove`, because rpm has no purge: it does not
        // track configuration as separately removable the way dpkg's conffiles
        // are, and a file the administrator edited is left behind as
        // `.rpmsave` whatever is asked of it.
        //
        // Aliasing the two would normally be a family answering a question it
        // was never asked. It is not one here, because the question is never
        // put: `has_purge_for` reports false on this family, so the field
        // offering the choice is not drawn and nothing reaches this method
        // asking for a purge. It is implemented rather than left to panic
        // because a trait method that cannot be called is still a method, and
        // `unreachable!()` in a tool that runs as root is a promise about
        // callers rather than about code.
        self.remove(executor, package)
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
    fn purging_is_removing_here_and_the_family_says_so() {
        // The two are the same command because rpm has no purge. That is only
        // defensible because the choice is never offered: if `has_purge_for`
        // ever answered true here, an operator would pick "purge", get a
        // removal, and be told nothing. The two assertions belong together for
        // that reason — either alone permits the combination that lies.
        let removed = MockExecutor::new();
        DnfPackages.remove(&removed, "fail2ban").expect("removes");

        let purged = MockExecutor::new();
        DnfPackages.purge(&purged, "fail2ban").expect("purges");

        assert_eq!(removed.recorded_lines(), ["dnf remove -y fail2ban"]);
        assert_eq!(purged.recorded_lines(), removed.recorded_lines());
        assert!(
            !RhelBackend::new().has_purge_for(),
            "a family whose purge is a removal must not offer the choice"
        );
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
            Capability::UnattendedUpgrades,
        ] {
            assert!(
                !backend.has_package_for(capability),
                "{capability:?} must report no package on RHEL"
            );
        }
    }

    #[test]
    fn docker_is_the_only_capability_needing_a_repository_registered() {
        // A package name alone would be a lie here: `docker-ce-rootless-extras`
        // is in no repository a stock RHEL host has, so the task must know to
        // register one before asking for it.
        let backend = RhelBackend::new();

        assert!(backend.repository_for(Capability::DockerRootless).is_some());

        for capability in [
            Capability::Ssh,
            Capability::Wireguard,
            Capability::Nftables,
            Capability::Caddy,
            Capability::Crowdsec,
        ] {
            assert!(
                backend.repository_for(capability).is_none(),
                "{capability:?} must not carry a repository"
            );
        }
    }

    #[test]
    fn the_rebuilds_are_served_by_a_different_path_than_red_hats_own() {
        // Docker builds one set of packages for RHEL and another for the
        // rebuilds. Pointing a host at the wrong one yields a repository whose
        // `$releasever` resolves to nothing it carries — an empty repository
        // rather than an error, which reads as a broken install.
        let rhel = RhelBackend::for_distribution("rhel")
            .repository_for(Capability::DockerRootless)
            .expect("docker must resolve");
        let rocky = RhelBackend::for_distribution("rocky")
            .repository_for(Capability::DockerRootless)
            .expect("docker must resolve");

        assert!(rhel.base_url.ends_with("/rhel"), "{}", rhel.base_url);
        assert!(rocky.base_url.ends_with("/centos"), "{}", rocky.base_url);
    }

    #[test]
    fn every_rebuild_expects_the_same_signing_key() {
        // Both paths serve the same key — fetched and found to hash
        // identically — so a fingerprint that varied by distribution would be
        // inventing a difference that does not exist.
        let fingerprints: Vec<&str> = ["rhel", "rocky", "almalinux", "centos"]
            .into_iter()
            .map(|id| {
                RhelBackend::for_distribution(id)
                    .repository_for(Capability::DockerRootless)
                    .expect("docker must resolve")
                    .fingerprint
            })
            .collect();

        assert!(
            fingerprints.windows(2).all(|pair| pair[0] == pair[1]),
            "{fingerprints:?}"
        );
        assert_eq!(fingerprints[0], DOCKER_RPM_FINGERPRINT);
    }

    #[test]
    fn the_expected_key_is_dockers_rpm_key_and_not_its_deb_one() {
        // Written out rather than compared against the constant, which would
        // only prove it equals itself. The value is the whole security
        // property: it is what an attacker who replaced the key on the CDN
        // cannot also replace, so a typo in it would not fail anywhere else —
        // it would refuse every legitimate key, or accept a wrong one.
        //
        // The literal below is Docker's *RPM* key, from docs.docker.com and
        // confirmed against two keyservers. Docker's Debian documentation
        // publishes a different fingerprint for a different key, and using
        // that one here is the mistake this pins against.
        assert_eq!(
            DOCKER_RPM_FINGERPRINT,
            "060A61C51B558A7F742B77AAC52FEB6B621E9F35"
        );
        assert_ne!(
            DOCKER_RPM_FINGERPRINT, "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            "that is the .deb key; the RPMs are signed by another"
        );
    }

    #[test]
    fn a_family_with_no_third_party_repository_offers_no_manager() {
        // The default: nothing this tool installs on Arch or Alpine comes from
        // outside the distribution, so neither can register anything at all.
        //
        // Debian was in this list and no longer is. It packages `docker.io`,
        // which carries no rootless setup script, so the engine comes from
        // Docker's own repository exactly as it does on RHEL — and while this
        // test asserted otherwise, the Debian backend named a package no
        // Debian suite serves and the install failed on a host with no
        // repository to fetch it from.
        for family in [Family::Arch, Family::Alpine] {
            assert!(
                super::super::for_family(family).repositories().is_none(),
                "{family} must not be able to register repositories"
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
