//! Debian, Ubuntu and derivatives.
//!
//! Package names and unit names live here and nowhere else. Note that Debian
//! also ships `ssh.socket` alongside `ssh.service`, which matters when
//! changing the port — see the SSH port task.

use super::apt_periodic::AptPeriodic;
use super::apt_repositories::AptRepositories;
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
    AccountReader, AccountWriter, AutomaticUpdates, BinaryInstaller, FileEditor, PackageManager,
    Repository, RepositoryManager, ServiceManager, SysctlManager, UserServiceManager,
    WireguardTools,
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
/// rootless install has nothing to run. Verified by unpacking the `.deb`
/// rather than by reading documentation — it carries
/// `/usr/bin/dockerd-rootless-setuptool.sh`, `dockerd-rootless.sh` and
/// `rootlesskit`.
///
/// Like RHEL's, this name is *not* in a repository the host already has —
/// Debian packages `docker.io` and nothing named `docker-ce-*` in any suite —
/// so [`Backend::repository_for`] is what tells the task to register one
/// first. That was missing for as long as the name was here: `apt-get install`
/// reported the package as having "no installation candidate", which reads as
/// the name being wrong rather than as the repository being absent.
const DOCKER_ROOTLESS_PACKAGE: &str = "docker-ce-rootless-extras";

/// Where Docker serves packages for Debian.
///
/// Ubuntu is served from a sibling path and by the same key: the two archives
/// are byte-identical, so one fingerprint below covers both. Which path a host
/// uses follows its `ID`, since a derivative fetching Debian's suites would ask
/// for a codename that path does not serve.
const DOCKER_REPO_DEBIAN: &str = "https://download.docker.com/linux/debian";

/// Where it serves packages for Ubuntu and its derivatives.
const DOCKER_REPO_UBUNTU: &str = "https://download.docker.com/linux/ubuntu";

/// Where each path serves its signing key.
const DOCKER_KEY_DEBIAN: &str = "https://download.docker.com/linux/debian/gpg";
const DOCKER_KEY_UBUNTU: &str = "https://download.docker.com/linux/ubuntu/gpg";

/// The fingerprint of the key Docker signs its `.deb` packages with.
///
/// **Not** the RPM fingerprint in [`super::rhel`]. The two archives are signed
/// by different keys with different UIDs — `Docker Release (CE deb)` against
/// `Docker Release (CE rpm)` — and using either where the other belongs would
/// refuse every legitimate key.
///
/// Docker's own installation pages no longer print this value; they only fetch
/// the key. It was therefore taken from `keys.openpgp.org` and
/// `keyserver.ubuntu.com` — two hosts with different operators, neither of them
/// the one serving the key — and in both cases derived from the raw packet
/// bytes rather than read off a rendered page. That independence is what makes
/// compiling it in worth anything: whoever can replace the key on the CDN
/// cannot also replace this constant.
///
/// This is the *primary* key. Docker signs its `InRelease` with a subkey
/// (`D3306A018370199E527AE7997EA0A9C3F273FCD8`), so a check comparing a
/// signature's issuer against this value would fail on a correct key. The
/// verification asks `gpg` for the first `fpr`, which is the primary's, and
/// lets it walk the binding signature.
const DOCKER_DEB_FINGERPRINT: &str = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88";

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

/// mise on Debian: there is none, for the reason Zellij records above.
///
/// Verified against the package databases of every current Debian and Ubuntu
/// suite: bookworm, trixie, forky and sid, and jammy through resolute. The
/// searches return matches and every one of them is a substring — `misery`,
/// and a long tail of `*-pro-mise-*` JavaScript packages. There is no `mise`.
///
/// Upstream documents `extrepo enable mise`, which is better provenance than
/// most third-party repositories: the fingerprint lives in Debian's own
/// `extrepo-data`, on Debian infrastructure, rather than on the host serving
/// the packages. It is still a repository added to the machine for one binary,
/// where the musl release is one artefact this build already carries a digest
/// for — so this resolves to the release installer, as RHEL and openSUSE do.
const MISE_PACKAGE: &str = "";

/// The Rust toolchain installer, on the suites that carry it.
///
/// `rustup` rather than `rustc`: the distribution package pins whatever version
/// the release froze, and a toolchain that cannot be updated is not one a build
/// can rely on.
///
/// **Trixie has it and bookworm does not** — `1.27.1-3+b1` in trixie, absent
/// from bookworm, verified per suite and reproduced in a container. Bookworm is
/// still oldstable, so an unconditional name here fails there exactly as `mise`
/// failed on trixie: `apt-get` sent after a package the suite has never
/// carried. The second name in this family that varies *within* it, after
/// Docker's repository, which is why [`DebianBackend::for_distribution`]
/// resolves it. Ubuntu carries `rustup` from noble onward, though in `universe`
/// rather than `main` — so a minimal cloud image with universe disabled falls
/// to the release installer, which is the right answer rather than a failure.
const RUST_PACKAGE_TRIXIE: &str = "rustup";

/// Git, in `main`.
const GIT_PACKAGE: &str = "git";

/// The GitHub CLI on Debian: `gh`, not `github-cli`.
///
/// In `main` since bookworm — contrary to a widely repeated claim that Debian
/// packages it nowhere, which `packages.debian.org`'s keyword search
/// encourages by not surfacing it. The binary package pages do.
///
/// Ubuntu carries the same name in `universe` rather than `main`, so a minimal
/// cloud image with universe disabled has no candidate and the release
/// installer answers instead — the same shape as `rustup` on that family.
///
/// What the package does not offer is currency: trixie ships 2.46 against
/// upstream's 2.97. That is a reason to prefer the release *where a
/// distribution ships nothing*, not a reason to bypass a package that exists.
const GITHUB_CLI_PACKAGE: &str = "gh";

/// The nftables front-end on Debian.
const NFTABLES_PACKAGE: &str = "nftables";

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
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
    automatic_updates: AptPeriodic,
    repositories: AptRepositories,
    /// Which of Docker's per-distribution paths serves this host.
    docker_repo_path: &'static str,
    /// Where that path serves its signing key.
    docker_key_path: &'static str,
    /// Whether this suite packages `rustup`.
    ///
    /// The second name that varies within this family. Resolved from the
    /// codename rather than from `VERSION_ID`, because the codename is what
    /// Debian and Ubuntu both have and what names a suite — Ubuntu declares a
    /// `VERSION_ID` of `24.04` where Debian declares `13`, and comparing those
    /// as numbers would need to know which family's scale it was reading.
    rust_package: &'static str,

    /// The suite Docker's repository is asked for.
    ///
    /// A fact about the host rather than about this build, and the reason this
    /// backend resolves a distribution at all: APT expands `$(ARCH)` and
    /// nothing else, so unlike dnf's `$releasever` the codename cannot be
    /// deferred to the package manager. `None` where the host declares none,
    /// which refuses the registration rather than guessing a suite.
    codename: Option<String>,
}

impl DebianBackend {
    /// Builds a backend for a named distribution in this family.
    ///
    /// Two things vary within this family rather than between families, and
    /// both concern the one repository this tool registers. The `ID` decides
    /// which of Docker's paths serves the host — Ubuntu's suites are not
    /// Debian's, so a derivative pointed at the Debian path would ask for a
    /// codename it does not carry. The codename itself is read from the host,
    /// since there is no variable APT would expand for it.
    ///
    /// The mechanism is the one [`super::rhel::RhelBackend`] already used for
    /// the same repository, reached here for a second reason.
    pub fn for_distribution(id: &str, codename: Option<&str>) -> Self {
        let (repo, key) = match id.to_ascii_lowercase().as_str() {
            // Ubuntu, Linux Mint, Pop!_OS and anything else reaching this
            // family through `ID_LIKE`. Docker builds one set of packages for
            // Debian's suites and another for Ubuntu's.
            "ubuntu" | "linuxmint" | "pop" | "elementary" | "zorin" | "neon" => {
                (DOCKER_REPO_UBUNTU, DOCKER_KEY_UBUNTU)
            }
            _ => (DOCKER_REPO_DEBIAN, DOCKER_KEY_DEBIAN),
        };

        // Named rather than compared: the suites that carry `rustup` are a list
        // this build knows, and a host declaring a codename none of them names
        // falls to the verified installer. That is the safe direction — a
        // future suite installs a checksummed artefact rather than failing on a
        // package nobody has confirmed it has.
        let rust = match codename.map(str::to_ascii_lowercase).as_deref() {
            Some("trixie" | "forky" | "sid" | "noble" | "questing" | "resolute") => {
                RUST_PACKAGE_TRIXIE
            }
            _ => "",
        };

        Self {
            docker_repo_path: repo,
            docker_key_path: key,
            codename: codename.map(str::to_owned),
            rust_package: rust,
            ..Self::new()
        }
    }

    pub const fn new() -> Self {
        Self {
            // Debian's paths are the default; `for_distribution` narrows to
            // Ubuntu's when the `ID` says so.
            docker_repo_path: DOCKER_REPO_DEBIAN,
            docker_key_path: DOCKER_KEY_DEBIAN,
            codename: None,
            // Empty until a distribution is resolved, which routes to the
            // verified installer. A backend built without one knows of no suite
            // and must not claim a package on its behalf.
            rust_package: "",
            repositories: AptRepositories::new(),
            packages: AptPackages,
            services: SystemdServices::new(),
            files: UnixFiles::new(),
            accounts: UnixAccounts::new(),
            account_writer: ShadowAccounts::new(),
            sysctl: ProcfsSysctl::new(),
            wireguard: WgTools::new(),
            user_services: SystemdUserServices::new(),
            binaries: ReleaseInstaller::new(),
            automatic_updates: AptPeriodic::new(),
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
            Capability::Rust => self.rust_package,
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
            // The rootless engine is a user unit, addressed through
            // `user_services` rather than by name here.
            Capability::DockerRootless => DOCKER_USER_UNIT,
            Capability::Caddy => CADDY_SERVICE,
            // None of these is a service.
            Capability::Fish | Capability::Zellij | Capability::Mise | Capability::Rust => "",
            // A front-end rather than a daemon: the ruleset lives in the
            // kernel and `nft` only speaks to it.
            Capability::Nftables => "",
            Capability::Fail2ban => FAIL2BAN_SERVICE,
            Capability::Crowdsec => CROWDSEC_SERVICE,
            // Driven by a timer the package ships, not by a unit of its own.
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
            // Git's system-wide file, which `git config --system` writes and
            // which is where a `safe.directory` covering every account belongs.
            // The per-account file is `~/.gitconfig`, which this cannot name:
            // it depends on whose account is being configured.
            Capability::Git => "/etc/gitconfig",
            // Configured per account under `$XDG_CONFIG_HOME` or `~/.config`,
            // so there is no system path to name. Since 2.97 the token is not
            // in a file at all by default — it goes to the system credential
            // store, falling back to plaintext only when none is available.
            Capability::GithubCli => "",
            Capability::UnattendedUpgrades => "/etc/apt/apt.conf.d",
        }
    }

    fn packages(&self) -> &dyn PackageManager {
        &self.packages
    }

    fn repositories(&self) -> Option<&dyn RepositoryManager> {
        Some(&self.repositories)
    }

    fn repository_for(&self, capability: Capability) -> Option<Repository> {
        match capability {
            // The one capability Debian's own repositories do not carry:
            // `docker.io` is the distribution's Docker and it ships no
            // rootless setup script, so the engine comes from Docker's own
            // repository or not at all. Registered only after the key that
            // arrives matches a fingerprint this build took from two
            // keyservers, neither of them the host serving the packages.
            Capability::DockerRootless => Some(Repository {
                name: "docker",
                base_url: self.docker_repo_path,
                key_url: self.docker_key_path,
                fingerprint: DOCKER_DEB_FINGERPRINT,
                // Read from the host: there is no `$releasever` here, and a
                // suite named wrongly registers a repository serving nothing.
                suite: self.codename.clone(),
            }),
            _ => None,
        }
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

    fn automatic_updates(&self) -> Option<&dyn AutomaticUpdates> {
        Some(&self.automatic_updates)
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

    fn remove(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // No `--auto-remove`: it pulls out whatever the package left orphaned,
        // and what that reaches cannot be stated before it runs. On a host
        // where Caddy arrived alongside its own dependencies, removing it that
        // way takes them too — including any another package came to rely on
        // since.
        let command = Command::new("env")
            .args([
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "remove",
                "-y",
                package,
            ])
            .privileged();

        run_checked(executor, &command)
    }

    fn purge(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // This is the family where the distinction is sharpest: `remove` leaves
        // conffiles in place and dpkg keeps the package in its status as
        // "deinstall ok config-files", which is why `is_installed` demands
        // exactly "install ok installed" rather than trusting the exit code.
        let command = Command::new("env")
            .args([
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "purge",
                "-y",
                package,
            ])
            .privileged();

        run_checked(executor, &command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn the_rootless_engine_comes_from_a_repository_the_host_does_not_have() {
        // The failure this closes: `docker-ce-rootless-extras` is not in any
        // Debian suite, so naming it while declaring no repository produced
        // "Package has no installation candidate" on a stock host — which
        // reads as a wrong package name rather than a missing source.
        let backend = DebianBackend::for_distribution("debian", Some("trixie"));

        assert!(backend.repositories().is_some());

        let repository = backend
            .repository_for(Capability::DockerRootless)
            .expect("the engine's repository must be declared");

        assert_eq!(repository.suite.as_deref(), Some("trixie"));
        assert!(
            repository.base_url.contains("/linux/debian"),
            "{repository:?}"
        );
    }

    #[test]
    fn the_deb_key_is_not_the_rpm_one() {
        // The two archives are signed by different keys with different UIDs,
        // so using either where the other belongs refuses every legitimate
        // key. Pinned in both directions, here and in the RHEL backend.
        assert_ne!(
            DOCKER_DEB_FINGERPRINT, "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
            "that is the .rpm key; the .debs are signed by another"
        );
    }

    #[test]
    fn ubuntu_is_served_by_its_own_path() {
        // Docker builds one set of packages for Debian's suites and another
        // for Ubuntu's, so a derivative pointed at the Debian path would ask
        // for a codename that path does not carry.
        let ubuntu = DebianBackend::for_distribution("ubuntu", Some("noble"));
        let debian = DebianBackend::for_distribution("debian", Some("trixie"));

        let path_of = |backend: &DebianBackend| {
            backend
                .repository_for(Capability::DockerRootless)
                .expect("declared")
                .base_url
        };

        assert!(path_of(&ubuntu).contains("/linux/ubuntu"));
        assert!(path_of(&debian).contains("/linux/debian"));
    }

    #[test]
    fn a_host_declaring_no_codename_carries_no_suite() {
        // Not defaulted to `stable`, which is a moving target, nor to a
        // codename this build happens to know: either registers a repository
        // that serves nothing, and the install then reports the package as
        // missing rather than the suite as wrong.
        let backend = DebianBackend::for_distribution("debian", None);

        assert!(
            backend
                .repository_for(Capability::DockerRootless)
                .expect("declared")
                .suite
                .is_none()
        );
    }

    #[test]
    fn the_unpackaged_developer_tools_resolve_to_no_package() {
        // Both route to the verified release installer instead. Zellij was
        // already recorded as absent; mise was named as though Debian carried
        // it, and no suite ever has — `apt-get` answered "Unable to locate
        // package mise" on trixie.
        let backend = DebianBackend::new();

        for capability in [Capability::Zellij, Capability::Mise] {
            assert!(
                !backend.has_package_for(capability),
                "{capability:?} is unpackaged on Debian and must route to a release"
            );
        }
    }

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
    fn removing_keeps_the_configuration_and_purging_does_not() {
        // The whole reason the operator is asked which they meant: `remove`
        // leaves conffiles for a reinstall to find, `purge` deletes them, and
        // the difference is not recoverable once made.
        let removed = MockExecutor::new();
        AptPackages.remove(&removed, "fail2ban").expect("removes");

        let purged = MockExecutor::new();
        AptPackages.purge(&purged, "fail2ban").expect("purges");

        assert_eq!(
            removed.recorded_lines(),
            ["env DEBIAN_FRONTEND=noninteractive apt-get remove -y fail2ban"]
        );
        assert_eq!(
            purged.recorded_lines(),
            ["env DEBIAN_FRONTEND=noninteractive apt-get purge -y fail2ban"]
        );
        assert!(removed.any_privileged());
        assert!(purged.any_privileged());
    }

    #[test]
    fn removal_never_reaches_beyond_the_package_named() {
        // `--auto-remove` takes whatever the package left orphaned, and what
        // that reaches cannot be stated before it runs — including packages
        // something else came to depend on since.
        let mock = MockExecutor::new();

        AptPackages.remove(&mock, "caddy").expect("removes");
        AptPackages.purge(&mock, "caddy").expect("purges");

        for line in mock.recorded_lines() {
            assert!(
                !line.contains("--auto-remove"),
                "removal must not cascade: {line}"
            );
        }
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
