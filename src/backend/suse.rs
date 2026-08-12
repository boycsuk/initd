//! openSUSE and SLES: `zypper`, systemd, the shadow suite.
//!
//! Mechanically close to RHEL — systemd, `wheel`, glibc, rpm underneath — so
//! most shared implementations apply unchanged. Two things make it its own
//! family rather than a variant of that one, and both were measured on
//! `opensuse/tumbleweed` and `opensuse/leap` 16.0 rather than assumed.
//!
//! **The administrative group grants nothing on its own.** `wheel` exists and
//! is the right group, but the rule is shipped commented out in
//! `/usr/etc/sudoers`. Every other family in this tree treats "in the group"
//! and "can escalate" as the same fact; here they are not, which is why
//! [`Backend::admin_group_grants_alone`] exists at all. See [`SUDOERS_DROPIN`].
//!
//! **The two variants disagree with each other.** Tumbleweed packages Zellij
//! and Leap 16.0 does not. Every other family resolves one set of names; this
//! one resolves a distribution, as RHEL already does for Docker's repository
//! paths — see [`SuseBackend::for_distribution`].

use super::nftables::Nftables;
use super::procfs_sysctl::ProcfsSysctl;
use super::release_installer::ReleaseInstaller;
use super::rpm_packages;
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

/// The OpenSSH server package.
///
/// openSUSE splits OpenSSH the way Debian does — `openssh` is the suite and
/// `openssh-server` the daemon — and both resolve. The server is named because
/// that is the capability the tasks need.
const SSH_PACKAGE: &str = "openssh-server";

/// The SSH unit — `sshd`, as on Arch and RHEL.
///
/// Measured: the package ships `sshd.service`, `sshd.socket` and `sshd@.service`
/// on both variants. Debian's `ssh.service` does not exist here.
const SSH_SERVICE: &str = "sshd.service";

/// Where the OpenSSH server reads its configuration.
///
/// The canonical path, and on a fresh openSUSE host it does not exist:
/// `openssh-server` installs its configuration to `/usr/etc/ssh/sshd_config`
/// under the `/usr/etc` split, leaving `/etc/ssh/` holding only the drop-in
/// directory. Measured on Tumbleweed — `cat /etc/ssh/sshd_config` fails on a
/// host where sshd runs perfectly well.
///
/// This path is still the right one to name, for two measured reasons. `sshd -T`
/// reads it by default, so a file written here is the daemon's effective
/// configuration — `PermitRootLogin yes` written to it came back from `sshd -T`
/// having overridden a drop-in that said otherwise. And it is where an
/// administrator's changes belong: editing the `/usr/etc` copy would put this
/// tool's edits in a file rpm owns and replaces on upgrade.
///
/// What makes naming it safe is [`Backend::ensure_config_present`], which seeds
/// it from the packaged copy before any task reads it.
const SSH_CONFIG: &str = "/etc/ssh/sshd_config";

/// The configuration the package actually ships, under the `/usr/etc` split.
///
/// Copied to [`SSH_CONFIG`] rather than edited in place: rpm owns this file and
/// restores it whenever `openssh-server` is upgraded, so an edit here is one
/// that silently reverts.
const SSH_CONFIG_PACKAGED: &str = "/usr/etc/ssh/sshd_config";

/// The WireGuard tools, in the distribution's own repositories.
const WIREGUARD_PACKAGE: &str = "wireguard-tools";

/// The unit template that brings an interface up.
const WIREGUARD_SERVICE: &str = "wg-quick@";

/// Where WireGuard keeps its configuration.
const WIREGUARD_CONFIG: &str = "/etc/wireguard";

/// Docker is packaged, unlike on RHEL.
///
/// openSUSE ships the Moby-project runtime as `docker` in its own repositories,
/// so unlike Red Hat this family registers no third-party repository for it —
/// which is why [`Backend::repository_for`] is left at its default here.
const DOCKER_PACKAGE: &str = "docker";

/// The rootless engine's user unit, once a mechanism exists to install it.
const DOCKER_USER_UNIT: &str = "docker.service";

/// Where the rootless engine keeps its daemon configuration.
const DOCKER_CONFIG: &str = ".config/docker/daemon.json";

/// Caddy is packaged, unlike on RHEL.
const CADDY_PACKAGE: &str = "caddy";

/// The Caddy unit, once installed.
const CADDY_SERVICE: &str = "caddy.service";

/// Where Caddy reads its configuration.
const CADDY_CONFIG: &str = "/etc/caddy/Caddyfile";

/// fish is packaged on both variants.
const FISH_PACKAGE: &str = "fish";

/// Zellij is packaged on Tumbleweed and absent from Leap 16.0.
///
/// The one name in this tree that varies *within* a family, which is why it is
/// resolved by [`SuseBackend::for_distribution`] rather than named as a
/// constant here. Leap's empty name routes it to the release installer, which
/// is the same musl artefact Debian and RHEL already install.
const ZELLIJ_PACKAGE_TUMBLEWEED: &str = "zellij";

/// mise is unpackaged on both variants, and published as a musl release.
///
/// Measured with an exact-match search and again without one: nothing under
/// that name in either variant's repositories. The empty name routes this to
/// the release installer, as it does on RHEL.
const MISE_PACKAGE: &str = "";

/// The Rust toolchain manager, packaged here unlike on RHEL.
const RUST_PACKAGE: &str = "rustup";

/// Git, in `oss` on both variants.
const GIT_PACKAGE: &str = "git";

/// The GitHub CLI: `gh` here, as on Debian rather than as on Arch.
///
/// openSUSE sides with Debian on the name and with Arch on currency — 2.96
/// against Debian's 2.46. Packaged on both Tumbleweed and Leap 16.0, so unlike
/// Zellij this one does not vary within the family.
const GITHUB_CLI_PACKAGE: &str = "gh";

/// The nftables front-end.
///
/// Packaged rather than preinstalled — neither `nft` nor `firewall-cmd` is in
/// either base image, and installing this package is what provides `nft`
/// (measured). firewalld is absent from both, so unlike RHEL this family
/// presents one front-end rather than two.
const NFTABLES_PACKAGE: &str = "nftables";

/// What owns `sysctl` here.
///
/// Measured on `opensuse/tumbleweed`: `rpm -qf` answers `procps`, agreeing
/// with Debian rather than with the other two RPM families.
const SYSCTL_PACKAGE: &str = "procps";

/// fail2ban is packaged, unlike on RHEL where it is EPEL-only.
const FAIL2BAN_PACKAGE: &str = "fail2ban";

/// The fail2ban unit.
const FAIL2BAN_SERVICE: &str = "fail2ban.service";

/// CrowdSec is unpackaged, and publishes no verifiable artefact.
///
/// Absent from both variants' repositories. The reasoning for not installing it
/// another way is the one RHEL already records: its releases carry no checksum
/// files and its documented install is a script piped into a shell.
const CROWDSEC_PACKAGE: &str = "";

/// The CrowdSec unit, were it installed.
const CROWDSEC_SERVICE: &str = "crowdsec.service";

/// Unattended upgrades have no single package this backend can name.
///
/// openSUSE's mechanism is `zypper-automatic`/`transactional-update` depending
/// on whether the host is transactional, which is a property of the
/// installation rather than of the family — the same reason RHEL declares this
/// absent rather than naming one of its two.
const UNATTENDED_PACKAGE: &str = "";

/// The group granting sudo — `wheel`, as on Arch and RHEL.
///
/// The name is right and, uniquely in this tree, not sufficient. See
/// [`SUDOERS_DROPIN`].
const ADMIN_GROUP: &str = "wheel";

/// Where the rule granting `wheel` is written.
///
/// openSUSE ships `/usr/etc/sudoers` with the rule commented out:
///
/// ```text
/// ## Uncomment to allow members of group wheel to execute any command
/// # %wheel ALL=(ALL:ALL) ALL
/// ```
///
/// Verified as the distribution's default rather than an artefact of the
/// container image: `rpm -V sudo` reports the file unmodified on both variants.
///
/// A drop-in is written rather than that file edited. `sudoers.d` is included
/// by the shipped configuration, is empty on a stock host, and belongs to the
/// administrator — editing the packaged file instead would be overwritten on
/// upgrade and would make this tool the author of a file rpm believes it owns.
const SUDOERS_DROPIN: &str = "/etc/sudoers.d/initd-wheel";

/// The mode `sudoers.d` entries must carry.
///
/// sudo refuses to read a drop-in that is group- or world-writable and logs
/// nothing an operator would find, so a laxer mode fails by making the grant
/// silently not happen — the same failure this whole method exists to prevent.
const SUDOERS_MODE: u32 = 0o440;

/// Backend for the SUSE family.
pub struct SuseBackend {
    packages: ZypperPackages,
    services: SystemdServices,
    files: UnixFiles,
    accounts: UnixAccounts,
    account_writer: ShadowAccounts,
    sysctl: ProcfsSysctl,
    wireguard: WgTools,
    user_services: SystemdUserServices,
    binaries: ReleaseInstaller,
    /// Whether this distribution packages Zellij.
    ///
    /// The one name that varies within the family: Tumbleweed carries it, Leap
    /// 16.0 does not.
    zellij_package: &'static str,
}

impl SuseBackend {
    /// Builds a backend for a named distribution in this family.
    ///
    /// The `ID` decides one thing: whether Zellij resolves to a package or to
    /// the release installer. Tumbleweed packages it and Leap 16.0 does not —
    /// measured on both, and the first divergence in this tree that lives
    /// inside a family rather than between two.
    pub fn for_distribution(id: &str) -> Self {
        let zellij = match id.to_ascii_lowercase().as_str() {
            "opensuse-tumbleweed" => ZELLIJ_PACKAGE_TUMBLEWEED,
            // Leap, SLES, and anything else reaching this family through
            // `ID_LIKE`. The empty name routes to the release installer, whose
            // musl artefact is the one Debian already installs.
            _ => "",
        };

        Self {
            zellij_package: zellij,
            ..Self::new()
        }
    }

    pub const fn new() -> Self {
        Self {
            // Leap's answer is the default because the conservative one is
            // right when the `ID` says nothing: a package name that turns out
            // to be absent fails the install, where the release installer
            // works on both.
            zellij_package: "",
            packages: ZypperPackages,
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

impl Backend for SuseBackend {
    fn family(&self) -> Family {
        Family::Suse
    }

    /// rpm underneath, so the same answer RHEL gives, for the same reason.
    ///
    /// Measured rather than inherited: `zypper` has no `purge` subcommand at
    /// all, and `zypper rm` offers nothing that discards configuration. An
    /// edited file survives as `.rpmsave` whatever is asked.
    fn has_purge_for(&self) -> bool {
        false
    }

    fn package_for(&self, capability: Capability) -> &'static str {
        match capability {
            Capability::Ssh => SSH_PACKAGE,
            Capability::Wireguard => WIREGUARD_PACKAGE,
            Capability::DockerRootless => DOCKER_PACKAGE,
            Capability::Caddy => CADDY_PACKAGE,
            Capability::Fish => FISH_PACKAGE,
            Capability::Zellij => self.zellij_package,
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
            // A front-end rather than a daemon, as on RHEL: the ruleset lives
            // in the kernel and `nft` only speaks to it.
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

    /// Seeds `/etc/ssh/sshd_config` from the packaged copy under `/usr/etc`.
    ///
    /// The one family that needs this. See [`SSH_CONFIG`] for why the canonical
    /// path is named despite being absent, and why the packaged file is copied
    /// rather than edited where it lies.
    ///
    /// Idempotent by construction: it copies only when the target is missing,
    /// which is also what keeps it from overwriting an administrator's existing
    /// configuration on every task that reads one.
    fn ensure_config_present(&self, executor: &dyn Executor, capability: Capability) -> Result<()> {
        // Only SSH is split this way. Caddy, fail2ban and the rest write to
        // /etc when installed, so naming them here would copy files that are
        // already in place.
        if !matches!(capability, Capability::Ssh) {
            return Ok(());
        }

        if self.files.exists(executor, SSH_CONFIG)? {
            return Ok(());
        }

        // Nothing to seed from is not an error: `ssh.install` runs before the
        // package exists, and a task that writes the file outright needs no
        // seed at all. Reporting a failure here would turn "the package is not
        // installed yet" into a task that refuses to start.
        if !self.files.exists(executor, SSH_CONFIG_PACKAGED)? {
            return Ok(());
        }

        // `cp -p` rather than a read-then-write: it preserves owner and mode,
        // and never holds the contents in this process. Measured on Leap — the
        // packaged file is `0640 root:root` and arrives that way.
        //
        // Preserving rather than choosing a mode is the point. This tool has no
        // opinion about what `sshd_config` should be, and the distribution
        // does; a seed that widened it would hand the operator a file they did
        // not write and did not loosen. Note `sshd -t` accepts a `0666` config,
        // so nothing downstream would report the mistake — which is the reason
        // to preserve rather than the reason not to bother.
        let copy = Command::new("cp")
            .args(["-p", SSH_CONFIG_PACKAGED, SSH_CONFIG])
            .privileged();

        run_checked(executor, &copy)
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

    /// The one family where it does not.
    ///
    /// See [`SUDOERS_DROPIN`] for what was measured and where the grant goes.
    fn admin_group_grants_alone(&self) -> bool {
        false
    }

    /// Creates `wheel`, which a minimally installed openSUSE does not have.
    ///
    /// `system-group-wheel` is required only by the desktop patterns — measured
    /// on Tumbleweed, where neither `sudo` nor `patterns-base-minimal_base`
    /// pulls it in. The group is created rather than that package installed:
    /// one command is a smaller thing to do to somebody's server than a package
    /// whose entire content is this group.
    ///
    /// `-f` is what makes it idempotent — it succeeds when the group is already
    /// there — so this needs no prior question and is safe on every account
    /// created.
    fn ensure_admin_group(&self, executor: &dyn Executor, group: &str) -> Result<()> {
        let command = Command::new("groupadd").args(["-f", group]).privileged();

        run_checked(executor, &command)
    }

    fn grant_admin(&self, executor: &dyn Executor, group: &str) -> Result<()> {
        // One write, then the mode — not the create-empty-then-chmod-then-write
        // sequence `wireguard.install` uses. That pattern is right when the
        // hazard is *disclosure*, because an empty file discloses nothing; it
        // is wrong here, and measurably so: `write` stages through a temporary
        // and moves it over the target, carrying the target's previous mode
        // with it, so a chmod placed between two writes is undone by the second
        // one. The file would end up at whatever mode the empty placeholder
        // had, and sudo ignores a drop-in it considers too permissive without
        // saying why — the silent failure this whole method exists to prevent.
        //
        // The exposure this accepts is the reverse of a secret's: a sudoers
        // rule is world-readable by design, and the risk is a *permissive*
        // window, not a readable one. `write` creates the staging file with the
        // final mode already applied, so no such window exists.
        self.files.write(
            executor,
            SUDOERS_DROPIN,
            &format!("%{group} ALL=(ALL:ALL) ALL\n"),
        )?;
        self.files
            .set_mode(executor, SUDOERS_DROPIN, SUDOERS_MODE)?;

        // Validated rather than assumed, and this is not the same check
        // `sshd -t` was found unable to make: `visudo -c` parses the whole
        // configuration including this drop-in, and a sudoers file that does
        // not parse disables sudo entirely rather than just ignoring the bad
        // line. That is the one failure mode worse than not granting.
        let check = Command::new("visudo").args(["-c"]).privileged();

        run_checked(executor, &check)
    }

    fn accounts(&self) -> &dyn AccountReader {
        &self.accounts
    }

    fn account_writer(&self) -> &dyn AccountWriter {
        &self.account_writer
    }

    fn firewalls(&self) -> &[&dyn FirewallManager] {
        // One front-end, unlike RHEL: firewalld is not installed on either
        // variant's base image, and openSUSE's own default is firewalld on a
        // full installation but nftables is what `nft` drives directly. Only
        // the one this tool can resolve without guessing is offered.
        const FIREWALLS: &[&dyn FirewallManager] = &[&Nftables::new()];

        FIREWALLS
    }

    fn sysctl(&self) -> &dyn SysctlManager {
        &self.sysctl
    }

    // `selinux` is left at the trait's default, which answers `NoSelinux` —
    // the same answer Debian, Arch and Alpine give. Measured rather than
    // assumed from RHEL's kinship: neither `getenforce` nor `aa-status` is
    // present on either variant. openSUSE uses AppArmor on a full
    // installation, which is not SELinux and does not label ports, so there is
    // nothing for `semanage` to do here.

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

/// Package management through `zypper`.
#[derive(Debug, Clone, Copy)]
pub struct ZypperPackages;

impl PackageManager for ZypperPackages {
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // `--non-interactive` before the subcommand rather than `-y` after it:
        // zypper is interactive by default and prompts for licence agreements
        // and vendor changes as well as for confirmation. A prompt none of
        // those flags cover would hang the TUI, which is the failure
        // `DEBIAN_FRONTEND=noninteractive` prevents on Debian.
        let command = Command::new("zypper")
            .args(["--non-interactive", "install", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool> {
        // Shared with RHEL: the question is about rpm's database rather than
        // about zypper. This file used to answer it "for the reason RHEL
        // records", which is the sentence that says a function was wanted.
        rpm_packages::is_installed(executor, package)
    }

    fn remove(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // No `--clean-deps`: it cascades, removing dependencies this tool never
        // installed. That is the decision apt and pacman each record as "no
        // cascade" and the one zypper makes opt-in rather than default.
        let command = Command::new("zypper")
            .args(["--non-interactive", "remove", package])
            .privileged();

        run_checked(executor, &command)
    }

    fn purge(&self, executor: &dyn Executor, package: &str) -> Result<()> {
        // The same command as `remove`, because zypper has no purge — measured:
        // it is not a subcommand, and `zypper rm` offers nothing that discards
        // configuration. rpm leaves an edited file as `.rpmsave` regardless.
        //
        // Reachable only if `has_purge_for` ever answered true here, which it
        // does not, so the interface never offers the choice. Implemented
        // rather than left to panic for the reason RHEL's records.
        self.remove(executor, package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn installs_the_suse_ssh_package_name() {
        let mock = MockExecutor::new();

        ZypperPackages
            .install(&mock, SuseBackend::new().package_for(Capability::Ssh))
            .expect("install must succeed");

        assert_eq!(
            mock.recorded_lines(),
            ["zypper --non-interactive install openssh-server"]
        );
        assert!(mock.any_privileged());
    }

    #[test]
    fn ssh_takes_debians_package_name_and_archs_unit_name() {
        // The same split RHEL has, and measured here rather than inherited from
        // it: the package ships `sshd.service`, and Debian's `ssh.service` does
        // not exist on either variant.
        let backend = SuseBackend::new();

        assert_eq!(backend.package_for(Capability::Ssh), "openssh-server");
        assert_eq!(backend.service_for(Capability::Ssh), "sshd.service");
    }

    #[test]
    fn install_is_noninteractive() {
        // zypper prompts by default, and a prompt under the alternate screen is
        // unanswerable — the interface simply appears to hang.
        let mock = MockExecutor::new();

        ZypperPackages
            .install(&mock, "openssh-server")
            .expect("runs");

        let args = mock.single_command().args;
        assert!(
            args.contains(&"--non-interactive".to_owned()),
            "must not prompt: {args:?}"
        );
    }

    #[test]
    fn removing_does_not_cascade() {
        // `--clean-deps` would take dependencies this tool never installed.
        let mock = MockExecutor::new();

        ZypperPackages.remove(&mock, "fail2ban").expect("removes");

        let args = mock.single_command().args;
        assert!(
            !args.contains(&"--clean-deps".to_owned()),
            "removal must not cascade: {args:?}"
        );
    }

    #[test]
    fn purging_is_removing_here_and_the_family_says_so() {
        // Both halves together, as on RHEL: either alone permits the
        // combination that lies — offering a choice whose two answers do the
        // same thing and telling the operator nothing.
        let removed = MockExecutor::new();
        ZypperPackages
            .remove(&removed, "fail2ban")
            .expect("removes");

        let purged = MockExecutor::new();
        ZypperPackages.purge(&purged, "fail2ban").expect("purges");

        assert_eq!(
            removed.recorded_lines(),
            ["zypper --non-interactive remove fail2ban"]
        );
        assert_eq!(purged.recorded_lines(), removed.recorded_lines());
        assert!(
            !SuseBackend::new().has_purge_for(),
            "a family whose purge is a removal must not offer the choice"
        );
    }

    #[test]
    fn the_installed_query_reads_the_local_database() {
        let mock = MockExecutor::with_replies([Reply::ok("openssh-server-9.9p1-1.1.x86_64")]);

        ZypperPackages
            .is_installed(&mock, "openssh-server")
            .expect("query must succeed");

        assert_eq!(mock.recorded_lines(), ["rpm -q openssh-server"]);
        assert!(!mock.any_privileged(), "a query must not escalate");
    }

    #[test]
    fn the_administrative_group_is_wheel_and_grants_nothing_alone() {
        // The finding this family exists to record. The name is the same one
        // Arch and RHEL use, and unlike there, membership is not the whole
        // answer: openSUSE ships `%wheel` commented out in /usr/etc/sudoers,
        // verified unmodified by `rpm -V` on both variants.
        //
        // Both assertions belong together: the name alone reads as agreement
        // with RHEL, which is exactly the wrong conclusion to draw.
        let backend = SuseBackend::new();

        assert_eq!(backend.admin_group(), "wheel");
        assert!(
            !backend.admin_group_grants_alone(),
            "membership alone must not be reported as sufficient"
        );
    }

    #[test]
    fn granting_writes_a_dropin_that_sudo_will_actually_read() {
        // Three properties, and each one silently grants nothing if wrong:
        // the rule must name the group, the file must land in sudoers.d, and
        // the mode must be 0440 — sudo ignores a group-writable drop-in and
        // says nothing about why.
        let mock = MockExecutor::new();

        SuseBackend::new()
            .grant_admin(&mock, "wheel")
            .expect("granting must succeed");

        let lines = mock.recorded_lines().join("\n");

        assert!(
            lines.contains("/etc/sudoers.d/initd-wheel"),
            "the grant must go in a drop-in: {lines}"
        );
        assert!(
            lines.contains("440"),
            "sudo refuses a drop-in it can write: {lines}"
        );

        // Read off stdin rather than the rendered line: `write` feeds contents
        // to `tee` on stdin precisely so they never reach argv, and `Command`'s
        // Display omits it. Asserting on the line would have looked for the
        // rule where it can never appear — and passed only if the code did the
        // one thing this project forbids.
        let rule = mock
            .recorded()
            .into_iter()
            .find_map(|command| command.stdin)
            .expect("the rule must be written");

        assert_eq!(rule, "%wheel ALL=(ALL:ALL) ALL\n");
    }

    #[test]
    fn the_administrative_group_is_created_where_the_system_lacks_it() {
        // `wheel` is not on a stock openSUSE server: `system-group-wheel` is
        // required only by the desktop patterns, and neither `sudo` nor
        // `patterns-base-minimal_base` pulls it in — measured on Tumbleweed.
        //
        // This lives apart from `grant_admin` because of *when* it is needed,
        // which a container found rather than review: `usermod -aG` against a
        // missing group exits 6, so putting the creation inside the grant left
        // `users.create` failing at the membership step it never reached the
        // grant from. The two read as one job and happen at different moments.
        let mock = MockExecutor::new();

        SuseBackend::new()
            .ensure_admin_group(&mock, "wheel")
            .expect("ensuring the group must succeed");

        assert_eq!(mock.recorded_lines(), ["groupadd -f wheel"]);
        assert!(mock.any_privileged(), "creating a group needs rights");
    }

    #[test]
    fn ensuring_the_group_does_not_fail_when_it_already_exists() {
        // `-f` is the whole idempotence story, and this runs on every account
        // created — so without it, the second administrator on a host would
        // fail at a group that is already correct.
        let mock = MockExecutor::new();

        SuseBackend::new()
            .ensure_admin_group(&mock, "wheel")
            .expect("ensuring the group must succeed");

        let args = mock.single_command().args;
        assert!(
            args.contains(&"-f".to_owned()),
            "must tolerate an existing group: {args:?}"
        );
    }

    #[test]
    fn the_mode_is_applied_after_the_write_that_would_undo_it() {
        // Written against a defect this had rather than as a restatement of the
        // code. The first attempt followed `wireguard.install`'s
        // create-empty/chmod/write order, and it silently produced a drop-in at
        // the wrong mode: `write` stages through a temporary and moves it over
        // the target, carrying the previous mode along, so a chmod sitting
        // between two writes is undone by the second one.
        //
        // Sudo ignores a drop-in it considers too permissive and logs nothing,
        // so the failure is invisible on the machine — the account simply
        // cannot escalate. Hence the assertion is on ordering rather than on
        // the final chmod existing: the broken version issued that chmod too.
        let mock = MockExecutor::new();

        SuseBackend::new()
            .grant_admin(&mock, "wheel")
            .expect("granting must succeed");

        let lines = mock.recorded_lines();
        let last_move = lines
            .iter()
            .rposition(|line| line.starts_with("mv "))
            .expect("the write must stage and move");
        let mode_at = lines
            .iter()
            .rposition(|line| line.contains("chmod 440"))
            .expect("the mode must be set");

        assert!(
            mode_at > last_move,
            "a mode set before the final move is carried away by it: {lines:?}"
        );
    }

    #[test]
    fn granting_validates_the_result() {
        // A sudoers file that does not parse disables sudo entirely rather than
        // ignoring the offending line, which is worse than not granting at all.
        let mock = MockExecutor::new();

        SuseBackend::new()
            .grant_admin(&mock, "wheel")
            .expect("granting must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.contains("visudo")),
            "the result must be validated: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn tumbleweed_packages_zellij_and_leap_does_not() {
        // The first divergence inside a family in this tree. Measured: an
        // exact-match search finds it on Tumbleweed and not on Leap 16.0.
        // Leap's empty name is an answer — it routes to the release installer,
        // the same musl artefact Debian already installs.
        let tumbleweed = SuseBackend::for_distribution("opensuse-tumbleweed");
        let leap = SuseBackend::for_distribution("opensuse-leap");

        assert_eq!(tumbleweed.package_for(Capability::Zellij), "zellij");
        assert!(
            !leap.has_package_for(Capability::Zellij),
            "Leap 16.0 carries no zellij and must say so"
        );
    }

    #[test]
    fn an_unknown_suse_takes_the_answer_that_works_on_both() {
        // SLES, and anything reaching this family through `ID_LIKE`. Naming a
        // package that may be absent fails the install; the release installer
        // works either way, so the conservative answer is the default.
        for id in ["sles", "opensuse-microos", "something-unheard-of"] {
            assert!(
                !SuseBackend::for_distribution(id).has_package_for(Capability::Zellij),
                "{id} must fall back to the release installer"
            );
        }
    }

    #[test]
    fn the_capabilities_suse_ships_resolve_to_a_package() {
        // The other half of the absence assertions: declaring everything absent
        // would leave a backend that installs nothing. These are the ones
        // measured present in both variants' own repositories — several of
        // which RHEL has to fetch as releases.
        let backend = SuseBackend::new();

        for capability in [
            Capability::Ssh,
            Capability::Wireguard,
            Capability::Nftables,
            Capability::Caddy,
            Capability::Fish,
            Capability::Rust,
            Capability::Fail2ban,
            Capability::DockerRootless,
        ] {
            assert!(
                backend.has_package_for(capability),
                "{capability:?} is packaged on openSUSE and must resolve"
            );
        }
    }

    #[test]
    fn the_capabilities_suse_does_not_ship_report_no_package() {
        // Measured absent in both variants, with and without exact matching.
        let backend = SuseBackend::new();

        for capability in [
            Capability::Mise,
            Capability::Crowdsec,
            Capability::UnattendedUpgrades,
        ] {
            assert!(
                !backend.has_package_for(capability),
                "{capability:?} must report no package on openSUSE"
            );
        }
    }

    #[test]
    fn seeding_preserves_what_the_distribution_chose() {
        // `-p` is the whole assertion. The packaged file is `0640 root:root` on
        // Leap, and a copy without it lands at the umask — a file the operator
        // did not write and did not loosen. Nothing downstream would say so:
        // `sshd -t` accepts a `0666` config, measured in a container.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""), // /etc/ssh/sshd_config absent
            Reply::ok(""),         // the packaged copy is there
            Reply::ok(""),         // cp
        ]);

        SuseBackend::new()
            .ensure_config_present(&mock, Capability::Ssh)
            .expect("seeding must succeed");

        let copy = mock
            .recorded_lines()
            .into_iter()
            .find(|line| line.starts_with("cp "))
            .expect("the packaged file must be copied");

        assert!(copy.contains("-p"), "mode and owner must survive: {copy}");
        assert!(copy.contains(SSH_CONFIG_PACKAGED), "{copy}");
        assert!(copy.contains(SSH_CONFIG), "{copy}");
    }

    #[test]
    fn a_config_already_in_place_is_left_alone() {
        // The half that matters more: this runs on every SSH task, so a seed
        // that copied unconditionally would overwrite the administrator's own
        // configuration with the packaged one — silently, and on a file the
        // tool is about to report having edited.
        let mock = MockExecutor::with_replies([Reply::ok("")]); // it exists

        SuseBackend::new()
            .ensure_config_present(&mock, Capability::Ssh)
            .expect("seeding must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.starts_with("cp ")),
            "an existing configuration must not be replaced: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn this_family_registers_no_third_party_repository() {
        // Unlike RHEL, which must register Docker's. openSUSE packages Docker
        // itself, so nothing here comes from outside the distribution.
        let backend = SuseBackend::new();

        assert!(backend.repositories().is_none());
        assert!(backend.repository_for(Capability::DockerRootless).is_none());
    }
}
