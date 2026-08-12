//! Per-family backends.
//!
//! A backend bundles the capability implementations for one distribution
//! family *and* translates logical names into real ones. Adding a distribution
//! means adding one module here — never editing a task.

pub mod alpine;
pub mod apt_periodic;
pub mod apt_repositories;
pub mod arch;
pub mod backup_index;
pub mod busybox_accounts;
pub mod debian;
pub mod firewalld;
pub mod nftables;
pub mod openrc;
pub mod posix_accounts;
pub mod procfs_sysctl;
pub mod release_installer;
pub mod rhel;
pub mod rpm_packages;
pub mod rpm_repositories;
pub mod semanage;
pub mod shadow_accounts;
pub mod suse;
pub mod systemd;
pub mod systemd_user;
pub mod unix_accounts;
pub mod unix_files;
pub mod wg_tools;

use crate::backend::nftables::Nftables;
use crate::backend::semanage::NoSelinux;
use crate::distro::{Distro, Family};
use crate::domain::{
    AccountReader, AccountWriter, AutomaticUpdates, BinaryInstaller, FileEditor, FirewallManager,
    PackageManager, Repository, RepositoryManager, SelinuxManager, ServiceManager, SysctlManager,
    UserServiceManager, WireguardTools,
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

    /// Whether removing a package here can also discard its configuration.
    ///
    /// Three families distinguish the two: apt keeps conffiles until asked to
    /// purge, pacman writes `.pacsave` unless told `-n`, apk preserves modified
    /// files unless told `--purge`. RHEL and openSUSE do not — rpm has no
    /// purge, and a file the administrator edited is left as `.rpmsave`
    /// whatever is asked. Both answer for rpm rather than for their own front
    /// end, which is why neither `dnf` nor `zypper` is the name that matters.
    ///
    /// Asked so the interface can decline to offer a choice that does not
    /// exist. A field with two options that behave identically is worse than
    /// no field: it invites an operator to make a decision, then ignores it.
    fn has_purge_for(&self) -> bool {
        true
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

    /// Makes [`Backend::path_for`] name a file that exists.
    ///
    /// Four families need nothing here: the packages they install write their
    /// configuration under `/etc`, so the path is readable the moment the
    /// capability is installed. openSUSE follows the `/usr/etc` split — the
    /// packaged `sshd_config` lives there and `/etc/ssh/sshd_config` is absent
    /// on a fresh host — and the five SSH tasks read that path before editing
    /// it, so on that family they would fail before writing anything.
    ///
    /// Called before a task reads a capability's configuration, and required to
    /// be idempotent: it runs on every such task, and most of the time the file
    /// is already there.
    ///
    /// This is a path question rather than a task one, which is why it lives
    /// beside `path_for` instead of in the tasks. Five of them read
    /// `sshd_config`; fixing it in each is the shape of change where the sixth
    /// is the one that forgets.
    fn ensure_config_present(
        &self,
        _executor: &dyn Executor,
        _capability: Capability,
    ) -> Result<()> {
        Ok(())
    }

    /// The group that grants administrative rights on this distribution.
    ///
    /// `sudo` on Debian, `wheel` on Arch and RHEL. The divergence matters more
    /// than most: `usermod -aG sudo` on Arch exits zero and grants nothing,
    /// leaving an account that looks provisioned and cannot escalate.
    fn admin_group(&self) -> &'static str;

    /// Makes [`Backend::admin_group`] name a group that exists.
    ///
    /// Four families ship it with the system and need nothing here. openSUSE
    /// takes `wheel` from `system-group-wheel`, which only its desktop patterns
    /// require — measured, neither installing `sudo` nor
    /// `patterns-base-minimal_base` pulls it in — so a minimally installed
    /// server has no such group.
    ///
    /// Called before an account is added to the group rather than as part of
    /// granting, because `usermod -aG` against a missing group exits 6: the
    /// membership fails first, and nothing later gets the chance to fix it.
    /// Separated from [`Backend::grant_admin`] for that reason alone — the two
    /// read as one job and happen at different moments.
    ///
    /// Required to be idempotent: it runs on every account created.
    fn ensure_admin_group(&self, _executor: &dyn Executor, _group: &str) -> Result<()> {
        Ok(())
    }

    /// Whether joining [`Backend::admin_group`] is by itself enough to escalate.
    ///
    /// Four families answer yes, which is why this was a constant for so long:
    /// the group's name was the whole answer, and a task that added an account
    /// to it was done. openSUSE is the first to disagree — `wheel` exists and
    /// is the right group, but the rule granting it is shipped *commented out*
    /// in `/usr/etc/sudoers`:
    ///
    /// ```text
    /// ## Uncomment to allow members of group wheel to execute any command
    /// # %wheel ALL=(ALL:ALL) ALL
    /// ```
    ///
    /// Measured on `opensuse/tumbleweed` and `opensuse/leap` 16.0, and `rpm -V`
    /// reports the file unmodified — so this is the distribution's default
    /// rather than an artefact of the container image, which was the reading
    /// that had to be ruled out before changing a trait over it.
    ///
    /// What that costs is the failure this whole layer exists to prevent, one
    /// level deeper than the name: `usermod -aG wheel` succeeds, membership
    /// reads back true, and the account still cannot escalate. Both callers are
    /// harmed differently — `users.create` reports an administrator it did not
    /// make, and `users.lock-root` *verifies* membership before locking root,
    /// so it would approve the one state it exists to refuse and leave nobody
    /// able to administer the machine.
    ///
    /// A backend answering `false` must implement [`Backend::grant_admin`].
    fn admin_group_grants_alone(&self) -> bool {
        true
    }

    /// Makes membership of [`Backend::admin_group`] actually confer escalation.
    ///
    /// Called only where [`Backend::admin_group_grants_alone`] is `false`, and
    /// only after the account is already in the group. The default is
    /// unreachable for the four families that grant on membership; it returns
    /// `Ok(())` rather than panicking, because a trait method that cannot be
    /// called is still a method and `unreachable!()` in a tool running as root
    /// is a promise about callers rather than about code — the same reasoning
    /// [`crate::backend::rhel::DnfPackages::purge`] records for its own
    /// unreachable branch.
    fn grant_admin(&self, _executor: &dyn Executor, _group: &str) -> Result<()> {
        Ok(())
    }

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
    ///
    /// nftables alone by default, which is what four of the five families
    /// answer. Where Debian has `ufw` active the nftables implementation
    /// reports itself unavailable rather than fighting it, so the single
    /// candidate still holds there. RHEL overrides this: it is the one family
    /// offering two, and the order it puts them in is load-bearing.
    fn firewalls(&self) -> &[&dyn FirewallManager] {
        const FIREWALLS: &[&dyn FirewallManager] = &[&Nftables::new()];

        FIREWALLS
    }

    /// Kernel parameters.
    fn sysctl(&self) -> &dyn SysctlManager;

    /// Registers package repositories the distribution does not ship.
    ///
    /// The most consequential capability here: what it adds decides where a
    /// machine's software comes from from then on, not just what is installed
    /// today. Which is why a [`Repository`] cannot be expressed without a
    /// fingerprint published independently of the key it verifies — see
    /// [`crate::domain::repositories`].
    ///
    /// Returns `None` for families whose packaging has no such mechanism, and
    /// for those where nothing this tool installs needs one.
    fn repositories(&self) -> Option<&dyn RepositoryManager> {
        None
    }

    /// How this family configures unattended updates, where it has a mechanism.
    ///
    /// `None` by default and on four of the five families, each for a reason
    /// recorded beside `updates.unattended-security`'s refusal: Arch is a
    /// rolling release with no equivalent, Alpine ships none, and RHEL's
    /// package name moved between releases the backend cannot distinguish.
    /// Returning `None` rather than an implementation that writes nothing keeps
    /// "there is no mechanism here" distinguishable from "it did nothing".
    fn automatic_updates(&self) -> Option<&dyn AutomaticUpdates> {
        None
    }

    /// The repository providing a capability, where one has to be registered.
    ///
    /// Separate from [`Backend::package_for`] because the two answer different
    /// questions: that one names a package in a repository the host already
    /// has, this one names a repository the host does not. Docker is the case —
    /// Red Hat ships Podman and packages no Docker at all, while Docker Inc
    /// publishes a repository whose signing key can be verified.
    fn repository_for(&self, capability: Capability) -> Option<Repository> {
        let _ = capability;
        None
    }

    /// The mandatory access control layer, where the family has one.
    ///
    /// Separate from every other capability because it is not a different
    /// spelling of something — it is a second authority that can refuse what
    /// the first permitted. A port SELinux has not labelled is one a valid,
    /// successfully written configuration cannot make the daemon bind, and
    /// `sshd -t` approves the file either way.
    ///
    /// Families without one return an implementation that reports nothing
    /// enforcing, so a task asks the same question everywhere rather than
    /// branching on the distribution.
    /// Nothing enforces by default, which is the answer on four of the five
    /// families: a constant rather than a question put to the host. Tasks still
    /// ask, which is what keeps the check out of them. RHEL is the one family
    /// that has one, and whether it is *enforcing* is asked of the host there.
    fn selinux(&self) -> &dyn SelinuxManager {
        const SELINUX: &NoSelinux = &NoSelinux::new();

        SELINUX
    }

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
///
/// Takes the distribution's own `ID` alongside its family because one thing
/// below this layer needs it: Docker publishes a repository per distribution
/// rather than per family, and Rocky and AlmaLinux are served by `linux/centos`
/// where Red Hat's own is `linux/rhel`. That is a URL rather than a behaviour,
/// so it is resolved here like every other name instead of splitting the family
/// in two — and tasks stay unable to ask which distribution they run on.
pub fn for_family(family: Family) -> Box<dyn Backend> {
    match family {
        Family::Debian => Box::new(debian::DebianBackend::new()),
        Family::Arch => Box::new(arch::ArchBackend::new()),
        Family::Alpine => Box::new(alpine::AlpineBackend::new()),
        Family::Rhel => Box::new(rhel::RhelBackend::new()),
        Family::Suse => Box::new(suse::SuseBackend::new()),
    }
}

/// Builds the backend for a detected distribution.
///
/// What the running program uses. [`for_family`] remains for callers that have
/// only a family — chiefly tests asserting a property every member of one
/// shares — and resolves the same backend with the family's own defaults.
///
/// The `ID` narrows two things, both of them names rather than behaviours.
///
/// On RHEL, Docker publishes a repository per distribution rather than per
/// family: Rocky and AlmaLinux are served by `linux/centos` where Red Hat's own
/// is `linux/rhel`. On SUSE, Tumbleweed packages Zellij and Leap 16.0 does not,
/// so the same capability resolves to a package on one and to a verified
/// release on the other.
///
/// Both are resolved here rather than by splitting either family in two, and
/// tasks remain unable to ask which distribution they are running on. That the
/// second case exists at all is the finding SUSE contributed: until it, a
/// family was assumed to speak with one voice.
pub fn for_distro(distro: &Distro) -> Box<dyn Backend> {
    match distro.family {
        Family::Rhel => Box::new(rhel::RhelBackend::for_distribution(&distro.id)),
        Family::Suse => Box::new(suse::SuseBackend::for_distribution(&distro.id)),
        // Debian resolves two things rather than one, and the second is not a
        // name at all: Docker's repository is keyed by suite, and APT expands
        // no variable for it, so the codename is carried in from the detected
        // distribution rather than deferred to the package manager.
        Family::Debian => Box::new(debian::DebianBackend::for_distribution(
            &distro.id,
            distro.codename.as_deref(),
        )),
        family => for_family(family),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_family_that_cannot_purge_is_the_exception_rather_than_the_rule() {
        // Iterating `ALL` for the same reason the dispatch test does: a new
        // family inherits the default `true`, and this is where that shows up
        // as a decision somebody has to have made rather than as silence.
        //
        // This comment used to predict that "a fifth family using rpm would
        // answer the same way". SUSE is that family and it does — measured
        // rather than inherited from the kinship: `zypper` has no `purge`
        // subcommand at all, and `zypper rm` offers nothing that discards
        // configuration. Both answer for rpm rather than for their own front
        // end, which is why the two names below sit together.
        let without: Vec<_> = Family::ALL
            .iter()
            .filter(|&&family| !for_family(family).has_purge_for())
            .map(|&family| family.to_string())
            .collect();

        assert_eq!(without, ["rhel", "suse"]);
    }

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
    fn the_families_that_grant_on_membership_alone_say_so() {
        // The supposition four families share and the fifth breaks. Naming the
        // four rather than iterating `ALL` is deliberate: a new family must
        // answer this question by being added here, not inherit an answer from
        // a loop that never mentions it.
        for family in [Family::Debian, Family::Arch, Family::Alpine, Family::Rhel] {
            assert!(
                for_family(family).admin_group_grants_alone(),
                "{family} grants on membership and must say so"
            );
        }
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
