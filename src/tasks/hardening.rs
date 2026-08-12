//! Brute-force protection and unattended security updates.
//!
//! Defence in depth rather than a gap being plugged. `ssh.harden` already
//! writes `MaxAuthTries 3` and `LoginGraceTime 30`, and with key-only
//! authentication a password cannot be brute-forced at all — so nothing here
//! is required for a hardened host, and a tool that implied otherwise would be
//! selling something.
//!
//! What these do add is the noise floor: a banner drops the addresses that
//! knock repeatedly, which keeps the log readable and costs an attacker their
//! cheapest option.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::UpdatePolicy;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{Check, Conflict, Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Confirmation, Node, Progress, Support, Task, report};

/// The port SSH listens on unless it has been moved.
const DEFAULT_SSH_PORT: u32 = 22;

/// Builds the hardening category.
pub fn category() -> Category {
    Category::new(
        "Hardening",
        vec![
            Node::Category(Category::new(
                "Brute-force protection",
                vec![
                    Node::Reversible {
                        forward: Box::new(InstallFail2ban),
                        inverse: Box::new(UninstallFail2ban),
                    },
                    Node::Reversible {
                        forward: Box::new(InstallCrowdsec),
                        inverse: Box::new(UninstallCrowdsec),
                    },
                ],
            )),
            Node::Reversible {
                forward: Box::new(UnattendedUpgrades),
                inverse: Box::new(DisableUnattendedUpgrades),
            },
        ],
    )
}

/// Installs fail2ban and protects the SSH port with it.
pub struct InstallFail2ban;

impl InstallFail2ban {
    /// Name of the parameter holding the port to watch.
    pub const SSH_PORT: &'static str = "ssh_port";

    /// Where the jail this tool owns is written.
    ///
    /// A drop-in of its own rather than an edit to `jail.local`, which the
    /// administrator and the distribution also write to. Note the filename
    /// carries no second dot: the same rule that makes
    /// `/etc/sudoers.d/alice.conf` silently ignored applies to several
    /// drop-in directories, so a plain name is the safe habit.
    const JAIL: &'static str = "/etc/fail2ban/jail.d/initd-sshd.conf";
}

impl Task for InstallFail2ban {
    fn id(&self) -> &'static str {
        "fail2ban.install"
    }

    fn title(&self) -> &'static str {
        "Install fail2ban"
    }

    fn description(&self) -> &'static str {
        "Watches the authentication log and bans addresses that fail \
         repeatedly. Everything stays on this host — nothing is reported \
         anywhere."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fail2ban)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fail2ban.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::SSH_PORT, "SSH port", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .with_hint("the port the jail watches"),
        ]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // Packaged in openSUSE's own repositories on both variants, which
            // is the difference from RHEL below: same rpm ecosystem, and this
            // one carries it without a third-party repository.
            Family::Debian | Family::Arch | Family::Alpine | Family::Suse => Support::Yes,
            Family::Rhel => Support::No(
                "has never been in a base repository, in any release. Being \
                 Python there is no static binary to verify, and `sshguard` is \
                 EPEL-only too — RHEL ships no log-scanning tool of its own",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Not a warning that something broke: a statement that these two do
        // not belong on one host. Both write ban rules through the firewall
        // and neither observes the other's, so a host running both bans twice
        // and unbans unpredictably.
        vec![Consequence::Conflicts {
            task: "crowdsec.install",
            over: Conflict::BanRules,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let port = values.port(Self::SSH_PORT)?;

        backend
            .packages()
            .install(executor, backend.package_for(Capability::Fail2ban))?;

        // The jail names the port explicitly rather than relying on the `ssh`
        // service name, which resolves through /etc/services and therefore
        // means 22 whatever sshd is actually listening on.
        let jail = format!(
            "# Managed by initd.\n\
             [sshd]\n\
             enabled = true\n\
             port = {port}\n\
             maxretry = 5\n\
             bantime = 1h\n\
             findtime = 10m\n"
        );

        let backup = backend.files().write(executor, Self::JAIL, &jail)?;

        // Only where a jail was already there — this file is one this tool
        // owns, so the ordinary case is creating it and there is no previous
        // version to keep. Re-running with a different port is the case that
        // records: the state worth going back to is the port that was watched
        // before.
        crate::backend::backup_index::record_and_report(
            executor,
            backend.files(),
            self.id(),
            backup.as_ref(),
            backend.service_for(Capability::Fail2ban),
            progress,
        );

        backend
            .services()
            .enable_and_start(executor, backend.service_for(Capability::Fail2ban))?;

        report(
            progress,
            &Msg::TaskWatchingForFailures {
                service: port.to_string(),
            },
        );

        Ok(Outcome::Done)
    }
}

/// Installs CrowdSec.
pub struct InstallCrowdsec;

impl Task for InstallCrowdsec {
    fn id(&self) -> &'static str {
        "crowdsec.install"
    }

    fn title(&self) -> &'static str {
        "Install CrowdSec"
    }

    fn description(&self) -> &'static str {
        "Bans addresses that attacked other hosts before they reach this one, \
         by consulting a shared reputation network. In exchange this host \
         reports the attacks it sees."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Crowdsec)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["crowdsec.install"]
    }

    /// It sends data off the machine, which is a decision rather than a
    /// setting — an administrator should be asked before it starts.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Change
    }

    fn support(&self, family: Family) -> Support {
        match family {
            Family::Debian | Family::Arch => Support::Yes,
            Family::Alpine => Support::No(
                "Alpine does not package it, so the task is shown unsupported \
                 rather than being offered a package name `apk` would reject",
            ),
            Family::Rhel => Support::No(
                "publishes no checksums with its releases, and its documented \
                 install pipes a script into a shell to register a repository \
                 — the pattern this project rejects in its own installer",
            ),
            Family::Suse => Support::No(
                "absent from both Tumbleweed's and Leap's repositories, \
                 searched with and without exact matching. The route left is \
                 the one RHEL refuses for the same reason: releases carrying \
                 no checksums, installed by a script piped into a shell",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        vec![
            Consequence::Conflicts {
                task: "fail2ban.install",
                over: Conflict::BanRules,
            },
            // The bouncer is what actually blocks. Without it CrowdSec detects
            // and decides and nothing enforces, which reads as a working
            // install right up until an attack is not stopped.
            Consequence::Invalidates {
                task: "crowdsec.install",
                reason: Reason::RequiresSetting {
                    setting: "a bouncer — the agent decides, it does not block",
                },
                check: Some(Check {
                    command: Command::new("cscli").args(["bouncers", "list"]),
                    resolved_when_stdout_contains: "firewall".to_owned(),
                }),
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        backend
            .packages()
            .install(executor, backend.package_for(Capability::Crowdsec))?;

        backend
            .services()
            .enable_and_start(executor, backend.service_for(Capability::Crowdsec))?;

        report(
            progress,
            &Msg::TaskServiceRunning {
                service: "crowdsec".to_owned(),
            },
        );
        report(progress, &Msg::TaskCrowdsecDetectsOnly);

        Ok(Outcome::Done)
    }
}

/// Applies security updates without being asked.
///
/// Holds no path and no syntax. Where the policy is written and how it is
/// spelled belong to the family — this task names the intent and lets
/// [`crate::domain::AutomaticUpdates`] express it.
pub struct UnattendedUpgrades;

impl Task for UnattendedUpgrades {
    fn id(&self) -> &'static str {
        "updates.unattended-security"
    }

    fn title(&self) -> &'static str {
        "Apply security updates automatically"
    }

    fn description(&self) -> &'static str {
        "Installs security updates as they are published, without waiting for \
         someone to log in. Security only — a feature upgrade that changes \
         behaviour is still yours to decide."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::UnattendedUpgrades)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["updates.unattended-security"]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            Family::Debian => Support::Yes,
            Family::Arch => Support::No(
                "a rolling release with no equivalent mechanism: upgrading it \
                 unattended means pulling whatever landed today, including \
                 changes that need manual intervention",
            ),
            Family::Alpine => Support::No(
                "Alpine ships no unattended-upgrades equivalent; inventing one \
                 under this task id would make the families silently disagree \
                 about what the task does",
            ),
            Family::Rhel => Support::No(
                "packaged, but under a name that moved: `dnf-automatic` on \
                 RHEL 9, `dnf5-plugin-automatic` on RHEL 10, with four timers \
                 collapsed to one. The backend resolves a family rather than a \
                 release, so it cannot name both — and either name is wrong on \
                 half the family",
            ),
            Family::Suse => Support::No(
                "the mechanism depends on how the host was installed rather \
                 than on the family: a transactional host updates through \
                 `transactional-update` and an ordinary one through zypper's \
                 own timer, and the two reboot differently. The backend \
                 resolves a family, so it cannot tell which this is",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Says plainly that it will not reboot. An administrator who assumes it
        // does is one running a patched kernel that is not the running kernel.
        vec![Consequence::Invalidates {
            task: "updates.unattended-security",
            reason: Reason::NeedsRestart {
                service: "the host, for a kernel update to take effect",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // Asked of the backend rather than assumed to exist. A family with no
        // mechanism is not a family where this quietly does nothing: the task
        // declares itself unsupported there, and this is the guard that makes
        // the declaration structural rather than a promise.
        let updates = backend
            .automatic_updates()
            .ok_or(Error::CapabilityUnavailable {
                capability: "unattended updates",
            })?;

        backend.packages().install(
            executor,
            backend.package_for(Capability::UnattendedUpgrades),
        )?;

        // Security only, and no automatic reboot. A tool that reboots a server
        // on its own schedule is one nobody can plan around; the consequence
        // says a reboot is needed rather than taking it. How that is spelled —
        // which file, which syntax — belongs to the family, not here.
        updates.configure(executor, UpdatePolicy::SECURITY_ONLY)?;

        // Read back rather than assumed: on Debian the package ships a debconf
        // question whose answer decides whether any of this runs, and a policy
        // file alone does not enable the timer.
        if !updates.is_scheduled(executor)? {
            return Err(Error::TimerNotEnabled {
                timer: updates.timer().to_owned(),
            });
        }

        report(progress, &Msg::TaskUpgradesAutomatic);
        report(progress, &Msg::TaskUpgradesNoReboot);

        Ok(Outcome::Done)
    }
}

/// Removes fail2ban.
pub struct UninstallFail2ban;

impl Task for UninstallFail2ban {
    fn id(&self) -> &'static str {
        "fail2ban.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall fail2ban"
    }

    fn description(&self) -> &'static str {
        "Stops fail2ban, disables it at boot and removes it. Addresses it had \
         banned are unbanned by the daemon stopping — the bans live in its \
         own state, not in the firewall's saved ruleset."
    }

    fn support(&self, family: Family) -> Support {
        InstallFail2ban.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fail2ban)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fail2ban.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Fail2ban)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // The machine goes back to admitting unlimited authentication
        // attempts. Worth saying out loud: an operator removing fail2ban to
        // install crowdsec has a window between the two where neither watches.
        vec![Consequence::Invalidates {
            task: "fail2ban.install",
            reason: Reason::RequiresSetting {
                setting: "nothing now rate-limits repeated authentication failures",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Fail2ban,
            "fail2ban",
        )
    }
}

/// Removes CrowdSec.
pub struct UninstallCrowdsec;

impl Task for UninstallCrowdsec {
    fn id(&self) -> &'static str {
        "crowdsec.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall CrowdSec"
    }

    fn description(&self) -> &'static str {
        "Stops CrowdSec, disables it at boot and removes it. This host stops \
         contributing what it sees to the reputation network, and stops \
         benefiting from what the network has seen."
    }

    fn support(&self, family: Family) -> Support {
        InstallCrowdsec.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Crowdsec)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["crowdsec.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Crowdsec)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        vec![Consequence::Invalidates {
            task: "crowdsec.install",
            reason: Reason::RequiresSetting {
                setting: "nothing now blocks addresses the network has seen attacking others",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Crowdsec,
            "crowdsec",
        )
    }
}

/// Stops applying security updates automatically.
pub struct DisableUnattendedUpgrades;

impl Task for DisableUnattendedUpgrades {
    fn id(&self) -> &'static str {
        "updates.unattended-security.disable"
    }

    fn title(&self) -> &'static str {
        "Stop applying security updates automatically"
    }

    fn description(&self) -> &'static str {
        "Removes unattended-upgrades. Security updates stop being applied \
         without anyone asking — which is the point of removing it, and worth \
         stating because the machine goes on looking exactly the same."
    }

    fn support(&self, family: Family) -> Support {
        UnattendedUpgrades.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::UnattendedUpgrades)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["updates.unattended-security"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::UnattendedUpgrades)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // The one uninstall here whose effect is invisible: nothing stops
        // working, updates simply stop arriving. A host left in this state
        // looks healthy for as long as it takes to matter.
        vec![Consequence::Invalidates {
            task: "updates.unattended-security",
            reason: Reason::RequiresSetting {
                setting: "security updates now need applying by hand",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::UnattendedUpgrades,
            "unattended-upgrade",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::Confirmation;

    fn port_values(port: u32) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(InstallFail2ban::SSH_PORT, port.to_string());
        values
    }

    #[test]
    fn the_two_banners_each_name_the_other() {
        // Not a warning that something broke: a statement that these do not
        // belong on one host. Both write ban rules through the firewall and
        // neither observes the other's.
        let fail2ban =
            InstallFail2ban.consequences(for_family(Family::Debian).as_ref(), &port_values(22));
        let crowdsec =
            InstallCrowdsec.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        assert!(
            fail2ban.iter().any(
                |c| matches!(c, Consequence::Conflicts { task, .. } if *task == "crowdsec.install")
            ),
            "{fail2ban:?}"
        );
        assert!(
            crowdsec.iter().any(
                |c| matches!(c, Consequence::Conflicts { task, .. } if *task == "fail2ban.install")
            ),
            "{crowdsec:?}"
        );
    }

    #[test]
    fn a_conflict_offers_no_verification() {
        // The tool cannot tell which one the administrator meant to keep, so
        // there is nothing here for it to settle.
        let consequences =
            InstallFail2ban.consequences(for_family(Family::Debian).as_ref(), &port_values(22));

        let conflict = consequences
            .iter()
            .find(|c| matches!(c, Consequence::Conflicts { .. }))
            .expect("the conflict must be declared");

        assert!(conflict.check().is_none());
        assert!(!conflict.is_external(), "the other task is on this host");
    }

    #[test]
    fn the_jail_names_the_port_rather_than_the_service() {
        // `port = ssh` resolves through /etc/services and therefore means 22
        // whatever sshd is actually listening on — a jail watching a port
        // nobody knocks on.
        let mock = MockExecutor::with_replies([
            Reply::ok(""), // apt-get update, before the install
            Reply::ok(""), // install
            Reply::ok(""), // write the jail
            Reply::ok(""), // enable
        ]);
        let backend = for_family(Family::Debian);

        InstallFail2ban
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("installing must succeed");

        let jail = mock
            .recorded()
            .into_iter()
            .find_map(|c| c.stdin)
            .expect("the jail must be written");

        assert!(jail.contains("port = 2222"), "{jail}");
        assert!(!jail.contains("port = ssh"), "{jail}");
    }

    #[test]
    fn crowdsec_says_it_does_not_block_on_its_own() {
        // Without a bouncer it detects and decides and nothing enforces, which
        // reads as a working install right up until an attack is not stopped.
        let consequences =
            InstallCrowdsec.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        let bouncer = consequences
            .iter()
            .find(|c| matches!(c, Consequence::Invalidates { .. }))
            .expect("the missing bouncer must be declared");

        assert!(bouncer.check().is_some(), "it is answerable from this host");
    }

    #[test]
    fn sending_data_off_the_machine_is_confirmed_first() {
        // A reputation network is a decision, not a setting.
        assert!(InstallCrowdsec.confirmation() == Confirmation::Change);
        assert!(InstallFail2ban.confirmation() == Confirmation::Change);
    }

    #[test]
    fn unattended_upgrades_are_debian_only() {
        // Arch is a rolling release with no equivalent: upgrading it unattended
        // means pulling whatever landed today. The TUI greys the task out with
        // the reason rather than the tool inventing a different operation.
        assert!(UnattendedUpgrades.supports(Family::Debian));
        assert!(!UnattendedUpgrades.supports(Family::Arch));
    }

    #[test]
    fn a_family_without_a_mechanism_offers_none_to_write_with() {
        // The shape this refactor bought. The task used to build `/etc/apt`
        // paths and APT syntax itself, so the only thing keeping an APT policy
        // off an Arch host was the support declaration — a promise rather than
        // a structure. Now the backend has to offer a mechanism, and four of
        // the five families offer none.
        for family in [Family::Arch, Family::Alpine, Family::Rhel, Family::Suse] {
            assert!(
                for_family(family).automatic_updates().is_none(),
                "{family} must offer no mechanism"
            );
        }

        assert!(
            for_family(Family::Debian).automatic_updates().is_some(),
            "Debian is the one family with one"
        );
    }

    #[test]
    fn arch_packages_no_unattended_upgrades() {
        // The empty name is the honest answer, and it is what keeps the task
        // from being offered there.
        assert!(!for_family(Family::Arch).has_package_for(Capability::UnattendedUpgrades));
        assert!(for_family(Family::Debian).has_package_for(Capability::UnattendedUpgrades));
    }

    #[test]
    fn upgrades_never_reboot_on_their_own() {
        // A tool that reboots a server on its own schedule is one nobody can
        // plan around. The consequence says a reboot is needed instead.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),        // apt-get update, before the install
            Reply::ok(""),        // install
            Reply::ok(""),        // the policy file exists?
            Reply::ok(""),        // back it up
            Reply::ok(""),        // stage it
            Reply::ok("644"),     // stat -c %a
            Reply::ok(""),        // chmod
            Reply::ok(""),        // mv: publish it
            Reply::ok("enabled"), // the timer is on
        ]);
        let backend = for_family(Family::Debian);

        UnattendedUpgrades
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("the task must succeed");

        let policy = mock
            .recorded()
            .into_iter()
            .find_map(|c| c.stdin)
            .expect("the policy must be written");

        assert!(policy.contains("Automatic-Reboot \"false\""), "{policy}");
    }

    #[test]
    fn a_policy_nothing_will_apply_is_an_error() {
        // Writing the file does not start anything: the package ships a debconf
        // question whose answer decides whether the timer runs at all.
        let mock =
            MockExecutor::with_replies([Reply::ok(""), Reply::ok(""), Reply::ok("disabled")]);
        let backend = for_family(Family::Debian);

        let err = UnattendedUpgrades
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect_err("a disabled timer must fail");

        assert!(matches!(err, Error::TimerNotEnabled { .. }), "{err:?}");
    }

    #[test]
    fn the_reboot_is_declared_rather_than_taken() {
        let consequences = UnattendedUpgrades
            .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        assert!(
            matches!(
                consequences[0],
                Consequence::Invalidates {
                    reason: Reason::NeedsRestart { .. },
                    ..
                }
            ),
            "{consequences:?}"
        );
    }

    #[test]
    fn the_jail_filename_carries_no_second_dot() {
        // The same rule that makes /etc/sudoers.d/alice.conf silently ignored
        // applies to several drop-in directories, so a plain name is the safe
        // habit rather than a coincidence.
        let name = InstallFail2ban::JAIL
            .rsplit('/')
            .next()
            .expect("the path has a filename");

        assert_eq!(name.matches('.').count(), 1, "{name} has an extra dot");
    }
}
