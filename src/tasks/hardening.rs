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
use crate::tasks::consequence::{Check, Conflict, Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Support, Task, report};

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
                    Node::Task(Box::new(InstallFail2ban)),
                    Node::Task(Box::new(InstallCrowdsec)),
                ],
            )),
            Node::Task(Box::new(UnattendedUpgrades)),
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

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::SSH_PORT, "SSH port", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .with_hint("the port the jail watches"),
        ]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            Family::Debian | Family::Arch | Family::Alpine => Support::Yes,
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

        backend.files().write(executor, Self::JAIL, &jail)?;

        backend
            .services()
            .enable_and_start(executor, backend.service_for(Capability::Fail2ban))?;

        report(progress, format!("watching {port} for repeated failures"));

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

    /// It sends data off the machine, which is a decision rather than a
    /// setting — an administrator should be asked before it starts.
    fn is_destructive(&self) -> bool {
        true
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

        report(progress, "crowdsec is running".to_owned());
        report(
            progress,
            "it detects and decides; install a bouncer to make it block".to_owned(),
        );

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

        report(
            progress,
            "security updates will be applied automatically".to_owned(),
        );
        report(progress, "reboots stay yours to schedule".to_owned());

        Ok(Outcome::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};

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
        assert!(InstallCrowdsec.is_destructive());
        assert!(!InstallFail2ban.is_destructive());
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
        // a structure. Now the backend has to offer a mechanism, and three of
        // the four families offer none.
        for family in [Family::Arch, Family::Alpine, Family::Rhel] {
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
            Reply::ok(""),        // install
            Reply::ok(""),        // the policy file exists?
            Reply::ok(""),        // back it up
            Reply::ok(""),        // write it
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
