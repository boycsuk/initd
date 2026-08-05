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
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, OutputLine, Stream};
use crate::tasks::consequence::{Check, Conflict, Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Task};

/// Families supporting the log-parsing banner.
const SUPPORTED: &[Family] = &[Family::Debian, Family::Arch, Family::Alpine];

/// Families packaging the reputation-network banner.
///
/// Alpine does not, so the task is shown unsupported there rather than being
/// offered a package name `apk` would reject.
const CROWDSEC_SUPPORTED: &[Family] = &[Family::Debian, Family::Arch];

/// Families supporting unattended upgrades.
///
/// Debian only, and deliberately. Arch is a rolling release with no equivalent
/// mechanism: upgrading it unattended means pulling whatever landed today,
/// including changes that need manual intervention. Inventing a different
/// operation under the same task id would make the two families silently
/// disagree about what the task does.
const UPGRADE_SUPPORTED: &[Family] = &[Family::Debian];

/// The port SSH listens on unless it has been moved.
const DEFAULT_SSH_PORT: u32 = 22;

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

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

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
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

    fn supported_families(&self) -> &'static [Family] {
        CROWDSEC_SUPPORTED
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
pub struct UnattendedUpgrades;

impl UnattendedUpgrades {
    /// Where the policy this tool writes lives.
    const POLICY: &'static str = "/etc/apt/apt.conf.d/51initd-unattended";
}

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

    fn supported_families(&self) -> &'static [Family] {
        UPGRADE_SUPPORTED
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
        backend.packages().install(
            executor,
            backend.package_for(Capability::UnattendedUpgrades),
        )?;

        // Security only, and no automatic reboot. A tool that reboots a server
        // on its own schedule is one nobody can plan around; the consequence
        // says a reboot is needed rather than taking it.
        //
        // `51` orders this after the package's own `50unattended-upgrades`, so
        // these values win without that file being edited.
        let policy = "// Managed by initd.\n\
             APT::Periodic::Update-Package-Lists \"1\";\n\
             APT::Periodic::Unattended-Upgrade \"1\";\n\
             Unattended-Upgrade::Automatic-Reboot \"false\";\n";

        backend.files().write(executor, Self::POLICY, policy)?;

        // Read back rather than assumed: the package ships a debconf question
        // whose answer decides whether any of this runs, and a policy file
        // alone does not enable the timer.
        let check = Command::new("systemctl").args(["is-enabled", "apt-daily-upgrade.timer"]);

        if executor.run(&check)?.stdout.trim() != "enabled" {
            return Err(Error::TimerNotEnabled {
                timer: "apt-daily-upgrade.timer".to_owned(),
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
