//! APT's unattended-upgrades, as [`AutomaticUpdates`].
//!
//! Debian's mechanism, and the only one implemented: the other four families
//! declare `updates.unattended-security` unsupported, each for its own reason
//! recorded beside the declaration. This exists so those reasons are the only
//! thing keeping them out — before it, the task wrote `/etc/apt` paths itself,
//! so a family that named a package would still have had an APT policy file
//! written onto it.

use crate::domain::automatic_updates::{AutomaticUpdates, UpdatePolicy};
use crate::domain::files::FileEditor;
use crate::error::Result;
use crate::exec::{Command, Executor};

/// Configures updates through `APT::Periodic`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AptPeriodic;

impl AptPeriodic {
    pub const fn new() -> Self {
        Self
    }

    /// Where this tool's policy is written.
    ///
    /// A drop-in of its own, numbered `51` so it is read after the package's
    /// own `50unattended-upgrades` and wins without that file being edited —
    /// the administrator's copy stays theirs, and re-running replaces this file
    /// rather than appending to a shared one.
    ///
    /// Note the filename carries no second dot: APT ignores drop-ins whose
    /// name contains one unless the suffix is `.conf`, the same rule that makes
    /// `/etc/sudoers.d/alice.conf` silently ignored.
    const POLICY: &'static str = "/etc/apt/apt.conf.d/51initd-unattended";

    /// The unit that actually performs the upgrade.
    const TIMER: &'static str = "apt-daily-upgrade.timer";
}

impl AutomaticUpdates for AptPeriodic {
    fn configure(&self, executor: &dyn Executor, policy: UpdatePolicy) -> Result<()> {
        // `Unattended-Upgrade::Allowed-Origins` decides what is taken, and the
        // package's own `50unattended-upgrades` already restricts it to the
        // security suites on a stock install. Restating it here would mean
        // naming Debian's suites, which move between releases; what this file
        // adds is the periodic schedule and the refusal to reboot.
        let update_lists = u8::from(policy.security_only);
        let reboot = if policy.automatic_reboot {
            "true"
        } else {
            "false"
        };

        let contents = format!(
            "// Managed by initd.\n\
             APT::Periodic::Update-Package-Lists \"{update_lists}\";\n\
             APT::Periodic::Unattended-Upgrade \"1\";\n\
             Unattended-Upgrade::Automatic-Reboot \"{reboot}\";\n"
        );

        FileEditor::write(
            &crate::backend::unix_files::UnixFiles,
            executor,
            Self::POLICY,
            &contents,
        )?;

        Ok(())
    }

    fn is_scheduled(&self, executor: &dyn Executor) -> Result<bool> {
        // Read back rather than assumed: the package ships a debconf question
        // whose answer decides whether any of this runs, and a policy file
        // alone does not enable the timer.
        let check = Command::new("systemctl").args(["is-enabled", Self::TIMER]);

        Ok(executor.run(&check)?.stdout.trim() == "enabled")
    }

    fn timer(&self) -> &'static str {
        Self::TIMER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn the_policy_takes_updates_and_refuses_to_reboot() {
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok(""), Reply::ok("")]);

        AptPeriodic::new()
            .configure(&mock, UpdatePolicy::SECURITY_ONLY)
            .expect("writing the policy must succeed");

        let written = mock
            .recorded()
            .iter()
            .find_map(|command| {
                (command.program == "tee")
                    .then(|| command.stdin.clone())
                    .flatten()
            })
            .expect("the policy must be written");

        assert!(
            written.contains("APT::Periodic::Unattended-Upgrade \"1\""),
            "{written}"
        );
        assert!(
            written.contains("Unattended-Upgrade::Automatic-Reboot \"false\""),
            "a tool that reboots on its own schedule cannot be planned around: {written}"
        );
    }

    #[test]
    fn the_policy_lands_in_a_drop_in_of_its_own() {
        // Not an edit to `50unattended-upgrades`, which is the package's file
        // and the administrator's to change.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok(""), Reply::ok("")]);

        AptPeriodic::new()
            .configure(&mock, UpdatePolicy::SECURITY_ONLY)
            .expect("writing the policy must succeed");

        let commands = mock.recorded_lines();

        assert!(
            commands
                .iter()
                .any(|command| command.contains("51initd-unattended")),
            "{commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.contains("50unattended-upgrades")),
            "the package's own file must be left alone: {commands:?}"
        );
    }

    #[test]
    fn a_timer_that_is_not_enabled_is_reported_as_such() {
        // The case the debconf question produces: the policy is written and
        // nothing ever runs it.
        let enabled = MockExecutor::with_replies([Reply::ok("enabled\n")]);
        let disabled = MockExecutor::with_replies([Reply::ok("disabled\n")]);

        assert!(
            AptPeriodic::new()
                .is_scheduled(&enabled)
                .expect("the query must succeed")
        );
        assert!(
            !AptPeriodic::new()
                .is_scheduled(&disabled)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn the_timer_is_named_for_a_report_that_can_be_acted_on() {
        assert_eq!(AptPeriodic::new().timer(), "apt-daily-upgrade.timer");
    }
}
