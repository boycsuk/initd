//! Unattended security update capability.
//!
//! A capability rather than a detail inside the task, because "apply security
//! updates without waiting for someone to log in" is the same intent
//! everywhere and almost nothing about expressing it survives the crossing.
//! APT reads `APT::Periodic::*` keys from `/etc/apt/apt.conf.d` and enables
//! `apt-daily-upgrade.timer`; dnf reads an ini file at
//! `/etc/dnf/automatic.conf` and enables `dnf-automatic.timer`. The file, its
//! syntax, and the unit that runs it differ — only the intent is shared.
//!
//! The task previously wrote the APT form directly while calling itself
//! `updates.unattended-security`, which made the `Capability` indirection for
//! the *package name* decorative: even had another family named a package, the
//! task would have written an APT policy into `/etc/apt` on it. Declaring the
//! task unsupported elsewhere kept that correct, and made the shape of the code
//! disagree with the shape of the problem.
//!
//! Two properties every implementation owes the caller:
//!
//! 1. **Security updates only.** A feature upgrade that changes behaviour is
//!    the administrator's to schedule, and a mechanism that took both would be
//!    one nobody could leave running.
//! 2. **No automatic reboot.** A tool that reboots a server on its own
//!    schedule is one nobody can plan around. The consequence says a reboot may
//!    be needed; taking it is not this task's decision.

use crate::error::Result;
use crate::exec::Executor;

/// What the administrator asked for, independent of how it is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdatePolicy {
    /// Whether to take only security updates.
    ///
    /// Always `true` today. Present as a field rather than assumed because the
    /// distinction is the point of the task, and an implementation that
    /// silently took everything would be a different operation under the same
    /// name.
    pub security_only: bool,
    /// Whether the mechanism may reboot the host on its own.
    ///
    /// Always `false` today, for the reason in the module docs.
    pub automatic_reboot: bool,
}

impl UpdatePolicy {
    /// The policy this tool offers: security updates, no reboot.
    pub const SECURITY_ONLY: Self = Self {
        security_only: true,
        automatic_reboot: false,
    };
}

/// Configures unattended updates on the administered system.
pub trait AutomaticUpdates {
    /// Writes the configuration expressing `policy`.
    ///
    /// The package is installed by the caller through `Capability`, since that
    /// is a name rather than a behaviour; everything after it is here.
    fn configure(&self, executor: &dyn Executor, policy: UpdatePolicy) -> Result<()>;

    /// Whether the mechanism is actually scheduled to run.
    ///
    /// Asked rather than assumed, and separate from `configure` because
    /// writing a policy file does not start anything: on Debian the package
    /// ships a debconf question whose answer decides whether the timer is
    /// enabled at all, so a configured host that never runs an upgrade is an
    /// ordinary outcome worth reporting rather than a failure to write.
    fn is_scheduled(&self, executor: &dyn Executor) -> Result<bool>;

    /// The unit that runs it, for a report naming what to enable.
    fn timer(&self) -> &'static str;
}
