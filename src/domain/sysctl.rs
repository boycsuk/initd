//! Kernel parameter capability.
//!
//! A capability of its own rather than a detail inside the tasks that need it,
//! because the parameters are shared by components that know nothing about each
//! other: `net.ipv4.ip_forward` is required by WireGuard and
//! `net.ipv4.ip_unprivileged_port_start` by rootless Docker, and both are the
//! same file on disk.
//!
//! Field evidence for the split: a repository this design was reviewed against
//! configured forwarding twice, from two scripts, by two different mechanisms —
//! one appending to `/etc/sysctl.conf`, the other writing `/etc/sysctl.d/`.
//! Either alone works; together they drift, and the value that survives a
//! reboot is whichever is read last.

use crate::error::Result;
use crate::exec::Executor;

/// A kernel parameter and the value a task needs it to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// Dotted name, as `sysctl` spells it.
    pub key: &'static str,
    /// The value required.
    pub value: &'static str,
}

/// Reads and sets kernel parameters.
pub trait SysctlManager {
    /// The value a parameter currently holds.
    fn get(&self, executor: &dyn Executor, key: &str) -> Result<String>;

    /// Sets a parameter now and across reboots.
    ///
    /// Both halves are required and neither is sufficient: a value applied only
    /// at runtime is gone after a reboot, and one written only to a file has
    /// not taken effect yet — a task that did either alone would report success
    /// over a system that does not behave as described.
    ///
    /// Implementations must write to a dedicated drop-in rather than appending
    /// to a shared file, so that repeating the operation replaces the previous
    /// value instead of accumulating contradictory lines.
    fn set(&self, executor: &dyn Executor, setting: Setting) -> Result<()>;

    /// Whether a parameter already holds the value a task needs.
    fn holds(&self, executor: &dyn Executor, setting: Setting) -> Result<bool> {
        Ok(self.get(executor, setting.key)?.trim() == setting.value)
    }
}
