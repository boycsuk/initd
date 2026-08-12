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
    /// Whether the tool that reads and writes them is on this host.
    ///
    /// Asked for the same reason [`FirewallManager`](crate::domain::firewall::FirewallManager)
    /// asks it, and added after the omission was collected on: `sysctl` is
    /// packaged separately on four of the five families and absent from a
    /// freshly provisioned RHEL, so a task going straight to it fails with a
    /// missing binary — which reads as a broken tool rather than a package
    /// nobody installed.
    ///
    /// The two halves of the operation fail differently, which is why this is
    /// asked once up front instead of being inferred from either. Reading runs
    /// unprivileged and raises [`Error::ProgramNotFound`](crate::error::Error);
    /// writing is wrapped in `sudo`, so the binary that gets spawned *exists*
    /// and what comes back is an exit code 127 with `sudo: sysctl: command not
    /// found` on stderr — a generic command failure carrying the real cause in
    /// text nothing parses.
    ///
    /// An absent binary must answer `false` rather than raise, or this repeats
    /// the defect it exists to fix one layer up.
    fn is_available(&self, executor: &dyn Executor) -> Result<bool>;

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
    ///
    /// Only the running value: this answers "is it in effect", not "will it
    /// survive". [`Self::is_persisted`] answers the other half, and callers
    /// deciding whether there is work to do need both.
    fn holds(&self, executor: &dyn Executor, setting: Setting) -> Result<bool> {
        Ok(self.get(executor, setting.key)?.trim() == setting.value)
    }

    /// Whether this tool's drop-in already records the value.
    ///
    /// Asked because the running value alone cannot answer it. A kernel may
    /// hold the right value for reasons that do not outlive a reboot — another
    /// tool set it, an image ships it that way, a container inherits it — and
    /// a task that stopped at [`Self::holds`] would report success over a host
    /// where the setting vanishes on restart. Docker is the case that surfaced
    /// it: `net.ipv4.ip_forward` is already `1` in every container, so the
    /// task did nothing and said it was done.
    fn is_persisted(&self, executor: &dyn Executor, setting: Setting) -> Result<bool>;
}
