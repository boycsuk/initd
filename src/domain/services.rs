//! Service management capability.

use crate::error::Result;
use crate::exec::Executor;

/// Whether a service is running and whether it starts at boot.
///
/// Both are reported because they are independent: a service can be running
/// but disabled, which after a reboot means it is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceState {
    pub active: bool,
    pub enabled: bool,
}

/// Enables, starts and reloads services.
///
/// Implementations know their distribution's unit names: SSH is `ssh.service`
/// on Debian and `sshd.service` on Arch.
pub trait ServiceManager {
    /// Starts the service now and enables it at boot.
    fn enable_and_start(&self, executor: &dyn Executor, service: &str) -> Result<()>;

    /// Re-reads configuration without dropping existing connections.
    ///
    /// Preferred over restarting for SSH: a restart would cut the very session
    /// the administrator is connected through.
    fn reload(&self, executor: &dyn Executor, service: &str) -> Result<()>;

    /// Reports whether the service is active and enabled.
    fn state(&self, executor: &dyn Executor, service: &str) -> Result<ServiceState>;

    /// Stops the service now and stops it starting at boot.
    ///
    /// The exact inverse of [`enable_and_start`](Self::enable_and_start), and
    /// both halves are load-bearing: a unit that was stopped but left enabled
    /// is running again after a reboot, having reported that it was stopped.
    /// That is the same shape of mistake the firewall made by writing rules the
    /// boot never replayed.
    ///
    /// Succeeds when the unit does not exist. Removing a package takes its unit
    /// with it, so an uninstall that stops the service after removing the
    /// package would otherwise fail at the last step having done everything it
    /// was asked.
    fn disable_and_stop(&self, executor: &dyn Executor, service: &str) -> Result<()>;
}
