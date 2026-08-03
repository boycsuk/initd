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
}
