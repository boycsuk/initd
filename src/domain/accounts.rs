//! Account lookup capability.
//!
//! Restricting SSH to a named set of accounts is only safe if those accounts
//! exist: `AllowUsers admn` is a configuration `sshd -t` accepts and that
//! matches nobody, so every login is refused. The check needs a capability of
//! its own because the command that answers it is not universal — `getent` is
//! absent from busybox, which Alpine ships.

use crate::error::Result;
use crate::exec::Executor;

/// Queries the accounts defined on the administered system.
pub trait AccountReader {
    /// Whether an account with this name exists.
    fn exists(&self, executor: &dyn Executor, user: &str) -> Result<bool>;
}
