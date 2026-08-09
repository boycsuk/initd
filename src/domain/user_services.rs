//! Per-user service capability.
//!
//! Distinct from [`super::services::ServiceManager`], which drives system
//! units. A rootless container engine runs as an ordinary account, under that
//! account's own service manager, and the two are not the same thing: the
//! system manager cannot see a user unit and `systemctl --user` cannot see a
//! system one.
//!
//! Lingering is the part that has no analogue above. A user's services stop
//! when their last session ends unless the account is explicitly allowed to
//! keep them running, so a container engine installed without it dies at
//! logout and — because a user unit is wanted by `default.target` rather than
//! by anything the system reaches at boot — never comes back after a reboot.

use crate::error::Result;
use crate::exec::Executor;

/// Manages services belonging to one account.
pub trait UserServiceManager {
    /// Whether the account may keep services running with no session open.
    fn is_lingering(&self, executor: &dyn Executor, user: &str) -> Result<bool>;

    /// Allows the account to keep services running with no session open.
    fn enable_linger(&self, executor: &dyn Executor, user: &str) -> Result<()>;

    /// Enables and starts one of the account's own services.
    fn enable_and_start(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<()>;

    /// Whether one of the account's services is running.
    fn is_active(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<bool>;

    /// Stops one of the account's services and stops it starting at login.
    ///
    /// Succeeds when the unit does not exist, for the same reason the
    /// system-wide [`disable_and_stop`](crate::domain::ServiceManager::disable_and_stop)
    /// does: an uninstall that removed the engine took its unit with it.
    fn disable_and_stop(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<()>;

    /// Stops the account keeping services running with no session open.
    ///
    /// The inverse of [`enable_linger`](Self::enable_linger). Left behind, it
    /// is a lingering account with nothing to linger for — harmless, and
    /// exactly the kind of residue that makes an uninstall untrustworthy.
    fn disable_linger(&self, executor: &dyn Executor, user: &str) -> Result<()>;

    /// The subordinate UID and GID ranges delegated to the account.
    ///
    /// A rootless engine maps container users onto this range, so an account
    /// without one cannot start a container at all. Reported rather than
    /// assumed because the range is allocated when the account is created and
    /// a system that predates that convention may have none.
    fn has_subordinate_ids(&self, executor: &dyn Executor, user: &str) -> Result<bool>;
}
