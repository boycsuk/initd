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
    /// Whether the account's own service manager can be reached at all.
    ///
    /// Asked because the mechanism that makes it reachable is allowed to fail
    /// silently. `runuser -l` is relied on to establish a login session, and it
    /// is `pam_systemd` inside that session which sets `XDG_RUNTIME_DIR` and
    /// `DBUS_SESSION_BUS_ADDRESS` — but Debian lists it in `/etc/pam.d/runuser-l`
    /// as `-session optional pam_systemd.so`, where the leading `-` means a
    /// failure is not even logged. The shell then starts perfectly, with an
    /// empty environment, and every `systemctl --user` after it addresses
    /// nothing.
    ///
    /// Reported from a Debian 13 host and reproduced under systemd as PID 1:
    /// with the session established the variables are populated even without
    /// lingering, and with `systemd-logind` unable to create one the command
    /// fails with `Failed to connect to user scope bus via local transport:
    /// $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined`. That text
    /// names two variables and no cause, and points at `--machine=<user>@.host`,
    /// which is advice for a different problem.
    ///
    /// **Exporting the variables was measured and rejected.** The bus socket
    /// lives *inside* `/run/user/<uid>`, which `logind` creates; pointing at a
    /// directory nothing created answers `No such file or directory`, so the
    /// value would be a spelling of the same failure. What this returns is
    /// therefore a fact to refuse on, not a thing to repair.
    fn session_is_reachable(&self, executor: &dyn Executor, user: &str) -> Result<bool>;

    /// Whether any account on this host has a rootless engine set up.
    ///
    /// Asked by the interface rather than by a task, and asked of *any* account
    /// because the row is drawn before a username has been typed. A task that
    /// has one checks that one instead.
    ///
    /// The question exists because the obvious one is wrong: `docker.rootless`
    /// installs a package and `docker.rootless-off` deliberately leaves it —
    /// another account may be running its own engine from it — so a row keyed
    /// on the package went on offering to remove a setup that had just been
    /// removed, and nothing the uninstall did could ever change that answer.
    ///
    /// What the setup leaves is a *user unit*, written by upstream's script
    /// into the account's own systemd directory and deleted by its `uninstall`
    /// — verified on the host that reported this, where the directory was gone
    /// afterwards.
    ///
    /// Defaulted to `false` because it is a fact about systemd: OpenRC has no
    /// per-user manager at all, which is why `docker.rootless` refuses Alpine,
    /// and "no account has one" is the truthful answer there rather than a
    /// stand-in for one.
    fn any_account_has_engine(&self, _executor: &dyn Executor) -> Result<bool> {
        Ok(false)
    }

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
