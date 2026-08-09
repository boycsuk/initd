//! Package management capability.

use crate::error::Result;
use crate::exec::Executor;

/// Installs and queries packages.
///
/// Implementations know their distribution's package manager *and* its package
/// names: `openssh-server` on Debian is `openssh` on Arch. Callers ask for a
/// capability, never for a package name.
pub trait PackageManager {
    /// Installs a package, doing nothing if it is already present.
    fn install(&self, executor: &dyn Executor, package: &str) -> Result<()>;

    /// Whether the package is currently installed.
    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool>;

    /// Removes a package, leaving its configuration behind.
    ///
    /// Never cascades. Every family offers a flag that also removes whatever
    /// the package left orphaned — `apt-get --auto-remove`, `pacman -Rs` — and
    /// none of them is used here: an operator who asked to remove Caddy asked
    /// about Caddy, and a removal that reaches further is one whose extent
    /// cannot be stated before it runs. Cleaning up orphans is a different
    /// operation, and one this tool does not offer.
    fn remove(&self, executor: &dyn Executor, package: &str) -> Result<()>;

    /// Removes a package and the configuration files it owns.
    ///
    /// Separate from [`remove`](Self::remove) because the difference is not
    /// recoverable: a purged `/etc/fail2ban/jail.local` is gone, while a
    /// removed-not-purged package leaves it for a reinstall to find. The
    /// operator is asked which they meant rather than a default being chosen
    /// on their behalf.
    ///
    /// No default implementation, deliberately. Aliasing this to `remove`
    /// would be a family answering a question it was never asked — and RHEL is
    /// exactly that family, since rpm has no purge and leaves modified
    /// configuration as `.rpmsave`. It says so itself through
    /// [`Backend::has_purge_for`](crate::backend::Backend::has_purge_for)
    /// rather than quietly doing something else.
    fn purge(&self, executor: &dyn Executor, package: &str) -> Result<()>;
}
