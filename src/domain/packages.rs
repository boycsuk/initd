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
}
