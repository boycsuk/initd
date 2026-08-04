//! Installing a binary that no package manager provides.
//!
//! A capability rather than a special case inside one task, because the gap it
//! covers is not "a different package name" — it is a different installation
//! *mechanism*. Zellij is `pacman -S zellij` on Arch and has no package at all
//! in any Debian or Ubuntu suite, so one family installs from its repository
//! and the other downloads a release. `PackageManager` cannot express that.
//!
//! Every download is checked against a digest compiled into this binary. A
//! checksum fetched from the host serving the artefact proves only that the
//! transfer completed: an attacker who can replace one can replace the other.
//! A pinned digest means compromising *this* project's release rather than
//! upstream's, which is the same reasoning the project's own installer follows.

use crate::error::Result;
use crate::exec::Executor;

/// A release this build knows how to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// Upstream version, as the operator selects it.
    pub version: &'static str,
    /// Where the archive is fetched from.
    pub url: &'static str,
    /// SHA-256 of the archive, compiled in rather than fetched.
    pub sha256: &'static str,
    /// Path of the binary inside the archive.
    pub archive_member: &'static str,
}

/// Installs binaries from verified release archives.
pub trait BinaryInstaller {
    /// Whether a binary is already on `PATH`.
    fn is_installed(&self, executor: &dyn Executor, program: &str) -> Result<bool>;

    /// Downloads, verifies and installs one release.
    ///
    /// Implementations must verify before extracting. An archive unpacked and
    /// then checked has already written whatever it contained, and the check
    /// becomes a report rather than a defence.
    fn install(&self, executor: &dyn Executor, program: &str, release: &Release) -> Result<()>;
}
