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

/// What a downloaded artefact turns out to be.
///
/// Three of the four tools here publish a tar archive with the binary inside
/// it; `rustup-init` publishes the binary itself. The difference cannot be
/// papered over, because `tar -xf` against an ELF fails — so the shape is named
/// here rather than guessed at from the URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    /// The path of the binary inside a tar archive.
    Member(&'static str),

    /// The download *is* the binary, under the name it must carry.
    ///
    /// The name is not decoration. `rustup-init` dispatches on `argv[0]` — it
    /// is the same executable as `cargo` and `rustc`, deciding which of them to
    /// be from the name it was invoked under — so a copy left at a `mktemp`
    /// path exits with `unknown proxy name: 'tmp'` rather than installing
    /// anything. Measured before this shipped, not after.
    Bare(&'static str),
}

/// A release this build knows how to verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Release {
    /// Upstream version, as the operator selects it.
    pub version: &'static str,
    /// Whether the download is an archive to open or a binary to place.
    pub payload: Payload,
    /// One artefact per architecture this project ships for.
    ///
    /// Separate because the digest is a property of the *artefact*, not of the
    /// version: an aarch64 archive and an x86_64 archive of the same release
    /// hash differently, so a single digest would fail verification on one of
    /// the two machines this tool targets.
    pub artefacts: &'static [Artefact],
}

/// One downloadable build of a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Artefact {
    /// Machine name as `uname -m` reports it.
    pub arch: &'static str,
    /// Where the archive is fetched from.
    pub url: &'static str,
    /// SHA-256 of the archive, compiled in rather than fetched.
    pub sha256: &'static str,
}

impl Release {
    /// The artefact for a machine, if this release has one.
    ///
    /// An architecture with no artefact is not installable rather than being
    /// served someone else's binary — the same limit pinned digests impose on
    /// versions.
    pub fn artefact_for(&self, arch: &str) -> Option<&'static Artefact> {
        self.artefacts.iter().find(|artefact| artefact.arch == arch)
    }
}

/// Installs binaries from verified release archives.
pub trait BinaryInstaller {
    /// Whether a binary is already on `PATH`.
    /// `&'static str` because the name reaches `Command::locating`, which
    /// builds a `sh -c` script around it. Every caller names a program it was
    /// compiled knowing about, so the bound costs nothing and stops a value
    /// from a form or an argument list ever getting there.
    fn is_installed(&self, executor: &dyn Executor, program: &'static str) -> Result<bool>;

    /// Downloads, verifies and installs one release.
    ///
    /// Implementations must verify before extracting. An archive unpacked and
    /// then checked has already written whatever it contained, and the check
    /// becomes a report rather than a defence.
    fn install(&self, executor: &dyn Executor, program: &str, release: &Release) -> Result<()>;

    /// Downloads and verifies an installer, then runs it once as an account.
    ///
    /// Distinct from [`install`](Self::install) because the artefact is not the
    /// tool: `rustup-init` installs `rustup` and thirteen symlinks into the
    /// account's own `~/.cargo/bin` and then has no further purpose, so leaving
    /// it in `/usr/local/bin` would put a spent installer on `PATH` for
    /// everybody. It is fetched, checked, executed and discarded.
    ///
    /// Run as `user` rather than as root, and that is the whole reason this
    /// takes an account at all. rustup resolves `~/.cargo` and `~/.rustup` from
    /// the environment *at run time*, so an installer run as root writes root's
    /// toolchain however the invocation is dressed up — measured, and its own
    /// anti-root guard does not fire on a genuine root login. Where a toolchain
    /// lands has to be decided here rather than left to the artefact.
    ///
    /// Implementations must verify before executing, for the reason
    /// [`install`](Self::install) must verify before extracting — running an
    /// unverified binary as root is the worse half of the same mistake.
    fn run_installer(
        &self,
        executor: &dyn Executor,
        program: &str,
        release: &Release,
        user: &str,
        args: &str,
    ) -> Result<()>;

    /// Whether *this tool's* copy of the binary is in place.
    ///
    /// Distinct from [`is_installed`](Self::is_installed), which asks whether
    /// the program is anywhere on `PATH`. That is the right question before
    /// installing — a host that already has zellij needs no download, wherever
    /// it came from — and the wrong one before removing, where the difference
    /// is a file this tool never wrote.
    ///
    /// The failure it exists to prevent was reproducible: an operator with
    /// `~/.cargo/bin/zellij` satisfies `is_installed`, so a row keyed on that
    /// answer offers to uninstall a binary `/usr/local/bin` does not contain.
    /// Acting on it either reports success having done nothing, or deletes
    /// somebody else's file from a directory this tool does not own.
    fn is_installed_here(&self, executor: &dyn Executor, program: &'static str) -> Result<bool>;

    /// Where the shell would find this program, if anywhere.
    ///
    /// Returned so the interface can name *which* copy it found. A row that
    /// says "installed elsewhere" without saying where sends the operator
    /// looking for something the tool has already located.
    fn location_of(&self, executor: &dyn Executor, program: &'static str)
    -> Result<Option<String>>;

    /// Removes the copy this tool installed.
    ///
    /// Implementations must build the path from their own install directory
    /// and never from [`location_of`](Self::location_of). The whole point is
    /// that a binary found elsewhere is not this tool's to delete, and a
    /// removal that trusted a looked-up path would do exactly what the
    /// distinction exists to prevent.
    fn remove(&self, executor: &dyn Executor, program: &'static str) -> Result<()>;
}
