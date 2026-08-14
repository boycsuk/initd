//! Package management capability.

use crate::error::Result;
use crate::exec::Executor;

/// Installs and queries packages.
///
/// Implementations know their distribution's package manager *and* its package
/// names: `openssh-server` on Debian is `openssh` on Arch. Callers ask for a
/// capability, never for a package name.
pub trait PackageManager {
    /// Installs one or more packages, doing nothing to those already present.
    ///
    /// A slice rather than a single name, because a capability is not always
    /// one package: Docker's engine is five on the families whose installation
    /// page lists it that way, and they must reach the package manager in one
    /// invocation so it resolves them as one transaction. Passing them as a
    /// space-joined string was the alternative and is wrong at this layer —
    /// every implementation puts `package` into a single `argv` element, so the
    /// whole string would arrive as one nonexistent package name, and each
    /// backend would have to remember to split it.
    fn install(&self, executor: &dyn Executor, packages: &[&str]) -> Result<()>;

    /// Installs only what is missing, and touches nothing when nothing is.
    ///
    /// The promise [`install`](Self::install)'s first line already made and did
    /// not keep. Every package manager treats an already-installed package as
    /// the state being asked for, so re-running was *correct* — it was just
    /// loud: a task run twice printed a full `apt-get update`, a dependency
    /// resolution and `already the newest version` before doing the thing it
    /// was actually asked to do. Reported by an operator watching the same
    /// eight lines scroll past on every run and reasonably asking why a tool
    /// that had just checked was installing anyway.
    ///
    /// Cheap to ask and expensive to skip asking: `is_installed` is one query
    /// per package against a local database, where the install it avoids
    /// reaches the network to refresh an index.
    ///
    /// Still one transaction for whatever *is* missing, which is why this
    /// filters rather than looping: two packages installed separately can each
    /// take the other's dependencies, and the ordering that decides which is
    /// not something any caller states.
    ///
    /// Defaulted so no family implements it. What differs between them is how
    /// to install and how to ask, and both are answered above.
    fn install_missing(&self, executor: &dyn Executor, packages: &[&str]) -> Result<()> {
        let mut missing = Vec::new();

        for package in packages {
            if !self.is_installed(executor, package)? {
                missing.push(*package);
            }
        }

        if missing.is_empty() {
            return Ok(());
        }

        self.install(executor, &missing)
    }

    /// Whether the package is currently installed.
    fn is_installed(&self, executor: &dyn Executor, package: &str) -> Result<bool>;

    /// Removes packages, leaving their configuration behind.
    ///
    /// Never cascades. Every family offers a flag that also removes whatever
    /// the package left orphaned — `apt-get --auto-remove`, `pacman -Rs` — and
    /// none of them is used here: an operator who asked to remove Caddy asked
    /// about Caddy, and a removal that reaches further is one whose extent
    /// cannot be stated before it runs. Cleaning up orphans is a different
    /// operation, and one this tool does not offer.
    ///
    /// A slice for the same reason [`install`](Self::install) takes one, and
    /// this asymmetry was a defect rather than a design: installing Docker's
    /// engine puts down five packages on Debian and removing it took only the
    /// first, so `docker` stayed on the host — the client lives in
    /// `docker-ce-cli` — and an operator who uninstalled the engine still had a
    /// working `docker` command. Reported from a live host.
    ///
    /// One invocation rather than a loop, so the package manager resolves them
    /// as one transaction: removed one at a time, the first would take the
    /// others' dependencies with it or refuse for depending on them, and which
    /// of the two depends on an ordering nothing here states.
    fn remove(&self, executor: &dyn Executor, packages: &[&str]) -> Result<()>;

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
    fn purge(&self, executor: &dyn Executor, packages: &[&str]) -> Result<()>;
}
