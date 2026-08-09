//! File editing capability.
//!
//! Files are read and written through the [`Executor`] rather than `std::fs`
//! so that privilege escalation applies — `/etc/ssh/sshd_config` is not
//! writable by an ordinary user — and so that a future SSH executor works
//! without changing any call site.

use crate::error::Result;
use crate::exec::Executor;

/// Where a backup was written, so it can be restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub original: String,
    pub copy: String,
}

/// Reads and writes files on the administered system.
///
/// Writing always takes a backup first: every file this tool touches can lock
/// an administrator out of the server if it ends up malformed.
pub trait FileEditor {
    /// Reads a file's contents.
    fn read(&self, executor: &dyn Executor, path: &str) -> Result<String>;

    /// Whether the path exists.
    fn exists(&self, executor: &dyn Executor, path: &str) -> Result<bool>;

    /// Whether the path is a symbolic link.
    ///
    /// Asked before writing anywhere inside a directory an unprivileged account
    /// owns. Every tool this trait drives follows links — `install -d`, `chown`
    /// and `tee` all operate on the target, measured on `debian:13` — so a user
    /// who replaces their own `~/.ssh` with a link to somewhere else has root
    /// apply the mode, the ownership and the file contents *there* instead.
    /// Reproduced: a directory owned by root came back owned by the account
    /// that planted the link.
    fn is_symlink(&self, executor: &dyn Executor, path: &str) -> Result<bool>;

    /// Copies the file aside and returns where the copy landed.
    fn backup(&self, executor: &dyn Executor, path: &str) -> Result<Backup>;

    /// Writes contents to a file, taking a backup first when it already
    /// exists.
    ///
    /// Returns the backup, or `None` when the file is newly created.
    fn write(&self, executor: &dyn Executor, path: &str, contents: &str) -> Result<Option<Backup>>;

    /// Writes contents to a file, leaving no copy of the previous version.
    ///
    /// For the one file whose previous version must not survive the write:
    /// `wg0.conf` holds the server's private key and every peer's preshared
    /// key, so the sidecar copy [`write`](Self::write) leaves is a second copy
    /// of all of them, sitting beside the original for as long as the host
    /// lives.
    ///
    /// A separate method rather than a flag on `write` because the guarantee is
    /// the caller's whole reason for choosing it: a boolean would be read as a
    /// tuning knob by the ten callers that want the ordinary behaviour, and the
    /// one that does not is the one where getting it wrong leaks key material.
    /// It returns no [`Backup`] for the same reason — there is nothing to
    /// revert to, and a caller holding an `Option` would be invited to wonder
    /// why it is always `None`.
    ///
    /// The tradeoff this accepts: a write that fails partway leaves no copy to
    /// restore. Tolerable only because the write is atomic — contents are
    /// staged beside the target and moved over it — so the file is either the
    /// old version or the new one, never a third state.
    fn write_uncopied(&self, executor: &dyn Executor, path: &str, contents: &str) -> Result<()>;

    /// Restores a backup over the original, undoing a failed change.
    fn restore(&self, executor: &dyn Executor, backup: &Backup) -> Result<()>;

    /// Sets a file's octal permission mode, e.g. `0o600`.
    fn set_mode(&self, executor: &dyn Executor, path: &str, mode: u32) -> Result<()>;

    /// Creates a directory and any missing parents, with the given mode.
    fn create_dir(&self, executor: &dyn Executor, path: &str, mode: u32) -> Result<()>;

    /// Sets the owning user and group of a path.
    fn set_owner(&self, executor: &dyn Executor, path: &str, owner: &str) -> Result<()>;
}
