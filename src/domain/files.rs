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

/// A write into a directory owned by an unprivileged account.
///
/// A struct rather than seven parameters because six of them are strings and
/// two are modes: a call site that transposed `dir_mode` and `file_mode`, or
/// `path` and `dir`, would compile and would silently write a key with the
/// wrong permissions — which sshd answers by ignoring the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedDirWrite<'a> {
    /// The directory to create if missing, e.g. `~/.ssh`.
    pub dir: &'a str,
    /// Octal mode for the directory, e.g. `0o700`.
    pub dir_mode: u32,
    /// The file to write inside it.
    pub path: &'a str,
    /// Octal mode for the file, e.g. `0o600`.
    pub file_mode: u32,
    /// The account that must end up owning both.
    pub owner: &'a str,
    /// What to write.
    pub contents: &'a str,
}

/// Reads and writes files on the administered system.
///
/// Writing always takes a backup first: every file this tool touches can lock
/// an administrator out of the server if it ends up malformed.
pub trait FileEditor {
    /// Reads a file's contents.
    fn read(&self, executor: &dyn Executor, path: &str) -> Result<String>;

    /// Reads a file that is world-readable, without escalating.
    ///
    /// For the caller that must work where no password can be asked for. The
    /// interface's probe thread runs with `Prompting::Refuse` — it may not raise
    /// a prompt under a tree the operator is reading — so a privileged read
    /// there does not fail loudly, it returns `NoTerminalForPrompt` and the row
    /// falls back to whatever the caller does with an error. For the kernel
    /// parameter rows that meant `Presence::Unknown`, which draws the forward
    /// verb: applying a setting appeared to do nothing at all.
    ///
    /// Separate from [`read`](Self::read) rather than replacing it, and the
    /// separation is the safety: `read` also opens `sshd_config`, mode `600`,
    /// where dropping privilege would turn a readable file into an error. Only
    /// a caller that knows its file is world-readable may use this — the sysctl
    /// drop-in is `0644` in a `0755` directory by deliberate choice, so the
    /// privilege bought nothing there.
    ///
    /// Defaulted to the privileged read so the four implementations that have
    /// no unprivileged case are untouched, and so a new one is correct before
    /// it is optimised.
    fn read_unprivileged(&self, executor: &dyn Executor, path: &str) -> Result<String> {
        self.read(executor, path)
    }

    /// Whether the path exists.
    fn exists(&self, executor: &dyn Executor, path: &str) -> Result<bool>;

    /// Whether a world-readable path exists, without escalating.
    ///
    /// The companion to [`read_unprivileged`](Self::read_unprivileged), and
    /// needed for the same reason: a probe that cannot ask for a password must
    /// not be stopped by a question about a path anyone may look at.
    fn exists_unprivileged(&self, executor: &dyn Executor, path: &str) -> Result<bool> {
        self.exists(executor, path)
    }

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

    /// Writes a file inside a directory its owner controls, in one step.
    ///
    /// For the write whose destination sits in an unprivileged account's home.
    /// [`is_symlink`](Self::is_symlink) answers the question once, and every
    /// command after it is a fresh lookup of the same path: `chown` and `chmod`
    /// follow links, so an account that replants one between two of those
    /// commands has root apply ownership or a mode wherever it now points. The
    /// check and the act have to be inseparable, and across several privileged
    /// subprocesses they cannot be.
    ///
    /// So the directory, its mode and owner, the file, its mode and owner, and
    /// the contents are one invocation that re-checks as it goes and refuses on
    /// a link. Contents arrive on stdin; nothing interpolates into a script.
    ///
    /// The caller passes the whole file, having read and appended to it first:
    /// this replaces rather than appends, so what a key is added to is decided
    /// where the keys are understood rather than inside a shell script.
    fn write_in_owned_dir(&self, executor: &dyn Executor, spec: &OwnedDirWrite<'_>) -> Result<()>;
}
