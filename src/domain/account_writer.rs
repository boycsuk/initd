//! Account creation and modification capability.
//!
//! Separate from [`super::accounts::AccountReader`] because the two have
//! different risk profiles and different implementations: reading the passwd
//! database is unprivileged and universal, while creating an account, granting
//! it administrative rights or locking one out are privileged operations whose
//! commands differ by what the distribution ships.
//!
//! The administrative group is the divergence that motivates the capability:
//! Debian grants sudo through `sudo`, Arch and RHEL through `wheel`. Adding a
//! user to a group that does not exist is the failure mode to guard against —
//! `usermod -aG sudo` on Arch exits zero and grants nothing.

use crate::error::Result;
use crate::exec::Executor;

/// How an account's password is set up when it is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPolicy {
    /// No password is set, so password authentication cannot succeed.
    ///
    /// Safe only alongside a sudo rule that does not ask for one: an account
    /// with no password and a sudo rule that prompts for it can never
    /// authenticate, which is a broken administrator rather than a hardened
    /// one.
    Locked,
}

/// How an account is barred from logging in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMethod {
    /// Expire the account, which refuses every authentication method.
    ///
    /// The important one, and the reason this is an enum rather than a single
    /// `lock` call. A `!`-prefixed password hash — what `passwd -l` writes —
    /// is checked by PAM's auth phase, and public-key authentication never
    /// reaches that phase: `sshd` reads `authorized_keys` and never calls
    /// `pam_authenticate`. OpenSSH's own locked-account check exists but is
    /// compiled behind `!UsePAM`, and `UsePAM yes` is the default everywhere
    /// this tool runs.
    ///
    /// So a locked password alone leaves key-based root login working, which
    /// is the opposite of what locking root is asked for. Expiry is recorded
    /// in a different shadow field and is honoured by every method.
    Expire,
}

/// Creates and modifies accounts on the administered system.
pub trait AccountWriter {
    /// Creates an account with a home directory and a login shell.
    fn create(
        &self,
        executor: &dyn Executor,
        user: &str,
        shell: &str,
        password: PasswordPolicy,
    ) -> Result<()>;

    /// Adds an account to a supplementary group.
    ///
    /// Fails when the group does not exist rather than reporting success:
    /// `usermod -aG` is happy to be told about a group the system has never
    /// heard of, and the account silently gains nothing.
    fn add_to_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<()>;

    /// Whether a group exists.
    fn group_exists(&self, executor: &dyn Executor, group: &str) -> Result<bool>;

    /// Whether an account is a member of a group.
    fn is_in_group(&self, executor: &dyn Executor, user: &str, group: &str) -> Result<bool>;

    /// Changes an account's login shell.
    ///
    /// The shell must already be listed in `/etc/shells`; a shell absent from
    /// it is refused by `chsh` and, on some systems, by services that consult
    /// the list before granting a session.
    fn set_shell(&self, executor: &dyn Executor, user: &str, shell: &str) -> Result<()>;

    /// Bars an account from logging in by any method.
    fn lock(&self, executor: &dyn Executor, user: &str, method: LockMethod) -> Result<()>;

    /// Whether an account is barred from logging in.
    fn is_locked(&self, executor: &dyn Executor, user: &str) -> Result<bool>;

    /// The login shells the system will accept.
    ///
    /// Read rather than assumed: `/usr/bin/fish` and `/bin/fish` are both real
    /// locations depending on the distribution, and offering one the system
    /// does not list produces an account that cannot log in.
    fn valid_shells(&self, executor: &dyn Executor) -> Result<Vec<String>>;
}
