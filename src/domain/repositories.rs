//! Third-party package repository capability.
//!
//! The most consequential thing in this layer, and the one whose shape matters
//! more than its interface. Registering a repository changes where a machine's
//! software comes from — every future update of every package that repository
//! carries, not just the one being installed today. So the question is not
//! whether this tool *can* add one, but whether it can prove the one it added
//! is the one it meant to.
//!
//! [`Repository::fingerprint`] is what makes that provable, and it is a
//! required field rather than an option. A repository declares a key URL, and
//! fetching a key from a URL the same document named proves nothing: whoever
//! controls the document controls the key. A fingerprint published somewhere
//! else — in the project's documentation, on a keyserver — is a value that can
//! be compiled into this build and compared against what arrives, which is the
//! same reasoning as the checksums in [`super::binaries`]. An attacker would
//! have to compromise this binary rather than a transport or a CDN.
//!
//! A repository whose fingerprint cannot be found published independently is
//! therefore not representable here, and that is deliberate. CrowdSec's
//! packagecloud repository and Caddy's COPR both fall on that side: their keys
//! are served by the hosts that serve their packages and appear on no
//! keyserver, so registering either would be trusting a document to vouch for
//! itself.

use crate::error::Result;
use crate::exec::Executor;

/// A repository this build knows how to register, and can prove it registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repository {
    /// Short identifier, used in the file name and in messages.
    pub name: &'static str,

    /// Where the repository's metadata lives.
    pub base_url: &'static str,

    /// Where its signing key is served.
    pub key_url: &'static str,

    /// The signing key's fingerprint, uppercase and without spaces.
    ///
    /// Compiled in from a source independent of `key_url` — the project's own
    /// documentation, or a keyserver. Compared against the key that actually
    /// arrives, and a mismatch refuses the registration rather than warning
    /// about it: a warning about a key that is not the expected one is a
    /// warning nobody can act on, and the packages it would then sign are the
    /// ones this check exists to keep off the machine.
    pub fingerprint: &'static str,
}

/// Registers package repositories, having verified whose they are.
pub trait RepositoryManager {
    /// Whether this repository is already registered.
    fn is_registered(&self, executor: &dyn Executor, repository: &Repository) -> Result<bool>;

    /// Registers a repository after checking its key against the fingerprint.
    ///
    /// Implementations must fetch the key, derive its fingerprint, and refuse
    /// when it does not match — before writing anything that would make the
    /// repository usable. Writing first and checking after leaves a window in
    /// which an unverified repository is installable, which is the whole of
    /// what this is meant to prevent.
    fn register(&self, executor: &dyn Executor, repository: &Repository) -> Result<()>;
}
