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

use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// A repository this build knows how to register, and can prove it registered.
///
/// Not `Copy`, because [`Repository::suite`] is a fact about the host rather
/// than about this build: the others are values compiled in, and that one is
/// read from `/etc/os-release` at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// Short identifier, used in the file name and in messages.
    pub name: &'static str,

    /// Where the repository's metadata lives.
    pub base_url: &'static str,

    /// The suite to fetch, where the packaging names one.
    ///
    /// `None` on rpm, whose `$releasever` dnf expands from the running system.
    /// APT has no equivalent — it expands `$(ARCH)` and nothing else, measured
    /// against `sources.list(5)` rather than assumed — so the codename reaches
    /// the definition from the detected distribution. A repository that named
    /// the wrong suite would register successfully and serve nothing, which is
    /// the failure this field exists to make impossible to write by accident.
    pub suite: Option<String>,

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

/// Fetches a repository's signing key and reports the fingerprint it has.
///
/// Derived on the host rather than trusted from anywhere: the point of the
/// comparison is that the value in this binary came from somewhere the serving
/// host does not control, so the other side of it has to be computed from the
/// bytes that arrived.
///
/// Shared by every packaging front-end rather than implemented per family. The
/// two copies this replaces were byte-identical, and a check deciding where a
/// machine's software comes from is the one place where drift between copies is
/// a vulnerability rather than a defect: hardening one and forgetting the other
/// leaves a family verifying nothing while the trait's contract still says it
/// does. What differs per family is the definition written *after* the key is
/// established, which is why that half stays in the backends.
///
/// The first `fpr` is the primary key's, which the APT side learned matters:
/// Docker signs its `InRelease` with a subkey, so a check comparing the
/// signature's issuer against this value would refuse a correct key. Pinning
/// the primary and letting `gpg` walk the binding signature is what makes the
/// subkey a detail rather than a special case.
pub fn fingerprint_of(executor: &dyn Executor, repository: &Repository) -> Result<String> {
    // One script, because the key must not survive the check: a key file left
    // behind after a mismatch is one a later run could import.
    let script = format!(
        "set -eu\n\
         key=$(mktemp)\n\
         trap 'rm -f \"$key\"' EXIT\n\
         curl -fsSL --proto '=https' --tlsv1.2 -o \"$key\" '{url}'\n\
         gpg --show-keys --with-fingerprint --with-colons \"$key\" \
           | awk -F: '$1 == \"fpr\" {{ print $10; exit }}'\n",
        url = repository.key_url
    );

    let command = Command::new("sh").args(["-c", &script]);
    let output = executor.run(&command)?;

    if !output.success() {
        return Err(Error::RepositoryKeyUnverifiable {
            repository: repository.name.to_owned(),
        });
    }

    Ok(output.stdout.trim().to_ascii_uppercase())
}

/// Checks a repository's key against the fingerprint compiled in for it.
///
/// Refused rather than warned about. A warning about a key that is not the
/// expected one is a warning nobody can act on, and the packages it would sign
/// are the ones this check exists to keep off the machine.
///
/// Callers must reach this before writing anything that makes the repository
/// usable — the ordering the [`RepositoryManager::register`] contract requires.
pub fn verify_key(executor: &dyn Executor, repository: &Repository) -> Result<()> {
    let found = fingerprint_of(executor, repository)?;
    let expected = repository.fingerprint.to_ascii_uppercase();

    if found != expected {
        return Err(Error::RepositoryKeyMismatch {
            repository: repository.name.to_owned(),
            expected,
            found,
        });
    }

    Ok(())
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
    ///
    /// "Usable" is the precise word and not a hedge. A refused key must leave
    /// no source, no keyring and no key on disk; it may leave behind whatever
    /// the check itself needed in order to run. [`super::super::backend::apt_repositories`]
    /// is the case: neither `curl` nor `gpg` is present on a bare Debian image,
    /// so it installs them first, and a mismatched fingerprint therefore ends
    /// with three ordinary tools installed and no repository. Stated here
    /// rather than left to the implementation, because a reader of this
    /// contract would otherwise form the stronger belief that nothing whatever
    /// runs before the check.
    fn register(&self, executor: &dyn Executor, repository: &Repository) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::exec::mock::{MockExecutor, Reply};

    /// A repository standing in for any: the values are what the comparison
    /// uses, and none of them is specific to a packaging front-end.
    fn repository() -> Repository {
        Repository {
            name: "docker",
            base_url: "https://download.docker.com/linux/debian",
            suite: Some("trixie".to_owned()),
            key_url: "https://download.docker.com/linux/debian/gpg",
            fingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
        }
    }

    #[test]
    fn a_key_that_cannot_be_fetched_is_unverifiable_rather_than_mismatched() {
        // The two are different actions for the operator — a network that
        // refused the key says retry, a wrong key says stop — so a failed
        // fetch must not fall through to the comparison and be reported as
        // whatever the empty output happens not to equal.
        let mock =
            MockExecutor::with_replies([Reply::failure(6, "curl: (6) could not resolve host")]);

        let result = verify_key(&mock, &repository());

        assert!(matches!(
            result,
            Err(Error::RepositoryKeyUnverifiable { .. })
        ));
    }

    #[test]
    fn a_fingerprint_is_compared_without_regard_to_case() {
        // `gpg` answers uppercase and a fingerprint published in documentation
        // is often lowercase. A comparison sensitive to that would refuse the
        // right key, which is the failure that teaches people to skip the check.
        let mock =
            MockExecutor::with_replies([Reply::ok("9dc858229fc7dd38854ae2d88d81803c0ebfcd88\n")]);

        assert!(verify_key(&mock, &repository()).is_ok());
    }

    #[test]
    fn a_mismatched_fingerprint_is_refused() {
        // The case the capability exists for. Both front-ends now reach this
        // one function, so the refusal is asserted here rather than twice.
        let mock =
            MockExecutor::with_replies([Reply::ok("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\n")]);

        let result = verify_key(&mock, &repository());

        assert!(matches!(result, Err(Error::RepositoryKeyMismatch { .. })));
    }
}
