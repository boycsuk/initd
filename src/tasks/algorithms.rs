//! Narrowing sshd's algorithm lists to what the local OpenSSH supports.
//!
//! The hardened lists published for `sshd_config` name algorithms that do not
//! exist on every release: post-quantum key exchange arrived in OpenSSH 9,
//! and a server old enough to need hardening is exactly the one that will not
//! recognise it. Writing a name the daemon cannot parse is not a warning —
//! `sshd -t` rejects the file and the change is rolled back entire — so the
//! lists are intersected with what `ssh -Q` reports before anything is
//! written.
//!
//! The query runs through the `Executor` like every other command, and asks
//! `ssh` rather than `sshd`: `sshd -Q` refuses to run unless invoked by
//! absolute path, and hardcoding one would break the moment a distribution
//! moved it.

use crate::exec::{Command, Executor};

/// Key exchange algorithms, strongest first.
///
/// Source: the OpenSSH hardening guides at sshaudit.com, cross-checked against
/// `man sshd_config` (consulted 2026-08-03). The `@libssh.org` spelling of
/// curve25519 names the same algorithm as the bare one and is kept for clients
/// that only know the older name.
const PREFERRED_KEX: &[&str] = &[
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group-exchange-sha256",
];

/// Ciphers, strongest first.
///
/// AEAD constructions lead. The CTR modes trail them for clients too old to
/// speak either; CBC is absent, being what the padding-oracle attacks target.
const PREFERRED_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
];

/// Message authentication codes, strongest first.
///
/// Encrypt-then-MAC only: the alternative authenticates the plaintext after
/// decrypting, which is what makes a timing attack worth mounting.
const PREFERRED_MACS: &[&str] = &[
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "umac-128-etm@openssh.com",
];

/// Host key signature algorithms, strongest first.
const PREFERRED_HOST_KEYS: &[&str] = &[
    "ssh-ed25519",
    "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "rsa-sha2-512-cert-v01@openssh.com",
    "rsa-sha2-256-cert-v01@openssh.com",
];

/// Fewest algorithms that may remain before a directive is left unwritten.
///
/// Two rather than one. A list naming a single algorithm is more brittle than
/// no list at all: it refuses every client that lacks that one algorithm,
/// whereas the compiled-in default admits a reasonable range. Narrowing is
/// only worth doing while an alternative survives.
const MINIMUM_ALGORITHMS: usize = 2;

/// A class of algorithm sshd negotiates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Kex,
    Cipher,
    Mac,
    HostKey,
}

/// Every class, so a caller can apply the whole set without repeating it.
pub const ALL_CLASSES: [Class; 4] = [Class::Kex, Class::Cipher, Class::Mac, Class::HostKey];

impl Class {
    /// The `sshd_config` directive this class writes.
    pub const fn directive(self) -> &'static str {
        match self {
            Self::Kex => "KexAlgorithms",
            Self::Cipher => "Ciphers",
            Self::Mac => "MACs",
            Self::HostKey => "HostKeyAlgorithms",
        }
    }

    /// The `ssh -Q` query naming this class.
    ///
    /// Canonical query names only. `ssh -Q HostKeyAlgorithms` returns the same
    /// list as `key-sig` but is an alias added in OpenSSH 8.2, and a
    /// capability query that itself needs a recent OpenSSH cannot protect an
    /// old one — it would exit with `Unsupported query` on precisely the
    /// versions this filtering exists for. `key-sig` has worked since 7.6.
    pub const fn query(self) -> &'static str {
        match self {
            Self::Kex => "kex",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
            Self::HostKey => "key-sig",
        }
    }

    /// The preference-ordered hardened list for this class.
    pub const fn preferred(self) -> &'static [&'static str] {
        match self {
            Self::Kex => PREFERRED_KEX,
            Self::Cipher => PREFERRED_CIPHERS,
            Self::Mac => PREFERRED_MACS,
            Self::HostKey => PREFERRED_HOST_KEYS,
        }
    }
}

/// The hardened list for this class, reduced to what this OpenSSH supports.
///
/// Returns `None` when the directive should be left alone: the query could not
/// be answered, or too little of the hardened list survived it. Never falls
/// back to writing the list unfiltered — that is the outcome this module
/// exists to prevent.
///
/// The intersection walks the hardened list rather than the query output.
/// `Ciphers` and `KexAlgorithms` are preference lists and the daemon offers
/// them in the order written, while `ssh -Q` prints in the binary's own order,
/// which leads with `3des-cbc`. Iterating the query would therefore put the
/// weakest surviving algorithm first.
pub fn hardened_for(executor: &dyn Executor, class: Class) -> Option<String> {
    let available = supported(executor, class)?;

    let kept: Vec<&str> = class
        .preferred()
        .iter()
        .copied()
        .filter(|name| available.iter().any(|found| found == name))
        .collect();

    (kept.len() >= MINIMUM_ALGORITHMS).then(|| kept.join(","))
}

/// What the local OpenSSH supports for one class of algorithm.
///
/// `ssh -Q` is a capability query: it lists what the binary can parse,
/// including algorithms nobody should enable. Intersecting it with a hardened
/// list is what turns it into a recommendation.
///
/// `None` rather than an error, and deliberately so: a capability query that
/// cannot be answered is an expected outcome — `ssh` absent from a minimal
/// image, or a query name this release does not know — and must degrade to
/// leaving one directive alone rather than failing a task that has other work
/// to do. The caller reports the skip.
fn supported(executor: &dyn Executor, class: Class) -> Option<Vec<String>> {
    // Unprivileged: this reads nothing sensitive, and asking for root would
    // spend an escalation on a question any user may ask.
    let command = Command::new("ssh").args(["-Q", class.query()]);
    let output = executor.run(&command).ok()?;

    if !output.success() {
        return None;
    }

    let names: Vec<String> = output
        .stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();

    (!names.is_empty()).then_some(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn the_intersection_keeps_the_hardened_order_not_the_query_order() {
        // The property the whole module rests on. `ssh -Q cipher` leads with
        // 3des-cbc on a real system, so walking its order would put the
        // weakest surviving algorithm at the head of sshd's preference.
        let mock = MockExecutor::with_replies([Reply::ok(
            "3des-cbc\naes128-ctr\nchacha20-poly1305@openssh.com\naes256-gcm@openssh.com\n",
        )]);

        let value = hardened_for(&mock, Class::Cipher).expect("three hardened ciphers survive");

        assert_eq!(
            value,
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-ctr"
        );
    }

    #[test]
    fn a_weak_algorithm_offered_by_the_binary_is_never_written() {
        // `ssh -Q` reports capability, not recommendation.
        let mock = MockExecutor::with_replies([Reply::ok(
            "3des-cbc\naes128-cbc\naes256-ctr\naes128-ctr\n",
        )]);

        let value = hardened_for(&mock, Class::Cipher).expect("two CTR modes survive");

        assert!(!value.contains("cbc"), "got: {value}");
    }

    #[test]
    fn an_algorithm_this_build_lacks_is_left_out() {
        // An OpenSSH without post-quantum key exchange must not be handed one.
        let mock = MockExecutor::with_replies([Reply::ok(
            "curve25519-sha256\ndiffie-hellman-group16-sha512\n",
        )]);

        let value = hardened_for(&mock, Class::Kex).expect("two hardened kex survive");

        assert!(!value.contains("sntrup761"), "got: {value}");
        assert_eq!(value, "curve25519-sha256,diffie-hellman-group16-sha512");
    }

    #[test]
    fn a_failed_query_yields_no_directive() {
        // Old OpenSSH answers an unknown query name this way. Writing the
        // hardened list regardless would reject the whole configuration.
        let mock =
            MockExecutor::with_replies([Reply::failure(255, "Unsupported query \"key-sig\"")]);

        assert!(hardened_for(&mock, Class::HostKey).is_none());
    }

    #[test]
    fn empty_query_output_yields_no_directive() {
        let mock = MockExecutor::with_replies([Reply::ok("\n  \n")]);

        assert!(hardened_for(&mock, Class::Mac).is_none());
    }

    #[test]
    fn an_intersection_below_the_floor_is_skipped() {
        // One cipher is more brittle than the compiled-in default: it refuses
        // every client that lacks that single algorithm.
        let mock = MockExecutor::with_replies([Reply::ok("3des-cbc\naes256-ctr\n")]);

        assert!(hardened_for(&mock, Class::Cipher).is_none());
    }

    #[test]
    fn an_intersection_at_the_floor_is_written() {
        let mock = MockExecutor::with_replies([Reply::ok("aes256-ctr\naes128-ctr\n")]);

        assert_eq!(
            hardened_for(&mock, Class::Cipher).expect("two is enough"),
            "aes256-ctr,aes128-ctr"
        );
    }

    #[test]
    fn the_query_is_unprivileged() {
        // A capability query must not spend a sudo timestamp.
        let mock = MockExecutor::with_replies([Reply::ok("curve25519-sha256\n")]);

        hardened_for(&mock, Class::Kex);

        assert!(!mock.any_privileged(), "got: {:?}", mock.recorded_lines());
    }

    #[test]
    fn every_class_queries_a_canonical_name() {
        // The names `ssh -Q help` lists. Directive-name aliases like
        // HostKeyAlgorithms were added in OpenSSH 8.2 and would fail on the
        // very releases this filtering protects.
        const CANONICAL: [&str; 12] = [
            "cipher",
            "cipher-auth",
            "compression",
            "kex",
            "kex-gss",
            "key",
            "key-cert",
            "key-plain",
            "key-sig",
            "mac",
            "protocol-version",
            "sig",
        ];

        for class in ALL_CLASSES {
            assert!(
                CANONICAL.contains(&class.query()),
                "{:?} queries {}, which is not a canonical name",
                class,
                class.query()
            );
        }
    }

    #[test]
    fn every_class_declares_a_usable_preference_list() {
        for class in ALL_CLASSES {
            assert!(
                class.preferred().len() >= MINIMUM_ALGORITHMS,
                "{:?} could never meet its own floor",
                class
            );
        }
    }
}
