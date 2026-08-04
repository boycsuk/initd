//! WireGuard key material and peer administration.
//!
//! Behind a trait for the same reason as the rest: `wg` and `wg-quick` come
//! from the `wireguard-tools` package on both families implemented today, but
//! bringing an interface up is `wg-quick@wg0.service` under systemd and a
//! different mechanism everywhere else, and Alpine has neither.
//!
//! Key generation is a capability rather than a detail because private keys
//! must never pass through an argument: arguments are visible in `/proc` to
//! every user on the box for as long as the process lives.

use crate::error::Result;
use crate::exec::Executor;

/// A public/private keypair, plus the shared secret that armours it.
///
/// The preshared key is generated alongside rather than offered as an option.
/// It costs one line of configuration and adds a symmetric layer that survives
/// an attacker who records traffic now and breaks the asymmetric exchange
/// later — which is the threat model for a VPN whose sessions are long-lived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keypair {
    pub private: String,
    pub public: String,
    pub preshared: String,
}

/// Generates keys and inspects a running interface.
pub trait WireguardTools {
    /// Generates a keypair and a preshared key.
    ///
    /// Implementations must not pass the private key as an argument to
    /// anything: `/proc/<pid>/cmdline` is world-readable, so an argument is a
    /// secret published to every account on the host.
    fn generate_keypair(&self, executor: &dyn Executor) -> Result<Keypair>;

    /// Derives the public key from a private one.
    fn public_key_of(&self, executor: &dyn Executor, private: &str) -> Result<String>;

    /// Whether an interface is currently up.
    fn is_up(&self, executor: &dyn Executor, interface: &str) -> Result<bool>;
}
