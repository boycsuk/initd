//! Packet filtering capability.
//!
//! Behind a trait because Linux has three filtering front-ends in active use
//! and a server may present any of them: `nftables` is the modern in-kernel
//! subsystem, `iptables` is the legacy interface most existing documentation
//! still assumes, and `ufw` is Debian's wrapper over whichever of the two is
//! installed. They are not interchangeable — a rule added with one is not
//! visible to another's listing — so which one is in use has to be resolved on
//! the host rather than assumed.
//!
//! This is also what makes WireGuard's `PostUp` writable at all: the masquerade
//! rule it installs is spelled differently for `nft` and for `iptables`, and a
//! configuration that hard-codes the wrong one leaves a VPN that connects and
//! routes nothing.

use crate::error::Result;
use crate::exec::Executor;

/// Transport protocol a rule names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Lowercase name, as every front-end spells it on the command line.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Whether the firewall is filtering, and what it does by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallState {
    /// Whether filtering is active at all.
    pub active: bool,
    /// Ports currently allowed inbound, as `port/protocol`.
    ///
    /// Reported so the interface can say what is open rather than only whether
    /// something is: an administrator about to change the SSH port needs to
    /// know which port is currently reachable.
    pub allowed: Vec<String>,
}

/// Manages inbound packet filtering.
pub trait FirewallManager {
    /// The front-end this implementation drives, for display.
    fn name(&self) -> &'static str;

    /// Whether this front-end is present on the host.
    ///
    /// Resolved rather than assumed: a Debian server may have `ufw` installed
    /// and inactive while `nft` holds the real ruleset.
    fn is_available(&self, executor: &dyn Executor) -> Result<bool>;

    /// Turns on filtering with a default-deny inbound policy.
    ///
    /// Implementations must allow the port SSH is currently listening on
    /// before the policy takes effect. Enabling default-deny over a remote
    /// session is otherwise the last thing that session does.
    fn enable(&self, executor: &dyn Executor, keep_open: &[(u32, Protocol)]) -> Result<()>;

    /// Allows a port inbound.
    fn allow(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()>;

    /// Whether a port is currently allowed inbound.
    fn is_allowed(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool>;

    /// Reports whether filtering is active and what it admits.
    fn state(&self, executor: &dyn Executor) -> Result<FirewallState>;
}
