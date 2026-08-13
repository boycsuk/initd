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
use crate::exec::{Command, Executor};

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

    /// Turns filtering off again, and stops it returning at boot.
    ///
    /// The inverse of [`enable`](Self::enable), and deliberately narrower than
    /// "turn the firewall off": an implementation removes only what this tool
    /// created. A host filtering through rules somebody else wrote keeps them —
    /// a task named for undoing its own change must not become the one that
    /// flushed a ruleset it never made.
    ///
    /// Both halves, for the reason `enable` and `persist` are two calls: a
    /// table removed from the kernel while the boot still replays it is a
    /// firewall that comes back at the next restart, and reporting it as off
    /// would be true for as long as nobody rebooted.
    fn disable(&self, executor: &dyn Executor) -> Result<()>;

    /// Allows a port inbound.
    fn allow(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()>;

    /// Makes the current ruleset survive a reboot.
    ///
    /// Separate from [`enable`](Self::enable) and [`allow`](Self::allow)
    /// because the two questions have different answers per front-end, and
    /// conflating them is how a firewall ends up applied and not kept:
    /// `firewall-cmd` writes runtime and permanent configuration through
    /// distinct flags, while `nft` only ever speaks to the kernel and the
    /// ruleset it holds is gone at the next boot unless something wrote it to
    /// disk.
    ///
    /// The sysctl capability learned this first, and the lesson transfers
    /// exactly: a value can be right for reasons that do not outlive a restart,
    /// so a task that stops at the running state reports success over a host
    /// where the setting vanishes. A firewall that vanishes is the more
    /// expensive half of that mistake — the server comes back with every port
    /// open and nothing says so.
    ///
    /// Called after the ruleset is in place, so that what gets saved is what
    /// was just applied.
    ///
    /// Answers whether the ruleset will actually be replayed, which is not the
    /// same as whether saving it succeeded: a host may have nowhere to register
    /// the replay. Measured on `alpine:3.23`, where OpenRC ships in its own
    /// package so a container has neither `rc-update` nor an init script — and
    /// a chroot or a minimal image is the same situation anywhere. `false`
    /// there rather than an error, because the rules *are* applied and *are*
    /// written where a boot would read them; what is missing is the boot. An
    /// error would report the firewall as not enabled, which is worse and
    /// false.
    fn persist(&self, executor: &dyn Executor) -> Result<bool>;

    /// Whether the ruleset currently in the kernel would survive a reboot.
    ///
    /// Asked so a task can report "already done" honestly: the running state
    /// alone cannot answer it, which is precisely the failure this pair exists
    /// to close.
    fn is_persisted(&self, executor: &dyn Executor) -> Result<bool>;

    /// Whether a port is currently allowed inbound.
    fn is_allowed(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool>;

    /// Reports whether filtering is active and what it admits.
    fn state(&self, executor: &dyn Executor) -> Result<FirewallState>;

    /// How to ask this front-end, later, whether a port is open.
    ///
    /// Returned as a command rather than run, because a consequence is declared
    /// while a task is being *defined* — running anything there would execute
    /// commands the administrator never asked for.
    ///
    /// It belongs to the front-end for the same reason `allow` does. A task
    /// spelling the query itself has to pick one, and the one it would pick is
    /// `nft`: on RHEL the rule was written through firewalld and lives in a
    /// zone, so `nft list table inet initd` names a table that does not exist —
    /// the answer would be "still open to fix" for a port that is already
    /// correct, forever, on the one family where the tool installs a different
    /// front-end than the others.
    fn open_port_check(&self, port: u32, protocol: Protocol) -> (Command, String);
}
