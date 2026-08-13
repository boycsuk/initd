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

/// How a port came to be admitted, and therefore whether it can be closed.
///
/// Not decoration. firewalld admits SSH on a stock RHEL host as the *service*
/// `ssh` rather than as `22/tcp`, and `firewall-cmd --remove-port 22/tcp`
/// against that exits **zero having closed nothing** — a removal this tool
/// would otherwise report as done over a port that is still open. Anything
/// offering to close a port has to know which of these it is holding, which is
/// why the origin travels beside the spec rather than being recovered later by
/// guessing at its shape.
///
/// A range is deliberately *not* a variant. `--list-ports` reporting
/// `8000-8080/tcp` yields one `Direct` row spelled that way, because
/// `--remove-port 8000-8080/tcp` closes it wholesale: the range as written is
/// both the honest description and the closeable unit. Expanding it into the
/// ports it covers would offer eighty-one removals, none of which work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortOrigin {
    /// Named directly, and closed by naming it again.
    Direct,
    /// Admitted by a named service; closing it means removing the service,
    /// which is a different operation on a different subject.
    Service(String),
}

/// One port a front-end admits inbound, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedPort {
    /// The port as the front-end spells it: `port/protocol`.
    pub spec: String,
    /// What admitted it.
    pub origin: PortOrigin,
}

impl AllowedPort {
    /// A port named directly, which is the only kind this tool closes.
    pub fn direct(spec: impl Into<String>) -> Self {
        Self {
            spec: spec.into(),
            origin: PortOrigin::Direct,
        }
    }
}

/// Whether the firewall is filtering, and what it does by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallState {
    /// Whether filtering is active at all.
    pub active: bool,
    /// Ports currently allowed inbound.
    ///
    /// Reported so the interface can say what is open rather than only whether
    /// something is: an administrator about to change the SSH port needs to
    /// know which port is currently reachable.
    pub allowed: Vec<AllowedPort>,
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

    /// Closes a port this front-end admits directly.
    ///
    /// The inverse of [`allow`](Self::allow), and narrower than "close this
    /// port" deliberately. A front-end may admit a port by a route this cannot
    /// undo: firewalld's stock RHEL arrangement admits SSH as the *service*
    /// `ssh`, and `--remove-port 22/tcp` against that exits zero having closed
    /// nothing. Callers are expected to have consulted [`PortOrigin`] first,
    /// and this reports what happened rather than assuming.
    ///
    /// Answers whether the port is closed *afterwards*, read back from the
    /// host rather than inferred from an exit status. The sysctl capability
    /// learned this first and the lesson transfers exactly: a command that
    /// succeeded says something about the command, and a caller reporting
    /// "closed" from it would be true about the call and false about the
    /// machine. It is also the whole of the partial-failure story — a batch
    /// closing several ports counts these answers rather than needing an
    /// outcome variant of its own.
    ///
    /// Does not persist. Whoever calls this calls [`persist`](Self::persist)
    /// afterwards, for the reason stated there in the more dangerous
    /// direction: a port removed from the kernel while the boot still replays
    /// the old ruleset is a port that reopens at the next restart, reported as
    /// closed.
    fn close(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool>;

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

    /// How to ask this front-end, later, whether it is filtering at all.
    ///
    /// Returned rather than run for the same reason as `open_port_check`, and
    /// belonging to the front-end for the same reason too: the question is
    /// spelled differently per implementation, and a task asking it directly
    /// would have to pick one. It exists so `firewall.manage-ports` can declare
    /// what it needs — a policy to add a rule to — where the interface can read
    /// it, instead of that fact living only inside the task's own `run`.
    fn active_check(&self) -> (Command, String);
}
