//! `firewalld` implementation of [`FirewallManager`].
//!
//! The supported front-end on RHEL, where it is installed and running out of
//! the box. It is not a sibling of [`Nftables`](super::nftables::Nftables) the
//! way two package managers are siblings: both drive the same kernel subsystem,
//! and on a host running firewalld the two cannot be used together. nftables
//! evaluates every chain registered on a hook, and while `accept` merely passes
//! a packet to the next chain, `drop` takes effect immediately — so a table of
//! this tool's own with a drop policy overrides whatever firewalld admits. An
//! administrator would open a port with `firewall-cmd`, be told it succeeded,
//! and find it still closed. Which of the two acts is therefore resolved per
//! host by [`super::firewall_for`], and never layered.
//!
//! Two things about firewalld shape this implementation and have no equivalent
//! in the nftables one:
//!
//! - **There is no such thing as turning filtering on.** firewalld filters
//!   whenever it runs, and its default zone already rejects what it was not
//!   told to admit. `enable` therefore opens the ports first and starts the
//!   daemon second, which is also why it cannot lock anybody out.
//! - **A port may be open without being a port.** RHEL admits SSH as the
//!   *service* `ssh` rather than as `22/tcp`, so asking about the port alone
//!   answers "closed" on a stock machine where SSH is plainly reachable.

use super::systemd::run_checked;
use crate::domain::firewall::{FirewallManager, FirewallState, Protocol};
use crate::error::Result;
use crate::exec::{Command, Executor};

/// The zone rules are written to.
///
/// firewalld's own default, and the one an interface lands in unless it was
/// moved. Resolving `--get-default-zone` per call was rejected: a rule written
/// to a zone no interface is in silently filters nothing, and a tool that
/// followed the default wherever it pointed would make that failure invisible.
/// Naming the zone means the rules are somewhere an administrator can find.
const ZONE: &str = "public";

/// Exit status `firewall-cmd --state` reports when the daemon is not running.
const NOT_RUNNING: i32 = 252;

/// Exit status reported when the daemon started but failed.
///
/// Distinct from not running, and treated the same way here: a daemon in this
/// state holds no ruleset, so driving it would report success and filter
/// nothing.
const RUNNING_BUT_FAILED: i32 = 251;

/// Manages filtering through `firewall-cmd`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Firewalld;

impl Firewalld {
    pub const fn new() -> Self {
        Self
    }

    /// A port as firewalld spells it: `port/protocol`.
    fn port_spec(port: u32, protocol: Protocol) -> String {
        format!("{port}/{}", protocol.as_str())
    }

    /// Adds a port to both the running configuration and the stored one.
    ///
    /// Two calls rather than one followed by `--reload`, which is what
    /// firewalld's own documentation recommends. The reason is not tidiness:
    /// `--reload` discards runtime changes that were never persisted, so a
    /// sequence that opened a port in runtime and then reloaded would close it
    /// again — and if that port were SSH, the session issuing the reload would
    /// be what closed. `--complete-reload` is never used at all: it drops
    /// connection state and terminates established sessions by design.
    fn add_port(executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()> {
        let spec = Self::port_spec(port, protocol);

        for args in [
            vec!["--zone", ZONE, "--add-port", &spec],
            vec!["--permanent", "--zone", ZONE, "--add-port", &spec],
        ] {
            // Idempotent on firewalld's side: adding a port that is already
            // open reports `ALREADY_ENABLED` on stderr and exits zero, which is
            // why this neither checks first nor treats stderr as failure.
            let command = Command::new("firewall-cmd").args(args).privileged();

            run_checked(executor, &command)?;
        }

        Ok(())
    }

    /// The ports a named service covers.
    ///
    /// Read from `--info-service`, whose `ports:` line lists them space
    /// separated in the same `port/protocol` form as `--list-ports`.
    fn service_ports(executor: &dyn Executor, service: &str) -> Result<Vec<String>> {
        let command = Command::new("firewall-cmd").args(["--info-service", service]);

        let output = executor.run(&command)?;

        if !output.success() {
            // A service firewalld cannot describe contributes no ports rather
            // than failing the question it was asked as part of.
            return Ok(Vec::new());
        }

        Ok(output
            .stdout
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ports:"))
            .flat_map(str::split_whitespace)
            .map(str::to_owned)
            .collect())
    }

    /// The services currently admitted in the zone.
    fn services(executor: &dyn Executor) -> Result<Vec<String>> {
        let command = Command::new("firewall-cmd").args(["--zone", ZONE, "--list-services"]);

        let output = executor.run(&command)?;

        if !output.success() {
            return Ok(Vec::new());
        }

        Ok(output
            .stdout
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    }

    /// Every port the zone admits, whether named directly or through a service.
    ///
    /// The two sources are kept together because an administrator asking what
    /// is open does not care which of firewalld's two ways admitted it — and on
    /// a stock RHEL host the answer for SSH comes entirely from the service.
    fn open_ports(executor: &dyn Executor) -> Result<Vec<String>> {
        let command = Command::new("firewall-cmd").args(["--zone", ZONE, "--list-ports"]);

        let output = executor.run(&command)?;

        let mut ports: Vec<String> = if output.success() {
            output
                .stdout
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        } else {
            Vec::new()
        };

        for service in Self::services(executor)? {
            ports.extend(Self::service_ports(executor, &service)?);
        }

        Ok(ports)
    }

    /// Whether a `port/protocol` spec covers a port, honouring ranges.
    ///
    /// firewalld admits `8000-8080/tcp` wherever it admits `8080/tcp`, and a
    /// service is free to declare its ports either way, so a string comparison
    /// would answer "closed" for a port inside a range that is plainly open.
    fn spec_covers(spec: &str, port: u32, protocol: Protocol) -> bool {
        let Some((ports, spec_protocol)) = spec.split_once('/') else {
            return false;
        };

        if spec_protocol != protocol.as_str() {
            return false;
        }

        match ports.split_once('-') {
            Some((first, last)) => {
                let (Ok(first), Ok(last)) = (first.parse::<u32>(), last.parse::<u32>()) else {
                    return false;
                };

                (first..=last).contains(&port)
            }
            None => ports.parse::<u32>().is_ok_and(|listed| listed == port),
        }
    }
}

impl FirewallManager for Firewalld {
    fn name(&self) -> &'static str {
        "firewalld"
    }

    fn is_available(&self, executor: &dyn Executor) -> Result<bool> {
        // `--state` rather than `--version`: the question is which front-end
        // holds this host's ruleset, and an installed daemon that is not
        // running holds none. It exits 252 when stopped and 251 when it started
        // and failed, and neither is an error to report upwards — they are the
        // answer.
        let command = Command::new("firewall-cmd").arg("--state");

        let output = executor.run(&command)?;

        if matches!(output.code, NOT_RUNNING | RUNNING_BUT_FAILED) {
            return Ok(false);
        }

        Ok(output.success())
    }

    fn persist(&self, executor: &dyn Executor) -> Result<bool> {
        // Nothing to do, and that is a property of this front-end rather than
        // an omission. Every port goes in twice — runtime and `--permanent` —
        // in `add_port`, and `enable` turns the unit on with `enable --now`, so
        // both halves of "survives a reboot" are already done by the time
        // anything could call this.
        //
        // Implemented explicitly rather than defaulted on the trait: a default
        // would be inherited by the next front-end added, and "does nothing" is
        // the wrong answer for anything that is not firewalld. The nftables
        // implementation is what shows why — there, forgetting this leaves a
        // server that comes back from a reboot with every port open.
        //
        // Whether the unit is enabled is still read rather than assumed:
        // `enable` turns it on, and a host where that did not take is one where
        // the rules do not come back.
        self.is_persisted(executor)
    }

    fn is_persisted(&self, executor: &dyn Executor) -> Result<bool> {
        // The unit being enabled is the whole question here: the rules are in
        // the permanent configuration already, and what decides whether they
        // come back is whether firewalld starts to read them.
        let command = Command::new("systemctl").args(["is-enabled", "firewalld"]);

        Ok(executor.run(&command)?.success())
    }

    fn enable(&self, executor: &dyn Executor, keep_open: &[(u32, Protocol)]) -> Result<()> {
        // The ports go in before the daemon starts, which is the opposite of
        // the nftables implementation's problem and for the same reason. There
        // the ruleset had to be applied atomically because a default-deny
        // policy would otherwise land before the rule admitting SSH; here
        // filtering does not exist until firewalld runs, so writing the stored
        // configuration first means it is already admitting SSH the moment it
        // begins to filter. `firewall-offline-cmd` is what writes it, because
        // `firewall-cmd` needs the daemon this has not started yet.
        for (port, protocol) in keep_open {
            let spec = Self::port_spec(*port, *protocol);
            let command = Command::new("firewall-offline-cmd")
                .args(["--zone", ZONE, "--add-port", &spec])
                .privileged();

            run_checked(executor, &command)?;
        }

        // `enable --now` rather than `start`: a firewall that filters until the
        // next reboot and then stops is worse than one that never started, in
        // that nothing reports it.
        let command = Command::new("systemctl")
            .args(["enable", "--now", "firewalld"])
            .privileged();

        run_checked(executor, &command)?;

        // The same ports again, now through the running daemon. The offline
        // call above wrote the stored configuration, which a daemon that was
        // *already* running would not have read — and this is reached in that
        // case too, since starting a started unit succeeds.
        for (port, protocol) in keep_open {
            Self::add_port(executor, *port, *protocol)?;
        }

        Ok(())
    }

    fn allow(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()> {
        Self::add_port(executor, port, protocol)
    }

    /// Asks firewalld's own zone, since that is where the rule was written.
    ///
    /// `--list-ports` rather than `--query-port`: a check carries one command
    /// and a needle, and `--query-port` answers `yes`/`no` — a needle of `yes`
    /// would match the word wherever it appeared. Listing the zone's ports and
    /// looking for the spec keeps the needle specific to what was asked.
    ///
    /// The limitation is worth stating because `is_allowed` does not share it:
    /// that method also expands services and honours ranges, so a port admitted
    /// as the *service* `ssh` — the stock RHEL arrangement — is not named here.
    /// A single command cannot do the expansion. The direction of the error is
    /// the safe one: it reports unresolved what may already be handled, and the
    /// administrator is pointed at a setting that turns out to be fine.
    fn open_port_check(&self, port: u32, protocol: Protocol) -> (Command, String) {
        (
            Command::new("firewall-cmd").args(["--zone", ZONE, "--list-ports"]),
            format!("{port}/{}", protocol.as_str()),
        )
    }

    fn is_allowed(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool> {
        // Deliberately more than `--query-port`, which answers only for ports
        // named directly. RHEL admits SSH as the service `ssh`, so on a stock
        // host the port question returns false for a port that is open — the
        // default case, not an edge one.
        //
        // What this still does not cover is rich rules and source ports, which
        // can also admit traffic. A host using those gets an answer that is too
        // conservative rather than one that is wrong: it reports closed what is
        // open, and the caller offers to open it again, which firewalld treats
        // as a no-op.
        Ok(Self::open_ports(executor)?
            .iter()
            .any(|spec| Self::spec_covers(spec, port, protocol)))
    }

    fn state(&self, executor: &dyn Executor) -> Result<FirewallState> {
        if !self.is_available(executor)? {
            return Ok(FirewallState {
                active: false,
                allowed: Vec::new(),
            });
        }

        // Active whenever the daemon runs: firewalld has no filtering to switch
        // on, and its default zone rejects what it was not told to admit. That
        // differs from the nftables implementation, where active means this
        // tool's own table exists.
        Ok(FirewallState {
            active: true,
            allowed: Self::open_ports(executor)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_stopped_daemon_is_not_available() {
        // Exit 252 is firewalld reporting that it is not running, which is an
        // answer rather than a failure to propagate.
        let mock = MockExecutor::with_replies([Reply::failure(NOT_RUNNING, "not running")]);

        let available = Firewalld::new()
            .is_available(&mock)
            .expect("a stopped daemon must not raise");

        assert!(!available);
    }

    #[test]
    fn a_daemon_that_started_and_failed_is_not_available() {
        // Distinct exit status, same conclusion: it holds no ruleset, so
        // driving it would report success and filter nothing.
        let mock = MockExecutor::with_replies([Reply::failure(RUNNING_BUT_FAILED, "failed")]);

        let available = Firewalld::new()
            .is_available(&mock)
            .expect("a failed daemon must not raise");

        assert!(!available);
    }

    #[test]
    fn a_running_daemon_is_available() {
        let mock = MockExecutor::with_replies([Reply::ok("running")]);

        assert!(
            Firewalld::new()
                .is_available(&mock)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn availability_is_asked_without_privilege() {
        // Asked before the tool knows it will need any, so it must not prompt.
        let mock = MockExecutor::with_replies([Reply::ok("running")]);

        Firewalld::new().is_available(&mock).expect("runs");

        assert!(!mock.any_privileged());
    }

    #[test]
    fn enabling_opens_the_ports_before_starting_the_daemon() {
        // The ordering that makes this safe over a remote session. firewalld
        // does not filter until it runs, so the stored configuration must
        // already admit SSH when it starts.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Firewalld::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        let lines = mock.recorded_lines();
        let offline = lines
            .iter()
            .position(|line| line.starts_with("firewall-offline-cmd"))
            .expect("the port must be written offline");
        let start = lines
            .iter()
            .position(|line| line.contains("systemctl"))
            .expect("the daemon must be started");

        assert!(
            offline < start,
            "the port must be open before the daemon filters: {lines:?}"
        );
    }

    #[test]
    fn enabling_never_completely_reloads() {
        // `--complete-reload` drops connection state and terminates established
        // sessions, which over SSH means the session running it.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Firewalld::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("complete-reload")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn allowing_writes_both_the_running_and_the_stored_configuration() {
        // One without the other is a rule that vanishes at reboot, or one that
        // does nothing until then.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        Firewalld::new()
            .allow(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        let lines = mock.recorded_lines();

        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|line| !line.contains("--permanent")),
            "the runtime configuration must be written: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("--permanent")),
            "the stored configuration must be written: {lines:?}"
        );
    }

    #[test]
    fn allowing_never_reloads() {
        // The pair of calls exists precisely to avoid `--reload`, which
        // discards runtime changes that were never persisted.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        Firewalld::new()
            .allow(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("reload")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_port_opened_directly_is_allowed() {
        let mock = MockExecutor::with_replies([Reply::ok("2222/tcp"), Reply::ok("")]);

        assert!(
            Firewalld::new()
                .is_allowed(&mock, 2222, Protocol::Tcp)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_port_open_only_through_a_service_is_still_allowed() {
        // The case a `--query-port` implementation would get wrong, and it is
        // the default one: stock RHEL admits SSH as a service, not as 22/tcp.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok("ssh dhcpv6-client"),
            Reply::ok("ssh\n  ports: 22/tcp\n  protocols:\n"),
            Reply::ok("dhcpv6-client\n  ports: 546/udp\n  protocols:\n"),
        ]);

        assert!(
            Firewalld::new()
                .is_allowed(&mock, 22, Protocol::Tcp)
                .expect("the query must succeed"),
            "a service admitting the port must answer the port question"
        );
    }

    #[test]
    fn a_port_inside_an_open_range_is_allowed() {
        // firewalld admits ranges wherever it admits ports, and a string
        // comparison would call an open port closed.
        let mock = MockExecutor::with_replies([Reply::ok("8000-8080/tcp"), Reply::ok("")]);

        assert!(
            Firewalld::new()
                .is_allowed(&mock, 8080, Protocol::Tcp)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_port_outside_an_open_range_is_not_allowed() {
        // The other direction: a range must not admit everything near it.
        let mock = MockExecutor::with_replies([Reply::ok("8000-8080/tcp"), Reply::ok("")]);

        assert!(
            !Firewalld::new()
                .is_allowed(&mock, 8081, Protocol::Tcp)
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_port_allowed_over_tcp_is_not_allowed_over_udp() {
        // WireGuard is UDP and SSH is TCP on adjacent numbers often enough that
        // conflating them would open the wrong thing.
        let mock = MockExecutor::with_replies([Reply::ok("51820/tcp"), Reply::ok("")]);

        assert!(
            !Firewalld::new()
                .is_allowed(&mock, 51820, Protocol::Udp)
                .expect("the query must succeed"),
            "a tcp rule must not satisfy a udp question"
        );
    }

    #[test]
    fn a_stopped_daemon_reports_inactive_rather_than_failing() {
        let mock = MockExecutor::with_replies([Reply::failure(NOT_RUNNING, "not running")]);

        let state = Firewalld::new()
            .state(&mock)
            .expect("a stopped daemon must not raise");

        assert!(!state.active);
        assert!(state.allowed.is_empty());
    }

    #[test]
    fn the_state_lists_ports_and_services_together() {
        // An administrator asking what is open does not care which of
        // firewalld's two ways admitted it.
        let mock = MockExecutor::with_replies([
            Reply::ok("running"),
            Reply::ok("51820/udp"),
            Reply::ok("ssh"),
            Reply::ok("ssh\n  ports: 22/tcp\n  protocols:\n"),
        ]);

        let state = Firewalld::new()
            .state(&mock)
            .expect("the query must succeed");

        assert!(state.active);
        assert_eq!(state.allowed, ["51820/udp", "22/tcp"]);
    }
}
