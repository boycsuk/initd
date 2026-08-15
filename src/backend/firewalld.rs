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
use crate::domain::firewall::{AllowedPort, FirewallManager, FirewallState, PortOrigin, Protocol};
use crate::error::{Error, Result};
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

/// Exit status reported when polkit refused the query.
///
/// Not an answer, unlike the two above it, and that difference is the whole
/// reason it is named. firewalld authorizes *reads* through polkit — measured
/// on `rockylinux:9` against a running daemon, where an unprivileged
/// `--list-services`, `--list-ports`, `--info-service` and `--state` each
/// answer `NotAuthorizedException: Not Authorized(uid)` and exit 253, while
/// the same commands under `sudo` answer `cockpit dhcpv6-client ssh` and
/// `running`.
///
/// A refusal read as an empty listing is the failure `nftables::state` was
/// already fixed for, one front-end along: `close` asks `is_allowed` to
/// confirm what `--remove-port` did, and a listing that could not be read
/// answers "the port is gone" for the one case `--remove-port` cannot
/// handle — a port the zone admits as a service, which on a stock RHEL host
/// is SSH.
const NOT_AUTHORIZED: i32 = 253;

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

    /// Removes a port from both the running configuration and the stored one.
    ///
    /// The mirror of [`add_port`](Self::add_port), and two calls for the same
    /// reason rather than a similar one: removing from runtime alone leaves a
    /// port that any later `--reload` restores, and removing from the permanent
    /// configuration alone leaves it open until the next boot. Either half on
    /// its own reports a closed port that is not closed, in one case
    /// immediately and in the other eventually.
    ///
    /// `--reload` is not called here either, and here the argument is sharper:
    /// a batch that opens one port and closes another would have the opening
    /// discarded by a reload standing between them.
    fn remove_port(executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()> {
        let spec = Self::port_spec(port, protocol);

        for args in [
            vec!["--zone", ZONE, "--remove-port", &spec],
            vec!["--permanent", "--zone", ZONE, "--remove-port", &spec],
        ] {
            // Idempotent in the same shape as adding: removing a port that is
            // not there reports `NOT_ENABLED` on stderr and exits zero. That is
            // also what removing a port admitted only by a *service* looks
            // like, which is why the caller reads the state back afterwards
            // instead of believing this.
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
        // Privileged for the reason [`NOT_AUTHORIZED`] records: firewalld
        // authorizes reads through polkit, and there is no polkit agent under
        // a TUI. Every write here already escalates; the reads did not, and
        // answered nothing on a live RHEL host.
        let command = Command::new("firewall-cmd")
            .args(["--info-service", service])
            .privileged();

        let output = executor.run(&command)?;

        if output.code == NOT_AUTHORIZED {
            return Err(Error::FirewallStateUnreadable);
        }

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
        let command = Command::new("firewall-cmd")
            .args(["--zone", ZONE, "--list-services"])
            .privileged();

        let output = executor.run(&command)?;

        // A refusal is not "this zone admits no services". Reported, because
        // the difference decides whether `close` may believe its own
        // read-back: on a stock RHEL host SSH is admitted as a service, and an
        // empty list here is what let a port that stayed open be reported as
        // closed.
        if output.code == NOT_AUTHORIZED {
            return Err(Error::FirewallStateUnreadable);
        }

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
    ///
    /// Specs only, for the questions that ask whether a port is *covered*.
    /// Anything meaning to *close* one needs [`admitted`](Self::admitted)
    /// instead, since the two sources come apart the moment a removal is
    /// attempted.
    fn open_ports(executor: &dyn Executor) -> Result<Vec<String>> {
        Ok(Self::admitted(executor)?
            .into_iter()
            .map(|port| port.spec)
            .collect())
    }

    /// Every port the zone admits, each carrying what admitted it.
    ///
    /// The distinction `open_ports` discards. `--list-ports` names ports that
    /// `--remove-port` closes; a service names ports that it does not, and
    /// firewalld reports success either way — so the caller that means to close
    /// something has to be told which it is holding before it tries.
    ///
    /// A range stays one row rather than being expanded into the ports it
    /// covers. `--remove-port 8000-8080/tcp` closes it wholesale, so the range
    /// as written is both the honest description and the closeable unit;
    /// expanding it would offer eighty-one removals, none of which work.
    fn admitted(executor: &dyn Executor) -> Result<Vec<AllowedPort>> {
        let command = Command::new("firewall-cmd")
            .args(["--zone", ZONE, "--list-ports"])
            .privileged();

        let output = executor.run(&command)?;

        if output.code == NOT_AUTHORIZED {
            return Err(Error::FirewallStateUnreadable);
        }

        let mut ports: Vec<AllowedPort> = if output.success() {
            output
                .stdout
                .split_whitespace()
                .map(AllowedPort::direct)
                .collect()
        } else {
            Vec::new()
        };

        for service in Self::services(executor)? {
            ports.extend(
                Self::service_ports(executor, &service)?
                    .into_iter()
                    .map(|spec| AllowedPort {
                        spec,
                        origin: PortOrigin::Service(service.clone()),
                    }),
            );
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
        // Searched where system tools live rather than on the inherited `PATH`,
        // for the reason `Command::locating` records: this process runs as the
        // operator, and a non-root login need not carry `/usr/sbin`. Not a
        // lookup, because a lookup cannot answer this question — the point of
        // `--state` is to separate an installed daemon that is stopped from one
        // that is absent, and both have the binary on disk.
        //
        // Worth more here than it looks. firewalld is the *first* candidate
        // RHEL offers, so a `firewall-cmd` invisible on `PATH` reads as absent
        // and silently promotes nftables — which would then write a table of
        // this tool's own over a host whose ruleset firewalld holds, exactly
        // the outcome `RhelBackend::firewalls` orders these two to prevent.
        let command = Command::new("firewall-cmd")
            .arg("--state")
            .with_env("PATH", crate::exec::LOOKUP_PATH);

        // An absent `firewall-cmd` answers the question as surely as a stopped
        // daemon does, and mapping only the exit codes left the one case that
        // never produces one. It matters most here because firewalld is the
        // *first* candidate RHEL offers: a host whose administrator removed it
        // to drive `nft` directly — a state this backend documents as ordinary
        // rather than broken — failed on the first candidate and never reached
        // the second.
        let output = match executor.run(&command) {
            Ok(output) => output,
            Err(Error::ProgramNotFound { .. }) => return Ok(false),
            Err(other) => return Err(other),
        };

        if matches!(output.code, NOT_RUNNING | RUNNING_BUT_FAILED) {
            return Ok(false);
        }

        // A refusal proves the opposite of absence: polkit only has something
        // to refuse when the daemon is there to answer. Left unprivileged
        // deliberately — this runs while the tree is drawn, where escalating
        // would raise a password prompt for a row nobody asked for — so the
        // refusal is read rather than avoided.
        //
        // The direction matters more here than anywhere else in this file.
        // firewalld is the *first* candidate RHEL offers, so answering `false`
        // promotes nftables, and this tool would then write `inet initd` with
        // `policy drop` over a host whose ruleset firewalld holds — the exact
        // outcome `RhelBackend::firewalls` orders the two to prevent, reached
        // by the one path that ordering cannot see.
        if output.code == NOT_AUTHORIZED {
            return Ok(true);
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
        //
        // The word, not the exit code. `systemctl is-enabled` exits 0 for
        // `static`, `indirect` and `enabled-runtime` as readily as for
        // `enabled` — measured on this host, where `static` units answer 0 —
        // and a `static` unit does not start at boot. firewalld ships `static`
        // on RHEL often enough that this is the ordinary case rather than the
        // odd one, so the exit code reported a firewall surviving a reboot
        // that would not come back.
        //
        // Both siblings already compare the word: `systemd::state` and
        // `apt_periodic::is_enabled`. The nftables side of this same trait has
        // a test named for the property — "a ruleset only in the kernel is not
        // reported as persisted" — and this side had neither the test nor the
        // check.
        let command = Command::new("systemctl").args(["is-enabled", "firewalld"]);

        // `executor.run` rather than `run_capturing`: `disabled` exits 1, and
        // that is an answer rather than a failure to report.
        Ok(executor.run(&command)?.stdout.trim() == "enabled")
    }

    fn disable(&self, executor: &dyn Executor) -> Result<()> {
        // Simpler than the nftables inverse, because firewalld *is* the thing
        // filtering: stop the daemon and the host stops filtering. There is no
        // table of this tool's own to remove, and the stored zone
        // configuration is left alone deliberately — the ports an
        // administrator added over months are not this task's to discard, and
        // a daemon that is not running enforces none of them anyway.
        //
        // `disable --now` mirrors the `enable --now` above: stopping without
        // disabling is a firewall that returns at the next reboot, which this
        // task would have reported as off.
        let command = Command::new("systemctl")
            .args(["disable", "--now", "firewalld"])
            .privileged();

        run_checked(executor, &command)
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

    fn close(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool> {
        Self::remove_port(executor, port, protocol)?;

        // Asked through `is_allowed`, which expands services and honours
        // ranges, so this answers `false` for exactly the case `--remove-port`
        // cannot handle: a port the zone admits as a service. On a stock RHEL
        // host that is SSH, and the two commands above will have reported
        // success while changing nothing.
        Ok(!self.is_allowed(executor, port, protocol)?)
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
    fn active_check(&self) -> (Command, String) {
        // `--state` prints `running` and exits 0 when the daemon holds the
        // ruleset, which is the whole of what "filtering" means here: firewalld
        // has nothing to switch on, and its default zone already rejects what
        // it was not told to admit. That is why this differs from the nftables
        // implementation, which asks whether this tool's own table exists.
        //
        // The word rather than the exit code, because a `Check` is a substring
        // match on stdout: a stopped daemon exits 252 and a failed one 251, and
        // neither prints `running`.
        (
            Command::new("firewall-cmd").arg("--state"),
            "running".to_owned(),
        )
    }

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
            allowed: Self::admitted(executor)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_refused_query_does_not_read_as_an_absent_daemon() {
        // polkit only has something to refuse when the daemon is there to
        // answer, so 253 proves presence. Answering `false` would promote
        // nftables — the first candidate RHEL offers being firewalld — and
        // write a `policy drop` table of this tool's own over a host whose
        // ruleset firewalld holds.
        let mock = MockExecutor::with_replies([Reply::failure(NOT_AUTHORIZED, "Not Authorized")]);

        let available = Firewalld::new()
            .is_available(&mock)
            .expect("a refusal must not raise");

        assert!(
            available,
            "a daemon that refused the question is still the daemon in charge"
        );
        assert!(
            !mock.any_privileged(),
            "the probe runs while the tree is drawn and must not prompt"
        );
    }

    #[test]
    fn a_refused_listing_is_not_read_as_an_empty_one() {
        // The failure `nftables::state` was already fixed for, one front-end
        // along. `close` confirms `--remove-port` through `is_allowed`, and a
        // listing that could not be read answers "the port is gone" for the
        // one case `--remove-port` cannot handle: a port the zone admits as a
        // service, which on a stock RHEL host is SSH.
        let mock = MockExecutor::with_replies([Reply::failure(NOT_AUTHORIZED, "Not Authorized")]);

        let err = Firewalld::new()
            .is_allowed(&mock, 22, Protocol::Tcp)
            .expect_err("a refused listing must not answer the question");

        assert!(matches!(err, Error::FirewallStateUnreadable), "{err:?}");
    }

    #[test]
    fn closing_a_port_reads_it_back_through_a_privileged_listing() {
        // Measured on `rockylinux:9` against a running daemon: unprivileged,
        // every read answers `NotAuthorizedException` and exits 253; through
        // `sudo` the same commands answer `cockpit dhcpv6-client ssh` and
        // `running`. The writes always escalated and the reads did not.
        let mock = MockExecutor::with_replies([
            Reply::ok(""), // --remove-port, runtime
            Reply::ok(""), // --remove-port, permanent
            Reply::ok(""), // --list-ports
            Reply::ok(""), // --list-services
        ]);

        Firewalld::new()
            .close(&mock, 22, Protocol::Tcp)
            .expect("closing must succeed");

        assert!(
            mock.recorded()
                .iter()
                .filter(|command| command.args.iter().any(|arg| arg.starts_with("--list")))
                .all(|command| command.needs_root),
            "every listing must escalate: {:?}",
            mock.recorded_lines()
        );
    }

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
    fn an_absent_front_end_is_not_available() {
        // The case the exit codes above cannot express: no `firewall-cmd` at
        // all, so no process runs and no status comes back. It must answer the
        // question rather than raise, because RHEL asks firewalld *first* — an
        // administrator who removed it to drive `nft` directly would otherwise
        // fail on the first candidate and never reach the second.
        let mock = MockExecutor::with_replies([Reply::NotFound]);

        let available = Firewalld::new()
            .is_available(&mock)
            .expect("an absent binary must not raise");

        assert!(!available);
    }

    #[test]
    fn availability_is_asked_without_privilege() {
        // Asked before the tool knows it will need any, so it must not prompt.
        let mock = MockExecutor::with_replies([Reply::ok("running")]);

        Firewalld::new().is_available(&mock).expect("runs");

        assert!(!mock.any_privileged());
    }

    #[test]
    fn availability_is_asked_where_firewall_cmd_actually_lives() {
        // Unprivileged, so it is spawned under the environment this process
        // inherited — which belongs to the operator, not to root, and on a
        // non-root login need not contain `/usr/sbin`. `nft` had the identical
        // defect one module over.
        //
        // Not solved with a lookup the way `nft` was, because a lookup cannot
        // answer this question: `--state` exists to tell a stopped daemon from
        // an absent one, and both have the binary on disk.
        //
        // It matters more here than the shared cause suggests. firewalld is the
        // first candidate RHEL offers, so an invisible `firewall-cmd` reads as
        // absent and silently promotes nftables — which would write a table of
        // this tool's own over a host whose ruleset firewalld holds, the very
        // outcome the ordering in `RhelBackend::firewalls` exists to prevent.
        let mock = MockExecutor::with_replies([Reply::ok("running")]);

        Firewalld::new().is_available(&mock).expect("runs");

        let searched = mock
            .single_command()
            .env
            .into_iter()
            .find(|(key, _)| key == "PATH")
            .map(|(_, value)| value)
            .expect("the state query must carry a PATH of its own");

        assert!(
            searched.split(':').any(|entry| entry == "/usr/sbin"),
            "firewall-cmd must be looked for where it lives: {searched}"
        );
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
    fn closing_writes_both_the_running_and_the_stored_configuration() {
        // The mirror of allowing, and wrong in both directions if either half
        // is skipped: runtime alone is a port any later reload restores, and
        // permanent alone is a port that stays open until the next boot.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            // The read-back, through `--list-ports` and then the services.
            Reply::ok(""),
            Reply::ok(""),
        ]);

        let closed = Firewalld::new()
            .close(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        assert!(closed);

        let lines = mock.recorded_lines();

        let removals: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("--remove-port"))
            .collect();

        assert_eq!(removals.len(), 2, "{removals:?}");
        assert!(
            removals.iter().any(|line| !line.contains("--permanent")),
            "the runtime configuration must be written: {removals:?}"
        );
        assert!(
            removals.iter().any(|line| line.contains("--permanent")),
            "the stored configuration must be written: {removals:?}"
        );
    }

    #[test]
    fn closing_never_reloads() {
        // Sharper here than for allowing: a batch that opens one port and
        // closes another would have the opening discarded by a reload standing
        // between them.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Firewalld::new()
            .close(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        for line in mock.recorded_lines() {
            assert!(!line.contains("--reload"), "must not reload: {line}");
        }
    }

    #[test]
    fn a_port_a_service_admits_is_reported_as_still_open() {
        // The case the whole design exists for. On a stock RHEL host `22/tcp`
        // is admitted by the service `ssh`, and `--remove-port 22/tcp` against
        // that exits zero having closed nothing. Believing the exit status
        // would report a closed port over a session that is still reachable —
        // and, worse, over one an operator now thinks is protected.
        let mock = MockExecutor::with_replies([
            // Both removals "succeed".
            Reply::ok(""),
            Reply::ok(""),
            // The read-back finds nothing named directly...
            Reply::ok(""),
            // ...but the service still admits it.
            Reply::ok("ssh"),
            Reply::ok("ssh\n  ports: 22/tcp\n  protocols:\n"),
        ]);

        let closed = Firewalld::new()
            .close(&mock, 22, Protocol::Tcp)
            .expect("the call must succeed");

        assert!(
            !closed,
            "a port a service admits is still open after --remove-port"
        );
    }

    #[test]
    fn closing_a_port_named_directly_reports_it_closed() {
        // The other half of the pair above: where `--remove-port` is the right
        // instrument, the answer must be an unqualified yes.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("51820/udp"),
            Reply::ok(""),
        ]);

        let closed = Firewalld::new()
            .close(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        assert!(closed);
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

        let specs: Vec<&str> = state
            .allowed
            .iter()
            .map(|port| port.spec.as_str())
            .collect();

        assert_eq!(specs, ["51820/udp", "22/tcp"]);
    }

    #[test]
    fn a_port_a_service_admits_says_which_service() {
        // The finding this distinction exists for. On a stock RHEL host the
        // `22/tcp` in a listing came from the service `ssh`, and
        // `--remove-port 22/tcp` against it exits zero having closed nothing —
        // so a caller offering to close it has to be told before it tries,
        // rather than discovering it from an exit status that says success.
        let mock = MockExecutor::with_replies([
            Reply::ok("running"),
            Reply::ok("51820/udp"),
            Reply::ok("ssh"),
            Reply::ok("ssh\n  ports: 22/tcp\n  protocols:\n"),
        ]);

        let state = Firewalld::new()
            .state(&mock)
            .expect("the query must succeed");

        let direct = state
            .allowed
            .iter()
            .find(|port| port.spec == "51820/udp")
            .expect("the directly-named port must be listed");

        let by_service = state
            .allowed
            .iter()
            .find(|port| port.spec == "22/tcp")
            .expect("the service-admitted port must be listed");

        assert_eq!(direct.origin, PortOrigin::Direct);
        assert_eq!(by_service.origin, PortOrigin::Service("ssh".to_owned()));
    }

    #[test]
    fn a_range_stays_one_row_rather_than_the_ports_it_covers() {
        // `--remove-port 8000-8080/tcp` closes the range wholesale, so the
        // range as written is the closeable unit. Expanding it would offer
        // eighty-one removals, none of which work.
        let mock = MockExecutor::with_replies([
            Reply::ok("running"),
            Reply::ok("8000-8080/tcp"),
            Reply::ok(""),
        ]);

        let state = Firewalld::new()
            .state(&mock)
            .expect("the query must succeed");

        assert_eq!(state.allowed, [AllowedPort::direct("8000-8080/tcp")]);
    }

    #[test]
    fn a_unit_that_does_not_start_at_boot_is_not_reported_as_persisted() {
        // `systemctl is-enabled` exits 0 for `static`, `indirect` and
        // `enabled-runtime` as readily as for `enabled` — measured, and
        // firewalld ships `static` on RHEL often enough for this to be the
        // ordinary case. Reading the exit code reported a firewall surviving a
        // reboot it would not come back from, which is the mirror of what
        // `a_ruleset_only_in_the_kernel_is_not_reported_as_persisted` pins on
        // the nftables side. This side had no test at all.
        for answer in ["static\n", "indirect\n", "enabled-runtime\n", "disabled\n"] {
            let mock = MockExecutor::with_replies([Reply::ok(answer)]);

            assert!(
                !Firewalld::new()
                    .is_persisted(&mock)
                    .expect("the question must be answerable"),
                "{} does not start at boot",
                answer.trim()
            );
        }

        let mock = MockExecutor::with_replies([Reply::ok("enabled\n")]);

        assert!(
            Firewalld::new()
                .is_persisted(&mock)
                .expect("the question must be answerable"),
            "an enabled unit is the one case that does come back"
        );
    }
}
