//! `nftables` implementation of [`FirewallManager`].
//!
//! The modern in-kernel filtering subsystem, and the default on current Debian
//! and Arch. Rules live in a table this tool owns rather than in `filter`,
//! which the distribution and other software also write to: a table of its own
//! can be listed, reasoned about and removed without disturbing anything else.
//!
//! `ufw` is deliberately not implemented as a sibling. It is a wrapper over
//! whichever backend is installed, so driving both it and `nft` on one host is
//! how a rule ends up invisible to the tool that did not write it. Where `ufw`
//! is active, this implementation reports itself unavailable.

use super::systemd::run_checked;
use crate::domain::firewall::{FirewallManager, FirewallState, Protocol};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// The table this tool owns.
///
/// Named for the tool so its rules are distinguishable from the distribution's
/// own. `inet` covers IPv4 and IPv6 in one table — a rule added only to `ip`
/// leaves the same port reachable over IPv6, which is the quiet way a firewall
/// ends up not filtering.
const TABLE: &str = "inet initd";

/// The chain holding inbound rules.
const CHAIN: &str = "input";

/// Where systemd's `nftables.service` reads the ruleset at boot.
///
/// Measured rather than assumed: both `debian:13` and `archlinux:latest` ship
/// the unit with `ExecStart=/usr/sbin/nft -f /etc/nftables.conf` (Arch spells
/// the binary `/usr/bin/nft`; the file is the same). Writing this file is
/// therefore what makes a ruleset outlive a reboot on a systemd host.
const SYSTEMD_RULES: &str = "/etc/nftables.conf";

/// The unit that replays [`SYSTEMD_RULES`] at boot.
///
/// Enabling it is half of persisting: a file nothing reads restores nothing.
const SYSTEMD_UNIT: &str = "nftables.service";

/// Where Alpine's OpenRC service keeps the ruleset.
///
/// A different path from the systemd families — measured on `alpine:3.23`,
/// where `apk info -L nftables` owns `etc/nftables.nft` and ships no
/// `/etc/nftables.conf` at all. Its init script defaults `rules_file` to this,
/// and offers `save` as an extra command.
const OPENRC_RULES: &str = "/etc/nftables.nft";

/// Alpine's OpenRC service name.
const OPENRC_SERVICE: &str = "nftables";

/// Manages filtering through `nft`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Nftables;

impl Nftables {
    pub const fn new() -> Self {
        Self
    }

    /// The rule matching one port.
    fn rule(port: u32, protocol: Protocol) -> String {
        format!("{} dport {port} accept", protocol.as_str())
    }

    /// Where the ruleset has to be written for the boot to replay it, and what
    /// replays it.
    ///
    /// Resolved by asking the host rather than by naming a family. The split is
    /// between init systems, not distributions: Alpine's OpenRC script reads a
    /// different path than systemd's unit, and a Debian running OpenRC is the
    /// case that a `match` on the family would get wrong. `systemctl` being
    /// present is the same question `SystemdServices` already answers by being
    /// the implementation a family resolved to.
    /// A missing `systemctl` is an answer here rather than a failure, which is
    /// why the error is matched instead of propagated: the executor reports an
    /// absent binary as [`Error::ProgramNotFound`], and on Alpine that is
    /// precisely how "this host does not run systemd" presents itself.
    /// Propagating it failed `firewall.enable` outright on the one family the
    /// branch exists for — measured on `alpine:3.23`, where the task reported
    /// `executable systemctl was not found in PATH` over a firewall it had
    /// already applied.
    fn persistence_target(executor: &dyn Executor) -> Result<(&'static str, BootService)> {
        let systemd = Command::new("systemctl").arg("--version");

        match executor.run(&systemd) {
            Ok(output) if output.success() => Ok((SYSTEMD_RULES, BootService::Systemd)),
            Ok(_) | Err(Error::ProgramNotFound { .. }) => Ok((OPENRC_RULES, BootService::OpenRc)),
            Err(other) => Err(other),
        }
    }

    /// Turns on whatever replays the ruleset at boot.
    ///
    /// Reports whether it could, rather than failing: a host may have no
    /// service manager to ask. `alpine:3.23` is the measured case — OpenRC
    /// ships in its own package, so a container has neither `rc-update` nor
    /// `/etc/init.d/nftables`, and a chroot or a minimal image is the same
    /// situation on any family.
    ///
    /// Failing the task there would be the wrong trade. The ruleset is applied
    /// and has been written to the file a boot would replay; what is missing is
    /// the thing that replays it, on a host that may not boot at all. Refusing
    /// would turn "the firewall is on and will need one more step" into "the
    /// firewall did not go on", which is worse and false.
    fn enable_at_boot(executor: &dyn Executor, service: BootService) -> Result<bool> {
        let command = match service {
            BootService::Systemd => Command::new("systemctl")
                .args(["enable", SYSTEMD_UNIT])
                .privileged(),
            // `rc-update add` is idempotent and reports success for a service
            // already in the runlevel.
            BootService::OpenRc => Command::new("rc-update")
                .args(["add", OPENRC_SERVICE, "default"])
                .privileged(),
        };

        // A missing service manager answers the question the same way a
        // refusing one does: nothing will replay this.
        match executor.run(&command) {
            Ok(output) => Ok(output.success()),
            Err(Error::ProgramNotFound { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }
}

/// What replays the ruleset at boot on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootService {
    Systemd,
    OpenRc,
}

impl FirewallManager for Nftables {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn is_available(&self, executor: &dyn Executor) -> Result<bool> {
        // `--version` rather than `list ruleset`: listing needs privilege, and
        // availability is asked before the tool knows it will need any.
        let command = Command::new("nft").arg("--version");

        Ok(executor.run(&command)?.success())
    }

    fn enable(&self, executor: &dyn Executor, keep_open: &[(u32, Protocol)]) -> Result<()> {
        // The whole ruleset is written in one `nft -f -` rather than as a
        // sequence of commands. A default-deny policy applied before the rule
        // admitting SSH would drop the session issuing the next command, and
        // between two commands there is a window where exactly that is true.
        let mut ruleset = String::new();

        // Idempotent: `add table` on an existing table is a no-op, and
        // `delete` after it clears whatever the previous run left, so a repeat
        // does not stack duplicate rules.
        ruleset.push_str(&format!("add table {TABLE}\n"));
        ruleset.push_str(&format!("delete table {TABLE}\n"));
        ruleset.push_str(&format!("add table {TABLE}\n"));
        ruleset.push_str(&format!(
            "add chain {TABLE} {CHAIN} {{ type filter hook input priority 0; policy drop; }}\n"
        ));

        // Established traffic first: without it the policy drops the replies to
        // connections this host opened, and an administrator sees a server that
        // cannot reach its own package mirror.
        ruleset.push_str(&format!(
            "add rule {TABLE} {CHAIN} ct state established,related accept\n"
        ));

        // Loopback, for the same reason: services talking to themselves over
        // 127.0.0.1 are inbound traffic as far as the hook is concerned.
        ruleset.push_str(&format!("add rule {TABLE} {CHAIN} iif lo accept\n"));

        for (port, protocol) in keep_open {
            ruleset.push_str(&format!(
                "add rule {TABLE} {CHAIN} {}\n",
                Self::rule(*port, *protocol)
            ));
        }

        // The ruleset travels on stdin rather than as an argument: it holds
        // newlines and braces, and anything that had to be shell-escaped is a
        // command injection waiting to happen on a tool that runs as root.
        let command = Command::new("nft")
            .args(["-f", "-"])
            .stdin(ruleset)
            .privileged();

        run_checked(executor, &command)
    }

    fn allow(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<()> {
        // Checked first so that repeating the operation does not add a second
        // identical rule: nft accepts duplicates and evaluates the first.
        if self.is_allowed(executor, port, protocol)? {
            return Ok(());
        }

        let command = Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "initd",
                CHAIN,
                protocol.as_str(),
                "dport",
                &port.to_string(),
                "accept",
            ])
            .privileged();

        run_checked(executor, &command)
    }

    fn persist(&self, executor: &dyn Executor) -> Result<bool> {
        // `nft` speaks only to the kernel, so nothing said so far survives a
        // reboot. What restores a ruleset at boot is a service replaying a
        // file, and which file that is depends on the init system rather than
        // on the distribution: systemd's unit reads /etc/nftables.conf,
        // Alpine's OpenRC script reads /etc/nftables.nft.
        //
        // The whole ruleset is dumped rather than this tool's table alone. The
        // file is what the boot replays *instead of* whatever the kernel holds,
        // so writing only `inet initd` into it would silently drop every rule
        // the distribution or another tool had put in `filter`.
        let dump = Command::new("nft").args(["list", "ruleset"]).privileged();
        let output = executor.run(&dump)?;

        if !output.success() {
            return Err(Error::CommandFailed {
                command: dump.to_string(),
                code: output.code,
                stderr: output.stderr,
            });
        }

        let (rules_file, service) = Self::persistence_target(executor)?;

        // Through `tee` on stdin for the same reason the ruleset above is fed
        // on stdin: it carries newlines and braces, and anything needing shell
        // escaping is a root-level injection.
        let write = Command::new("tee")
            .arg(rules_file)
            .stdin(output.stdout)
            .privileged();

        run_checked(executor, &write)?;

        // A file nothing reads restores nothing. Enabling is idempotent on
        // both init systems, and is the half that is easy to forget because
        // the firewall works perfectly until the machine restarts.
        Self::enable_at_boot(executor, service)
    }

    fn is_persisted(&self, executor: &dyn Executor) -> Result<bool> {
        // Whether this tool's own table is in the file the boot replays. The
        // running ruleset cannot answer it — that it is loaded now says
        // nothing about whether it comes back — which is the whole reason this
        // question is asked separately.
        let (rules_file, _) = Self::persistence_target(executor)?;

        let command = Command::new("grep")
            .args(["-q", &format!("table {TABLE}"), rules_file])
            .privileged();

        Ok(executor.run(&command)?.success())
    }

    /// The same listing `is_allowed` reads, and the same rule text it matches.
    ///
    /// Built from `rule` rather than spelled out again, so the needle cannot
    /// drift from what `allow` writes — the two are the same claim asked at
    /// different times.
    fn open_port_check(&self, port: u32, protocol: Protocol) -> (Command, String) {
        (
            Command::new("nft")
                .args(["list", "table", "inet", "initd"])
                .privileged(),
            Self::rule(port, protocol),
        )
    }

    fn is_allowed(&self, executor: &dyn Executor, port: u32, protocol: Protocol) -> Result<bool> {
        let command = Command::new("nft")
            .args(["list", "table", "inet", "initd"])
            .privileged();

        let output = executor.run(&command)?;

        if !output.success() {
            // No table means nothing is allowed by this tool, which is an
            // answer rather than a failure.
            return Ok(false);
        }

        Ok(output
            .stdout
            .lines()
            .any(|line| line.trim() == Self::rule(port, protocol)))
    }

    fn state(&self, executor: &dyn Executor) -> Result<FirewallState> {
        let command = Command::new("nft")
            .args(["list", "table", "inet", "initd"])
            .privileged();

        let output = executor.run(&command)?;

        if !output.success() {
            return Ok(FirewallState {
                active: false,
                allowed: Vec::new(),
            });
        }

        // Parsed back out of the listing rather than remembered: the ruleset is
        // the state, and anything this tool cached would be wrong the moment
        // someone edited it by hand.
        let allowed = output
            .stdout
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let protocol = parts.next()?;
                let dport = parts.next()?;
                let port = parts.next()?;

                (dport == "dport" && matches!(protocol, "tcp" | "udp"))
                    .then(|| format!("{port}/{protocol}"))
            })
            .collect();

        Ok(FirewallState {
            active: true,
            allowed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    /// The ruleset fed to `nft -f -`.
    ///
    /// Read off the recorded command rather than from its rendered line: the
    /// ruleset travels on stdin precisely so it never becomes an argument.
    fn ruleset_written(mock: &MockExecutor) -> String {
        mock.single_command()
            .stdin
            .expect("the ruleset must be fed on stdin")
    }

    #[test]
    fn enabling_admits_ssh_in_the_same_ruleset_that_denies_everything() {
        // The window this closes: a default-deny policy applied first, then a
        // rule admitting SSH, drops the session issuing the second command.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Nftables::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        let stdin = ruleset_written(&mock);

        assert!(stdin.contains("policy drop"), "{stdin}");
        assert!(stdin.contains("tcp dport 22 accept"), "{stdin}");
    }

    #[test]
    fn enabling_keeps_established_connections_and_loopback() {
        // Without these a default-deny policy drops the replies to connections
        // this host opened, and every service talking to 127.0.0.1.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Nftables::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        let stdin = ruleset_written(&mock);

        assert!(
            stdin.contains("ct state established,related accept"),
            "{stdin}"
        );
        assert!(stdin.contains("iif lo accept"), "{stdin}");
    }

    #[test]
    fn the_table_covers_both_address_families() {
        // A rule added only to `ip` leaves the same port reachable over IPv6.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Nftables::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        let stdin = ruleset_written(&mock);

        assert!(stdin.contains("add table inet initd"), "{stdin}");
    }

    #[test]
    fn enabling_twice_does_not_stack_rules() {
        // The table is deleted and recreated, so a repeat leaves one copy of
        // each rule rather than two.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        Nftables::new()
            .enable(&mock, &[(22, Protocol::Tcp)])
            .expect("enabling must succeed");

        let stdin = ruleset_written(&mock);

        assert!(stdin.contains("delete table inet initd"), "{stdin}");
    }

    #[test]
    fn persisting_writes_the_ruleset_where_the_boot_replays_it() {
        // The bug this closes: `nft` only ever speaks to the kernel, so every
        // rule the tool wrote was gone at the next restart — a server that came
        // back with every port open, reporting nothing. The sysctl capability
        // had already learned this ("the value was real; its persistence was
        // not"); the firewall is the half where it costs more.
        let mock = MockExecutor::with_replies([
            Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
            Reply::ok("systemd 257"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Nftables::new()
            .persist(&mock)
            .expect("persisting must succeed");

        let lines = mock.recorded_lines();

        assert!(
            lines.iter().any(|line| line == "tee /etc/nftables.conf"),
            "the ruleset must reach the file the unit reads: {lines:?}"
        );

        assert!(
            lines
                .iter()
                .any(|line| line == "systemctl enable nftables.service"),
            "a file nothing replays restores nothing: {lines:?}"
        );
    }

    #[test]
    fn persisting_saves_the_whole_ruleset_rather_than_this_tools_table() {
        // The file replaces whatever the kernel holds at boot, so writing only
        // `inet initd` into it would silently drop every rule the distribution
        // or another tool had put in `filter`.
        let whole = "table inet filter {\n}\ntable inet initd {\n}\n";
        let mock = MockExecutor::with_replies([
            Reply::ok(whole),
            Reply::ok("systemd 257"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Nftables::new()
            .persist(&mock)
            .expect("persisting must succeed");

        let saved = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .and_then(|command| command.stdin)
            .expect("the ruleset travels on stdin");

        assert_eq!(saved, whole);
    }

    #[test]
    fn an_openrc_host_saves_to_its_own_path() {
        // Alpine ships no /etc/nftables.conf and no unit; `apk info -L
        // nftables` owns `etc/nftables.nft`, and its init script defaults
        // `rules_file` to that. Measured on alpine:3.23. The split is between
        // init systems rather than families, which is why it is resolved by
        // asking the host instead of by naming a distribution.
        let mock = MockExecutor::with_replies([
            Reply::ok("table inet initd {\n}"),
            Reply::failure(127, "systemctl: not found"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        Nftables::new()
            .persist(&mock)
            .expect("persisting must succeed");

        let lines = mock.recorded_lines();

        assert!(
            lines.iter().any(|line| line == "tee /etc/nftables.nft"),
            "an OpenRC host keeps its ruleset elsewhere: {lines:?}"
        );

        assert!(
            lines
                .iter()
                .any(|line| line == "rc-update add nftables default"),
            "and replays it through its own service: {lines:?}"
        );
    }

    #[test]
    fn a_host_with_nothing_to_replay_the_ruleset_saves_it_and_says_so() {
        // Measured on alpine:3.23: OpenRC ships in its own package, so a
        // container has neither `rc-update` nor /etc/init.d/nftables. Failing
        // the task there would report the firewall as not enabled, when it is
        // enabled and saved — what is missing is the boot that would replay it,
        // on a host that may never boot.
        let mock = MockExecutor::with_replies([
            Reply::ok("table inet initd {\n}"),          // list ruleset
            Reply::failure(127, "systemctl: not found"), // which init
            Reply::ok(""),                               // tee: saved anyway
            Reply::failure(127, "rc-update: not found"), // nothing to enable
        ]);

        let replayed = Nftables::new()
            .persist(&mock)
            .expect("saving must not fail for want of a service manager");

        assert!(
            !replayed,
            "and the caller must be told it will not come back"
        );

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.starts_with("tee ")),
            "the ruleset is still written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_ruleset_only_in_the_kernel_is_not_reported_as_persisted() {
        // `grep` failing means the table is not in the file the boot reads.
        // Answering true here is what would let a task report "already done"
        // over a firewall that ends at the next restart.
        let mock = MockExecutor::with_replies([Reply::ok("systemd 257"), Reply::failure(1, "")]);

        assert!(
            !Nftables::new()
                .is_persisted(&mock)
                .expect("the question must be answerable")
        );
    }

    #[test]
    fn a_saved_ruleset_is_reported_as_persisted() {
        let mock = MockExecutor::with_replies([Reply::ok("systemd 257"), Reply::ok("")]);

        assert!(
            Nftables::new()
                .is_persisted(&mock)
                .expect("the question must be answerable")
        );
    }

    #[test]
    fn allowing_a_port_that_is_already_allowed_does_nothing() {
        // nft accepts duplicate rules and evaluates the first, so a repeat
        // would grow the ruleset without changing behaviour.
        let mock = MockExecutor::with_replies([Reply::ok(
            "table inet initd {\n  chain input {\n    tcp dport 2222 accept\n  }\n}",
        )]);

        Nftables::new()
            .allow(&mock, 2222, Protocol::Tcp)
            .expect("the call must succeed");

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "only the check must run: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_port_allowed_over_tcp_is_not_allowed_over_udp() {
        // WireGuard is UDP and SSH is TCP on adjacent numbers often enough
        // that conflating them would open the wrong thing.
        let mock = MockExecutor::with_replies([Reply::ok(
            "table inet initd {\n  chain input {\n    tcp dport 51820 accept\n  }\n}",
        )]);

        let allowed = Nftables::new()
            .is_allowed(&mock, 51820, Protocol::Udp)
            .expect("the query must succeed");

        assert!(!allowed, "a tcp rule must not satisfy a udp question");
    }

    #[test]
    fn a_missing_table_means_nothing_is_allowed() {
        // Not an error: a host where this tool has never run has no table, and
        // the honest answer is that it allows nothing.
        let mock = MockExecutor::with_replies([Reply::failure(1, "No such file or directory")]);

        let allowed = Nftables::new()
            .is_allowed(&mock, 22, Protocol::Tcp)
            .expect("a missing table must not raise");

        assert!(!allowed);
    }

    #[test]
    fn the_state_lists_what_is_open() {
        // An administrator about to change the SSH port needs to know which
        // port is currently reachable.
        let mock = MockExecutor::with_replies([Reply::ok(
            "table inet initd {\n  chain input {\n    ct state established,related accept\n    \
             tcp dport 22 accept\n    udp dport 51820 accept\n  }\n}",
        )]);

        let state = Nftables::new()
            .state(&mock)
            .expect("the query must succeed");

        assert!(state.active);
        assert_eq!(state.allowed, ["22/tcp", "51820/udp"]);
    }

    #[test]
    fn availability_is_asked_without_privilege() {
        // Asked before the tool knows it will need any, so it must not prompt.
        let mock = MockExecutor::with_replies([Reply::ok("nftables v1.0.9")]);

        Nftables::new().is_available(&mock).expect("runs");

        assert!(!mock.any_privileged());
    }
}
