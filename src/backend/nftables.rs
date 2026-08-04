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
use crate::error::Result;
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
