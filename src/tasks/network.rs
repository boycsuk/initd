//! Firewall and kernel networking parameters.
//!
//! Grouped together because they are the two things every other component
//! needs and neither belongs to any of them: WireGuard needs forwarding and an
//! open UDP port, rootless Docker needs unprivileged ports, Caddy needs 80 and
//! 443, and SSH needs whichever port it was moved to. Owned here, they are set
//! once and asked about by name.

use crate::backend::{Backend, Capability, firewall_for};
use crate::domain::firewall::Protocol;
use crate::domain::sysctl::Setting;
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::tasks::consequence::{Consequence, External, Protocol as WarnProtocol, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Task, report, supported_everywhere};

/// The port SSH listens on unless it has been moved.
///
/// Kept open when filtering is first enabled: a default-deny policy that did
/// not admit the current session would end it.
const DEFAULT_SSH_PORT: u32 = 22;

/// Forwarding, which routes packets between interfaces.
const IP_FORWARD: Setting = Setting {
    key: "net.ipv4.ip_forward",
    value: "1",
};

/// The lowest port an unprivileged process may bind.
///
/// 80 rather than 0: it admits the two ports a web server needs without
/// handing every process below 1024 to any user on the box.
const UNPRIVILEGED_PORT_START: Setting = Setting {
    key: "net.ipv4.ip_unprivileged_port_start",
    value: "80",
};

/// Builds the network category.
pub fn category() -> Category {
    Category::new(
        "Network",
        vec![
            Node::Category(Category::new(
                "Firewall",
                vec![
                    Node::Task(Box::new(FirewallStatus)),
                    Node::Task(Box::new(EnableFirewall)),
                    Node::Task(Box::new(AllowPort)),
                ],
            )),
            Node::Category(Category::new(
                "Kernel parameters",
                vec![
                    Node::Task(Box::new(EnableIpForward)),
                    Node::Task(Box::new(EnableUnprivilegedPorts)),
                ],
            )),
        ],
    )
}

/// Reports what the firewall is doing.
///
/// Listed before the tasks that change anything: an administrator about to
/// move the SSH port needs to know which port is currently reachable, and
/// finding out by losing the session is the expensive way.
pub struct FirewallStatus;

impl Task for FirewallStatus {
    fn id(&self) -> &'static str {
        "firewall.status"
    }

    fn title(&self) -> &'static str {
        "Show the firewall status"
    }

    fn description(&self) -> &'static str {
        "Reports whether inbound filtering is active and which ports it admits. \
         Changes nothing."
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // Resolved rather than assumed: a host may have a front-end installed
        // and never have run it, and reporting on one that is not there would
        // describe a ruleset nothing is enforcing. On RHEL this also decides
        // *which* front-end answers, since firewalld and `nft` cannot both be
        // driven.
        let Some(firewall) = firewall_for(backend, executor)? else {
            // Names what was looked for rather than only that nothing answered:
            // on RHEL two front-ends were tried, and "no firewall" would leave
            // an administrator guessing which.
            let tried: Vec<&str> = backend
                .firewalls()
                .iter()
                .map(|firewall| firewall.name())
                .collect();

            report(
                progress,
                format!("none of these is installed: {}", tried.join(", ")),
            );

            return Ok(Outcome::Done);
        };

        let state = firewall.state(executor)?;

        if !state.active {
            // Said plainly, because "no rules" and "not filtering" look alike
            // in a listing and mean opposite things.
            report(progress, "inbound filtering is not active".to_owned());

            return Ok(Outcome::Done);
        }

        report(progress, "inbound denied by default".to_owned());

        if state.allowed.is_empty() {
            report(progress, "no ports are open".to_owned());
        } else {
            for port in &state.allowed {
                report(progress, format!("  {port} is open"));
            }
        }

        Ok(Outcome::Done)
    }
}

/// Turns on default-deny inbound filtering.
pub struct EnableFirewall;

impl Task for EnableFirewall {
    fn id(&self) -> &'static str {
        "firewall.enable"
    }

    fn title(&self) -> &'static str {
        "Enable the firewall"
    }

    fn description(&self) -> &'static str {
        "Denies inbound traffic by default, admitting established connections, \
         loopback, and the port SSH is listening on. Open anything else with \
         firewall.allow-port."
    }

    /// A default-deny policy applied without admitting the current session is
    /// the last thing that session does, so this is confirmed like any other
    /// lockout risk.
    fn is_destructive(&self) -> bool {
        true
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::SSH_PORT, "SSH port", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .with_hint("kept open, so this session survives"),
        ]
    }

    supported_everywhere!();

    fn consequences(&self, _backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(port) = values.port(Self::SSH_PORT) else {
            return Vec::new();
        };

        // Everything else is now closed, and the administrator is the only one
        // who knows what else this host was serving.
        vec![Consequence::External {
            note: External::ProviderFirewall {
                port,
                protocol: WarnProtocol::Tcp,
            },
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let port = values.port(Self::SSH_PORT)?;
        // Installed rather than assumed. `nft` is packaged separately on every
        // family implemented today, and a task that went straight to enabling
        // would fail with "command not found" — which reads as a broken tool
        // rather than as a missing package.
        //
        // What is installed is the *last* candidate rather than the first: the
        // order in `firewalls()` runs from the front-end a family presents by
        // default to the one an administrator has to choose, and nothing here
        // should install firewalld onto a host whose administrator removed it.
        // Where a family offers one candidate this is that one.
        let firewall = match firewall_for(backend, executor)? {
            Some(firewall) => firewall,
            None => {
                let fallback = *backend
                    .firewalls()
                    .last()
                    .ok_or(Error::NoFirewallFrontEnd)?;

                report(progress, format!("installing {}", fallback.name()));

                backend
                    .packages()
                    .install(executor, backend.package_for(Capability::Nftables))?;

                fallback
            }
        };

        report(progress, format!("using {}", firewall.name()));

        // The SSH port is admitted in the same ruleset that installs the
        // policy, not afterwards: between two commands there is a window in
        // which everything is denied, and the session issuing the second one
        // does not survive it.
        firewall.enable(executor, &[(port, Protocol::Tcp)])?;

        report(progress, format!("inbound denied except {port}/tcp"));

        Ok(Outcome::Done)
    }
}

impl EnableFirewall {
    /// Name of the parameter holding the port to keep open.
    pub const SSH_PORT: &'static str = "ssh_port";
}

/// Opens one inbound port.
pub struct AllowPort;

impl AllowPort {
    /// Name of the parameter holding the port to open.
    pub const PORT: &'static str = "port";
    /// Name of the parameter holding the protocol.
    pub const PROTOCOL: &'static str = "protocol";
}

impl Task for AllowPort {
    fn id(&self) -> &'static str {
        "firewall.allow-port"
    }

    fn title(&self) -> &'static str {
        "Allow a port"
    }

    fn description(&self) -> &'static str {
        "Admits inbound traffic on one port. The protocol matters: WireGuard is \
         UDP, SSH and HTTP are TCP, and a rule for one does not admit the other."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::PORT, "Port", ParamKind::Port).with_hint("1-65535"),
            Param::new(Self::PROTOCOL, "Protocol", ParamKind::Protocol)
                .with_initial("tcp")
                .with_hint("tcp or udp"),
        ]
    }

    supported_everywhere!();

    fn consequences(&self, _backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(port) = values.port(Self::PORT) else {
            return Vec::new();
        };

        let protocol = match values.get(Self::PROTOCOL) {
            Ok("udp") => WarnProtocol::Udp,
            _ => WarnProtocol::Tcp,
        };

        // Opening a port here says nothing about whether the provider's edge
        // firewall admits it, and that is the layer administrators most often
        // forget.
        vec![Consequence::External {
            note: External::ProviderFirewall { port, protocol },
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let port = values.port(Self::PORT)?;
        let protocol = match values.get(Self::PROTOCOL)? {
            "udp" => Protocol::Udp,
            _ => Protocol::Tcp,
        };

        // A port opened on a front-end that is not the one filtering is a port
        // that stays closed, so this resolves rather than assuming.
        let firewall = firewall_for(backend, executor)?.ok_or(Error::NoFirewallFrontEnd)?;

        firewall.allow(executor, port, protocol)?;

        report(
            progress,
            format!("{port}/{} is open inbound", protocol.as_str()),
        );

        Ok(Outcome::Done)
    }
}

/// Enables IP forwarding.
pub struct EnableIpForward;

impl Task for EnableIpForward {
    fn id(&self) -> &'static str {
        "sysctl.ip-forward"
    }

    fn title(&self) -> &'static str {
        "Enable IP forwarding"
    }

    fn description(&self) -> &'static str {
        "Lets this host route packets between its interfaces, which a VPN needs \
         in order to carry its clients' traffic anywhere."
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        set_and_report(executor, backend, IP_FORWARD, progress)
    }
}

/// Lowers the port an unprivileged process may bind.
pub struct EnableUnprivilegedPorts;

impl Task for EnableUnprivilegedPorts {
    fn id(&self) -> &'static str {
        "sysctl.unprivileged-ports"
    }

    fn title(&self) -> &'static str {
        "Allow unprivileged binding to 80 and 443"
    }

    fn description(&self) -> &'static str {
        "Lets a process running as an ordinary user listen on 80 and 443, which \
         a rootless container engine needs in order to serve a website."
    }

    supported_everywhere!();

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // A running daemon does not re-read this. Docker's own documentation
        // makes the same point, and an administrator who skips it sees a
        // container that still cannot bind 80 with the parameter visibly set.
        vec![Consequence::Invalidates {
            task: "docker-rootless.install",
            reason: Reason::NeedsRestart {
                service: "docker.service",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        set_and_report(executor, backend, UNPRIVILEGED_PORT_START, progress)
    }
}

/// Applies a kernel parameter, saying whether it had to change anything.
///
/// Shared by both parameter tasks: they differ only in which setting they name,
/// and duplicating the sequence would let the two drift over what "already set"
/// means.
fn set_and_report(
    executor: &dyn Executor,
    backend: &dyn Backend,
    setting: Setting,
    progress: Progress<'_>,
) -> Result<Outcome> {
    let sysctl = backend.sysctl();

    // Both halves, because either alone is a system that does not behave as
    // the task describes. A kernel can hold the right value for reasons that
    // do not outlive a reboot — another tool set it, the image ships it that
    // way, a container inherits it — and stopping at the running value would
    // report success over a host where the setting vanishes on restart.
    //
    // Docker is where this surfaced: `net.ipv4.ip_forward` is already `1` in
    // every container, so the task found nothing to do, wrote no drop-in, and
    // said it was done. The value was real; its persistence was not.
    if sysctl.holds(executor, setting)? && sysctl.is_persisted(executor, setting)? {
        report(
            progress,
            format!("{} is already {}", setting.key, setting.value),
        );

        return Ok(Outcome::Done);
    }

    sysctl.set(executor, setting)?;

    report(
        progress,
        format!(
            "{} = {}, now and after a reboot",
            setting.key, setting.value
        ),
    );

    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Runs a task against a mock, returning its outcome and the commands run.
    fn run(
        task: &dyn Task,
        replies: Vec<Reply>,
        values: &ParamValues,
    ) -> (Result<Outcome>, Vec<String>) {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(Family::Debian);
        let outcome = task.run(&mock, backend.as_ref(), values, &mut |_| {});

        (outcome, mock.recorded_lines())
    }

    fn port_values(name: &'static str, port: u32) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(name, port.to_string());
        values
    }

    #[test]
    fn the_status_says_which_ports_are_open() {
        // What an administrator needs before moving the SSH port: losing the
        // session is the expensive way to find out which port was reachable.
        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            Reply::ok(
                "table inet initd {\n  chain input {\n    tcp dport 22 accept\n    \
                 udp dport 51820 accept\n  }\n}",
            ),
        ]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        FirewallStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |line| {
                lines.push(line.text)
            })
            .expect("the status must succeed");

        let output = lines.join("\n");

        assert!(output.contains("22/tcp"), "{output}");
        assert!(output.contains("51820/udp"), "{output}");
    }

    #[test]
    fn the_status_distinguishes_not_filtering_from_no_rules() {
        // An empty ruleset and an absent one look alike in a listing and mean
        // opposite things: one denies everything, the other denies nothing.
        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            Reply::failure(1, "No such file or directory"),
        ]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        FirewallStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |line| {
                lines.push(line.text)
            })
            .expect("the status must succeed");

        assert!(lines.join("\n").contains("not active"), "{lines:?}");
    }

    #[test]
    fn the_status_changes_nothing() {
        // It is offered before the tasks that do change things, so it must not
        // be one of them.
        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
        ]);
        let backend = for_family(Family::Debian);

        FirewallStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("the status must succeed");

        assert!(!FirewallStatus.is_destructive());
        assert!(
            mock.recorded_lines()
                .iter()
                .all(|c| c.contains("list") || c.contains("--version")),
            "only reads: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn enabling_the_firewall_keeps_the_current_ssh_port_open() {
        // The session running this task arrives on that port. A default-deny
        // policy that did not admit it would end the session that asked for it.
        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"), // already available
            Reply::ok(""),                // the ruleset
        ]);
        let backend = for_family(Family::Debian);

        EnableFirewall
            .run(
                &mock,
                backend.as_ref(),
                &port_values(EnableFirewall::SSH_PORT, 2222),
                &mut |_| {},
            )
            .expect("enabling must succeed");

        let ruleset = mock
            .recorded()
            .into_iter()
            .find_map(|command| command.stdin)
            .expect("the ruleset travels on stdin");

        assert!(ruleset.contains("tcp dport 2222 accept"), "{ruleset}");
    }

    #[test]
    fn enabling_the_firewall_warns_about_the_provider() {
        // Everything but SSH is now denied here, and the layer above this host
        // is one the tool cannot see.
        let consequences = EnableFirewall.consequences(
            for_family(Family::Debian).as_ref(),
            &port_values(EnableFirewall::SSH_PORT, 22),
        );

        assert_eq!(consequences.len(), 1, "{consequences:?}");
        assert!(consequences[0].is_external());
        assert!(
            consequences[0].check().is_none(),
            "an external warning offers no verification"
        );
    }

    #[test]
    fn the_firewall_front_end_is_installed_when_it_is_absent() {
        // `nft` is packaged separately on every family. Going straight to
        // enabling would fail with "command not found", which reads as a
        // broken tool rather than as a missing package.
        let mock = MockExecutor::with_replies([
            Reply::failure(127, "nft: not found"), // not available
            Reply::ok(""),                         // install
            Reply::ok(""),                         // the ruleset
        ]);
        let backend = for_family(Family::Debian);

        EnableFirewall
            .run(
                &mock,
                backend.as_ref(),
                &port_values(EnableFirewall::SSH_PORT, 22),
                &mut |_| {},
            )
            .expect("enabling must succeed");

        assert!(
            mock.recorded_lines().iter().any(|c| c.contains("nftables")),
            "the package must be installed: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_port_is_opened_for_the_protocol_that_was_asked_for() {
        // WireGuard is UDP. A rule written for TCP admits none of its traffic
        // while looking, in a listing, very much like it should.
        let mut values = ParamValues::new();
        values.set(AllowPort::PORT, "51820".to_owned());
        values.set(AllowPort::PROTOCOL, "udp".to_owned());

        let (outcome, commands) = run(
            &AllowPort,
            vec![
                Reply::ok("nftables v1.0.9"),
                Reply::failure(1, "no such table"),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("opening a port must succeed");

        assert!(
            commands
                .iter()
                .any(|c| c.contains("udp dport 51820 accept")),
            "{commands:?}"
        );
    }

    #[test]
    fn opening_a_port_defaults_to_tcp() {
        let mut values = ParamValues::new();
        values.set(AllowPort::PORT, "443".to_owned());
        values.set(AllowPort::PROTOCOL, "tcp".to_owned());

        let (outcome, commands) = run(
            &AllowPort,
            vec![
                // The front-end is resolved before anything is written: a port
                // opened on one that is not filtering stays closed.
                Reply::ok("nftables v1.0.9"),
                Reply::failure(1, "no such table"),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("opening a port must succeed");

        assert!(
            commands.iter().any(|c| c.contains("tcp dport 443 accept")),
            "{commands:?}"
        );
    }

    #[test]
    fn a_parameter_already_set_and_already_persisted_is_left_alone() {
        // Idempotent, and cheap: re-writing the drop-in would rewrite a file
        // and re-apply a value that is already live. Both conditions are
        // required — see the test below for the half that used to be missed.
        let (outcome, commands) = run(
            &EnableIpForward,
            vec![
                Reply::ok("1\n"),                     // the running value
                Reply::ok(""),                        // test -e: the drop-in exists
                Reply::ok("net.ipv4.ip_forward = 1"), // and records the value
            ],
            &ParamValues::new(),
        );

        outcome.expect("an already-set parameter must succeed");

        assert!(
            !commands.iter().any(|command| command.starts_with("tee")),
            "nothing needed writing: {commands:?}"
        );
    }

    #[test]
    fn a_value_that_is_live_but_not_persisted_is_written_anyway() {
        // The bug this replaces. `holds` reads the running value, which a
        // kernel can hold for reasons that do not outlive a reboot — another
        // tool set it, the image ships it that way, a container inherits it.
        // Stopping there reported success over a host where the setting
        // vanishes on restart, and the task promises "now and after a reboot".
        //
        // Found by running the real task in Docker, where
        // `net.ipv4.ip_forward` is already `1` in every container: the task
        // wrote no drop-in and said it was done.
        let (outcome, commands) = run(
            &EnableIpForward,
            vec![
                Reply::ok("1\n"),      // already live
                Reply::failure(1, ""), // but no drop-in of ours exists
                Reply::ok(""),         // sysctl -w
                Reply::ok(""),         // test -e inside the write
                Reply::ok(""),         // tee
                Reply::ok(""),         // chmod
            ],
            &ParamValues::new(),
        );

        outcome.expect("the task must succeed");

        assert!(
            commands.iter().any(|command| command.starts_with("tee")),
            "the drop-in must be written even though the value was live: {commands:?}"
        );
    }

    #[test]
    fn a_parameter_is_applied_now_and_persisted() {
        // Either half alone is a task that reports success over a system that
        // does not behave as described: runtime-only is gone after a reboot,
        // file-only has not taken effect yet.
        let (outcome, commands) = run(
            &EnableIpForward,
            vec![
                Reply::ok("0\n"), // currently off
                Reply::ok(""),    // sysctl -w
                Reply::ok(""),    // test -e on the drop-in
                Reply::ok(""),    // read it
                Reply::ok(""),    // write it
                Reply::ok(""),    // backup
                Reply::ok(""),    // chmod
            ],
            &ParamValues::new(),
        );

        outcome.expect("setting a parameter must succeed");

        assert!(
            commands
                .iter()
                .any(|c| c.contains("sysctl -w net.ipv4.ip_forward=1")),
            "the runtime value must be applied: {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.contains("99-initd.conf")),
            "the value must be persisted: {commands:?}"
        );
    }

    #[test]
    fn lowering_the_unprivileged_port_tells_docker_to_restart() {
        // A running daemon does not re-read this, so the parameter reads as set
        // while the container still cannot bind 80.
        let consequences = EnableUnprivilegedPorts
            .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        assert_eq!(consequences.len(), 1, "{consequences:?}");
        assert_eq!(
            consequences[0].task(),
            Some("docker-rootless.install"),
            "{consequences:?}"
        );
        assert!(!consequences[0].is_external());
    }

    #[test]
    fn the_unprivileged_port_floor_is_not_zero() {
        // 0 would hand every port below 1024 to any user on the box. 80 admits
        // the two a web server needs and nothing else.
        assert_eq!(UNPRIVILEGED_PORT_START.value, "80");
    }
}
