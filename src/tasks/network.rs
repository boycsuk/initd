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
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, External, Protocol as WarnProtocol, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Confirmation, Node, Progress, Task, report, supported_everywhere};

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
    /// Reads the ruleset and reports it; nothing is written.
    fn confirmation(&self) -> Confirmation {
        Confirmation::None
    }

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
                &Msg::TaskFirewallNoneInstalled {
                    tried: tried.join(", "),
                },
            );

            return Ok(Outcome::Done);
        };

        let state = firewall.state(executor)?;

        if !state.active {
            // Said plainly, because "no rules" and "not filtering" look alike
            // in a listing and mean opposite things.
            report(progress, &Msg::TaskFirewallInactive);

            return Ok(Outcome::Done);
        }

        report(progress, &Msg::TaskFirewallDefaultDeny);

        if state.allowed.is_empty() {
            report(progress, &Msg::TaskFirewallNoOpenPorts);
        } else {
            for port in &state.allowed {
                report(progress, &Msg::TaskFirewallPortOpen { port: port.clone() });
            }
        }

        // Reported because the running ruleset cannot be read for it, and the
        // difference is a whole firewall: `nft` holds its rules in the kernel
        // only, so a host filtering perfectly right now can come back from a
        // reboot with everything open. A status that says "denied by default"
        // and stops would be true and misleading in the same sentence.
        if firewall.is_persisted(executor)? {
            report(progress, &Msg::TaskFirewallPersisted);
        } else {
            report(progress, &Msg::TaskFirewallNotPersisted);
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
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
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

                report(
                    progress,
                    &Msg::TaskFirewallInstalling {
                        front_end: fallback.name().to_owned(),
                    },
                );

                backend
                    .packages()
                    .install(executor, backend.package_for(Capability::Nftables))?;

                fallback
            }
        };

        report(
            progress,
            &Msg::TaskFirewallUsing {
                front_end: firewall.name().to_owned(),
            },
        );

        // The SSH port is admitted in the same ruleset that installs the
        // policy, not afterwards: between two commands there is a window in
        // which everything is denied, and the session issuing the second one
        // does not survive it.
        firewall.enable(executor, &[(port, Protocol::Tcp)])?;

        // Applied and kept, because either alone is a host that does not
        // behave as the task describes. `nft` speaks only to the kernel, so a
        // ruleset that is not written to the file the boot replays is gone at
        // the next restart — and a server that comes back with every port open
        // reports nothing about it. Exactly the lesson the sysctl tasks
        // learned from a container that already held the right value: the
        // state was real, its persistence was not.
        // The answer decides which claim is made. A host with no service
        // manager — a container, a chroot — has the rules applied and written
        // where a boot would read them, with nothing to do the reading; saying
        // "after a reboot" there would be the same false promise this whole
        // change exists to remove.
        let replayed = firewall.persist(executor)?;

        report(
            progress,
            &if replayed {
                Msg::TaskFirewallEnabled { port }
            } else {
                Msg::TaskFirewallEnabledNotPersisted { port }
            },
        );

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
                .offering(&["tcp", "udp"])
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

        // Before the rule, not after it. This check existed at the end of the
        // task, where it reported "nothing is being filtered yet" over a rule
        // that had just been added — and on a host where `firewall.enable` had
        // never run, it was never reached at all: there is no table to add a
        // rule to, so `nft` fails first. Reported from a Debian 13 host as
        // `Error: Could not process rule: No such file or directory`, which
        // names a file for a table that was never created and reads as a
        // defect in the rule.
        //
        // Refused rather than repaired. Creating the table here would leave an
        // `accept` rule in a ruleset with no default-deny policy — a firewall
        // that filters nothing while looking configured, which is worse than
        // the error. And enabling the policy is not this task's to do: it can
        // end the session that asked for it, which is why `firewall.enable`
        // carries a lockout confirmation and this one does not.
        if !firewall.state(executor)?.active {
            return Err(Error::FirewallNotEnabled);
        }

        firewall.allow(executor, port, protocol)?;

        // Kept, for the same reason enabling is: a rule that only exists in the
        // kernel is a rule that ends at the next restart.
        let replayed = firewall.persist(executor)?;

        report(
            progress,
            &if replayed {
                Msg::TaskFirewallPortAllowed {
                    port,
                    protocol: protocol.as_str().to_owned(),
                }
            } else {
                Msg::TaskFirewallPortAllowedNotPersisted {
                    port,
                    protocol: protocol.as_str().to_owned(),
                }
            },
        );

        // The "nothing is being filtered yet" note that used to live here is
        // gone, and its absence is the fix rather than an omission. It reported
        // the condition *after* adding a rule, which on a host with no policy
        // is a rule that cannot be added at all — so the note was either
        // unreachable or printed over work that had already happened. The
        // condition is now refused before anything is written, above.
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

    // Before anything asks the kernel a question, because the tool that asks it
    // is a package on four of the five families and is missing from a freshly
    // provisioned RHEL — `rockylinux:9` ships no `sysctl` at all. Going
    // straight to the read failed with a missing binary, and the write failed
    // worse: it is wrapped in `sudo`, so the spawn succeeds and what surfaces
    // is exit 127 with `sudo: sysctl: command not found` buried on stderr.
    // Both read as a broken tool rather than as a package nobody installed,
    // which is the same wording `firewall.enable` installs `nftables` to avoid.
    //
    // Alpine never reaches the install: `sysctl` is a busybox applet there, so
    // it is always available and the backend names no package for it. An empty
    // name would mean "nothing to install" rather than "unknown", and this
    // refuses instead of running `apk add ""`.
    if !sysctl.is_available(executor)? {
        let package = backend.package_for(Capability::Sysctl);

        if package.is_empty() {
            return Err(Error::ProgramNotFound {
                program: "sysctl".to_owned(),
            });
        }

        report(
            progress,
            &Msg::TaskInstalling {
                what: package.to_owned(),
            },
        );

        backend.packages().install(executor, package)?;
    }

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
            &Msg::TaskSysctlAlready {
                key: setting.key.to_owned(),
                value: setting.value.to_owned(),
            },
        );

        return Ok(Outcome::Done);
    }

    sysctl.set(executor, setting)?;

    report(
        progress,
        &Msg::TaskSysctlSet {
            key: setting.key.to_owned(),
            value: setting.value.to_owned(),
        },
    );

    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::Confirmation;

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
            Reply::ok("systemd 257"),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        FirewallStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("the status must succeed");

        assert!(FirewallStatus.confirmation() == Confirmation::None);

        // Named as the verbs that change something rather than as the ones that
        // do not: the previous spelling allowed a command through for holding
        // the word `list`, so a writing command that happened to contain it
        // would have passed, while a plain read like `grep` failed.
        const MUTATES: [&str; 8] = [
            "add",
            "delete",
            "flush",
            "tee",
            "enable",
            "rc-update",
            "chmod",
            "cp",
        ];

        for line in mock.recorded_lines() {
            let verb = line.split_whitespace().nth(1).unwrap_or_default();

            assert!(
                !MUTATES.contains(&verb),
                "the status must only read, and `{line}` does not"
            );
        }
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
        //
        // `Reply::NotFound` rather than an exit code, and the difference is the
        // whole reason this branch shipped broken. An absent binary produces no
        // process and therefore no status: the `spawn` fails and the executor
        // raises `ProgramNotFound`. Scripted as `failure(127, …)` this test
        // passed for as long as `is_available` propagated that error, because
        // 127 is a *process* saying "not found" — a thing only a shell can
        // produce, and the shell is not in this path. The test asserted the
        // install on a host that had `nft` all along, and a Debian without the
        // package reported `nft --version` failing.
        let mock = MockExecutor::with_replies([
            Reply::NotFound, // no `nft` on this host at all
            Reply::ok(""),   // install
            Reply::ok(""),   // the ruleset
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
    fn enabling_the_firewall_keeps_it_across_a_reboot() {
        // The task reported "inbound denied except 22/tcp" over a ruleset that
        // lived in the kernel and nowhere else, so the next restart brought the
        // server back with every port open and nothing said so. The sysctl
        // tasks already refused to report success on the running value alone;
        // this is the same claim about the more expensive state.
        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),       // available
            Reply::ok(""),                      // the ruleset
            Reply::ok("table inet initd {\n}"), // list ruleset
            Reply::ok("systemd 257"),           // which init
            Reply::ok(""),                      // tee
            Reply::ok(""),                      // enable
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

        let lines = mock.recorded_lines();

        assert!(
            lines.iter().any(|line| line.starts_with("tee ")),
            "the ruleset must be written somewhere the boot reads: {lines:?}"
        );

        assert!(
            lines.iter().any(|line| line.contains("enable")),
            "and something must replay it: {lines:?}"
        );
    }

    #[test]
    fn a_port_is_not_opened_against_a_policy_that_does_not_exist() {
        // Reported from a Debian 13 host with `nft` installed and working:
        // `nft add rule inet initd input tcp dport 22 accept` answered
        // `Error: Could not process rule: No such file or directory`, naming a
        // file for a table nobody had created — `firewall.enable` had never
        // run. That reads as a defect in the rule.
        //
        // The task did carry a note for this condition, and it was written to
        // run *after* the rule: on a host with no table the rule cannot be
        // added at all, so the note was unreachable in exactly the case it
        // described.
        let mut values = ParamValues::new();
        values.set(AllowPort::PORT, "443".to_owned());
        values.set(AllowPort::PROTOCOL, "tcp".to_owned());

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),                   // `nft` is here
            Reply::failure(1, "No such file or directory"), // and no table is
        ]);
        let backend = for_family(Family::Debian);

        let error = AllowPort
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect_err("a port must not be opened against no policy");

        assert!(
            matches!(error, Error::FirewallNotEnabled),
            "the refusal must name the missing policy, not the missing file: {error:?}"
        );

        // The point of refusing rather than repairing: nothing may be written.
        // Creating the table here would leave an `accept` rule in a ruleset
        // with no default-deny policy — a firewall that filters nothing while
        // looking configured.
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|command| command.contains("add rule") || command.contains("add table")),
            "the host's ruleset must be untouched: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn opening_a_port_keeps_it_across_a_reboot() {
        // Same reasoning as enabling: a rule only in the kernel is a rule that
        // ends at the next restart.
        let mut values = ParamValues::new();
        values.set(AllowPort::PORT, "443".to_owned());
        values.set(AllowPort::PROTOCOL, "tcp".to_owned());

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),       // available
            Reply::ok("table inet initd {\n}"), // state: a policy is in place
            Reply::failure(1, ""),              // not already allowed
            Reply::ok(""),                      // add rule
            Reply::ok("table inet initd {\n}"), // list ruleset
            Reply::ok("systemd 257"),           // which init
            Reply::ok(""),                      // tee
            Reply::ok(""),                      // enable
        ]);
        let backend = for_family(Family::Debian);

        AllowPort
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect("opening must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.starts_with("tee ")),
            "the rule must outlive the kernel that holds it: {:?}",
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
                // The policy is in place: a port is only opened against one,
                // since against no policy every port is already reachable.
                Reply::ok("table inet initd {\n}"),
                Reply::failure(1, "no such table"), // is_allowed: not yet
                Reply::ok(""),                      // add rule
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
                // The policy is in place: a port is only opened against one,
                // since against no policy every port is already reachable.
                Reply::ok("table inet initd {\n}"),
                Reply::failure(1, "no such table"), // is_allowed: not yet
                Reply::ok(""),                      // add rule
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
                Reply::ok("Linux"),                   // sysctl is available
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
    fn the_sysctl_tool_is_installed_when_it_is_absent() {
        // `sysctl` is packaged separately on four of the five families, and a
        // freshly provisioned RHEL has none — measured on `rockylinux:9`, where
        // `dnf provides /usr/sbin/sysctl` answers `procps-ng` from baseos and
        // the image ships nothing. Reported from a Debian host as
        // `FAILED — sysctl.ip-forward / program sysctl`, which reads as a
        // broken tool rather than a package nobody installed.
        //
        // `Reply::NotFound` rather than a non-zero exit, for the reason the
        // firewall's own test records: an absent binary produces no process and
        // therefore no status.
        let (outcome, commands) = run(
            &EnableIpForward,
            vec![
                Reply::NotFound,  // no `sysctl` on this host
                Reply::ok(""),    // install
                Reply::ok("0\n"), // now it reads, and does not hold the value
                // `is_persisted` is never asked: `holds` is already false, and
                // `&&` short-circuits.
                Reply::ok(""), // sysctl -w
                Reply::ok(""), // test -e inside the write
                Reply::ok(""), // tee
                Reply::ok(""), // chmod
            ],
            &ParamValues::new(),
        );

        outcome.expect("the task must install the tool rather than fail");

        assert!(
            commands.iter().any(|command| command.contains("procps")),
            "the package must be installed: {commands:?}"
        );
    }

    #[test]
    fn alpine_is_refused_rather_than_sent_to_install_nothing() {
        // The family where an empty package name means "already there" rather
        // than "not packaged": `sysctl` is a busybox applet, so it cannot be
        // missing, and if it somehow is there is nothing to install. Without
        // this branch the task would run `apk add ""`.
        //
        // Both directions of the guard matter, which is why this test exists
        // beside the one above: an install branch that fired here would send a
        // package manager after an empty name, and one that refused everywhere
        // would leave Debian and RHEL exactly as broken as they were.
        //
        // The assertion that carries this test is the *second* one. Removing
        // the guard entirely leaves the error unchanged — `ProgramNotFound`
        // then comes from `sysctl -n` itself a line later — so an error-only
        // test would pass over the defect it is named for. What only the guard
        // produces is the absence of an install: without it, an empty package
        // name reaches `apk add`.
        let mock = MockExecutor::with_replies([Reply::NotFound]);
        let backend = for_family(Family::Alpine);

        let error = EnableIpForward
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect_err("an absent applet must be reported, not installed");

        assert!(
            matches!(error, Error::ProgramNotFound { ref program } if program == "sysctl"),
            "the error must name the tool: {error:?}"
        );

        let commands = mock.recorded_lines();

        // `apk` at all, not `apk add ""`: the empty name renders as nothing, so
        // matching the full line would pass against the very command this
        // rejects.
        assert!(
            !commands.iter().any(|command| command.contains("apk")),
            "nothing may be installed on the one family that always has it: {commands:?}"
        );

        // Which command ran, not how many. Both assertions above hold with the
        // guard deleted — the error then comes from `sysctl -n
        // net.ipv4.ip_forward` a line later, which is also one command and also
        // installs nothing — so a test that stopped there passed over the
        // defect it is named for. The availability check reads
        // `kernel.ostype`, a key chosen because every kernel carries it, and
        // that is the one observable difference between the two paths.
        assert_eq!(
            commands,
            ["sysctl -n kernel.ostype"],
            "the task must refuse at the availability check, not stumble into \
             the read: {commands:?}"
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
                Reply::ok("Linux"),    // sysctl is available
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
