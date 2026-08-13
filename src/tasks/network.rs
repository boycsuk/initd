//! Firewall and kernel networking parameters.
//!
//! Grouped together because they are the two things every other component
//! needs and neither belongs to any of them: WireGuard needs forwarding and an
//! open UDP port, rootless Docker needs unprivileged ports, Caddy needs 80 and
//! 443, and SSH needs whichever port it was moved to. Owned here, they are set
//! once and asked about by name.

use crate::backend::{Backend, Capability, firewall_for};
use crate::domain::firewall::{PortOrigin, Protocol};
use crate::domain::sysctl::Setting;
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::{Msg, SysctlHolding};
use crate::tasks::consequence::{
    Check, Consequence, External, Protocol as WarnProtocol, Reason, Requirement,
};
use crate::tasks::params::{LiveDefault, Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::ssh::DEFAULT_SSH_PORT;
use crate::tasks::{Category, Confirmation, Node, Progress, Task, report, supported_everywhere};

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
                // Enabling and disabling share a row, so it shows whichever the
                // host justifies: a row offering to enable a firewall that is
                // already filtering was reported as exactly the confusion the
                // reversible pairs elsewhere exist to avoid.
                vec![
                    Node::Task(Box::new(FirewallStatus)),
                    Node::Reversible {
                        forward: Box::new(EnableFirewall),
                        inverse: Box::new(DisableFirewall),
                    },
                    Node::Task(Box::new(ManagePorts)),
                ],
            )),
            Node::Category(Category::new(
                "Kernel parameters",
                // Pairs, so each row reports whether this tool is declaring
                // the parameter — reported as a task with no way to tell that
                // it had already been run.
                vec![
                    Node::Reversible {
                        forward: Box::new(EnableIpForward),
                        inverse: Box::new(DisableIpForward),
                    },
                    Node::Reversible {
                        forward: Box::new(EnableUnprivilegedPorts),
                        inverse: Box::new(DisableUnprivilegedPorts),
                    },
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
                // The origin is reported rather than kept for the code's own
                // use: a port admitted by a service is one this tool does not
                // close, and an administrator reading a list of open ports is
                // the person who most needs to know which of them behave
                // differently.
                report(
                    progress,
                    &Msg::TaskFirewallPortOpen {
                        port: port.spec.clone(),
                        admitted_by: match &port.origin {
                            PortOrigin::Direct => None,
                            PortOrigin::Service(service) => Some(service.clone()),
                        },
                    },
                );
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
        Self::ID
    }

    fn title(&self) -> &'static str {
        "Enable the firewall"
    }

    fn description(&self) -> &'static str {
        "Closes every inbound port except the ones named here. Nothing is being \
         opened: a default-deny policy means anything not admitted is dropped, \
         including the connection you are reading this over — which is why the \
         port your SSH listens on is asked for and admitted in the same step. \
         Established connections and loopback keep working. Open anything else \
         afterwards with firewall.manage-ports."
    }

    /// A default-deny policy applied without admitting the current session is
    /// the last thing that session does, so this is confirmed like any other
    /// lockout risk.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // "Port to keep open" rather than "SSH port": the field is not
            // asking which port SSH uses as a piece of trivia, it is asking
            // which one must survive the policy about to be applied. An
            // operator who only wants to "turn the firewall on" reads the
            // second label as an unrelated question — reported as exactly that
            // — and the answer they skip past is the one keeping their session
            // alive.
            // No warning on the field, by request. It was tried twice — beside
            // the label, then on a row of its own — and both were rejected as
            // clutter on a dialog whose whole content is one number. What the
            // warning said is not lost: the task's description carries it above
            // this form, and the confirmation that follows states it in full
            // with the port named, which is the screen that actually stands
            // between the operator and the change.
            Param::new(Self::SSH_PORT, "Port to keep open", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .defaulting_to_live(LiveDefault::SshPort),
        ]
    }

    supported_everywhere!();

    /// What the row reports is whether this host is *filtering*, not whether
    /// `nft` is installed — the probe treats this capability specially for
    /// exactly that reason. Every Debian has the package available and none of
    /// them filters until told to.
    fn subject(&self) -> Option<Capability> {
        Some(Capability::Nftables)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["firewall.enable"]
    }

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
                    .install(executor, &[backend.package_for(Capability::Nftables)])?;

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

    /// Id, named because the interface reaches for it when building the
    /// confirmation this task needs and no other does.
    ///
    /// A constant rather than a literal at the match site, for the reason
    /// `LockRoot::ID` records: matching on a literal puts the id in two places
    /// with nothing tying them together, and a rename would leave the dialog
    /// silently falling back to the generic warning.
    pub const ID: &'static str = "firewall.enable";
}

/// One `port/protocol` spec, as every front-end spells it.
///
/// Parsed rather than carried as a string so that a spec reaching a front-end
/// has already been proven to be one. A range is deliberately absent: the
/// specs this tool *writes* name a single port, and the ones it merely reads
/// back keep their string form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Spec {
    port: u32,
    protocol: Protocol,
}

impl Spec {
    /// Reads a spec, or nothing where the text is not one.
    ///
    /// `None` rather than an error because the callers parse a *set*: a host
    /// listing something this tool cannot act on — firewalld reports a range as
    /// one spec — must not fail the whole operation. What cannot be parsed is
    /// something this task leaves alone, which is also the honest treatment of
    /// a rule it did not write.
    fn parse(text: &str) -> Option<Self> {
        let (port, protocol) = text.split_once('/')?;

        Some(Self {
            port: port.parse().ok()?,
            protocol: match protocol {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => return None,
            },
        })
    }

    /// The spec as the front-ends and the parameter both spell it.
    fn text(self) -> String {
        format!("{}/{}", self.port, self.protocol.as_str())
    }
}

/// Reads a set of specs out of a parameter, keeping the order and dropping
/// repeats.
///
/// Order is kept so that what a task reports back reads like what the operator
/// typed. Repeats are dropped because the value declares a *set*: `443/tcp`
/// twice admits the port exactly as once does, and acting on it twice would
/// report two openings of one port.
fn specs_in(value: &str) -> Vec<Spec> {
    let mut specs = Vec::new();

    for spec in value.split_whitespace().filter_map(Spec::parse) {
        if !specs.contains(&spec) {
            specs.push(spec);
        }
    }

    specs
}

/// What the host currently admits inbound, as a [`ParamKind::PortList`] value.
///
/// The one place that question is turned into a parameter's text, because both
/// interfaces ask it: the table is populated from it and the CLI fills its
/// field from it. Two readings written separately would be two chances to
/// disagree about what "currently open" means, and the disagreement would show
/// up as the CLI closing a port the interface would have kept.
///
/// Answers an empty string where nothing can be read — no front-end, no
/// filtering, a command that failed. That is the safe direction for this
/// particular value only because the task refuses against an inactive policy
/// before acting on it; the field never reaches a host where an empty set
/// would be taken as "close everything".
pub fn open_ports_value(executor: &dyn Executor, backend: &dyn Backend) -> String {
    let Ok(Some(firewall)) = firewall_for(backend, executor) else {
        return String::new();
    };

    let Ok(state) = firewall.state(executor) else {
        return String::new();
    };

    state
        .allowed
        .iter()
        .map(|port| port.spec.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Declares which ports are open, opening and closing to match.
pub struct ManagePorts;

impl ManagePorts {
    /// Name of the parameter holding the ports that should be open.
    pub const PORTS: &'static str = "ports";

    /// Name of the parameter holding what was open when the operator was shown
    /// the set.
    ///
    /// Carried so that a port opened by somebody else, while the table was on
    /// screen, is reported rather than closed. Without it the difference
    /// between "the operator removed this" and "this appeared after they
    /// looked" cannot be told apart, and the tool would silently undo a change
    /// it never saw. Empty from the CLI, where there was no table and a
    /// declared set is exactly what was meant.
    pub const PORTS_WERE: &'static str = "ports_were";

    /// Identifies the task to the dialog that warns about closing the port a
    /// session arrived on.
    ///
    /// A constant for the reason `EnableFirewall::ID` records: a literal at the
    /// match site puts the id in two places with nothing tying them together.
    pub const ID: &'static str = "firewall.manage-ports";
}

impl Task for ManagePorts {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn title(&self) -> &'static str {
        "Manage ports"
    }

    fn description(&self) -> &'static str {
        "Declares which ports are admitted inbound: anything listed is opened, \
         anything removed is closed. The protocol matters — WireGuard is UDP, \
         SSH and HTTP are TCP, and a rule for one does not admit the other."
    }

    /// The strongest confirmation, because a set with a port left out of it is
    /// how a session ends.
    ///
    /// `firewall.enable` carries this for naming the wrong port to keep. Here
    /// the risk is quieter: the operator removes a row without connecting it to
    /// the connection they are reading the screen through, and nothing about
    /// deleting a table row announces that.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // Filled from the host before it is shown, which is what makes an
            // invocation naming no ports a no-op rather than "close
            // everything" — the worst reading the CLI could take.
            Param::new(Self::PORTS, "Open ports", ParamKind::PortList)
                .defaulting_to_live(LiveDefault::OpenPorts)
                .with_hint("port/protocol, space separated"),
            Param::new(Self::PORTS_WERE, "Previously open", ParamKind::PortList).optional(),
        ]
    }

    /// A policy to add rules to, which `firewall.enable` is what creates.
    ///
    /// The guard in `run` already refuses without one and names that task; this
    /// is the same fact where the *tree* can read it, so the row says so before
    /// a key is pressed rather than after. It was the case that prompted the
    /// mechanism: on a host with no firewall this row is drawn exactly like one
    /// that would work.
    fn requires(&self, backend: &dyn Backend) -> Vec<Requirement> {
        // No front-end at all is a different refusal — `NoFirewallFrontEnd` —
        // and not one another task fixes, so there is nothing to require.
        let Some(firewall) = backend.firewalls().first() else {
            return Vec::new();
        };

        let (command, needle) = firewall.active_check();

        vec![Requirement {
            task: EnableFirewall::ID,
            check: Check {
                command,
                resolved_when_stdout_contains: needle,
            },
        }]
    }

    supported_everywhere!();

    /// What the row reports is whether this host is *filtering*, the same
    /// question `firewall.enable` asks: there is nothing to manage against a
    /// host with no policy.
    fn subject(&self) -> Option<Capability> {
        Some(Capability::Nftables)
    }

    fn consequences(&self, _backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(ports) = values.get(Self::PORTS) else {
            return Vec::new();
        };

        // One note per port opened rather than one for the batch: the provider's
        // edge firewall admits ports individually, so a single note naming a
        // count would leave the administrator to work out which.
        specs_in(ports)
            .into_iter()
            .map(|spec| Consequence::External {
                note: External::ProviderFirewall {
                    port: spec.port,
                    protocol: match spec.protocol {
                        Protocol::Tcp => WarnProtocol::Tcp,
                        Protocol::Udp => WarnProtocol::Udp,
                    },
                },
            })
            .collect()
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let desired = specs_in(values.get(Self::PORTS)?);

        // A port managed on a front-end that is not the one filtering is a port
        // that stays as it was, so this resolves rather than assuming.
        let firewall = firewall_for(backend, executor)?.ok_or(Error::NoFirewallFrontEnd)?;

        let state = firewall.state(executor)?;

        // Before anything is written, and refused rather than repaired — the
        // reasoning the per-port task carried before this replaced it. There is
        // no table to add a rule to on a host where `firewall.enable` never
        // ran, so `nft` fails first with an error naming a file, which reads as
        // a defect in the rule. Creating the policy here is not this task's to
        // do: it can end the session that asked for it.
        if !state.active {
            return Err(Error::FirewallNotEnabled);
        }

        // Only what this tool can actually close is a candidate for closing.
        // firewalld admits SSH on a stock RHEL host as the service `ssh`, and
        // `--remove-port 22/tcp` against that succeeds while changing nothing —
        // so a set built from everything listed would report closing a port
        // that stays open.
        let closeable: Vec<Spec> = state
            .allowed
            .iter()
            .filter(|port| port.origin == PortOrigin::Direct)
            .filter_map(|port| Spec::parse(&port.spec))
            .collect();

        // What the operator was looking at, where they were looking at
        // anything. The CLI passes nothing and means the set it declared, so
        // the snapshot falls back to what the host holds now.
        let snapshot = match values.get(Self::PORTS_WERE) {
            Ok(were) if !were.trim().is_empty() => specs_in(were),
            _ => closeable.clone(),
        };

        let to_open: Vec<Spec> = desired
            .iter()
            .filter(|spec| !closeable.contains(spec))
            .copied()
            .collect();

        let to_close: Vec<Spec> = snapshot
            .iter()
            .filter(|spec| !desired.contains(spec) && closeable.contains(spec))
            .copied()
            .collect();

        // A port the host admits that the operator never saw and did not
        // declare: somebody else opened it while the table was on screen.
        // Reported and left alone, because closing it would undo a change this
        // tool has no evidence the operator meant to undo.
        let appeared: Vec<Spec> = closeable
            .iter()
            .filter(|spec| !desired.contains(spec) && !snapshot.contains(spec))
            .copied()
            .collect();

        // Opened before anything is closed. A set that moves SSH from 22 to
        // 2222 must have 2222 admitted before 22 goes, or the session dies in
        // the window between the two commands — the same reasoning that makes
        // `enable` build its ruleset in one transaction.
        for spec in &to_open {
            firewall.allow(executor, spec.port, spec.protocol)?;
        }

        // Said here rather than with the summary below, for the reason
        // `ssh/port.rs` states at its own backup line: each of the three steps
        // that follow can fail, and a task ending on an error returns no
        // `Outcome`, so none of the reports below are reached. Without this the
        // operator sees a failed `nft` for one port over a firewall that has
        // already admitted the others — which reads as nothing having happened,
        // and the natural response is to re-run with a set that no longer
        // matches what the host holds.
        //
        // Only when something was opened: a set that closes ports and opens
        // none has nothing to say here, and a line reporting zero is one more
        // thing to read past.
        if !to_open.is_empty() {
            report(
                progress,
                &Msg::TaskFirewallPortsOpened {
                    specs: to_open
                        .iter()
                        .map(|spec| spec.text())
                        .collect::<Vec<_>>()
                        .join(", "),
                },
            );
        }

        let mut refused = Vec::new();

        for spec in &to_close {
            if !firewall.close(executor, spec.port, spec.protocol)? {
                // The command reported success and the port is still open. Read
                // back rather than counted, so what is reported is what the
                // machine holds rather than what the calls returned.
                refused.push(spec.text());
            }
        }

        // Kept, for the same reason opening one was: a ruleset that only exists
        // in the kernel ends at the next restart — and a port reported closed
        // that reopens at boot is the more expensive half of that mistake.
        let replayed = firewall.persist(executor)?;

        report(
            progress,
            &Msg::TaskFirewallPortsApplied {
                opened: to_open.len(),
                closed: to_close.len() - refused.len(),
            },
        );

        if !refused.is_empty() {
            report(
                progress,
                &Msg::TaskFirewallPortsStillOpen {
                    specs: refused.join(", "),
                },
            );
        }

        if !appeared.is_empty() {
            report(
                progress,
                &Msg::TaskFirewallPortsAppearedSince {
                    specs: appeared
                        .iter()
                        .map(|spec| spec.text())
                        .collect::<Vec<_>>()
                        .join(", "),
                },
            );
        }

        if !replayed {
            report(progress, &Msg::TaskFirewallPortsNotPersisted);
        }

        Ok(Outcome::Done)
    }
}

/// Turns default-deny filtering off again.
///
/// The inverse of [`EnableFirewall`], so the row shows one verb or the other
/// according to what this host is actually doing — reported as a row offering
/// to enable a firewall that was already on.
pub struct DisableFirewall;

impl Task for DisableFirewall {
    fn id(&self) -> &'static str {
        "firewall.disable"
    }

    fn title(&self) -> &'static str {
        "Disable the firewall"
    }

    fn description(&self) -> &'static str {
        "Removes the inbound filtering this tool applied and stops it returning \
         at boot. Rules written by anything else are left alone. Every port \
         this host serves becomes reachable again, which is the state it was in \
         before the firewall was enabled."
    }

    /// Opening every port is not a lockout — nothing that was reachable stops
    /// being reachable — but it is not a change to make by pressing Enter
    /// without reading either.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Change
    }

    supported_everywhere!();

    /// The row this task's success changes, which is the pair it belongs to.
    ///
    /// Inverses have to declare this as much as their forward halves do, and
    /// the default of "nothing" is why they can forget: the interface re-probes
    /// only what a finished task names, so an inverse that names nothing leaves
    /// its own row showing the verb it just stopped being true. Reported as
    /// disabling the firewall and watching the row go on offering to disable it.
    fn affects(&self) -> &'static [&'static str] {
        &["firewall.enable"]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let firewall = firewall_for(backend, executor)?.ok_or(Error::NoFirewallFrontEnd)?;

        firewall.disable(executor)?;

        report(progress, &Msg::TaskFirewallDisabled);

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

    /// The row reports whether *this tool* declares the parameter, not whether
    /// the kernel holds the value: the probe reads the drop-in rather than
    /// `sysctl -n`, because something else on the host may be setting it and a
    /// row offering to undo that would undo somebody else's change.
    fn subject(&self) -> Option<Capability> {
        Some(Capability::Sysctl)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["sysctl.ip-forward"]
    }

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
            task: "docker.rootless",
            reason: Reason::NeedsRestart {
                service: "docker.service",
            },
            check: None,
        }]
    }

    /// The row reports whether *this tool* declares the parameter, not whether
    /// the kernel holds the value: the probe reads the drop-in rather than
    /// `sysctl -n`, because something else on the host may be setting it and a
    /// row offering to undo that would undo somebody else's change.
    fn subject(&self) -> Option<Capability> {
        Some(Capability::Sysctl)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["sysctl.unprivileged-ports"]
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
/// The parameter a kernel-parameter task declares, by its id.
///
/// Here rather than in the interface because the pairing of task to setting is
/// this module's own: the two constants are private, and a copy elsewhere would
/// be a second place to update when a third parameter is added.
pub fn declared_setting(forward_id: &str) -> Option<Setting> {
    match forward_id {
        "sysctl.ip-forward" => Some(IP_FORWARD),
        "sysctl.unprivileged-ports" => Some(UNPRIVILEGED_PORT_START),
        _ => None,
    }
}

/// Stops declaring IP forwarding.
pub struct DisableIpForward;

impl Task for DisableIpForward {
    fn id(&self) -> &'static str {
        "sysctl.ip-forward.undo"
    }

    fn title(&self) -> &'static str {
        "Stop declaring IP forwarding"
    }

    fn description(&self) -> &'static str {
        "Removes this tool's declaration of net.ipv4.ip_forward. The running \
         value is left alone: a kernel parameter has no unset state, and another \
         component — Docker, a VPN — may be relying on it. What changes is that \
         nothing here asserts it any more."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Sysctl)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["sysctl.ip-forward"]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        unset_and_report(executor, backend, IP_FORWARD, progress)
    }
}

/// Stops declaring the unprivileged port floor.
pub struct DisableUnprivilegedPorts;

impl Task for DisableUnprivilegedPorts {
    fn id(&self) -> &'static str {
        "sysctl.unprivileged-ports.undo"
    }

    fn title(&self) -> &'static str {
        "Stop declaring the unprivileged port floor"
    }

    fn description(&self) -> &'static str {
        "Removes this tool's declaration of net.ipv4.ip_unprivileged_port_start. \
         The running value is left alone, so a rootless container already bound \
         to 80 keeps serving until something restarts it."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Sysctl)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["sysctl.unprivileged-ports"]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        unset_and_report(executor, backend, UNPRIVILEGED_PORT_START, progress)
    }
}

/// Removes this tool's declaration of a parameter and says what that did.
///
/// The mirror of [`set_and_report`], and shared for the same reason: the two
/// inverses differ only in the setting they name.
fn unset_and_report(
    executor: &dyn Executor,
    backend: &dyn Backend,
    setting: Setting,
    progress: Progress<'_>,
) -> Result<Outcome> {
    let sysctl = backend.sysctl();

    if !sysctl.is_available(executor)? {
        return Err(Error::ProgramNotFound {
            program: "sysctl".to_owned(),
        });
    }

    sysctl.unset(executor, setting)?;

    // Read back rather than assumed, because the answer is usually "still set"
    // and that is the point: this removed a declaration, not a value. Saying
    // "removed" over a parameter that still reads 1 would be true about the
    // file and false about the machine.
    //
    // A failed read-back is its own answer rather than `false`. `unwrap_or(false)`
    // stood here and chose the branch that reads "no longer declared here" —
    // finished, nothing more to do — over a host whose kernel had not answered.
    // That is a claim about the machine on the strength of a question that
    // failed, and it is the direction this project's own rule warns about:
    // "could not be read" and "changed" call for different actions.
    let holding = match sysctl.holds(executor, setting) {
        Ok(true) => SysctlHolding::Yes,
        Ok(false) => SysctlHolding::No,
        Err(_) => SysctlHolding::Unknown,
    };

    report(
        progress,
        &Msg::TaskSysctlUnset {
            key: setting.key.to_owned(),
            holding,
        },
    );

    Ok(Outcome::Done)
}

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

        backend.packages().install(executor, &[package])?;
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

    #[test]
    fn a_read_back_that_fails_is_not_reported_as_no_longer_held() {
        // `unwrap_or(false)` stood where this match is and turned a failed
        // read-back into the branch that reads "no longer declared here" — the
        // one that sounds finished. The declaration is gone either way; what
        // the failure costs is knowing whether the kernel still holds the
        // value, and saying nothing about that is a claim nobody checked.
        let mock = MockExecutor::with_replies([
            Reply::ok("/usr/sbin/sysctl"),            // is_available
            Reply::failure(1, ""),                    // the drop-in does not exist
            Reply::failure(1, "sysctl: cannot stat"), // holds() fails
        ]);

        let mut lines = Vec::new();
        DisableIpForward
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &ParamValues::new(),
                &mut |line| lines.push(line.text),
            )
            .expect("removing a declaration that is not there still succeeds");

        let output = lines.join("\n");

        assert!(
            output.contains("could not be read back"),
            "an unanswered read-back must say so: {output}"
        );
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

        // `contains("enable")` stood here and cannot fail in the direction it
        // matters: "disable" contains "enable", so a regression turning the
        // boot-persistence step into its inverse satisfied it. The same shape
        // as the `is-active`/`inactive` case this project documents, in test
        // code rather than production. Matched as a whole word instead.
        assert!(
            lines
                .iter()
                .any(|line| line.split_whitespace().any(|word| word == "enable")),
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
        values.set(ManagePorts::PORTS, "443/tcp".to_owned());

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),                   // `nft` is here
            Reply::failure(1, "No such file or directory"), // and no table is
        ]);
        let backend = for_family(Family::Debian);

        let error = ManagePorts
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
    fn the_declared_set_keeps_its_changes_across_a_reboot() {
        // Same reasoning as enabling, and sharper for a removal: a port closed
        // only in the kernel reopens at the next restart, under a task that
        // reported it closed.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "443/tcp".to_owned());

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"), // available
            // The policy is in place, admitting nothing yet.
            Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
            Reply::failure(1, ""),              // is_allowed: not yet
            Reply::ok(""),                      // add rule
            Reply::ok("table inet initd {\n}"), // list ruleset
            Reply::ok("systemd 257"),           // which init
            Reply::ok(""),                      // tee
            Reply::ok(""),                      // enable
        ]);
        let backend = for_family(Family::Debian);

        ManagePorts
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect("declaring a set must succeed");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.starts_with("tee ")),
            "the ruleset must outlive the kernel that holds it: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_port_is_opened_for_the_protocol_that_was_asked_for() {
        // WireGuard is UDP. A rule written for TCP admits none of its traffic
        // while looking, in a listing, very much like it should.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "51820/udp".to_owned());

        let (outcome, commands) = run(
            &ManagePorts,
            vec![
                Reply::ok("nftables v1.0.9"),
                // The policy is in place: ports are only managed against one,
                // since against no policy every port is already reachable.
                Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
                Reply::failure(1, "no such table"), // is_allowed: not yet
                Reply::ok(""),                      // add rule
            ],
            &values,
        );

        outcome.expect("declaring a set must succeed");

        assert!(
            commands
                .iter()
                .any(|c| c.contains("udp dport 51820 accept")),
            "{commands:?}"
        );
    }

    #[test]
    fn the_declared_set_opens_what_is_missing_and_closes_what_is_gone() {
        // The whole of what a declaration means: the host is made to match it,
        // in both directions, and ports already right are left alone.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "22/tcp 443/tcp".to_owned());
        values.set(ManagePorts::PORTS_WERE, "22/tcp 8080/tcp".to_owned());

        let listing = "table inet initd { # handle 1\n\
                       \tchain input { # handle 1\n\
                       \t\ttcp dport 22 accept # handle 2\n\
                       \t\ttcp dport 8080 accept # handle 3\n\
                       \t}\n\
                       }";

        let (outcome, commands) = run(
            &ManagePorts,
            vec![
                Reply::ok("nftables v1.0.9"),
                // state: 22 and 8080 are open.
                Reply::ok(listing),
                Reply::failure(1, ""), // is_allowed(443): no
                Reply::ok(""),         // add rule 443
                Reply::ok(listing),    // handles_for(8080)
                Reply::ok(""),         // delete rule handle 3
                // The read-back: 8080 is gone.
                Reply::ok("table inet initd {\n  chain input {\n    tcp dport 22 accept\n  }\n}"),
                Reply::ok("table inet initd {\n}"), // list ruleset
                Reply::ok("systemd 257"),
                Reply::ok(""),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("declaring a set must succeed");

        assert!(
            commands.iter().any(|c| c.contains("tcp dport 443 accept")),
            "the missing port must be opened: {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.contains("delete rule")),
            "the removed port must be closed: {commands:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|c| c.contains("dport 22") && c.contains("delete")),
            "a port in both sets must be left alone: {commands:?}"
        );
    }

    #[test]
    fn a_port_is_opened_before_another_is_closed() {
        // A set that moves SSH from one port to another must have the new one
        // admitted before the old one goes, or the session dies in the window
        // between the two commands.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "2222/tcp".to_owned());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let listing = "table inet initd { # handle 1\n\
                       \tchain input { # handle 1\n\
                       \t\ttcp dport 22 accept # handle 2\n\
                       \t}\n\
                       }";

        let (outcome, commands) = run(
            &ManagePorts,
            vec![
                Reply::ok("nftables v1.0.9"),
                Reply::ok(listing),
                Reply::failure(1, ""), // is_allowed(2222): no
                Reply::ok(""),         // add rule 2222
                Reply::ok(listing),    // handles_for(22)
                Reply::ok(""),         // delete rule handle 2
                Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
                Reply::ok("table inet initd {\n}"),
                Reply::ok("systemd 257"),
                Reply::ok(""),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("declaring a set must succeed");

        let opened = commands
            .iter()
            .position(|c| c.contains("add rule"))
            .expect("the new port must be opened");

        let closed = commands
            .iter()
            .position(|c| c.contains("delete rule"))
            .expect("the old port must be closed");

        assert!(
            opened < closed,
            "the new port must be admitted first: {commands:?}"
        );
    }

    #[test]
    fn a_set_identical_to_the_host_writes_nothing() {
        // Idempotent, which is the property a declaration has and a sequence of
        // add-one-at-a-time operations does not.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "22/tcp".to_owned());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let (outcome, commands) = run(
            &ManagePorts,
            vec![
                Reply::ok("nftables v1.0.9"),
                Reply::ok("table inet initd {\n  chain input {\n    tcp dport 22 accept\n  }\n}"),
                Reply::ok("table inet initd {\n}"), // list ruleset, for persist
                Reply::ok("systemd 257"),
                Reply::ok(""),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("declaring the current set must succeed");

        assert!(
            !commands
                .iter()
                .any(|c| c.contains("add rule") || c.contains("delete rule")),
            "nothing must be written: {commands:?}"
        );
    }

    #[test]
    fn an_empty_declaration_closes_every_port() {
        // Drastic and coherent, and pinned so it cannot quietly become a
        // no-op: a firewall admitting nothing is a policy, and the field's
        // validator admits the empty set precisely so this can be asked for.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, String::new());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let listing = "table inet initd { # handle 1\n\
                       \tchain input { # handle 1\n\
                       \t\ttcp dport 22 accept # handle 2\n\
                       \t}\n\
                       }";

        let (outcome, commands) = run(
            &ManagePorts,
            vec![
                Reply::ok("nftables v1.0.9"),
                Reply::ok(listing),
                Reply::ok(listing), // handles_for(22)
                Reply::ok(""),      // delete rule handle 2
                Reply::ok("table inet initd {\n  chain input {\n  }\n}"),
                Reply::ok("table inet initd {\n}"),
                Reply::ok("systemd 257"),
                Reply::ok(""),
                Reply::ok(""),
            ],
            &values,
        );

        outcome.expect("declaring the empty set must succeed");

        assert!(
            commands.iter().any(|c| c.contains("delete rule")),
            "the empty set must close what was open: {commands:?}"
        );
    }

    #[test]
    fn what_was_opened_is_reported_even_when_the_closing_half_fails() {
        // The set is applied in two halves and the second can fail — a lost
        // privilege, an expired sudo timestamp, a rule nft rejects. A task that
        // ends on that error returns no `Outcome`, so the summary below it is
        // never reached, and the operator is left with a failed command over a
        // firewall that already admits the new ports. Re-running with a set
        // that no longer matches the host is the natural next move, which is
        // how a port nobody declared stays open.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "2222/tcp".to_owned());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let listing = "table inet initd { # handle 1\n\
                       \tchain input { # handle 1\n\
                       \t\ttcp dport 22 accept # handle 2\n\
                       \t}\n\
                       }";

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            Reply::ok(listing),
            Reply::ok(listing), // is_allowed(2222) — absent, so it is opened
            Reply::ok(""),      // add rule 2222
            Reply::ok(listing), // handles_for(22)
            Reply::ok(""),      // delete rule handle 2
            Reply::ok("table inet initd {\n}"), // read back: 22 is gone
            // `persist` dumps the ruleset before writing it anywhere, and that
            // is where this run stops.
            Reply::failure(1, "nft: lost privilege"),
        ]);
        let backend = for_family(Family::Debian);

        let mut lines = Vec::new();
        let outcome = ManagePorts.run(&mock, backend.as_ref(), &values, &mut |line| {
            lines.push(line.text)
        });

        assert!(outcome.is_err(), "the failure must still surface");

        let output = lines.join("\n");
        assert!(
            output.contains("2222/tcp"),
            "the port already admitted must be named before the failure: {output}"
        );
    }

    #[test]
    fn a_port_that_could_not_be_closed_is_reported_rather_than_claimed() {
        // The partial-failure case, read back rather than inferred. A rule the
        // listing did not name — hand-written, or spelled differently — is a
        // port still open after every delete reported success.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, String::new());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let listing = "table inet initd { # handle 1\n\
                       \tchain input { # handle 1\n\
                       \t\ttcp dport 22 accept # handle 2\n\
                       \t}\n\
                       }";

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            Reply::ok(listing),
            Reply::ok(listing), // handles_for
            Reply::ok(""),      // delete
            // The read-back still finds it.
            Reply::ok("table inet initd {\n  chain input {\n    tcp dport 22 accept\n  }\n}"),
            Reply::ok("table inet initd {\n}"),
            Reply::ok("systemd 257"),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        let mut lines = Vec::new();

        ManagePorts
            .run(&mock, backend.as_ref(), &values, &mut |line| {
                lines.push(line.text);
            })
            .expect("the task must not fail over a port it could not close");

        let output = lines.join("\n");

        assert!(
            output.contains("still open") && output.contains("22/tcp"),
            "the port that stayed open must be named: {output}"
        );
        assert!(
            !output.contains("closed 1"),
            "a port that is still open must not be counted as closed: {output}"
        );
    }

    #[test]
    fn a_port_that_appeared_since_the_set_was_read_is_left_alone() {
        // Somebody else opened it while the operator was deciding. Closing it
        // would undo a change this tool has no evidence anybody meant to undo,
        // so it is reported and left.
        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, "22/tcp".to_owned());
        values.set(ManagePorts::PORTS_WERE, "22/tcp".to_owned());

        let mock = MockExecutor::with_replies([
            Reply::ok("nftables v1.0.9"),
            // 9000 is here now, and was in neither set.
            Reply::ok(
                "table inet initd {\n  chain input {\n    tcp dport 22 accept\n    \
                 tcp dport 9000 accept\n  }\n}",
            ),
            Reply::ok("table inet initd {\n}"),
            Reply::ok("systemd 257"),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        let mut lines = Vec::new();

        ManagePorts
            .run(&mock, backend.as_ref(), &values, &mut |line| {
                lines.push(line.text);
            })
            .expect("declaring a set must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|c| c.contains("delete rule")),
            "a port nobody declared must not be closed: {:?}",
            mock.recorded_lines()
        );

        let output = lines.join("\n");

        assert!(
            output.contains("9000/tcp"),
            "the port that appeared must be named: {output}"
        );
    }

    #[test]
    fn managing_ports_asks_before_it_runs() {
        // A set with a port left out of it is how a session ends, and nothing
        // about deleting a table row announces that.
        assert_eq!(ManagePorts.confirmation(), Confirmation::Lockout);
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
            Some("docker.rootless"),
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
