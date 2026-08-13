//! Moving sshd to another port.
//!
//! The port is the one setting here whose effect an administrator can lock
//! themselves out with while the file stays valid: a daemon listening
//! somewhere the firewall does not admit refuses nobody and is reachable by
//! nobody. Which is why the consequences this declares are as much of the task
//! as the write itself.

use crate::backend::{Backend, Capability};
use crate::domain::firewall::Protocol as FirewallProtocol;
use crate::error::{Error, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::i18n::Msg;
use crate::tasks::consequence::{
    Consequence, External, Protocol, Reason, Requirement, firewall_check, program_check,
};
use crate::tasks::params::{LiveDefault, MAX_PORT, Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::sshd_config;
use crate::tasks::{Confirmation, Progress, Task, report, supported_everywhere};

use super::{DEFAULT_SSH_PORT, reload_ssh, revertible};

/// Changes the port sshd listens on.
///
/// Fieldless: the port is declared as a parameter and collected when the task
/// is run, so the tree can offer it without inventing a value.
pub struct ChangePort;

impl ChangePort {
    /// Name of the parameter holding the port to move sshd to.
    pub const PORT: &'static str = "port";
}

impl Task for ChangePort {
    fn id(&self) -> &'static str {
        "ssh.change-port"
    }

    fn title(&self) -> &'static str {
        "Change the SSH port"
    }

    fn description(&self) -> &'static str {
        "Changes the port sshd listens on, keeping a backup and validating \
         before reloading. The new port may also need firewall or SELinux \
         configuration."
    }

    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // Opens on the port the daemon is actually serving, so the field
            // states what is being changed *from* rather than asserting a `22`
            // that may be a year out of date. `docs/user-stories.md` has
            // promised this since before it was true.
            Param::new(Self::PORT, "Port", ParamKind::Port)
                .with_initial(DEFAULT_SSH_PORT.to_string())
                .defaulting_to_live(LiveDefault::SshPort)
                .with_hint("1-65535; opens on the current one"),
        ]
    }

    /// Moving the port of a daemon this host does not have changes nothing.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("sshd", "ssh.install")]
    }
    supported_everywhere!();

    fn consequences(&self, backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(port) = values.port(Self::PORT) else {
            // The port failed to parse, so the task will not run and there is
            // nothing downstream to invalidate.
            return Vec::new();
        };

        // Moving to the port sshd already uses changes nothing, so it
        // invalidates nothing. Warning anyway would train the administrator to
        // dismiss these without reading them.
        if port == DEFAULT_SSH_PORT {
            return Vec::new();
        }

        vec![
            Consequence::Invalidates {
                task: "firewall.manage-ports",
                reason: Reason::PortChanged {
                    from: DEFAULT_SSH_PORT.to_string(),
                    to: port.to_string(),
                },
                // Verifiable now that the firewall is modelled: the rule either
                // names the new port or it does not, and the ruleset is the
                // only honest answer. The front-end phrases the query, since
                // the one holding this host's ruleset is not the same on every
                // family — and the needle each returns is the whole rule rather
                // than the bare number, since `2222` also appears in `22220`.
                check: firewall_check(backend, port, FirewallProtocol::Tcp),
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port,
                    protocol: Protocol::Tcp,
                },
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let port = values.port(Self::PORT)?;

        // Checked again here rather than trusted from the interface: the CLI
        // reaches this same path without passing through a form.
        if port == 0 || port > MAX_PORT {
            return Err(Error::InvalidPort { port });
        }

        backend.ensure_config_present(executor, Capability::Ssh)?;

        let files = backend.files();
        let contents = files.read(executor, backend.path_for(Capability::Ssh))?;

        // An unset Port directive means sshd is on its default of 22.
        let current = sshd_config::directive_value(&contents, "Port")
            .unwrap_or_else(|| DEFAULT_SSH_PORT.to_string());

        if current == port.to_string() {
            report(
                progress,
                &Msg::TaskSshPortUnchanged {
                    port: current.clone(),
                },
            );
            return Ok(Outcome::Done);
        }

        let updated = sshd_config::set_directive(&contents, "Port", &port.to_string());

        report(
            progress,
            &Msg::TaskSshChangingPort {
                from: current.clone(),
                to: port.to_string(),
            },
        );
        let backup =
            sshd_config::write_validated(executor, backend, self.id(), &updated, progress)?;

        // Before the three steps below, each of which can fail: the socket
        // check, the SELinux probe and the labelling. `report_backup` documents
        // why that ordering is the helper's whole reason for existing — this is
        // the task with the most that can go wrong after the file is written,
        // and the one whose change is documented as able to cost the session
        // its own way back in.
        super::report_backup(backup.as_ref(), progress);

        // Debian ships ssh.socket alongside ssh.service. When it is active the
        // socket owns the listening port, so editing sshd_config alone changes
        // nothing. Detect and warn rather than silently reconfiguring units.
        warn_if_socket_activated(executor, backend, progress)?;

        // Before the reload, not after: SELinux confines which ports the
        // daemon's own domain may bind, so a reload onto an unlabelled port
        // leaves a daemon that will not start — from a file that is valid,
        // was written successfully, and that `sshd -t` approved. Labelling
        // afterwards would be labelling a port nothing is listening on.
        //
        // Asked of the host rather than of the family: RHEL ships SELinux
        // enabled and administrators disable it, and where nothing enforces
        // this costs one command that answers by exit code.
        if backend.selinux().is_enforcing(executor)? {
            report(progress, &Msg::TaskSshLabellingPort { port });

            backend.selinux().allow_ssh_port(
                executor,
                port,
                crate::domain::firewall::Protocol::Tcp,
            )?;
        }

        report(progress, &Msg::TaskSshPortSet { port });

        reload_ssh(executor, backend, progress)?;

        // The firewall and SELinux warnings above are exactly the reasons this
        // change can succeed and still leave the machine unreachable, which is
        // why the old port is kept available to go back to.
        Ok(revertible(backup, backend))
    }
}

/// Warns when socket activation would override the configured port.
fn warn_if_socket_activated(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    const SSH_SOCKET: &str = "ssh.socket";

    let state = backend.services().state(executor, SSH_SOCKET)?;

    if state.active || state.enabled {
        progress(OutputLine::new(
            Stream::Stderr,
            format!(
                "warning: {SSH_SOCKET} is active and defines the listening port \
                 itself. The port in sshd_config will not take effect until the \
                 socket unit is reconfigured or disabled."
            ),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    /// The value `ChangePort` declares.
    fn port_values(port: u32) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(ChangePort::PORT, port.to_string());
        values
    }

    #[test]
    fn changing_the_port_writes_and_validates() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),        // read
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 2222\n"),      // sshd -T: what the daemon would do
            // Recording the change. Refused rather than answered, which is a
            // state the tool has to handle anyway: no record is kept and the
            // task carries on. Scripted explicitly so the replies below still
            // answer the questions their comments name.
            Reply::failure(1, ""), // date -u: unavailable
            Reply::failure(3, ""), // ssh.socket is-active
            Reply::failure(1, ""), // ssh.socket is-enabled
            Reply::ok(""),         // reload
        ]);
        let backend = for_family(Family::Debian);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("Port 2222"));
    }

    #[test]
    fn an_enforcing_host_gets_the_port_labelled_before_the_reload() {
        // The ordering is the whole point. SELinux confines which ports the
        // daemon may bind, so a reload onto an unlabelled port leaves a daemon
        // that will not start — from a file `sshd -t` approved.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),        // read
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 2222\n"),      // sshd -T: what the daemon would do
            // Recording the change. Refused rather than answered, which is a
            // state the tool has to handle anyway: no record is kept and the
            // task carries on. Scripted explicitly so the replies below still
            // answer the questions their comments name.
            Reply::failure(1, ""), // date -u: unavailable
            Reply::failure(3, ""), // ssh.socket is-active
            Reply::failure(1, ""), // ssh.socket is-enabled
            Reply::ok(""),         // selinuxenabled
            Reply::ok(""),         // semanage port -a
            Reply::ok(""),         // reload
        ]);
        let backend = for_family(Family::Rhel);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let lines = mock.recorded_lines();
        let labelled = lines
            .iter()
            .position(|line| line.contains("semanage"))
            .expect("the port must be labelled: {lines:?}");
        let reloaded = lines
            .iter()
            .position(|line| line.contains("reload"))
            .expect("the daemon must be reloaded: {lines:?}");

        assert!(
            labelled < reloaded,
            "the label must precede the reload: {lines:?}"
        );
        assert!(
            lines[labelled].contains("2222") && lines[labelled].contains("ssh_port_t"),
            "the new port must be labelled for SSH: {lines:?}"
        );
    }

    #[test]
    fn a_host_that_does_not_enforce_is_not_asked_to_label_anything() {
        // `selinuxenabled` exits non-zero on a RHEL host whose administrator
        // turned SELinux off, and running `semanage` there would fail on a
        // policy that is not managed — reported as an error the administrator
        // would have to interpret, over a port that needed no label.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),        // read
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 2222\n"),      // sshd -T: what the daemon would do
            // Recording the change. Refused rather than answered, which is a
            // state the tool has to handle anyway: no record is kept and the
            // task carries on. Scripted explicitly so the replies below still
            // answer the questions their comments name.
            Reply::failure(1, ""), // date -u: unavailable
            Reply::failure(3, ""), // ssh.socket is-active
            Reply::failure(1, ""), // ssh.socket is-enabled
            Reply::failure(1, ""), // selinuxenabled: disabled
            Reply::ok(""),         // reload
        ]);
        let backend = for_family(Family::Rhel);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("semanage")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_family_without_selinux_runs_no_check_at_all() {
        // The four families that have no policy answer from a constant, so
        // the task's question costs them nothing — no command, no process.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),        // read
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 2222\n"),      // sshd -T: what the daemon would do
            // Recording the change. Refused rather than answered, which is a
            // state the tool has to handle anyway: no record is kept and the
            // task carries on. Scripted explicitly so the replies below still
            // answer the questions their comments name.
            Reply::failure(1, ""), // date -u: unavailable
            Reply::failure(3, ""), // ssh.socket is-active
            Reply::failure(1, ""), // ssh.socket is-enabled
            Reply::ok(""),         // reload
        ]);
        let backend = for_family(Family::Debian);

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |_| {})
            .expect("changing the port must succeed");

        let lines = mock.recorded_lines();
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("selinuxenabled") || line.contains("semanage")),
            "{lines:?}"
        );
    }

    #[test]
    fn changing_the_port_rejects_out_of_range_values() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        for port in [0, 70_000] {
            let err = ChangePort
                .run(&mock, backend.as_ref(), &port_values(port), &mut |_| {})
                .expect_err("an out-of-range port must be rejected");

            assert!(matches!(err, Error::InvalidPort { .. }), "{err:?}");
        }
    }

    #[test]
    fn changing_the_port_warns_when_socket_activation_is_in_play() {
        // Debian's ssh.socket owns the port; editing sshd_config alone would
        // silently do nothing.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),        // read
            Reply::ok("/usr/sbin/sshd\n"), // sshd is installed
            Reply::ok(""),                 // test -e
            Reply::ok(""),                 // cp
            Reply::ok(""),                 // install the staging file
            Reply::ok(""),                 // tee
            Reply::ok("600"),              // stat -c %a
            Reply::ok(""),                 // chmod
            Reply::ok(""),                 // mv
            Reply::ok(""),                 // sshd -t
            Reply::ok("port 2222\n"),      // sshd -T: what the daemon would do
            // Recording the change, refused rather than answered — a state the
            // tool handles by keeping no record and carrying on. Scripted so
            // the replies below still answer the questions they name.
            Reply::failure(1, ""), // date -u: unavailable
            Reply::ok("active\n"), // ssh.socket is active
            Reply::ok("enabled\n"),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        ChangePort
            .run(&mock, backend.as_ref(), &port_values(2222), &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            })
            .expect("changing the port must succeed");

        assert!(
            warnings.iter().any(|w| w.contains("ssh.socket")),
            "socket activation must be reported: {warnings:?}"
        );
    }

    #[test]
    fn moving_the_port_invalidates_the_firewall_rule() {
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let firewall = consequences
            .iter()
            .find(|c| c.task() == Some("firewall.manage-ports"))
            .expect("changing the port must name the firewall");

        assert!(matches!(
            firewall,
            Consequence::Invalidates {
                reason: Reason::PortChanged { from, to },
                ..
            } if from == "22" && to == "2222"
        ));
    }

    #[test]
    fn the_firewall_warning_can_be_verified() {
        // The firewall is on this host, so the tool can settle this one rather
        // than only reporting it — unlike the provider's edge firewall.
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let firewall = consequences
            .iter()
            .find(|c| c.task() == Some("firewall.manage-ports"))
            .expect("changing the port must name the firewall");

        let check = firewall
            .check()
            .expect("a rule on this host is answerable from it");

        // The whole rule, not the bare number: `2222` is also a substring of
        // `22220`, and this project has been bitten before by a needle that
        // matched the wrong answer.
        assert_eq!(check.resolved_when_stdout_contains, "tcp dport 2222 accept");
    }

    #[test]
    fn moving_the_port_warns_about_the_provider_firewall() {
        // The failure this exists for: a port opened locally that the provider
        // still blocks. Nothing on this host can observe that, so it is
        // reported as unverifiable rather than checked.
        let consequences =
            ChangePort.consequences(for_family(Family::Debian).as_ref(), &port_values(2222));

        let external: Vec<_> = consequences.iter().filter(|c| c.is_external()).collect();

        assert_eq!(external.len(), 1, "got: {consequences:?}");
        assert!(
            external[0].check().is_none(),
            "an external warning must not offer verification"
        );
    }

    #[test]
    fn keeping_the_current_port_invalidates_nothing() {
        // Re-running with 22 changes nothing, so it breaks nothing. Warning
        // anyway is how these get dismissed unread.
        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &port_values(22))
                .is_empty()
        );
    }

    #[test]
    fn a_port_that_does_not_parse_yields_no_consequences() {
        // The task will not run, so nothing downstream is affected. This must
        // not panic: `consequences` is called while rendering.
        let mut unparseable = ParamValues::new();
        unparseable.set(ChangePort::PORT, "not-a-port".to_owned());

        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &unparseable)
                .is_empty()
        );
        assert!(
            ChangePort
                .consequences(for_family(Family::Debian).as_ref(), &ParamValues::new())
                .is_empty()
        );
    }
}
