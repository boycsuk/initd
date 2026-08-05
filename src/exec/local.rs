//! Local process execution.
//!
//! The only real [`Executor`] today. Remote execution over SSH would be a
//! second implementation of the same trait.

use std::process::{Command as StdCommand, Stdio};
use std::thread;

use super::{Command, Executor, Output, TerminalBroker};
use crate::error::{Error, Result};
use crate::exec::privilege::{AuthNeed, PrivilegeEscalator};

/// Runs commands on the machine `initd` is running on.
pub struct LocalExecutor {
    escalator: Box<dyn PrivilegeEscalator>,
    /// Where to ask for the terminal when a helper is about to prompt.
    ///
    /// `None` on the command line, where the terminal is already ordinary and
    /// `sudo` can draw its own prompt — the interface is the only caller that
    /// has taken the screen away.
    broker: Option<Box<dyn TerminalBroker>>,
}

impl LocalExecutor {
    /// Builds an executor using the given escalation mechanism.
    pub fn new(escalator: Box<dyn PrivilegeEscalator>) -> Self {
        Self {
            escalator,
            broker: None,
        }
    }

    /// Builds an executor that can ask for the terminal before a prompt.
    pub fn with_broker(
        escalator: Box<dyn PrivilegeEscalator>,
        broker: Box<dyn TerminalBroker>,
    ) -> Self {
        Self {
            escalator,
            broker: Some(broker),
        }
    }

    /// Hands the terminal over if the helper is about to ask for a password.
    ///
    /// Asked *before* the command rather than recovered from afterwards,
    /// because `doas` without `persist` does not fail — it blocks on a prompt
    /// nobody can see, so there is no failure to detect. The probe is spawned
    /// here rather than through [`Executor::run`], which would recurse.
    fn ensure_authenticated(&self, command: &Command) -> Result<()> {
        if !command.needs_root {
            return Ok(());
        }

        let Some(broker) = self.broker.as_ref() else {
            return Ok(());
        };

        match self.escalator.auth_need() {
            AuthNeed::Never => return Ok(()),
            AuthNeed::Probe { program, args } => {
                if self.probe_succeeds(&program, &args) {
                    return Ok(());
                }
            }
            AuthNeed::Always => {}
        }

        let (program, args) = match self.escalator.preauth_command() {
            Some(pair) => pair,
            // Nothing to authenticate with on its own, so the terminal is
            // released around a no-op privileged command instead: it is the
            // real command's prompt, drawn where it can be answered.
            None => self.escalator.wrap(&Command::new("true").privileged())?,
        };

        if broker.authenticate(&program, &args)? {
            Ok(())
        } else {
            Err(Error::AuthenticationRefused {
                mechanism: self.escalator.name().to_owned(),
            })
        }
    }

    /// Whether the non-interactive probe reports the helper will not prompt.
    ///
    /// A probe that cannot even be spawned answers "it will prompt": assuming
    /// otherwise is what leaves an operator at a prompt they cannot see.
    fn probe_succeeds(&self, program: &str, args: &[String]) -> bool {
        StdCommand::new(program)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Applies privilege escalation when the command needs it.
    ///
    /// Returns the program and arguments actually spawned, which may be the
    /// command wrapped in `sudo`/`doas`/`run0`.
    fn resolve(&self, command: &Command) -> Result<(String, Vec<String>)> {
        if !command.needs_root {
            return Ok((command.program.clone(), command.args.clone()));
        }

        self.escalator.wrap(command)
    }

    /// Converts a finished process into an [`Output`], mapping a missing exit
    /// code (killed by signal) to an explicit error rather than a default.
    fn finish(
        command: &Command,
        code: Option<i32>,
        stdout: String,
        stderr: String,
    ) -> Result<Output> {
        let code = code.ok_or_else(|| Error::CommandTerminatedBySignal {
            command: command.to_string(),
        })?;

        Ok(Output {
            code,
            stdout,
            stderr,
        })
    }
}

impl Executor for LocalExecutor {
    fn run(&self, command: &Command) -> Result<Output> {
        // Before the command, never after: a helper that is going to prompt
        // does so on a terminal the interface still owns, and the prompt is
        // then invisible and unanswerable.
        self.ensure_authenticated(command)?;

        let (program, args) = self.resolve(command)?;

        let mut child = StdCommand::new(&program)
            .args(&args)
            .stdin(stdin_for(command))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| map_spawn_error(source, &program, command))?;

        let writer = spawn_stdin_writer(&mut child, command);

        let output = child
            .wait_with_output()
            .map_err(|source| Error::CommandIo {
                command: command.to_string(),
                source,
            })?;

        join_stdin_writer(writer, command)?;

        Self::finish(
            command,
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

/// What the child gets for stdin.
///
/// A command with a payload gets a pipe to receive it. Everything else
/// *inherits* the terminal rather than getting `/dev/null`, which is not a
/// detail: both Debian and Arch key sudo's authentication timestamp by
/// terminal, and a process with no terminal on stdin is refused even when the
/// session that spawned it has authenticated. Measured on both, in
/// `docs/sudo-timestamp-findings.md`.
fn stdin_for(command: &Command) -> Stdio {
    if command.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::inherit()
    }
}

/// Writes the command's stdin payload on a separate thread.
///
/// Writing inline would deadlock on payloads larger than the pipe buffer: the
/// child cannot drain stdin while we are not draining its stdout.
fn spawn_stdin_writer(
    child: &mut std::process::Child,
    command: &Command,
) -> Option<thread::JoinHandle<std::io::Result<()>>> {
    let data = command.stdin.clone()?;
    let mut pipe = child.stdin.take()?;

    Some(thread::spawn(move || {
        use std::io::Write as _;

        pipe.write_all(data.as_bytes())?;
        // Dropping the pipe closes it, which is what signals EOF to the child.
        drop(pipe);
        Ok(())
    }))
}

/// Waits for the stdin writer, surfacing a write failure as an error.
fn join_stdin_writer(
    writer: Option<thread::JoinHandle<std::io::Result<()>>>,
    command: &Command,
) -> Result<()> {
    let Some(writer) = writer else {
        return Ok(());
    };

    let joined = writer.join().map_err(|_| Error::CommandIo {
        command: command.to_string(),
        source: std::io::Error::other("stdin writer thread failed"),
    })?;

    joined.map_err(|source| Error::CommandIo {
        command: command.to_string(),
        source,
    })
}

/// Distinguishes "binary not in PATH" from other spawn failures.
///
/// The former is by far the most common and deserves a message naming the
/// missing program rather than a generic I/O error.
fn map_spawn_error(source: std::io::Error, program: &str, command: &Command) -> Error {
    if source.kind() == std::io::ErrorKind::NotFound {
        Error::ProgramNotFound {
            program: program.to_owned(),
        }
    } else {
        Error::CommandIo {
            command: command.to_string(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::privilege::NoEscalation;

    fn executor() -> LocalExecutor {
        LocalExecutor::new(Box::new(NoEscalation))
    }

    #[test]
    fn runs_a_command_and_captures_stdout() {
        let out = executor()
            .run(&Command::new("echo").arg("hello"))
            .expect("echo must run");

        assert!(out.success());
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn reports_non_zero_exit_codes() {
        let out = executor()
            .run(&Command::new("sh").args(["-c", "exit 3"]))
            .expect("sh must run");

        assert_eq!(out.code, 3);
        assert!(!out.success());
    }

    #[test]
    fn missing_program_is_a_named_error() {
        let err = executor()
            .run(&Command::new("initd-nonexistent-binary"))
            .expect_err("a missing binary must fail");

        assert!(matches!(err, Error::ProgramNotFound { .. }), "{err:?}");
    }

    /// A broker that answers as scripted and records that it was asked.
    ///
    /// The counter is shared rather than borrowed: `Box<dyn TerminalBroker>`
    /// is `'static`, so the test cannot hand out a reference to a local.
    #[derive(Debug)]
    struct ScriptedBroker {
        grants: bool,
        asked: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ScriptedBroker {
        fn new(grants: bool) -> (Self, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

            (
                Self {
                    grants,
                    asked: std::sync::Arc::clone(&asked),
                },
                asked,
            )
        }
    }

    impl TerminalBroker for ScriptedBroker {
        fn authenticate(&self, _program: &str, _args: &[String]) -> Result<bool> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.grants)
        }
    }

    /// How many times the broker was asked.
    fn times_asked(counter: &std::sync::atomic::AtomicUsize) -> usize {
        counter.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// An escalator that always claims a prompt is coming, without spawning
    /// anything — so the test does not depend on sudo being installed.
    #[derive(Debug)]
    struct AlwaysPrompts;

    impl PrivilegeEscalator for AlwaysPrompts {
        fn wrap(&self, command: &Command) -> Result<(String, Vec<String>)> {
            Ok((command.program.clone(), command.args.clone()))
        }

        fn name(&self) -> &str {
            "always-prompts"
        }

        fn auth_need(&self) -> crate::exec::privilege::AuthNeed {
            crate::exec::privilege::AuthNeed::Always
        }

        fn preauth_command(&self) -> Option<(String, Vec<String>)> {
            Some(("true".to_owned(), Vec::new()))
        }
    }

    #[test]
    fn an_unprivileged_command_never_asks_for_the_terminal() {
        let (broker, asked) = ScriptedBroker::new(true);
        let executor = LocalExecutor::with_broker(Box::new(AlwaysPrompts), Box::new(broker));

        executor
            .run(&Command::new("echo").arg("hello"))
            .expect("echo must run");

        assert_eq!(times_asked(&asked), 0);
    }

    #[test]
    fn a_refused_password_stops_the_command_from_running() {
        // The property that matters: a command whose authentication was
        // declined must not run at all. Running it anyway would prompt again
        // on a terminal the interface owns, which is the bug being fixed.
        let (broker, asked) = ScriptedBroker::new(false);
        let executor = LocalExecutor::with_broker(Box::new(AlwaysPrompts), Box::new(broker));

        let err = executor
            .run(&Command::new("echo").arg("hello").privileged())
            .expect_err("a refused password must fail the command");

        assert!(
            matches!(err, Error::AuthenticationRefused { .. }),
            "{err:?}"
        );
        assert_eq!(times_asked(&asked), 1);
    }

    #[test]
    fn a_granted_password_lets_the_command_through() {
        let (broker, asked) = ScriptedBroker::new(true);
        let executor = LocalExecutor::with_broker(Box::new(AlwaysPrompts), Box::new(broker));

        let out = executor
            .run(&Command::new("echo").arg("hello").privileged())
            .expect("echo must run once authenticated");

        assert_eq!(out.stdout.trim(), "hello");
        assert_eq!(times_asked(&asked), 1);
    }

    #[test]
    fn without_a_broker_a_privileged_command_behaves_as_it_always_did() {
        // The command line has an ordinary terminal, so sudo can prompt on its
        // own and nothing should change there.
        let executor = LocalExecutor::new(Box::new(NoEscalation));

        let out = executor
            .run(&Command::new("echo").arg("hello").privileged())
            .expect("echo must run");

        assert_eq!(out.stdout.trim(), "hello");
    }
}
