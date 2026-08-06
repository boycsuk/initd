//! Local process execution.
//!
//! The only real [`Executor`] today. Remote execution over SSH would be a
//! second implementation of the same trait.

use std::io::{BufRead as _, BufReader};
use std::process::{Command as StdCommand, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;

use super::{
    CancelToken, Command, Executor, Output, OutputLine, OutputObserver, Stream, TerminalBroker,
};
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
    /// Raised by the interface to stop the task between two commands.
    ///
    /// `None` on the command line: there is no interface to press a key, and a
    /// terminal `Ctrl-C` already signals the whole process group.
    cancel: Option<CancelToken>,
    /// Where each line goes as the command produces it.
    ///
    /// `None` on the command line, where the child's output is already on the
    /// terminal the operator is looking at. The interface takes the screen
    /// away, so it has to be handed the lines instead.
    observer: Option<Arc<dyn OutputObserver>>,
}

impl LocalExecutor {
    /// Builds an executor using the given escalation mechanism.
    pub fn new(escalator: Box<dyn PrivilegeEscalator>) -> Self {
        Self {
            escalator,
            broker: None,
            cancel: None,
            observer: None,
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
            cancel: None,
            observer: None,
        }
    }

    /// Gives the executor a flag the interface can raise to stop the task.
    #[must_use]
    pub fn cancelled_by(mut self, cancel: CancelToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Sends each line to `observer` as the command produces it.
    ///
    /// Without one the output is still captured and returned; the difference
    /// is only whether anybody sees it before the command ends.
    #[must_use]
    pub fn observed_by(mut self, observer: Arc<dyn OutputObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Runs a child, draining both pipes concurrently and reporting each line.
    ///
    /// Both pipes are read on their own threads, and neither may be read to
    /// completion before the other starts: a child that fills the pipe nobody
    /// is draining blocks writing to it, forever, while this waits for the
    /// stream it chose to read first. That is a deadlock reachable by any
    /// command chatty enough on the wrong stream — `apt` is.
    ///
    /// Lines are also collected, so `Output` still carries the whole of both
    /// streams: callers that classify a failure by its stderr, like the sshd
    /// config validation, must not have to observe to keep working.
    fn stream_child(
        &self,
        child: &mut std::process::Child,
        observer: &Arc<dyn OutputObserver>,
    ) -> (String, String) {
        let (sender, lines) = mpsc::channel();

        let readers: Vec<_> = [
            child.stdout.take().map(|pipe| {
                (
                    Stream::Stdout,
                    Box::new(pipe) as Box<dyn std::io::Read + Send>,
                )
            }),
            child.stderr.take().map(|pipe| {
                (
                    Stream::Stderr,
                    Box::new(pipe) as Box<dyn std::io::Read + Send>,
                )
            }),
        ]
        .into_iter()
        .flatten()
        .map(|(stream, pipe)| spawn_reader(pipe, stream, sender.clone()))
        .collect();

        // The senders held here would keep the channel open after both readers
        // finish, and the drain below would never end.
        drop(sender);

        let mut stdout = String::new();
        let mut stderr = String::new();

        for line in lines {
            // `Command` is announced by `run`, never read off a pipe, so the
            // readers below can only produce the two real streams.
            if let Stream::Stdout | Stream::Stderr = line.stream {
                let sink = if line.stream == Stream::Stdout {
                    &mut stdout
                } else {
                    &mut stderr
                };

                sink.push_str(&line.text);
                sink.push('\n');
            }

            observer.line(line);
        }

        for reader in readers {
            // A reader panicking is not worth failing the command over: the
            // process still ran, and its exit code is the answer being sought.
            let _ = reader.join();
        }

        (stdout, stderr)
    }

    /// Refuses to start a command once the operator has asked the task to stop.
    ///
    /// Checked before the command rather than after: a task stopped between two
    /// commands has completed whole steps only, which is the granularity the
    /// interface promises. Interrupting a running command would leave the step
    /// it was performing half applied, and tasks are not idempotent.
    fn check_not_cancelled(&self, command: &Command) -> Result<()> {
        let Some(cancel) = self.cancel.as_ref() else {
            return Ok(());
        };

        if cancel.is_cancelled() {
            return Err(Error::Cancelled {
                before: command.to_string(),
            });
        }

        Ok(())
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
        // First of all, and before authenticating: a task the operator has
        // stopped must not go on to ask them for a password.
        self.check_not_cancelled(command)?;

        // Before the command, never after: a helper that is going to prompt
        // does so on a terminal the interface still owns, and the prompt is
        // then invisible and unanswerable.
        self.ensure_authenticated(command)?;

        // The command before its output, so the pane reads as a transcript.
        // Rendered from the `Command` rather than from what was spawned, so a
        // privileged one appears as the task asked for it rather than wrapped
        // in whichever helper this host resolved — and `Display` omits stdin,
        // which is what keeps a WireGuard private key out of the pane.
        if let Some(observer) = self.observer.as_ref() {
            observer.line(OutputLine {
                stream: Stream::Command,
                text: command.to_string(),
            });
        }

        let (program, args) = self.resolve(command)?;

        let mut child = StdCommand::new(&program)
            .args(&args)
            .stdin(stdin_for(command))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| map_spawn_error(source, &program, command))?;

        let writer = spawn_stdin_writer(&mut child, command);

        // Two paths because only one of them can exist at a time:
        // `wait_with_output` takes the pipes, and draining them line by line
        // needs to have taken them first. The observed path is the interface's;
        // the other is the command line's, where the child's output already
        // reaches the terminal the operator is reading.
        let (code, stdout, stderr) = match self.observer.as_ref() {
            Some(observer) => {
                let (stdout, stderr) = self.stream_child(&mut child, observer);

                let status = child.wait().map_err(|source| Error::CommandIo {
                    command: command.to_string(),
                    source,
                })?;

                (status.code(), stdout, stderr)
            }
            None => {
                let output = child
                    .wait_with_output()
                    .map_err(|source| Error::CommandIo {
                        command: command.to_string(),
                        source,
                    })?;

                (
                    output.status.code(),
                    String::from_utf8_lossy(&output.stdout).into_owned(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                )
            }
        };

        join_stdin_writer(writer, command)?;

        Self::finish(command, code, stdout, stderr)
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

/// Reads one pipe line by line, forwarding each on the channel.
///
/// A line that is not valid UTF-8 ends that stream rather than failing the
/// command: the process is still waited on and its exit code still answers.
fn spawn_reader(
    pipe: Box<dyn std::io::Read + Send>,
    stream: Stream,
    sender: mpsc::Sender<OutputLine>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(text) = line else { break };

            // A send failure means the drain has gone; nothing would read
            // anything sent after it.
            if sender.send(OutputLine { stream, text }).is_err() {
                break;
            }
        }
    })
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

    /// An observer that keeps every line it was handed.
    #[derive(Debug, Default)]
    struct Recorder {
        lines: std::sync::Mutex<Vec<OutputLine>>,
    }

    impl OutputObserver for Recorder {
        fn line(&self, line: OutputLine) {
            self.lines
                .lock()
                .expect("no test panics while holding this")
                .push(line);
        }
    }

    impl Recorder {
        /// The recorded lines, as `stream:text`.
        fn seen(&self) -> Vec<String> {
            self.lines
                .lock()
                .expect("no test panics while holding this")
                .iter()
                .map(|line| {
                    let stream = match line.stream {
                        Stream::Stdout => "out",
                        Stream::Stderr => "err",
                        Stream::Command => "cmd",
                    };
                    format!("{stream}:{}", line.text)
                })
                .collect()
        }
    }

    #[test]
    fn an_observer_is_handed_each_line_of_both_streams() {
        let recorder = Arc::new(Recorder::default());
        let executor = LocalExecutor::new(Box::new(NoEscalation))
            .observed_by(Arc::clone(&recorder) as Arc<dyn OutputObserver>);

        executor
            .run(&Command::new("sh").args(["-c", "echo one; echo two >&2; echo three"]))
            .expect("sh must run");

        let seen = recorder.seen();

        assert!(seen.contains(&"out:one".to_owned()), "{seen:?}");
        assert!(seen.contains(&"err:two".to_owned()), "{seen:?}");
        assert!(seen.contains(&"out:three".to_owned()), "{seen:?}");
    }

    #[test]
    fn observing_does_not_stop_the_output_being_returned() {
        // The property every existing caller depends on: `sshd_config`
        // classifies a failure by reading stderr off the returned `Output`,
        // and it does not observe. Streaming must add a second reader of the
        // lines, not move them.
        let recorder = Arc::new(Recorder::default());
        let executor = LocalExecutor::new(Box::new(NoEscalation))
            .observed_by(Arc::clone(&recorder) as Arc<dyn OutputObserver>);

        let out = executor
            .run(&Command::new("sh").args(["-c", "echo captured; echo failed >&2; exit 3"]))
            .expect("sh must run");

        assert_eq!(out.code, 3);
        assert_eq!(out.stdout.trim(), "captured");
        assert_eq!(out.stderr.trim(), "failed");
    }

    #[test]
    fn a_command_chatty_on_one_stream_does_not_deadlock() {
        // Both pipes are drained concurrently. Reading one to completion first
        // hangs forever on a child that fills the other: the child blocks
        // writing to a pipe nobody empties, and never reaches the exit this
        // would be waiting for. `apt` is chatty enough on stderr to reach it.
        //
        // 64 KiB comfortably exceeds a 64 KiB pipe buffer once the newline of
        // each line is counted, so this hangs rather than fails if the
        // concurrency is lost.
        let recorder = Arc::new(Recorder::default());
        let executor = LocalExecutor::new(Box::new(NoEscalation))
            .observed_by(Arc::clone(&recorder) as Arc<dyn OutputObserver>);

        let out = executor
            .run(&Command::new("sh").args([
                "-c",
                "i=0; while [ $i -lt 4000 ]; do \
                 echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >&2; i=$((i+1)); done; echo done",
            ]))
            .expect("a chatty command must finish");

        assert!(out.success());
        assert_eq!(out.stdout.trim(), "done");
        assert_eq!(out.stderr.lines().count(), 4000);
    }

    #[test]
    fn without_an_observer_the_output_is_still_captured() {
        // The command line builds no observer and must behave as it did.
        let executor = LocalExecutor::new(Box::new(NoEscalation));

        let out = executor
            .run(&Command::new("sh").args(["-c", "echo plain; echo loud >&2"]))
            .expect("sh must run");

        assert_eq!(out.stdout.trim(), "plain");
        assert_eq!(out.stderr.trim(), "loud");
    }

    #[test]
    fn a_command_reading_stdin_still_streams_its_output() {
        // The stdin writer runs on its own thread beside the two readers; a
        // payload larger than the pipe buffer deadlocks if any of the three
        // waits on another.
        let recorder = Arc::new(Recorder::default());
        let executor = LocalExecutor::new(Box::new(NoEscalation))
            .observed_by(Arc::clone(&recorder) as Arc<dyn OutputObserver>);

        let payload = "x".repeat(128 * 1024);

        let out = executor
            .run(&Command::new("wc").arg("-c").stdin(payload.clone()))
            .expect("wc must run");

        assert!(out.success());
        assert_eq!(out.stdout.trim(), payload.len().to_string());
        assert!(!recorder.seen().is_empty(), "the count must be observed");
    }

    #[test]
    fn a_cancelled_task_runs_no_further_commands() {
        // The whole point of the flag: once the operator has asked to stop,
        // the next command must not run at all. A task that ran it anyway
        // would report CANCELLED having applied one more step than it says.
        let cancel = CancelToken::new();
        let executor = LocalExecutor::new(Box::new(NoEscalation)).cancelled_by(cancel.clone());

        // A file the command would create if it ran, so the assertion observes
        // the command's effect rather than only its reported error.
        let marker = std::env::temp_dir().join("initd-cancel-probe");
        let _ = std::fs::remove_file(&marker);
        let path = marker.to_string_lossy().into_owned();

        cancel.cancel();

        let err = executor
            .run(&Command::new("touch").arg(&path))
            .expect_err("a cancelled task must not run the command");

        assert!(matches!(err, Error::Cancelled { .. }), "{err:?}");
        assert!(!marker.exists(), "the command must not have run");
    }

    #[test]
    fn a_task_nobody_cancelled_runs_normally() {
        // The other direction, so the check cannot pass by refusing everything.
        let cancel = CancelToken::new();
        let executor = LocalExecutor::new(Box::new(NoEscalation)).cancelled_by(cancel);

        let out = executor
            .run(&Command::new("echo").arg("hello"))
            .expect("an uncancelled task must run");

        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn cancellation_names_the_command_it_stopped_before() {
        // The report has to say where the task stopped: "cancelled" alone
        // leaves the operator guessing which steps were applied.
        let cancel = CancelToken::new();
        let executor = LocalExecutor::new(Box::new(NoEscalation)).cancelled_by(cancel.clone());

        cancel.cancel();

        let err = executor
            .run(&Command::new("systemctl").args(["restart", "ssh.service"]))
            .expect_err("a cancelled task must fail");

        let Error::Cancelled { before } = err else {
            panic!("expected Cancelled, got {err:?}");
        };
        assert_eq!(before, "systemctl restart ssh.service");
    }

    #[test]
    fn a_cancelled_task_is_never_asked_for_a_password() {
        // Authentication happens after the cancellation check, so a task the
        // operator stopped does not go on to prompt them for a password.
        let (broker, asked) = ScriptedBroker::new(true);
        let cancel = CancelToken::new();
        let executor = LocalExecutor::with_broker(Box::new(AlwaysPrompts), Box::new(broker))
            .cancelled_by(cancel.clone());

        cancel.cancel();

        let err = executor
            .run(&Command::new("echo").arg("hello").privileged())
            .expect_err("a cancelled task must fail");

        assert!(matches!(err, Error::Cancelled { .. }), "{err:?}");
        assert_eq!(times_asked(&asked), 0, "a stopped task must not prompt");
    }

    #[test]
    fn without_a_token_nothing_changes() {
        // The command line builds no token, and must behave as it always did.
        let executor = LocalExecutor::new(Box::new(NoEscalation));

        let out = executor
            .run(&Command::new("echo").arg("hello"))
            .expect("echo must run");

        assert_eq!(out.stdout.trim(), "hello");
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
