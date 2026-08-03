//! Local process execution.
//!
//! The only real [`Executor`] today. Remote execution over SSH would be a
//! second implementation of the same trait.

use std::io::{BufRead, BufReader};
use std::process::{Command as StdCommand, Stdio};
use std::sync::mpsc;
use std::thread;

use super::{Command, Executor, Output, OutputLine, Stream};
use crate::error::{Error, Result};
use crate::exec::privilege::PrivilegeEscalator;

/// Runs commands on the machine `initd` is running on.
pub struct LocalExecutor {
    escalator: Box<dyn PrivilegeEscalator>,
}

impl LocalExecutor {
    /// Builds an executor using the given escalation mechanism.
    pub fn new(escalator: Box<dyn PrivilegeEscalator>) -> Self {
        Self { escalator }
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

    fn run_streaming(
        &self,
        command: &Command,
        on_line: &mut dyn FnMut(OutputLine),
    ) -> Result<Output> {
        let (program, args) = self.resolve(command)?;

        let mut child = StdCommand::new(&program)
            .args(&args)
            .stdin(stdin_for(command))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| map_spawn_error(source, &program, command))?;

        let writer = spawn_stdin_writer(&mut child, command);

        // Both pipes are drained concurrently: reading them in sequence would
        // deadlock as soon as the child filled the buffer of the other one.
        let (tx, rx) = mpsc::channel();
        let mut readers = Vec::new();

        if let Some(stdout) = child.stdout.take() {
            readers.push(spawn_reader(stdout, Stream::Stdout, tx.clone()));
        }
        if let Some(stderr) = child.stderr.take() {
            readers.push(spawn_reader(stderr, Stream::Stderr, tx.clone()));
        }

        // The original sender must go, or the loop below never sees the pipes
        // close and waits forever.
        drop(tx);

        let mut stdout_text = String::new();
        let mut stderr_text = String::new();

        for line in rx {
            match line.stream {
                Stream::Stdout => {
                    stdout_text.push_str(&line.text);
                    stdout_text.push('\n');
                }
                Stream::Stderr => {
                    stderr_text.push_str(&line.text);
                    stderr_text.push('\n');
                }
            }
            on_line(line);
        }

        for reader in readers {
            // A reader thread only panics if the channel is poisoned, which
            // cannot happen here; treat a join failure as an I/O error rather
            // than unwrapping.
            reader.join().map_err(|_| Error::CommandIo {
                command: command.to_string(),
                source: std::io::Error::other("output reader thread failed"),
            })?;
        }

        join_stdin_writer(writer, command)?;

        let status = child.wait().map_err(|source| Error::CommandIo {
            command: command.to_string(),
            source,
        })?;

        Self::finish(command, status.code(), stdout_text, stderr_text)
    }
}

/// Whether the child needs a stdin pipe or should inherit a closed one.
fn stdin_for(command: &Command) -> Stdio {
    if command.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
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

/// Reads a pipe line by line, forwarding each line to the collector.
#[cfg_attr(not(test), allow(dead_code))]
fn spawn_reader<R>(pipe: R, stream: Stream, tx: mpsc::Sender<OutputLine>) -> thread::JoinHandle<()>
where
    R: std::io::Read + Send + 'static,
{
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            // A malformed UTF-8 line ends that stream, but the process is
            // still waited on, so nothing is left dangling.
            let Ok(text) = line else { break };

            if tx.send(OutputLine { stream, text }).is_err() {
                break;
            }
        }
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

    #[test]
    fn streaming_forwards_lines_in_order() {
        let mut lines = Vec::new();
        let out = executor()
            .run_streaming(
                &Command::new("sh").args(["-c", "echo one; echo two"]),
                &mut |line| lines.push(line.text),
            )
            .expect("sh must run");

        assert!(out.success());
        assert_eq!(lines, ["one", "two"]);
    }

    #[test]
    fn streaming_tags_stderr_separately() {
        let mut stderr_lines = Vec::new();
        executor()
            .run_streaming(
                &Command::new("sh").args(["-c", "echo oops >&2"]),
                &mut |line| {
                    if line.stream == Stream::Stderr {
                        stderr_lines.push(line.text);
                    }
                },
            )
            .expect("sh must run");

        assert_eq!(stderr_lines, ["oops"]);
    }

    #[test]
    fn streaming_captures_output_as_well_as_forwarding_it() {
        let out = executor()
            .run_streaming(&Command::new("echo").arg("captured"), &mut |_| {})
            .expect("echo must run");

        assert_eq!(out.stdout.trim(), "captured");
    }

    #[test]
    fn streaming_does_not_deadlock_on_large_output() {
        // A single pipe's buffer is ~64 KiB; writing well past that on both
        // streams would hang an implementation that drained them in sequence.
        let mut count = 0_usize;
        let out = executor()
            .run_streaming(
                &Command::new("sh").args([
                    "-c",
                    "i=0; while [ $i -lt 4000 ]; do echo out-$i; echo err-$i >&2; i=$((i+1)); done",
                ]),
                &mut |_| count += 1,
            )
            .expect("sh must run");

        assert!(out.success());
        assert_eq!(count, 8000, "every line from both streams must arrive");
    }
}
