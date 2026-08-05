//! Local process execution.
//!
//! The only real [`Executor`] today. Remote execution over SSH would be a
//! second implementation of the same trait.

use std::process::{Command as StdCommand, Stdio};
use std::thread;

use super::{Command, Executor, Output};
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
}
