//! Command execution — the single choke point for running processes.
//!
//! `std::process::Command` appears nowhere else in the codebase. The trait
//! exists so that remote execution over SSH can be added later as a second
//! implementation without touching any call site.
//!
//! The signature supports streaming rather than only capturing at the end,
//! because the TUI renders command output live as it arrives.

pub mod local;
pub mod privilege;

#[cfg(test)]
pub mod mock;

use std::fmt;

use crate::error::Result;

/// A command to run: a program resolved through `PATH` plus its arguments.
///
/// Absolute paths are never hardcoded — binaries live in different locations
/// across distributions, so resolution is left to `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: String,
    pub args: Vec<String>,
    /// Whether the command must run with root privileges.
    pub needs_root: bool,
    /// Data fed to the process on stdin, if any.
    ///
    /// File contents travel through here rather than through arguments: an
    /// argument would have to be shell-escaped, and any mistake in that
    /// escaping is a command injection on a tool that runs as root.
    pub stdin: Option<String>,
}

impl Command {
    /// Builds an unprivileged command.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            needs_root: false,
            stdin: None,
        }
    }

    /// Feeds the given data to the process on stdin.
    #[must_use]
    pub fn stdin(mut self, data: impl Into<String>) -> Self {
        self.stdin = Some(data.into());
        self
    }

    /// Appends a single argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Appends several arguments.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Marks the command as requiring root.
    #[must_use]
    pub const fn privileged(mut self) -> Self {
        self.needs_root = true;
        self
    }
}

impl fmt::Display for Command {
    /// Renders the command as a readable line, for logs and error messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        Ok(())
    }
}

/// Which stream a line of output came from.
///
/// Consumed by the TUI's live output pane; built ahead of it deliberately, so
/// that adding streaming later does not mean redesigning this trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum Stream {
    Stdout,
    Stderr,
}

/// A single line of output, tagged with its origin.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub struct OutputLine {
    pub stream: Stream,
    pub text: String,
}

/// The result of a finished command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// Whether the command reported success.
    pub const fn success(&self) -> bool {
        self.code == 0
    }
}

/// Runs commands. The only path to process execution in `initd`.
pub trait Executor {
    /// Runs a command to completion, capturing its output.
    fn run(&self, command: &Command) -> Result<Output>;

    /// Runs a command, forwarding each output line as it is produced.
    ///
    /// The callback receives lines from both streams interleaved in arrival
    /// order, which is what the live output pane renders.
    #[cfg_attr(not(test), allow(dead_code))]
    fn run_streaming(
        &self,
        command: &Command,
        on_line: &mut dyn FnMut(OutputLine),
    ) -> Result<Output>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_command_with_args() {
        let cmd = Command::new("apt-get").arg("install").arg("-y");

        assert_eq!(cmd.program, "apt-get");
        assert_eq!(cmd.args, ["install", "-y"]);
        assert!(!cmd.needs_root);
    }

    #[test]
    fn display_renders_a_readable_line() {
        let cmd = Command::new("systemctl").args(["enable", "ssh.service"]);

        assert_eq!(cmd.to_string(), "systemctl enable ssh.service");
    }

    #[test]
    fn privileged_marks_the_command() {
        assert!(Command::new("pacman").privileged().needs_root);
    }

    #[test]
    fn output_reports_success_only_on_zero() {
        let ok = Output {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let failed = Output {
            code: 1,
            ..ok.clone()
        };

        assert!(ok.success());
        assert!(!failed.success());
    }
}
