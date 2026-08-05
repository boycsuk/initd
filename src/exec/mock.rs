//! Test double for [`Executor`].
//!
//! Records every command it receives and replies with preconfigured outputs,
//! including failures. This is what lets backend and task tests assert on the
//! exact command built — the test that proves the distro abstraction works.

use std::cell::RefCell;
use std::collections::VecDeque;

use super::{Command, Executor, Output};
use crate::error::Result;

/// A canned reply for one command.
#[derive(Debug, Clone)]
pub struct Reply {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Reply {
    /// A successful reply with the given stdout.
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// A failing reply with the given exit code and stderr.
    pub fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            code,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

impl Default for Reply {
    /// Success with no output — the default for commands a test does not care
    /// about.
    fn default() -> Self {
        Self::ok("")
    }
}

/// An [`Executor`] that runs nothing and records everything.
///
/// Interior mutability keeps the `Executor` signature free of `&mut self`,
/// which production code has no reason to require.
#[derive(Debug, Default)]
pub struct MockExecutor {
    recorded: RefCell<Vec<Command>>,
    replies: RefCell<VecDeque<Reply>>,
}

impl MockExecutor {
    /// A mock that replies with success to everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// A mock that replies with the given sequence, in order.
    ///
    /// Once the queue is exhausted, further commands get the default success
    /// reply, so tests only script the calls they care about.
    pub fn with_replies(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            recorded: RefCell::new(Vec::new()),
            replies: RefCell::new(replies.into_iter().collect()),
        }
    }

    /// Every command received, in order.
    pub fn recorded(&self) -> Vec<Command> {
        self.recorded.borrow().clone()
    }

    /// The commands received, rendered as readable lines.
    pub fn recorded_lines(&self) -> Vec<String> {
        self.recorded
            .borrow()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// The single command received, or a panic describing what was recorded.
    ///
    /// Test-only convenience: panicking here fails the test with a useful
    /// message, which is the desired behaviour in a test double.
    pub fn single_command(&self) -> Command {
        let recorded = self.recorded.borrow();
        assert_eq!(
            recorded.len(),
            1,
            "expected exactly one command, got: {:?}",
            self.recorded_lines()
        );
        recorded[0].clone()
    }

    /// Whether any recorded command was marked as privileged.
    pub fn any_privileged(&self) -> bool {
        self.recorded.borrow().iter().any(|cmd| cmd.needs_root)
    }

    /// Records a command and takes the next scripted reply.
    fn record(&self, command: &Command) -> Reply {
        self.recorded.borrow_mut().push(command.clone());
        self.replies.borrow_mut().pop_front().unwrap_or_default()
    }
}

impl Executor for MockExecutor {
    fn run(&self, command: &Command) -> Result<Output> {
        let reply = self.record(command);

        Ok(Output {
            code: reply.code,
            stdout: reply.stdout,
            stderr: reply.stderr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_the_commands_it_receives() {
        let mock = MockExecutor::new();

        mock.run(&Command::new("apt-get").arg("update"))
            .expect("mock never fails to run");
        mock.run(&Command::new("systemctl").arg("enable"))
            .expect("mock never fails to run");

        assert_eq!(
            mock.recorded_lines(),
            ["apt-get update", "systemctl enable"]
        );
    }

    #[test]
    fn replies_in_the_scripted_order() {
        let mock =
            MockExecutor::with_replies([Reply::ok("first"), Reply::failure(1, "second failed")]);

        let first = mock.run(&Command::new("a")).expect("runs");
        let second = mock.run(&Command::new("b")).expect("runs");

        assert_eq!(first.stdout, "first");
        assert!(first.success());
        assert_eq!(second.code, 1);
        assert_eq!(second.stderr, "second failed");
    }

    #[test]
    fn defaults_to_success_once_the_script_runs_out() {
        let mock = MockExecutor::with_replies([Reply::ok("scripted")]);

        mock.run(&Command::new("a")).expect("runs");
        let extra = mock.run(&Command::new("b")).expect("runs");

        assert!(extra.success(), "unscripted calls default to success");
    }

    #[test]
    fn tracks_whether_a_command_needed_root() {
        let mock = MockExecutor::new();

        mock.run(&Command::new("id")).expect("runs");
        assert!(!mock.any_privileged());

        mock.run(&Command::new("apt-get").privileged())
            .expect("runs");
        assert!(mock.any_privileged());
    }
}
