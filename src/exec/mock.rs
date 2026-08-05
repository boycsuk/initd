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
    /// Whether a command the test never scripted is an error.
    ///
    /// Off by default, which is what the existing tests rely on: most script
    /// only the calls they assert about and let the rest answer success.
    ///
    /// The cost of that leniency is worth naming, because it is why this flag
    /// exists. An unscripted command returns `Reply::default()`, which is
    /// *success with empty output* — so a task that grows a step gets a
    /// fabricated success from every test written before it, and all of them
    /// keep passing. The step is not merely unasserted; it is asserted to have
    /// worked, by a test that has never heard of it. Turning this on for a
    /// sequence-sensitive test makes the queue a statement about what the task
    /// runs rather than a convenience.
    strict: bool,
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
            strict: false,
        }
    }

    /// A mock that fails the test if the task runs a command it did not script.
    ///
    /// For tests whose subject is the *sequence* — which commands run, and in
    /// what order — rather than the outcome of one of them. Under
    /// [`Self::with_replies`] a command nobody scripted answers success, so
    /// such a test goes on passing after the task grows a step it has never
    /// seen. Here that is a failure naming the command, which is the point:
    /// the queue becomes the claim.
    pub fn with_exact_replies(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            recorded: RefCell::new(Vec::new()),
            replies: RefCell::new(replies.into_iter().collect()),
            strict: true,
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
    ///
    /// Panicking under `strict` is the intended behaviour of a test double:
    /// it fails the test that owns it, with the command that was not expected
    /// and the ones that came before it.
    fn record(&self, command: &Command) -> Reply {
        self.recorded.borrow_mut().push(command.clone());

        let reply = self.replies.borrow_mut().pop_front();

        match reply {
            Some(reply) => reply,
            None if self.strict => panic!(
                "unscripted command `{command}`; the script ran out after: {:?}",
                self.recorded_lines()
            ),
            None => Reply::default(),
        }
    }

    /// How many scripted replies were never used.
    ///
    /// The other direction of the same question: a task that stops running a
    /// command leaves its reply behind, and a test asserting only on what did
    /// run cannot notice. Zero means the script and the task agree.
    pub fn unused_replies(&self) -> usize {
        self.replies.borrow().len()
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
    #[should_panic(expected = "unscripted command")]
    fn a_strict_mock_refuses_a_command_nobody_scripted() {
        // The failure this buys: under the lenient mock an unscripted command
        // answers success, so a task that grows a step is *asserted to have
        // succeeded* by every test written before that step existed.
        let mock = MockExecutor::with_exact_replies([Reply::ok("scripted")]);

        mock.run(&Command::new("a")).expect("runs");
        let _ = mock.run(&Command::new("systemctl").arg("daemon-reload"));
    }

    #[test]
    fn a_strict_mock_allows_exactly_what_it_scripted() {
        // The other direction, so the check cannot pass by refusing everything.
        let mock = MockExecutor::with_exact_replies([Reply::ok("one"), Reply::ok("two")]);

        assert_eq!(mock.run(&Command::new("a")).expect("runs").stdout, "one");
        assert_eq!(mock.run(&Command::new("b")).expect("runs").stdout, "two");
        assert_eq!(mock.unused_replies(), 0);
    }

    #[test]
    fn leftover_replies_are_countable() {
        // A task that stops running a command leaves its reply behind, which a
        // test asserting only on what did run cannot otherwise notice.
        let mock = MockExecutor::with_exact_replies([Reply::ok("one"), Reply::ok("two")]);

        mock.run(&Command::new("a")).expect("runs");

        assert_eq!(mock.unused_replies(), 1);
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
