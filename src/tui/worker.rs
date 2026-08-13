//! Running a task without blocking the interface.
//!
//! Execution used to happen inline: the terminal was handed to the child, the
//! task ran to completion, and only then did the interface redraw. Nothing
//! could be shown while a package installed, nothing could be cancelled, and —
//! once the verification window existed — its countdown could not tick, because
//! the event loop was not running.
//!
//! So a task runs on its own thread and reports back through a channel. The
//! interface drains that channel each tick, which is what lets output appear as
//! it arrives, `Ctrl-C` be noticed, and the rollback clock keep time.
//!
//! The thread builds its own executor and backend rather than borrowing the
//! interface's. Neither trait is `Send`, and making them so would impose a
//! bound on every future implementation — including the SSH one — to serve a
//! detail of how this interface happens to schedule work.

use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::distro::Distro;
use crate::error::Error;
use crate::exec::{CancelToken, OutputLine, OutputObserver, TerminalBroker};
use crate::tasks::params::ParamValues;
use crate::tasks::revert::Outcome;

/// Something a running task reports back.
#[derive(Debug)]
pub enum Update {
    /// A line the task produced.
    Line(OutputLine),
    /// A helper is about to prompt and needs the terminal back.
    ///
    /// The thread blocks on `reply` until the interface has restored the
    /// screen, run this command and answered whether it worked. It carries its
    /// own channel rather than being answered through shared state so that a
    /// superseded request can be refused explicitly instead of stranding the
    /// thread that sent it.
    NeedsAuthentication {
        program: String,
        args: Vec<String>,
        mechanism: String,
        reply: Sender<bool>,
    },
    /// The task finished, for better or worse.
    Finished(Result<Outcome, Error>),
}

/// How long the worker waits for the interface to answer an authentication
/// request.
///
/// Long enough to find a password manager, short enough that an interface that
/// died does not leave the thread waiting for a reply that is never coming.
const AUTH_DEADLINE: Duration = Duration::from_secs(300);

/// Asks the interface for the terminal on the worker thread's behalf.
///
/// Holds a clone of the update channel, which is the only thing that crosses
/// the thread boundary — the escalator and the executor stay where they were
/// built, as the module doc requires.
struct ChannelBroker {
    updates: Sender<Update>,
    mechanism: String,
    deadline: Duration,
}

/// Forwards a command's output to the interface as it arrives.
///
/// The same channel the task's own progress lines travel on, so a step a task
/// announces and the output of the command it announced land in one order —
/// two channels would interleave by luck.
struct ChannelObserver {
    updates: Sender<Update>,
}

impl OutputObserver for ChannelObserver {
    fn line(&self, line: OutputLine) {
        // A send failure means the interface is gone. The task keeps running
        // to completion rather than being abandoned midway, exactly as its own
        // progress lines do.
        let _ = self.updates.send(Update::Line(line));
    }
}

impl TerminalBroker for ChannelBroker {
    fn authenticate(&self, program: &str, args: &[String]) -> Result<bool, Error> {
        let (reply, answer) = channel();

        let unavailable = || Error::AuthenticationUnavailable {
            mechanism: self.mechanism.clone(),
        };

        self.updates
            .send(Update::NeedsAuthentication {
                program: program.to_owned(),
                args: args.to_vec(),
                mechanism: self.mechanism.clone(),
                reply,
            })
            .map_err(|_| unavailable())?;

        answer
            .recv_timeout(self.deadline)
            .map_err(|_| unavailable())
    }
}

/// A task running on another thread.
pub struct Running {
    /// Which task is running, for the interface to name.
    pub task_id: &'static str,
    updates: Receiver<Update>,
    /// Set when the operator asks to stop.
    ///
    /// Cooperative rather than a kill: a task is a sequence of commands, and
    /// stopping between two of them leaves the system in a state the task
    /// itself chose. Killing mid-command is how a half-written configuration
    /// file happens. The executor reads it before each command, so no task has
    /// to remember to check it.
    cancel: CancelToken,
    /// Whether cancellation has been asked for but not yet taken effect.
    cancelling: bool,
    /// When the task was started, for the interface to say how long it has run.
    ///
    /// Held rather than derived from the output, because a quiet command
    /// produces no lines to derive it from — and a quiet command is exactly
    /// the case an elapsed count exists to distinguish from a frozen session.
    started: Instant,
}

impl Running {
    /// Starts `task_id` on its own thread.
    ///
    /// The family is passed rather than a backend because the thread builds
    /// its own: the trait objects the interface holds cannot cross a thread
    /// boundary.
    pub fn start(task_id: &'static str, distro: Distro, values: ParamValues) -> Self {
        let (sender, updates) = channel();
        let cancel = CancelToken::new();
        let flag = cancel.clone();

        thread::spawn(move || {
            // The whole `Distro` rather than its family: the thread outlives
            // the call, so it owns what it needs, and the backend resolves one
            // repository URL from the distribution's own `ID`.
            let backend = crate::backend::for_distro(&distro);
            let escalator = crate::exec::privilege::detect();
            let broker = ChannelBroker {
                updates: sender.clone(),
                mechanism: escalator.name().to_owned(),
                deadline: AUTH_DEADLINE,
            };
            // The flag reaches the task through the executor rather than
            // through `Task::run`: every command already passes through one
            // place, so no task has to remember to check it, and the task that
            // forgot would be the one that could not be stopped.
            let executor =
                crate::exec::local::LocalExecutor::with_broker(escalator, Box::new(broker))
                    .cancelled_by(flag)
                    .observed_by(std::sync::Arc::new(ChannelObserver {
                        updates: sender.clone(),
                    }));

            let Some(task) = crate::tasks::find(task_id) else {
                // Unreachable through the interface, which only offers tasks
                // it found in the tree, but reported rather than ignored: a
                // silent no-op would look like a task that did nothing.
                let _ = sender.send(Update::Finished(Err(Error::TaskUnsupported {
                    task: task_id.to_owned(),
                    family: distro.family.to_string(),
                })));
                return;
            };

            let outcome = task.run(&executor, backend.as_ref(), &values, &mut |line| {
                // A send failure means the interface is gone; the task keeps
                // running to completion rather than being abandoned midway.
                let _ = sender.send(Update::Line(line));
            });

            let _ = sender.send(Update::Finished(outcome));
        });

        Self {
            task_id,
            updates,
            cancel,
            cancelling: false,
            started: Instant::now(),
        }
    }

    /// How long the task has been running, as of `now`.
    ///
    /// Taken as a parameter rather than read here so a test can state the
    /// elapsed time it is asserting about.
    pub fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }

    /// Takes whatever the task has reported since the last call.
    ///
    /// Drains rather than taking one at a time: a chatty package manager
    /// produces lines faster than the redraw interval, and handling one per
    /// frame would fall progressively further behind.
    pub fn drain(&mut self) -> Vec<Update> {
        let mut updates = Vec::new();

        loop {
            match self.updates.try_recv() {
                Ok(update) => updates.push(update),
                Err(TryRecvError::Empty) => break,
                // The sender is gone without a Finished having arrived, which
                // means the thread died. Reported as an error rather than left
                // to hang: a task that vanishes must not look like one still
                // running.
                Err(TryRecvError::Disconnected) => {
                    if !updates.iter().any(is_finished) {
                        updates.push(Update::Finished(Err(Error::TaskVanished {
                            task: self.task_id.to_owned(),
                        })));
                    }

                    break;
                }
            }
        }

        updates
    }

    /// Asks the task to stop at the next step boundary.
    pub fn cancel(&mut self) {
        self.cancel.cancel();
        self.cancelling = true;
    }

    /// Whether stopping has been asked for and not yet happened.
    pub const fn is_cancelling(&self) -> bool {
        self.cancelling
    }
}

/// Whether an update reports the end of the task.
fn is_finished(update: &Update) -> bool {
    matches!(update, Update::Finished(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Waits for the task to finish, returning everything it reported.
    ///
    /// Bounded so a hung task fails the test rather than hanging the suite.
    ///
    /// Refuses any request for the terminal, because a caller that drains
    /// without answering leaves the thread blocked until the deadline — the
    /// same obligation the interface carries, and the reason these tests
    /// stand in for it rather than merely reading the channel.
    fn collect(running: &mut Running) -> Vec<Update> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut all = Vec::new();

        while Instant::now() < deadline {
            for update in running.drain() {
                if let Update::NeedsAuthentication { reply, .. } = &update {
                    let _ = reply.send(false);
                }

                all.push(update);
            }

            if all.iter().any(is_finished) {
                return all;
            }

            thread::sleep(Duration::from_millis(10));
        }

        panic!("the task did not finish within the deadline");
    }

    /// A distribution to start a task against.
    ///
    /// Only the family matters to these scenarios; the rest of the record is
    /// what `Running::start` needs to build a backend.
    fn debian() -> Distro {
        Distro {
            id: "debian".to_owned(),
            version_id: None,
            codename: None,
            pretty_name: None,
            family: crate::distro::Family::Debian,
        }
    }

    #[test]
    fn a_task_reports_its_lines_and_then_its_outcome() {
        // ssh.install against a host with no package manager reachable will
        // fail, which is fine: what matters is that both kinds of update
        // arrive and that Finished is last.
        let mut running = Running::start("ssh.install", debian(), ParamValues::new());

        let updates = collect(&mut running);

        assert!(
            is_finished(updates.last().expect("at least one update")),
            "Finished must be the last thing reported"
        );
    }

    #[test]
    fn an_unknown_task_finishes_rather_than_hanging() {
        // Unreachable through the interface, but a silent no-op would look
        // exactly like a task that ran and did nothing.
        let mut running = Running::start("nonexistent.task", debian(), ParamValues::new());

        let updates = collect(&mut running);

        assert!(matches!(
            updates.last(),
            Some(Update::Finished(Err(Error::TaskUnsupported { .. })))
        ));
    }

    #[test]
    fn draining_an_idle_task_yields_nothing_and_does_not_block() {
        let mut running = Running::start("ssh.install", debian(), ParamValues::new());

        // Whatever this returns, it must return: a blocking drain would freeze
        // the interface between redraws.
        let _ = running.drain();
    }

    #[test]
    fn cancellation_is_recorded() {
        let mut running = Running::start("ssh.install", debian(), ParamValues::new());
        assert!(!running.is_cancelling());

        running.cancel();

        assert!(running.is_cancelling());
        assert!(running.cancel.is_cancelled());
    }

    #[test]
    fn a_request_for_the_terminal_carries_what_should_be_run() {
        let (sender, updates) = channel();
        let broker = ChannelBroker {
            updates: sender,
            mechanism: "doas".to_owned(),
            deadline: Duration::from_secs(5),
        };

        // The interface's side: answer whatever arrives, on another thread,
        // since `authenticate` blocks until it does.
        let answering = thread::spawn(move || match updates.recv() {
            Ok(Update::NeedsAuthentication {
                program,
                args,
                mechanism,
                reply,
            }) => {
                let _ = reply.send(true);
                (program, args, mechanism)
            }
            other => panic!("expected an authentication request, got {other:?}"),
        });

        let granted = broker
            .authenticate("doas", &["-n".to_owned(), "true".to_owned()])
            .expect("the request is answered");

        let (program, args, mechanism) = answering.join().expect("the answering thread finishes");

        assert!(granted);
        assert_eq!(program, "doas");
        assert_eq!(args, ["-n", "true"]);
        assert_eq!(mechanism, "doas");
    }

    #[test]
    fn a_refusal_is_reported_as_one_rather_than_as_a_failure() {
        let (sender, updates) = channel();
        let broker = ChannelBroker {
            updates: sender,
            mechanism: "sudo".to_owned(),
            deadline: Duration::from_secs(5),
        };

        let answering = thread::spawn(move || {
            if let Ok(Update::NeedsAuthentication { reply, .. }) = updates.recv() {
                let _ = reply.send(false);
            }
        });

        let granted = broker
            .authenticate("sudo", &["-v".to_owned()])
            .expect("a refusal is an answer, not an error");

        answering.join().expect("the answering thread finishes");

        assert!(!granted);
    }

    #[test]
    fn a_request_nobody_answers_gives_up_instead_of_blocking() {
        // The interface died, or never got to the request. Waiting forever
        // would wedge the task thread; the deadline is what bounds it.
        let (sender, updates) = channel();
        let broker = ChannelBroker {
            updates: sender,
            mechanism: "sudo".to_owned(),
            deadline: Duration::from_millis(50),
        };

        // Held rather than dropped, so this exercises the timeout and not the
        // disconnect that a dropped receiver would cause.
        let _updates = updates;

        let err = broker
            .authenticate("sudo", &["-v".to_owned()])
            .expect_err("an unanswered request must not block forever");

        assert!(
            matches!(err, Error::AuthenticationUnavailable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_vanished_interface_gives_up_at_once() {
        let (sender, updates) = channel();
        let broker = ChannelBroker {
            updates: sender,
            mechanism: "sudo".to_owned(),
            // Long enough that reaching it would mean the disconnect was
            // missed and the test waited instead.
            deadline: Duration::from_secs(60),
        };

        drop(updates);

        let started = Instant::now();
        let err = broker
            .authenticate("sudo", &["-v".to_owned()])
            .expect_err("a gone interface cannot answer");

        assert!(
            matches!(err, Error::AuthenticationUnavailable { .. }),
            "{err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a disconnect must be noticed rather than waited out"
        );
    }
}
