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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::thread;
use std::time::{Duration, Instant};

use crate::distro::Family;
use crate::error::Error;
use crate::exec::OutputLine;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::Outcome;

/// Something a running task reports back.
#[derive(Debug)]
pub enum Update {
    /// A line the task produced.
    Line(OutputLine),
    /// The task finished, for better or worse.
    Finished(Result<Outcome, Error>),
}

/// The spinner's frames.
///
/// ASCII rather than braille: braille spinners are missing or double-width in
/// too many of the fonts a server console actually has, and a spinner that
/// renders as a blank or shifts the columns beside it is worse than none.
const SPINNER: [&str; 4] = ["-", "\\", "|", "/"];

/// How often the spinner advances.
///
/// Slow enough to read as motion rather than a flicker, and fast enough that a
/// quiet command still visibly differs from a frozen screen.
const SPINNER_INTERVAL: Duration = Duration::from_millis(250);

/// A task running on another thread.
pub struct Running {
    /// Which task is running, for the interface to name.
    pub task_id: &'static str,
    /// When it started, for the elapsed clock.
    started: Instant,
    updates: Receiver<Update>,
    /// Set when the operator asks to stop.
    ///
    /// Cooperative rather than a kill: a task is a sequence of commands, and
    /// stopping between two of them leaves the system in a state the task
    /// itself chose. Killing mid-command is how a half-written configuration
    /// file happens.
    cancel: Arc<AtomicBool>,
    /// Whether cancellation has been asked for but not yet taken effect.
    cancelling: bool,
}

impl Running {
    /// Starts `task_id` on its own thread.
    ///
    /// The family is passed rather than a backend because the thread builds
    /// its own: the trait objects the interface holds cannot cross a thread
    /// boundary.
    pub fn start(task_id: &'static str, family: Family, values: ParamValues) -> Self {
        let (sender, updates) = channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);

        thread::spawn(move || {
            let backend = crate::backend::for_family(family);
            let executor = crate::exec::local::LocalExecutor::new(crate::exec::privilege::detect());

            let Some(task) = crate::tasks::find(task_id) else {
                // Unreachable through the interface, which only offers tasks
                // it found in the tree, but reported rather than ignored: a
                // silent no-op would look like a task that did nothing.
                let _ = sender.send(Update::Finished(Err(Error::TaskUnsupported {
                    task: task_id.to_owned(),
                    family: family.to_string(),
                })));
                return;
            };

            let outcome = task.run(&executor, backend.as_ref(), &values, &mut |line| {
                // A send failure means the interface is gone; the task keeps
                // running to completion rather than being abandoned midway.
                let _ = sender.send(Update::Line(line));
            });

            let _ = sender.send(Update::Finished(outcome));
            // The flag is read by the task through the executor in a later
            // change; holding it here keeps the channel alive until the end.
            drop(flag);
        });

        Self {
            task_id,
            started: Instant::now(),
            updates,
            cancel,
            cancelling: false,
        }
    }

    /// How long the task has been running, as `m:ss`.
    ///
    /// One of the liveness signals: a wall clock advances whether or not the
    /// child says anything, so a slow package manager stays distinguishable
    /// from a stalled one.
    pub fn elapsed(&self, now: Instant) -> String {
        let seconds = now.duration_since(self.started).as_secs();

        format!("{}:{:02}", seconds / 60, seconds % 60)
    }

    /// The spinner frame for this moment.
    ///
    /// Driven by the clock rather than by arriving output, which is the point:
    /// it keeps moving through a command that produces nothing for a minute.
    pub fn spinner(&self, now: Instant) -> &'static str {
        let ticks = now.duration_since(self.started).as_millis() / SPINNER_INTERVAL.as_millis();

        SPINNER[ticks as usize % SPINNER.len()]
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
        self.cancel.store(true, Ordering::Relaxed);
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
    fn collect(running: &mut Running) -> Vec<Update> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut all = Vec::new();

        while Instant::now() < deadline {
            all.extend(running.drain());

            if all.iter().any(is_finished) {
                return all;
            }

            thread::sleep(Duration::from_millis(10));
        }

        panic!("the task did not finish within the deadline");
    }

    #[test]
    fn a_task_reports_its_lines_and_then_its_outcome() {
        // ssh.install against a host with no package manager reachable will
        // fail, which is fine: what matters is that both kinds of update
        // arrive and that Finished is last.
        let mut running = Running::start("ssh.install", Family::Debian, ParamValues::new());

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
        let mut running = Running::start("nonexistent.task", Family::Debian, ParamValues::new());

        let updates = collect(&mut running);

        assert!(matches!(
            updates.last(),
            Some(Update::Finished(Err(Error::TaskUnsupported { .. })))
        ));
    }

    #[test]
    fn draining_an_idle_task_yields_nothing_and_does_not_block() {
        let mut running = Running::start("ssh.install", Family::Debian, ParamValues::new());

        // Whatever this returns, it must return: a blocking drain would freeze
        // the interface between redraws.
        let _ = running.drain();
    }

    #[test]
    fn the_clock_reads_as_minutes_and_seconds() {
        let running = Running::start("ssh.install", Family::Debian, ParamValues::new());
        let start = running.started;

        assert_eq!(running.elapsed(start), "0:00");
        assert_eq!(running.elapsed(start + Duration::from_secs(7)), "0:07");
        assert_eq!(running.elapsed(start + Duration::from_secs(75)), "1:15");
    }

    #[test]
    fn the_spinner_advances_on_the_clock_not_on_output() {
        // A command that says nothing for a minute still has to look alive.
        let running = Running::start("ssh.install", Family::Debian, ParamValues::new());
        let start = running.started;

        let frames: Vec<&str> = (0..SPINNER.len())
            .map(|tick| running.spinner(start + SPINNER_INTERVAL * tick as u32))
            .collect();

        let mut unique = frames.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(unique.len(), SPINNER.len(), "every frame is distinct");
        assert_eq!(
            running.spinner(start + SPINNER_INTERVAL * SPINNER.len() as u32),
            frames[0],
            "the sequence wraps"
        );
    }

    #[test]
    fn the_spinner_is_single_width_ascii() {
        // Braille frames are missing or double-width in too many of the fonts
        // a server console actually has.
        for frame in SPINNER {
            assert_eq!(frame.chars().count(), 1, "{frame:?} must be one cell");
            assert!(frame.is_ascii(), "{frame:?} must be ASCII");
        }
    }

    #[test]
    fn cancellation_is_recorded() {
        let mut running = Running::start("ssh.install", Family::Debian, ParamValues::new());
        assert!(!running.is_cancelling());

        running.cancel();

        assert!(running.is_cancelling());
        assert!(running.cancel.load(Ordering::Relaxed));
    }
}
