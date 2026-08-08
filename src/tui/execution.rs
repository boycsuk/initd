//! Running a task and resolving what it leaves behind.
//!
//! The whole life of a run: starting it, draining what it reports, deciding
//! what its outcome means, and — for a change that can lock the administrator
//! out — opening the window in which it can still be undone.
//!
//! Separated from `app.rs` for navigation rather than for independence. These
//! methods reach nine of `App`'s twenty-one fields and share seven of them with
//! the key handlers, so the coupling is unchanged; what changes is that the
//! run's own logic is now readable in one place.

use std::time::Instant;

use super::app::App;
use super::auth::AuthRequest;
use super::status::State;
use super::verify::Verification;
use super::worker::{Running, Update};
use crate::error::{Error, Result};
use crate::exec::{OutputLine, Stream};
use crate::i18n::{Msg, RevertReason};
use crate::tasks;
use crate::tasks::Node;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::{Outcome, Revert};

impl App {
    /// Executes the selected task, streaming its output into the pane.
    pub(super) fn run_selected(&mut self, values: ParamValues) {
        let Some(Node::Task(task)) = self.selected_node() else {
            return;
        };

        let id = task.id();

        self.output.clear();
        self.status.set(State::Running, id);

        // Focus deliberately stays where it was. This used to move to the
        // output on the grounds that reading what is about to happen is the
        // natural next thing, which is true of the *pane* and not of the
        // *cursor*: the output is drawn and streaming either way, since the
        // right pane shows it as soon as there is any. What moving the focus
        // actually did was take the arrow keys away from the tree, so the row
        // the operator had selected stopped being the row the keys addressed —
        // and moving on to the next task meant pressing Tab first, to undo
        // something they had not asked for.

        // Kept because consequences are declared from the values the task ran
        // with, and those are reported once it finishes — by which point the
        // originals have been moved onto the worker thread.
        self.ran_with = values.clone();

        // The task runs on its own thread and reports back through a channel,
        // which the event loop drains each tick. Running it inline would
        // freeze the interface for the duration: no output as it arrives, no
        // way to cancel, and no clock for the verification window.
        self.running = Some(Running::start(id, self.distro.clone(), values));
    }
    /// Takes whatever the running task has reported since the last redraw.
    pub(super) fn poll_running(&mut self) {
        let Some(running) = self.running.as_mut() else {
            return;
        };

        let mut outcome = None;
        // Collected rather than applied inside the loop, which holds a mutable
        // borrow of `running`. Order is preserved either way: the lines a task
        // wrote before asking are pushed as they are drained.
        let mut requests = Vec::new();

        for update in running.drain() {
            match update {
                Update::Line(line) => self.output.push(line),
                Update::NeedsAuthentication {
                    program,
                    args,
                    mechanism,
                    reply,
                } => requests.push(AuthRequest {
                    program,
                    args,
                    mechanism,
                    reply,
                }),
                Update::Finished(result) => outcome = Some(result),
            }
        }

        // Read while the borrow is still in hand, so the requests below can
        // take `self` mutably.
        let cancelled = running.is_cancelling();
        let id = running.task_id;

        for request in requests {
            self.output.push(OutputLine {
                stream: Stream::Stderr,
                text: self.lang.render(&Msg::AuthenticationRequested {
                    mechanism: request.mechanism.clone(),
                }),
            });

            self.supersede_pending_auth(request);
        }

        let Some(outcome) = outcome else {
            return;
        };

        self.running = None;

        self.finish_run(id, outcome, cancelled);
    }
    /// Records how a finished task ended.
    ///
    /// Success and failure are pills of their own, so the outcome is legible
    /// from the left edge without reading the message beside it.
    pub(super) fn finish_run(&mut self, id: &str, outcome: Result<Outcome>, cancelled: bool) {
        // Cancellation is reported from what the task actually did, not from
        // the operator having asked: the request arrives between two commands,
        // and a task already on its last one runs to completion. Reporting the
        // intent would claim a stop that never happened, which is how a server
        // gets called half-configured when it is fully configured — and the
        // reverse, on the next run.
        if let Err(Error::Cancelled { ref before }) = outcome {
            self.status.set(
                State::Cancelled,
                self.lang.render(&Msg::StatusStoppedBefore {
                    task: id.to_owned(),
                    before: before.clone(),
                }),
            );
            return;
        }

        // Asked to stop, but the task finished first. Reported as whatever it
        // actually was, with the near miss said out loud rather than silently
        // dropped: the operator pressed a key and is owed an answer.
        if cancelled {
            self.output.push(OutputLine {
                stream: Stream::Stderr,
                text: self.lang.render(&Msg::StatusFinishedBeforeItCouldStop),
            });
        }

        // A change that can sever this session is not reported as done: it is
        // applied, and held open until the administrator proves they can still
        // get in. A failing task is reported in the status row rather than
        // tearing the interface down — the administrator stays in control.
        match outcome {
            Ok(result) => {
                // Stated before the verification window opens, so what the
                // change invalidated is on screen while there is still an undo
                // available. A failed task invalidates nothing, which is why
                // this sits on the success path only.
                self.report_consequences(id);

                match result {
                    Outcome::Revertible(revert) => self.begin_verification(id, revert),
                    Outcome::Done => self.status.set(State::Done, id),
                }
            }
            Err(ref err) => {
                // Into the pane as well as the status row. The row is one
                // line and is not truncated with an ellipsis, so a package
                // manager's stderr arriving through `CommandFailed` was cut
                // mid-sentence with no way to see the rest — and the pane is
                // the part an administrator can scroll and paste into a bug
                // report. The row keeps the summary so the outcome is legible
                // from the left edge without reading the pane.
                self.output.push(OutputLine {
                    stream: Stream::Stderr,
                    text: self.lang.render(&err.to_msg()),
                });
                self.status.set(
                    State::Failed,
                    self.lang.render(&Msg::StatusTaskFailed {
                        task: id.to_owned(),
                    }),
                );
            }
        }

        // After the match rather than inside its successful arm, because a
        // task that failed held the same password and reported nothing that
        // needed it. `ran_with` is kept so the consequences above can name what
        // the task invalidated; nothing reads it again until the next task
        // replaces it, so on a host where one account is created and nothing
        // else that is the rest of the session.
        if let Some(task) = tasks::find(id) {
            self.ran_with.forget_secrets(&task.params());
        }
    }
    /// Writes what the finished task invalidated into the output pane.
    ///
    /// Reported, never acted on: the administrator decides what to do about
    /// each one. Warnings the tool cannot verify carry a different marker from
    /// those it can, since presenting both alike would imply the provider's
    /// firewall had been checked when nothing checked it.
    pub(super) fn report_consequences(&mut self, id: &str) {
        let Some(task) = tasks::find(id) else {
            return;
        };

        let consequences = task.consequences(self.backend.as_ref(), &self.ran_with);

        if consequences.is_empty() {
            return;
        }

        let lang = self.lang;

        self.output.push(OutputLine {
            stream: Stream::Stdout,
            text: String::new(),
        });
        self.output.push(OutputLine {
            stream: Stream::Stdout,
            text: lang.render(&Msg::OutputConsequencesHeading),
        });

        for consequence in consequences {
            let marker = if consequence.is_external() {
                "⚠"
            } else {
                "!"
            };

            self.output.push(OutputLine {
                stream: Stream::Stdout,
                text: format!("  {marker} {}", lang.render(&consequence.message())),
            });
        }
    }
    /// Opens the window in which an applied change can still be undone.
    pub(super) fn begin_verification(&mut self, task: &str, revert: Revert) {
        let window = Verification::new(task, revert, Instant::now());

        self.status.set(
            State::Verify,
            self.lang.render(&Msg::StatusAppliedNotYetKept {
                task: task.to_owned(),
            }),
        );
        self.verification = Some(window);
    }
    /// Keeps an applied change, closing its window.
    pub(super) fn keep_change(&mut self) {
        let Some(window) = self.verification.take() else {
            return;
        };

        self.status.set(
            State::Done,
            self.lang.render(&Msg::StatusKept {
                task: window.task.clone(),
            }),
        );
    }
    /// Puts an applied change back, closing its window.
    ///
    /// A revert that itself fails is reported rather than swallowed: the
    /// administrator has to know the machine is in neither state.
    ///
    /// **Run on the event loop's own thread, unlike every other command this
    /// interface issues.** Tasks go to a worker precisely so a package
    /// installation cannot freeze the screen, and the exception here is not an
    /// oversight: `resolve_on_hangup` calls this immediately before the loop
    /// exits, so a revert handed to a thread would race the process ending —
    /// and losing the session is the case the verification window exists for
    /// rather than an edge of it. A revert that does not finish there leaves
    /// the configuration that locked the administrator out, having promised on
    /// screen that silence would put it back.
    ///
    /// The cost is bounded by what a revert is: a file copy and a `reload`,
    /// which is milliseconds against the seconds a task takes. Moving it to the
    /// worker would trade a pause nobody can perceive for a failure mode that
    /// costs someone their server.
    pub(super) fn revert_change(&mut self, reason: RevertReason) {
        let Some(window) = self.verification.take() else {
            return;
        };

        let outcome = window
            .revert()
            .apply(self.executor.as_ref(), self.backend.as_ref());

        match outcome {
            Ok(()) => self.status.set(
                State::Done,
                self.lang.render(&Msg::StatusReverted {
                    task: window.task.clone(),
                    reason,
                }),
            ),
            // The revert's own failure is rendered through the catalogue like
            // any other error, and interpolated into the line naming the task:
            // what failed is the restore, and the operator needs both halves.
            Err(ref err) => self.status.set(
                State::Failed,
                self.lang.render(&Msg::StatusRevertFailed {
                    task: window.task.clone(),
                    error: self.lang.render(&err.to_msg()),
                }),
            ),
        }
    }
    /// Puts an unconfirmed change back because the session is ending.
    ///
    /// This is the case the verification window exists for rather than an edge
    /// of it: `ssh.harden` and its neighbours can sever the very session that
    /// would confirm them, and the daemon answers a dropped connection with
    /// `SIGHUP`. Without this the countdown dies with the process and the
    /// configuration that locked the administrator out is the one left behind
    /// — the interface having promised on screen that silence puts it back.
    ///
    /// Silence is still what decides. Losing the session is not confirmation,
    /// so the change goes back for the same reason a lapsed window does, and
    /// the operator finds the machine as they left it.
    pub(super) fn resolve_on_hangup(&mut self) {
        if self.verification.is_some() {
            self.revert_change(RevertReason::SessionEnded);
        }
    }
    /// Puts the change back if its window has run out.
    ///
    /// Called from the event loop rather than driven by a key, because the
    /// whole point is that it happens when nobody is pressing anything.
    pub(super) fn expire_verification(&mut self) {
        let expired = self
            .verification
            .as_ref()
            .is_some_and(|window| window.has_expired(Instant::now()));

        if expired {
            self.revert_change(RevertReason::NoConfirmation);
        }
    }
}
