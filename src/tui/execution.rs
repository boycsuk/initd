//! Running a task and resolving what it leaves behind.
//!
//! The whole life of a run: starting it, draining what it reports, deciding
//! what its outcome means, and — for a change that can lock the administrator
//! out — opening the window in which it can still be undone.
//!
//! Separated from `app.rs` for navigation rather than for independence. These
//! methods reach nine of `App`'s twenty-seven fields and share seven of them with
//! the key handlers, so the coupling is unchanged; what changes is that the
//! run's own logic is now readable in one place.

use std::time::Instant;

use super::app::App;
use super::auth::AuthRequest;
use super::probe::Probe;
use super::verify::Verification;
use super::worker::{Running, Update};
use crate::backend::backup_index::BackupRecord;
use crate::error::{Error, Result};
use crate::exec::{Emphasis, OutputLine, Stream};
use crate::i18n::Msg;
use crate::tasks;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::{Outcome, Revert};

impl App {
    /// Executes the selected task, streaming its output into the pane.
    pub(super) fn run_selected(&mut self, values: ParamValues) {
        // Through `selected_task` rather than by matching `Node::Task` here.
        // That match accepted a lone task and silently dropped every
        // reversible row — sixteen of them, each the *undo* half of an install
        // — so a confirmed uninstall returned without running, clearing, or
        // reporting anything. Nothing distinguished it from a keypress that
        // never arrived. Which half a shared row means is a question the probe
        // answers, and `probe::task_for` is the one place that answers it:
        // drawing and running resolve through it precisely so a row cannot
        // render one verb and start the other.
        let Some(task) = self.selected_task() else {
            return;
        };

        let id = task.id();

        self.output.clear();

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
        // Dropped rather than left running alongside. The probe is read-only,
        // so nothing would break — but a package manager holds a lock, and an
        // answer measured while an install is half done describes neither the
        // machine before nor the machine after. The refresh when the task
        // finishes is the one that counts.
        self.probe = None;

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
            self.output.push(OutputLine::new(
                Stream::Stderr,
                self.lang.render(&Msg::AuthenticationRequested {
                    mechanism: request.mechanism.clone(),
                }),
            ));

            self.supersede_pending_auth(request);
        }

        let Some(outcome) = outcome else {
            return;
        };

        self.running = None;

        self.finish_run(id, outcome, cancelled);
    }
    /// Puts a recorded state back, reporting what happened either way.
    ///
    /// Done here rather than on the worker thread, unlike every task. A restore
    /// is one file copy and one reload — bounded, quick, and with no output to
    /// stream — where the worker exists for work that can take minutes and has
    /// to stay cancellable. Running it inline also keeps the refusals synchronous,
    /// which is what lets them be reported as the answer to the keypress that
    /// asked rather than arriving a tick later.
    ///
    /// Every outcome reaches the output pane, including the refusals. They are
    /// most of what makes this trustworthy: a restore that silently declined
    /// would be indistinguishable from one that silently succeeded.
    pub(super) fn restore_recorded(&mut self, record: BackupRecord) {
        let path = record.path.clone();

        match (Revert::FromIndex { record }).apply(self.executor.as_ref(), self.backend.as_ref()) {
            Ok(()) => {
                self.output.push(OutputLine::new(
                    Stream::Stdout,
                    self.lang
                        .render(&Msg::HistoryRestored { path: path.clone() }),
                ));
            }
            Err(ref err) => {
                // In fields rather than as one sentence, for the reason this
                // path's own comment already gave: a refusal naming two digests
                // does not fit on a row, and the digests are the evidence.
                let heading = Msg::OutputRevertFailedHeading { task: path };

                self.report_failure(&heading, err);
            }
        }
    }

    /// Takes whatever the probe has measured since the last redraw.
    ///
    /// Separate from [`poll_running`](Self::poll_running) rather than folded
    /// into it: the two report different shapes — a task produces output and
    /// an outcome, a probe produces facts — and a single channel carrying both
    /// would make every arm of the task drain handle a variant that cannot
    /// arrive while a task runs.
    pub(super) fn poll_probe(&mut self) {
        let Some(probe) = self.probe.as_mut() else {
            return;
        };

        for answer in probe.drain() {
            match answer {
                super::probe::Answer::Presence(measurement) => self
                    .presence
                    .record(measurement.forward_id, measurement.presence),
                super::probe::Answer::Readiness(measured) => {
                    self.readiness.record(measured.task_id, measured.readiness)
                }
            }
        }

        // Dropped once it has nothing left to say, so `probe.is_some()` means
        // "a measurement is in flight" rather than "one ran at some point".
        // The refresh after a task reads that distinction.
        if probe.is_finished() {
            self.probe = None;
        }
    }

    /// Re-measures whatever a finished task may have changed.
    ///
    /// Only what it named. Re-probing every pair would put a second of
    /// `fork`/`exec` between a task finishing and its row being readable, on
    /// the machine that just did the work.
    ///
    /// Forgetting first is the load-bearing half: until the new answer lands,
    /// the row falls back to its forward verb rather than showing what was
    /// measured about a machine that no longer exists.
    pub(super) fn refresh_presence_after(&mut self, id: &str) {
        let Some(task) = tasks::find(id) else {
            return;
        };

        // Requirements are re-measured after *every* task, unlike presences,
        // which are re-measured only where the task named a pair. A precondition
        // is a fact about the machine rather than about a row, and the task that
        // satisfies one rarely belongs to the same pair as the task that needs
        // it: `firewall.enable` names no pair that `firewall.manage-ports`
        // belongs to, and it is exactly the run that unblocks it. Keyed off
        // `affects` here, the one requirement in the tree would never update.
        //
        // Forgetting rather than re-measuring inline, for the reason the doc
        // above records: until the new answer lands the row says nothing, which
        // is the honest state — `Unknown` draws no warning.
        self.readiness = super::probe::RequirementState::default();

        let affected = task.affects();

        if affected.is_empty() {
            // Still worth a probe: the requirements were just dropped, and
            // nothing else would ask for them again.
            self.probe = Some(Probe::start(
                self.distro.clone(),
                Vec::new(),
                super::probe::requirements_in(
                    crate::tasks::tree().as_slice(),
                    self.backend.as_ref(),
                ),
            ));

            return;
        }

        let mut subjects = Vec::new();

        for forward_id in affected {
            self.presence.forget(forward_id);

            if let Some(forward) = tasks::find(forward_id)
                && let Some(capability) = forward.subject()
            {
                subjects.push((*forward_id, capability));
            }
        }

        if subjects.is_empty() {
            return;
        }

        // Replaces whatever was in flight. A probe started before this task ran
        // is measuring the machine as it was, so its remaining answers are
        // stale by definition — and the one it is part-way through may be about
        // the very row this task changed.
        self.probe = Some(Probe::start(
            self.distro.clone(),
            subjects,
            super::probe::requirements_in(crate::tasks::tree().as_slice(), self.backend.as_ref()),
        ));
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
        if let Err(ref cancellation @ Error::Cancelled { .. }) = outcome {
            // Into the pane rather than onto the border, for the reason a
            // failure goes there: an outcome is read in the transcript beside
            // the commands that produced it, and the command this task stopped
            // *before* is the whole content of the report.
            //
            // Through `report_failure` rather than three pushes of its own, so
            // the block a stopped task writes cannot drift from the one a failed
            // task writes — `Cancelled`'s single field is `command`, which is
            // what `Error::to_fields` already answers.
            let heading = Msg::OutputCancelledHeading {
                task: id.to_owned(),
            };

            self.report_failure(&heading, cancellation);
            self.output.scroll_to_tail();

            // Falls through to the shared tail rather than returning here. A
            // stopped task held the same password as one that ran to the end,
            // and stopped partway through whatever it was applying — so both
            // obligations below are *more* owed on this path, not less:
            // `forget_secrets` because the value is still in `ran_with`, and
            // `refresh_presence_after` because what the host holds is now
            // exactly what nobody knows.
            self.finish_bookkeeping(id);

            return;
        }

        // Asked to stop, but the task finished first. Reported as whatever it
        // actually was, with the near miss said out loud rather than silently
        // dropped: the operator pressed a key and is owed an answer.
        if cancelled {
            self.output.push(OutputLine::new(
                Stream::Stderr,
                self.lang.render(&Msg::StatusFinishedBeforeItCouldStop),
            ));
        }

        // A change that can sever this session is not reported as done: it is
        // applied, and held open until the administrator proves they can still
        // get in. A failing task is reported in the output pane rather than
        // tearing the interface down — the administrator stays in control.
        match outcome {
            Ok(result) => {
                // Stated before the verification window opens, so what the
                // change invalidated is on screen while there is still an undo
                // available. A failed task invalidates nothing, which is why
                // this sits on the success path only.
                self.report_consequences(id);

                if let Outcome::Revertible(revert) = result {
                    self.begin_verification(id, revert);
                }
            }
            Err(ref err) => {
                // The pane and nothing else. The row is one line and is not
                // truncated with an ellipsis, so a package manager's stderr
                // arriving through `CommandFailed` was cut mid-sentence with no
                // way to see the rest — and the pane is the part an
                // administrator can scroll and paste into a bug report. An
                // outcome belongs in the transcript beside the commands that
                // produced it, not on a border that truncates it.
                self.report_failure(
                    &Msg::OutputFailedHeading {
                        task: id.to_owned(),
                    },
                    err,
                );
            }
        }

        // The outcome is the last thing written, so the pane has to be at its
        // tail for it to be on screen. That is not automatic: a task that
        // narrates a line per account — `users.lock-root` examines twenty-one on
        // a stock `debian:13` — writes more than the pane is tall, so the report
        // lands below the visible rows and the screen shows the middle of the
        // scan. Measured in a container, where the refusal was correct and
        // invisible.
        //
        // This is the one place that overrides the operator's scroll position,
        // and only at the moment a task ends: `scroll_up` deliberately detaches
        // so that reading back is never interrupted by arriving output, but
        // nobody is reading back through a task they are waiting on — they
        // pressed a key and are owed its answer.
        self.output.scroll_to_tail();

        self.finish_bookkeeping(id);
    }

    /// Re-reads what the host holds and drops the secrets the task was given.
    ///
    /// Extracted so every way a task can end reaches it. It used to be the tail
    /// of `finish_run`, which the cancellation path returned before ever
    /// reaching — so a task stopped between two commands left the password it
    /// was handed in `ran_with` for the rest of the session, and left the tree
    /// showing an installed state that its half-applied work had invalidated.
    fn finish_bookkeeping(&mut self, id: &str) {
        // On the failure path deliberately: a task that failed halfway
        // installed the package and then could not enable the unit, so what the
        // host holds is exactly what nobody knows any more. Asking again is the
        // only way to find out, and the alternative — keeping the answer from
        // before it ran — describes a machine that may no longer exist.
        self.refresh_presence_after(id);

        // Outside the successful arm, because a task that failed held the same
        // password and reported nothing that needed it. `ran_with` is kept so
        // the consequences can name what the task invalidated; nothing reads it
        // again until the next task replaces it, so on a host where one account
        // is created and nothing else that is the rest of the session.
        if let Some(task) = tasks::find(id) {
            self.ran_with.forget_secrets(&task.params());
        }
    }
    /// Writes a failure into the output pane, as a heading and its fields.
    ///
    /// The pane rather than the status row, and this is the whole reason the
    /// row no longer names an outcome. A border is one line that ratatui
    /// truncates without an ellipsis, so a `CommandFailed` carrying a package
    /// manager's stderr lost most of it — and the transcript is both the place
    /// with room and the place an administrator can scroll and copy.
    ///
    /// The fields come from [`Error::to_fields`], which returns nothing for a
    /// variant that is a whole sentence with no value in it. Those fall back to
    /// the rendered sentence: a heading over an empty column would report less
    /// than the line it replaced.
    ///
    /// A blank line precedes the heading so the block reads as separate from
    /// the command output above it. Every line is `Stream::Stderr`, which is
    /// what colours it apart from the transcript, and what keeps it in
    /// `transcript()` for the clipboard.
    fn report_failure(&mut self, heading: &Msg, err: &Error) {
        let lang = self.lang;

        self.output
            .push(OutputLine::new(Stream::Stdout, String::new()));
        self.output
            .push(OutputLine::new(Stream::Stderr, lang.render(heading)));

        let fields = err.to_fields();

        if fields.is_empty() {
            self.output
                .push(OutputLine::new(Stream::Stderr, lang.render(&err.to_msg())));

            return;
        }

        for (label, value) in fields {
            self.output.push(OutputLine::new(
                Stream::Stderr,
                lang.render(&Msg::OutputErrorField { label, value }),
            ));
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

        self.output
            .push(OutputLine::new(Stream::Stdout, String::new()));
        self.output.push(OutputLine::new(
            Stream::Stdout,
            lang.render(&Msg::OutputConsequencesHeading),
        ));

        for consequence in consequences {
            // The marker and the colour say the same thing, deliberately. A
            // terminal without colour still distinguishes the two, and a reader
            // scanning a long transcript for what is theirs to chase sees the
            // colour before they read the glyph.
            let (marker, emphasis) = if consequence.is_external() {
                ("⚠", Emphasis::ConsequenceExternal)
            } else {
                ("!", Emphasis::Consequence)
            };

            self.output.push(
                OutputLine::new(
                    Stream::Stdout,
                    format!("  {marker} {}", lang.render(&consequence.message())),
                )
                .emphasised(emphasis),
            );
        }
    }
    /// Opens the window in which an applied change can still be undone.
    pub(super) fn begin_verification(&mut self, task: &str, revert: Revert) {
        self.verification = Some(Verification::new(task, revert, Instant::now()));
    }
    /// Keeps an applied change, closing its window.
    pub(super) fn keep_change(&mut self) {
        self.verification = None;
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
    pub(super) fn revert_change(&mut self) {
        let Some(window) = self.verification.take() else {
            return;
        };

        let outcome = window
            .revert()
            .apply(self.executor.as_ref(), self.backend.as_ref());

        // Into the pane rather than onto a border: the evidence for the worst
        // outcome this tool can reach — the machine in neither state — is
        // exactly the part a one-line border truncated. It is the same report a
        // failed task gets, under a heading that says the restore is what
        // failed.
        if let Err(ref err) = outcome {
            let heading = Msg::OutputRevertFailedHeading {
                task: window.task.clone(),
            };

            self.report_failure(&heading, err);
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
            self.revert_change();
        }

        // A task still running is told to stop, on the same flag `Ctrl-C` sets.
        // This looked at `verification` alone, so a hangup arriving mid-task
        // broke the event loop and returned from `run`, and the process exited
        // with the worker unjoined and the task's next commands still to come.
        //
        // What this does and does not buy is worth being exact about, because
        // the cancellation contract is cooperative by design: the executor
        // refuses the *next* command rather than interrupting the one running,
        // since a task killed mid-command leaves the step it was performing
        // half applied and nothing can say which half. So the command in flight
        // still finishes and the child is not killed. What stops is the task
        // going on to run further privileged commands against a machine whose
        // administrator has just lost the session — which, for a tree of tasks
        // that install packages and rewrite configuration, is the half worth
        // stopping.
        //
        // Left deliberately: the process exits immediately after this, so
        // whether the worker observes the flag is a race this cannot win. The
        // flag is set because it costs nothing and is correct if it is seen.
        if let Some(running) = self.running.as_mut()
            && !running.is_cancelling()
        {
            running.cancel();
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
            self.revert_change();
        }
    }
}
