//! The status line: one authoritative place for what the tool is doing.
//!
//! It rides the bottom border of the pane on the right, the way the tree's
//! census rides its own. That is a change from the full row this used to
//! occupy, and it costs the pill: a word on a filled background cannot sit on
//! a border without painting over it. What the pill carried is carried by
//! [`State::label`] instead, drawn as the first word of the line in the
//! state's colour — so the state is still readable with no colour at all, and
//! still costs nothing but the border it was already drawing.
//!
//! Two kinds of message share the line and must not be confused:
//!
//! - **The state and its message** describe what the tool is doing. They
//!   persist until the state itself changes.
//! - **A transient message** reports a refusal — "unsupported here", "already
//!   at the top level". It overrides the message for a couple of seconds and
//!   then disappears, but it *never* replaces the state's word: the operator
//!   must not lose sight of what the tool is doing because something was
//!   refused.
//!
//! Refusals flash in place rather than opening a toast or an overlay. A
//! message that occludes content is unacceptable when the content is the log
//! of a command running as root.

use std::time::{Duration, Instant};

use ratatui::style::Style;

use super::style;
use crate::i18n::Msg;

/// How long a refusal stays on screen.
///
/// Long enough to read a short sentence, short enough that it is gone before
/// the operator's next keystroke lands.
const TRANSIENT_LIFETIME: Duration = Duration::from_secs(2);

/// What the tool is doing, as a word plus the style that carries its meaning.
///
/// Every state has a word, so the row is readable with no colour at all; the
/// style is redundant reinforcement rather than the signal itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Waiting for input.
    Ready,
    /// A task is running.
    Running,
    /// The last task succeeded.
    Done,
    /// The last task failed.
    Failed,
    /// The last task was cancelled before it finished.
    ///
    /// The operator interrupted a running task with `Ctrl-C`.
    Cancelled,
    /// A change is applied but not yet kept.
    Verify,
    /// A confirmation dialog is open.
    Confirm,
    /// A parameter form is open, collecting input before the task runs.
    Input,
    /// The selected task cannot run on this host.
    Unsupported,
}

impl State {
    /// Whether this state is worth naming on the border.
    ///
    /// `Ready` is not. It is the state the tool is in whenever it is in no
    /// other, so a border reading `READY` for most of a session says only that
    /// the program is running — which the screen already says — and trains the
    /// eye to skip the one place a failure will appear. Every other state
    /// describes something the operator did not already know.
    ///
    /// Ready's *message* is still drawn when it has one: "cancelled" after a
    /// stopped task is the state's own word for what happened, and dropping it
    /// with the label would lose the report rather than a redundancy.
    pub const fn is_worth_naming(self) -> bool {
        !matches!(self, Self::Ready)
    }

    /// The message naming this state, for the catalogue to render.
    ///
    /// Returns a [`Msg`] rather than the word itself, the same seam
    /// `Error::to_msg` and `Consequence::message` use: the state is structured
    /// data and the wording belongs to the locale. That costs the `const` this
    /// was — a rendered message is an owned `String` — and nothing needed it in
    /// a const context.
    pub const fn label(self) -> Msg {
        match self {
            Self::Ready => Msg::PillReady,
            Self::Running => Msg::PillRunning,
            Self::Done => Msg::PillDone,
            Self::Failed => Msg::PillFailed,
            Self::Cancelled => Msg::PillCancelled,
            Self::Verify => Msg::PillVerify,
            Self::Confirm => Msg::PillConfirm,
            Self::Input => Msg::PillInput,
            Self::Unsupported => Msg::PillUnsupported,
        }
    }

    /// The pill's style.
    pub const fn style(self) -> Style {
        match self {
            Self::Ready | Self::Done => style::STATUS_READY,
            // Verifying is busy, not done: the change is applied but the tool
            // is still waiting to be told it worked.
            Self::Running | Self::Verify => style::STATUS_BUSY,
            Self::Failed | Self::Cancelled | Self::Confirm => style::STATUS_ERROR,
            // Collecting input is neither an error nor progress: the tool is
            // waiting on the operator, not on a command.
            Self::Input => style::STATUS_INPUT,
            Self::Unsupported => style::STATUS_INERT,
        }
    }
}

/// The state of the status row between frames.
#[derive(Debug)]
pub struct Status {
    state: State,
    /// What the current state is doing, beside the pill.
    message: String,
    /// A refusal and the moment it was raised.
    transient: Option<(String, Instant)>,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            state: State::Ready,
            message: String::new(),
            transient: None,
        }
    }
}

impl Status {
    pub fn new() -> Self {
        Self::default()
    }

    /// Moves to a new state, clearing any refusal still on screen.
    ///
    /// A refusal describes the state it was raised in; carrying it into the
    /// next one would leave the row describing something that already ended.
    pub fn set(&mut self, state: State, message: impl Into<String>) {
        self.state = state;
        self.message = message.into();
        self.transient = None;
    }

    /// Flashes a refusal without disturbing the state.
    pub fn flash(&mut self, message: impl Into<String>, now: Instant) {
        self.transient = Some((message.into(), now));
    }

    /// The pill for the current state.
    pub const fn state(&self) -> State {
        self.state
    }

    /// What to draw beside the pill, at a given moment.
    ///
    /// A refusal wins while it lives; the state's own message returns once it
    /// expires, without anything having to clear it.
    pub fn message(&self, now: Instant) -> &str {
        match &self.transient {
            Some((text, raised)) if now.duration_since(*raised) < TRANSIENT_LIFETIME => text,
            _ => &self.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    #[test]
    fn starts_ready_with_nothing_to_say() {
        let status = Status::new();

        assert_eq!(status.state(), State::Ready);
        assert_eq!(status.message(Instant::now()), "");
    }

    #[test]
    fn every_state_has_a_word_of_its_own() {
        // The row must be readable with no colour at all, so no two states may
        // share a label and none may be blank.
        let states = [
            State::Ready,
            State::Running,
            State::Done,
            State::Failed,
            State::Cancelled,
            State::Confirm,
            State::Unsupported,
        ];

        let mut labels: Vec<String> = states
            .iter()
            .map(|state| Lang::En.render(&state.label()))
            .collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();

        assert_eq!(labels.len(), count, "two states share a label");
        assert!(
            states
                .iter()
                .all(|state| !Lang::En.render(&state.label()).is_empty())
        );
    }

    #[test]
    fn a_refusal_overrides_the_message_but_not_the_pill() {
        // Losing sight of what the tool is doing because something was refused
        // is exactly what this separation prevents.
        let mut status = Status::new();
        status.set(State::Running, "installing openssh-server");

        let now = Instant::now();
        status.flash("a task is already running", now);

        assert_eq!(status.state(), State::Running, "the pill must survive");
        assert_eq!(status.message(now), "a task is already running");
    }

    #[test]
    fn a_refusal_expires_on_its_own() {
        let mut status = Status::new();
        status.set(State::Ready, "ready");

        let raised = Instant::now();
        status.flash("unsupported here", raised);

        let later = raised + TRANSIENT_LIFETIME;
        assert_eq!(
            status.message(later),
            "ready",
            "the state's message must return with nothing having cleared it"
        );
    }

    #[test]
    fn changing_state_drops_a_refusal_still_on_screen() {
        // A refusal describes the state it was raised in; carrying it forward
        // would leave the row describing something that already ended.
        let mut status = Status::new();
        let now = Instant::now();

        status.flash("already at the top level", now);
        status.set(State::Running, "installing");

        assert_eq!(status.message(now), "installing");
    }

    #[test]
    fn a_failed_state_reads_as_an_error_without_colour() {
        assert_eq!(Lang::En.render(&State::Failed.label()), "FAILED");
        assert_eq!(State::Failed.style(), style::STATUS_ERROR);
    }
}
