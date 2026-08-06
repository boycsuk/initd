//! Which key does what, and in which state.
//!
//! One entry point — [`App::on_key`] — over a tree of handlers, one per state
//! the interface can be in. `dispatch` reads the current [`Mode`] and hands the
//! key to exactly one of them, which is what keeps "a form swallows the keys
//! that are commands elsewhere" a property of one match rather than a rule
//! every handler has to remember.
//!
//! Separated from `app.rs` for navigation rather than for independence. This is
//! the group that reaches furthest into `App` — fourteen of its twenty fields —
//! so the file boundary does not buy any decoupling. It buys a reader who wants
//! to know what `Esc` does somewhere to look in one place.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;

use super::app::{App, Mode, Pane};
use super::app::{HELP_PAGE, PAGE_SCROLL};
use super::confirm::Confirm;
use super::field::Field;
use super::form::Form;
use super::help;
use super::search::Search;
use super::status::State;
use crate::i18n::{Msg, RevertReason};
use crate::tasks::Node;
use crate::tasks::params::ParamValues;

impl App {
    /// Handles a key press, routing to whichever dialog is open.
    ///
    /// Modal dialogs are checked first and swallow everything: inside a form,
    /// `j`, `k`, `/` and `q` are literal characters, not commands.
    /// No key needs the terminal any more: starting a task hands it to a
    /// thread rather than to a child process, so the whole path is testable.
    pub(super) fn on_key(&mut self, key: KeyEvent) {
        if let Some(values) = self.dispatch(key) {
            self.run_selected(values);
        }
    }
    /// Routes a key press, returning the values to run the selected task with.
    ///
    /// `Some` means the key was the one that starts the work; everything else
    /// is resolved in place.
    pub(super) fn dispatch(&mut self, key: KeyEvent) -> Option<ParamValues> {
        // The one place precedence is decided is `mode`; this only says what
        // each state does with a key. A state added there fails to compile
        // here until it is answered for, which is the point of deriving it.
        match self.mode() {
            Mode::Help => {
                self.on_help_key(key);
                None
            }
            // While a task runs the interface stays open — scrolling,
            // switching panes and reading all work — but nothing new may be
            // started and nothing may be answered. Only one task at a time,
            // and the keys that would start another are refused rather than
            // queued.
            Mode::Running => {
                self.on_running_key(key);
                None
            }
            // Semi-modal: reading is never blocked while a change is
            // unverified, but nothing new may be started until it is settled.
            Mode::Verifying => {
                self.on_verify_key(key);
                None
            }
            Mode::Filling => self.on_form_key(key),
            Mode::Confirming(_) => self.on_confirm_key(key),
            Mode::Searching(_) => {
                self.on_search_key(key);
                None
            }
            Mode::Browsing => {
                if self.on_navigation_key(key) {
                    return None;
                }

                if key.code == KeyCode::Enter && self.focus == Pane::Tree {
                    return self.activate();
                }

                None
            }
        }
    }
    /// Handles the keys that only move around, reporting whether one matched.
    ///
    /// Running a task is deliberately not here: it needs the terminal handed
    /// to a child process, and keeping that out of the navigation path is what
    /// lets every key below be exercised without one.
    fn on_navigation_key(&mut self, key: KeyEvent) -> bool {
        // Keys that mean the same thing whichever pane holds focus.
        match key.code {
            // `q` quits from any level; `Esc` means "go back", so that leaving
            // one level too many cannot drop the user out of the program.
            KeyCode::Char('q') => {
                self.should_quit = true;
                return true;
            }
            // Available from anywhere, since the moment someone needs the key
            // list is the moment they do not know which key to press.
            KeyCode::Char('?') => {
                self.help = Some(0);
                return true;
            }
            // Twenty-eight tasks across six areas is past what anybody keeps a
            // map of, and drilling down one level at a time answers "what is
            // in here" rather than "where is it".
            KeyCode::Char('/') => {
                self.search = Some(Search::new(self.cursor.tree()));
                return true;
            }
            // The only focus key. Overloading a movement key with focus is how
            // keys start leaking between panes.
            KeyCode::Tab => {
                self.focus = self.focus.other();
                return true;
            }
            _ => {}
        }

        match self.focus {
            Pane::Tree => self.on_tree_key(key),
            Pane::Output => self.on_output_key(key),
        }
    }
    /// Handles a movement key while the tree holds focus.
    ///
    /// `Enter` is not here: it runs a task, which needs the terminal.
    fn on_tree_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.leave_category();
            }
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous(),
            KeyCode::Char('g') => self.select_first(),
            KeyCode::Char('G') => self.select_last(),
            _ => return false,
        }

        true
    }
    /// Handles a key press while the output pane holds focus.
    ///
    /// Reading is never blocked, so these stay available while a task runs.
    fn on_output_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.output.scroll_down(1),
            KeyCode::Up | KeyCode::Char('k') => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            KeyCode::Char('g') => self.output.scroll_up(usize::MAX),
            // `G` and `f` both re-attach to the tail: one is the counterpart
            // of scrolling away, the other names what it does.
            KeyCode::Char('G' | 'f') => self.output.scroll_to_tail(),
            KeyCode::Char('w') => self.output.toggle_wrap(),
            KeyCode::Esc => self.focus = Pane::Tree,
            _ => return false,
        }

        true
    }
    /// Handles a key press while a task is running.
    ///
    /// Reading is never blocked — the log of what is happening is the reason
    /// to be watching — but every key that would change something is refused.
    fn on_running_key(&mut self, key: KeyEvent) {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Char('c') if control => self.cancel_running(),
            KeyCode::Tab => self.focus = self.focus.other(),
            KeyCode::Char('?') => self.help = Some(0),
            KeyCode::Down | KeyCode::Char('j') => self.output.scroll_down(1),
            KeyCode::Up | KeyCode::Char('k') => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            KeyCode::Char('G' | 'f') => self.output.scroll_to_tail(),
            KeyCode::Char('w') => self.output.toggle_wrap(),
            // Quitting mid-task is how a server ends up half-configured, so it
            // is refused with the way to actually stop.
            KeyCode::Char('q') => self.status.flash(
                self.lang.render(&Msg::StatusTaskRunningQuitRefused),
                Instant::now(),
            ),
            _ => self.status.flash(
                self.lang.render(&Msg::StatusTaskAlreadyRunning),
                Instant::now(),
            ),
        }
    }
    /// Asks the running task to stop at its next step boundary.
    pub(super) fn cancel_running(&mut self) {
        let Some(running) = self.running.as_mut() else {
            return;
        };

        if running.is_cancelling() {
            self.status.flash(
                self.lang.render(&Msg::StatusAlreadyStopping),
                Instant::now(),
            );
            return;
        }

        running.cancel();
        // Not "cancelled": the task has been asked to stop and has not yet
        // done so. Saying otherwise before the step finishes would be a lie
        // about what state the machine is in.
        self.status.set(
            State::Running,
            self.lang.render(&Msg::StatusStoppingAfterCurrentStep),
        );
    }
    /// Handles a key press while the help overlay is showing.
    ///
    /// The movement keys scroll it; everything else closes it, including the
    /// key that opened it. An overlay that has to be dismissed a particular
    /// way traps whoever opened it by accident.
    fn on_help_key(&mut self, key: KeyEvent) {
        let Some(scroll) = self.help else {
            return;
        };

        // The frame is not known here, so the clamp uses the reference size;
        // `render` clamps again against the real one.
        let limit = help::max_scroll(Rect::new(0, 0, 80, 24), self.lang);

        self.help = match key.code {
            KeyCode::Down | KeyCode::Char('j') => Some(scroll.saturating_add(1).min(limit)),
            KeyCode::Up | KeyCode::Char('k') => Some(scroll.saturating_sub(1)),
            KeyCode::PageDown => Some(scroll.saturating_add(HELP_PAGE).min(limit)),
            KeyCode::PageUp => Some(scroll.saturating_sub(HELP_PAGE)),
            KeyCode::Home | KeyCode::Char('g') => Some(0),
            KeyCode::End | KeyCode::Char('G') => Some(limit),
            _ => None,
        };
    }
    /// Handles a key press while a change is applied but not yet kept.
    ///
    /// `K` and `R` are uppercase deliberately: lowercase `k` is "move up"
    /// everywhere else in this interface, and this is the one place where a
    /// mistyped navigation key would do something unrecoverable. Scrolling
    /// stays available, because reading the log of what just happened is
    /// exactly what the administrator needs in order to decide.
    fn on_verify_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('K') => self.keep_change(),
            KeyCode::Char('R') => self.revert_change(RevertReason::Requested),
            KeyCode::Down | KeyCode::Char('j') => self.output.scroll_down(1),
            KeyCode::Up => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            // Every other key is refused rather than ignored: an unanswered
            // window is the one state where doing nothing has consequences.
            _ => self
                .status
                .flash(self.lang.render(&Msg::StatusVerifyKeysOnly), Instant::now()),
        }
    }
    /// Handles a key press while the search is open.
    ///
    /// Every printable character is literal, as in a form: a query naming a
    /// task id contains `.` and `-`, and a `/` typed a second time belongs in
    /// the query rather than reopening what is already open.
    fn on_search_key(&mut self, key: KeyEvent) {
        let Some(search) = self.search.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => {
                self.search = None;
                self.status.set(State::Ready, "");
            }
            KeyCode::Enter => self.jump_to_selected_match(),
            KeyCode::Down => search.select_next(),
            KeyCode::Up => search.select_previous(),
            // Closing on a backspace that has nothing left to delete: the
            // query is empty, so the operator is undoing having opened it.
            KeyCode::Backspace if !search.backspace(self.cursor.tree()) => {
                self.search = None;
                self.status.set(State::Ready, "");
            }
            KeyCode::Backspace => {}
            KeyCode::Char(character) => search.push(character, self.cursor.tree()),
            _ => {}
        }
    }
    /// Moves the tree cursor onto the selected match and closes the search.
    ///
    /// Navigates rather than running. The task under the cursor is then
    /// started with `Enter` like any other, so a search result goes through
    /// the same confirmation and the same parameter form — a path that skipped
    /// either would make a mistyped query the most dangerous key in the
    /// interface.
    fn jump_to_selected_match(&mut self) {
        let Some(found) = self.search.as_ref().and_then(Search::selected_match) else {
            return;
        };

        self.cursor
            .jump_to(&found.location.path, found.location.index);
        self.focus = Pane::Tree;
        self.search = None;
        self.status.set(State::Ready, "");
    }
    /// Handles a key press while the parameter form is open.
    ///
    /// Every printable character is literal here. Only `Tab`, `Enter`, `Esc`,
    /// the arrows and the `Ctrl-*` bindings stay commands.
    fn on_form_key(&mut self, key: KeyEvent) -> Option<ParamValues> {
        let form = self.form.as_mut()?;
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Esc => {
                // Discarding a form with work in it on a single keystroke is
                // how typed values get lost; an untouched one has nothing to
                // lose, so it closes outright.
                if form.is_untouched() || form.cancel_armed() {
                    self.form = None;
                    self.status
                        .set(State::Ready, self.lang.render(&Msg::StatusCancelled));
                } else {
                    form.arm_cancel();
                    self.status.flash(
                        self.lang.render(&Msg::StatusPressEscAgainToDiscard),
                        Instant::now(),
                    );
                }

                return None;
            }
            // Any other key means the operator carried on, so a stale "press
            // Esc again" cannot be answered several actions later.
            _ => form.disarm_cancel(),
        }

        // Keys that move between fields act on the form; the rest act on
        // whichever field has focus. Resolving which of the two a key means
        // before touching either keeps the focus guard in one place instead of
        // repeated around every editing key.
        let edit: fn(&mut Field) = match key.code {
            KeyCode::Tab | KeyCode::Down => {
                form.focus_next();
                return None;
            }
            KeyCode::BackTab | KeyCode::Up => {
                form.focus_previous();
                return None;
            }
            KeyCode::Enter => return self.submit_form(),
            // Readline's bindings win inside a text field.
            KeyCode::Char('u') if control => Field::clear_before_cursor,
            KeyCode::Char('k') if control => Field::clear_after_cursor,
            KeyCode::Char('w') if control => Field::delete_word,
            KeyCode::Char('a') if control => Field::home,
            KeyCode::Char('e') if control => Field::end,
            KeyCode::Char(character) if !control => {
                if let Some(field) = form.focused_mut() {
                    field.insert(character);
                }

                return None;
            }
            KeyCode::Backspace => Field::backspace,
            KeyCode::Delete => Field::delete,
            KeyCode::Left => Field::left,
            KeyCode::Right => Field::right,
            KeyCode::Home => Field::home,
            KeyCode::End => Field::end,
            _ => return None,
        };

        if let Some(field) = form.focused_mut() {
            edit(field);
        }

        None
    }
    /// Submits the form, or moves to the field standing in the way.
    ///
    /// On a field that is not the last, `Enter` advances rather than
    /// submitting: it is the same key that moves through a form everywhere
    /// else, and submitting early would surprise.
    fn submit_form(&mut self) -> Option<ParamValues> {
        let form = self.form.as_mut()?;

        if !form.on_last_field() {
            form.focus_next();
            return None;
        }

        // Pointing at the offending field beats refusing without saying which
        // one is wrong.
        if let Some(index) = form.first_invalid() {
            form.focus_on(index);
            self.status.flash(
                self.lang.render(&Msg::StatusFillEveryFieldFirst),
                Instant::now(),
            );
            return None;
        }

        let values = form.values();
        self.form = None;

        let destructive = self
            .selected_task()
            .is_some_and(crate::tasks::Task::is_destructive);

        if destructive {
            // The values are held for the confirmation to run with once the
            // operator consents.
            self.pending_values = values;
            self.open_confirmation();
            return None;
        }

        Some(values)
    }
    /// Handles a key press while the confirmation dialog is open.
    fn on_confirm_key(&mut self, key: KeyEvent) -> Option<ParamValues> {
        let confirm = self.confirm.as_mut()?;

        match key.code {
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => confirm.toggle(),
            // `n` and `Esc` both mean the safe answer, so the reflex to back
            // out of something lands on it whichever key it reaches for.
            KeyCode::Esc | KeyCode::Char('n' | 'N') => self.cancel_confirmation(),
            KeyCode::Char('y' | 'Y') => return self.accept_confirmation(),
            KeyCode::Enter => {
                if confirm.accepted {
                    return self.accept_confirmation();
                }

                self.cancel_confirmation();
            }
            _ => {}
        }

        None
    }
    /// Closes the dialog and yields the values the task should run with.
    fn accept_confirmation(&mut self) -> Option<ParamValues> {
        self.confirm = None;

        // Collected by the form before this dialog opened.
        Some(std::mem::take(&mut self.pending_values))
    }
    /// Closes the dialog, discarding anything collected for the task.
    fn cancel_confirmation(&mut self) {
        self.confirm = None;
        self.pending_values = ParamValues::new();
        self.status
            .set(State::Ready, self.lang.render(&Msg::StatusCancelled));
    }
    /// Acts on the selected row: descends into a category, or runs a task.
    fn activate(&mut self) -> Option<ParamValues> {
        let index = self.cursor.selected()?;

        if let Some(Node::Category(_)) = self.current_level().get(index) {
            self.enter_category(index);
            return None;
        }

        let task = self.selected_task()?;

        if !task.supports(self.distro.family) {
            // Pressing Enter on a row the host cannot run is a refusal, not a
            // state change: the reason flashes and the tool stays where it was.
            let reason = self.lang.render(&Msg::StatusTaskNotSupported {
                task: task.id().to_owned(),
                family: self.distro.family.to_string(),
            });
            self.status.flash(reason, Instant::now());
            return None;
        }

        // Values first, then consent, then the work: the confirmation states
        // what will happen, and it cannot do that before it knows the values.
        if task.needs_input() {
            self.form = Some(Form::new(task.title(), task.params()));
            return None;
        }

        if task.is_destructive() {
            self.open_confirmation();
            return None;
        }

        Some(ParamValues::new())
    }
    /// Opens the confirmation for the selected task.
    fn open_confirmation(&mut self) {
        let Some(task) = self.selected_task() else {
            return;
        };

        self.confirm = Some(
            Confirm::new(task.title(), task.description())
                .with_warning(self.lang.render(&Msg::ConfirmLockoutWarning)),
        );
    }
}
