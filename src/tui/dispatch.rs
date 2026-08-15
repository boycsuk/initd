//! Which key does what, and in which state.
//!
//! One entry point — [`App::on_key`] — over a tree of handlers, one per state
//! the interface can be in. `dispatch` reads the current [`Mode`] and hands the
//! key to exactly one of them, which is what keeps "a form swallows the keys
//! that are commands elsewhere" a property of one match rather than a rule
//! every handler has to remember.
//!
//! Separated from `app.rs` for navigation rather than for independence. This is
//! the group that reaches furthest into `App` — sixteen of its twenty-seven
//! fields — so the file boundary does not buy any decoupling. It buys a reader
//! who wants to know what `Esc` does somewhere to look in one place.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;

use super::app::{App, Mode, Pane};
use super::app::{HELP_PAGE, PAGE_SCROLL};
use super::clipboard;
use super::confirm::Confirm;
use super::field::Field;
use super::form::Form;
use super::help;
use super::history::History;
use super::ports::{Column, PortTable};
use super::search::Search;
use crate::exec::{OutputLine, Stream};
use crate::i18n::Msg;
use crate::tasks::network::{EnableFirewall, ManagePorts};
use crate::tasks::params::{LiveDefault, ParamKind, ParamValues, Suggestions};
use crate::tasks::ssh::{HardenSsh, HardenSshStrict};
use crate::tasks::users::{Credentials, DeleteUser, Examined, LockRoot, escalated_from};
use crate::tasks::{Confirmation, Node};

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
        // Ahead of the modes because a corrupted screen is not a state this
        // program is in: the modal states swallow every character they are
        // given, and a verification window is no easier to read through kernel
        // output than the tree is. Ctrl+L is the convention htop and nvtop
        // already answer to.
        //
        // The form is the one exception, and it is a real one rather than an
        // oversight: Ctrl+L there opens the list of values the host offers,
        // which `docs/ui.md` documents and which readline's neighbours in that
        // dialog (Ctrl-A, Ctrl-E, Ctrl-U, Ctrl-K, Ctrl-W) make the natural
        // spelling. Taking it globally silently broke that list — caught by
        // the test that presses it to open one. A form also covers the screen
        // it is drawn over, so it is the state least in need of this.
        if key.code == KeyCode::Char('l')
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && !matches!(self.mode(), Mode::Filling)
        {
            self.needs_full_redraw = true;
            return None;
        }

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
            Mode::EditingPorts => self.on_ports_key(key),
            Mode::Confirming(_) => self.on_confirm_key(key),
            Mode::Searching(_) => {
                self.on_search_key(key);
                None
            }
            Mode::Reviewing(_) => {
                self.on_history_key(key);
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
            // Fifty tasks across six areas is past what anybody keeps a
            // map of, and drilling down one level at a time answers "what is
            // in here" rather than "where is it".
            KeyCode::Char('/') => {
                self.search = Some(Search::new(self.cursor.tree()));
                return true;
            }
            // Folds the task's description away, giving the whole pane to the
            // output. The other direction was built first and was the wrong
            // half: hiding the transcript to make room for a description of a
            // task that is already running hides the thing being read.
            //
            // Nothing is discarded either way — the description is regenerated
            // from the selected task on every frame, and the transcript is
            // untouched. The key changes how the pane is divided, not what
            // exists.
            //
            // Focus is left alone, unlike the earlier version: the output keeps
            // being drawn in both states, so the arrows never end up addressing
            // a pane that is not there.
            KeyCode::Char('o') => {
                self.detail_shown = !self.detail_shown;
                return true;
            }
            // `h` is free now that the vim movement keys are gone, and the
            // objection to it went with them: it was the fourth way to leave
            // a category, pressed without looking by anyone navigating with
            // `hjkl`, so a slipped `Shift` would have opened a list that
            // restores configuration files. Nobody presses it by reflex now.
            //
            // Read from the host here rather than kept in step with the file:
            // this process is the only writer, so a copy taken on opening is
            // current for as long as the view is up.
            KeyCode::Char('h') => {
                self.history = Some(History::new(crate::backend::backup_index::read_all(
                    self.executor.as_ref(),
                    self.backend.files(),
                )));
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
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left => {
                self.leave_category();
            }
            // The counterpart to `Left`, and deliberately narrower than
            // `Enter`: it opens a category and does nothing at all on a task.
            //
            // `Enter` on a task starts it — through the form and the
            // confirmation, but it starts it. An arrow is a movement key, and
            // an operator arrowing down a level and overshooting onto a task
            // must not find that the next `Right` began changing the machine.
            // So this moves within the tree or it does nothing; running stays
            // on the key that means "act".
            KeyCode::Right => return self.enter_selected_category(),
            KeyCode::Down => self.select_next(),
            KeyCode::Up => self.select_previous(),
            KeyCode::Home => self.select_first(),
            KeyCode::End => self.select_last(),
            _ => return false,
        }

        true
    }
    /// Handles a key press while the output pane holds focus.
    ///
    /// Reading is never blocked, so these stay available while a task runs.
    ///
    /// The pane does two things and no others: it moves the view, and it hands
    /// the transcript over. Nothing here changes what was run or how it is
    /// laid out — a pane whose only job is to be read has no state worth
    /// giving the operator a key to disturb, and every key that did was one
    /// more binding to remember for no decision it helped make.
    fn on_output_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Down => self.output.scroll_down(1),
            KeyCode::Up => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            KeyCode::Home => self.output.scroll_up(usize::MAX),
            // `f` names what it does, which is what kept it when `G` went:
            // re-attaching to the tail has no arrow of its own, so dropping
            // both would leave scrolling away from the tail one-way.
            KeyCode::End => self.output.scroll_to_tail(),
            // A toggle rather than a second `End`, which is what it was. The
            // pane detaches on any upward scroll, so the state changes without
            // this key — and the bar names whichever half is next, which it
            // could not honestly do while both halves did the same thing.
            //
            // Detaching leaves the view where it is: an operator holding the
            // pane still on a line they are reading wants that line, not a jump
            // to the tail followed by scrolling back.
            KeyCode::Char('f') => self.output.toggle_following(),
            KeyCode::Char('y') => self.copy_output(),
            _ => return false,
        }

        true
    }

    /// Puts the whole transcript on the operator's clipboard.
    ///
    /// The mouse cannot do this: the terminal owns the selection and copies
    /// rectangles of screen, so dragging over the pane takes its border and
    /// the tree's flags, and takes only what the pane was wide enough to draw.
    ///
    /// Only a refusal is reported, and it goes into the pane. Success is
    /// silent: OSC 52 has no reply, so a line claiming the transcript was
    /// copied asserts something this tool cannot observe — and it would land in
    /// the transcript itself, so the next copy would carry the previous one's
    /// receipt into whatever bug report it was pasted into. A refusal is the
    /// half that is both observable and worth acting on.
    fn copy_output(&mut self) {
        if self.output.is_empty() {
            return;
        }

        if clipboard::copy(&self.output.transcript()) {
            return;
        }

        self.output.push(OutputLine::new(
            Stream::Stderr,
            self.lang.render(&Msg::StatusCopyFailed),
        ));
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
            KeyCode::Down => self.output.scroll_down(1),
            KeyCode::Up => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            KeyCode::End => self.output.scroll_to_tail(),
            // A toggle rather than a second `End`, which is what it was. The
            // pane detaches on any upward scroll, so the state changes without
            // this key — and the bar names whichever half is next, which it
            // could not honestly do while both halves did the same thing.
            //
            // Detaching leaves the view where it is: an operator holding the
            // pane still on a line they are reading wants that line, not a jump
            // to the tail followed by scrolling back.
            KeyCode::Char('f') => self.output.toggle_following(),
            // Folding the detail away is if anything more useful here than
            // while browsing: a task's output is the thing being read, and
            // giving it the whole pane is what somebody watching an install
            // wants. The help overlay has always listed `o` under *Running*
            // and `docs/ui.md` lists it as working anywhere, while this arm
            // did not exist — so the key was announced in two places and did
            // nothing, which is the shape of thing that gets reported as the
            // interface having frozen.
            KeyCode::Char('o') => self.detail_shown = !self.detail_shown,
            // Quitting mid-task is how a server ends up half-configured, so it
            // is refused: `Ctrl-C` is the way to actually stop.
            _ => {}
        }
    }
    /// Asks the running task to stop at its next step boundary.
    pub(super) fn cancel_running(&mut self) {
        let Some(running) = self.running.as_mut() else {
            return;
        };

        if running.is_cancelling() {
            return;
        }

        running.cancel();
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
            KeyCode::Down => Some(scroll.saturating_add(1).min(limit)),
            KeyCode::Up => Some(scroll.saturating_sub(1)),
            KeyCode::PageDown => Some(scroll.saturating_add(HELP_PAGE).min(limit)),
            KeyCode::PageUp => Some(scroll.saturating_sub(HELP_PAGE)),
            KeyCode::Home => Some(0),
            KeyCode::End => Some(limit),
            _ => None,
        };
    }
    /// Handles a key press while a change is applied but not yet kept.
    ///
    /// `K` and `R` are uppercase deliberately. They were capitals because `k`
    /// meant "move up" everywhere else, and they stay capitals now that it
    /// means nothing: this is the one window where a key pressed by accident
    /// does something unrecoverable, so it should cost a deliberate `Shift`
    /// rather than a letter that could be a typo. Scrolling stays available,
    /// because reading the log of what just happened is exactly what the
    /// administrator needs in order to decide.
    fn on_verify_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('K') => self.keep_change(),
            KeyCode::Char('R') => self.revert_change(),
            // The overlay draws over this window rather than replacing it, and
            // this is the state that most needs it: the two answers are
            // capitals, an unrecognised key does nothing, and there is a timer
            // running. `mode` has always ranked help above everything for
            // exactly this, and `mode_under_help` exists to keep painting what
            // it covers — but no key here ever set it, so the machinery was
            // built and unreachable from the three states that most need it.
            KeyCode::Char('?') => self.help = Some(0),
            KeyCode::Down => self.output.scroll_down(1),
            KeyCode::Up => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            // Every other key is refused: an unanswered window is the one
            // state where doing nothing has consequences.
            _ => {}
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
            KeyCode::Esc => self.search = None,
            KeyCode::Enter => self.jump_to_selected_match(),
            KeyCode::Down => search.select_next(),
            KeyCode::Up => search.select_previous(),
            // Closing on a backspace that has nothing left to delete: the
            // query is empty, so the operator is undoing having opened it.
            KeyCode::Backspace if !search.backspace(self.cursor.tree()) => {
                self.search = None;
            }
            KeyCode::Backspace => {}
            KeyCode::Char(character) => search.push(character, self.cursor.tree()),
            _ => {}
        }
    }
    /// Handles a key while the recorded changes are being reviewed.
    ///
    /// Movement keys mirror the tree's: an operator does not change how they
    /// move when a different list opens. `Esc` closes having changed nothing,
    /// which is what makes opening this safe to do out of curiosity.
    fn on_history_key(&mut self, key: KeyEvent) {
        let Some(history) = self.history.as_mut() else {
            return;
        };

        match key.code {
            KeyCode::Esc => self.history = None,
            KeyCode::Down => history.select_next(),
            KeyCode::Up => history.select_previous(),
            KeyCode::Home => history.select_first(),
            KeyCode::End => history.select_last(),
            KeyCode::Enter => self.confirm_selected_restore(),
            // Reachable here for the same reason as anywhere else, and with
            // more cause than most: `Enter` in this view puts a configuration
            // file back, and the keys that reach it are stated nowhere inside
            // the view itself.
            KeyCode::Char('?') => self.help = Some(0),
            _ => {}
        }
    }

    /// Asks before putting the selected record back.
    ///
    /// Through the same confirmation every other change goes through, and at
    /// the lockout tier: restoring an `sshd_config` is exactly as able to end
    /// the session as writing one was. A restore reachable on `Enter` alone
    /// would make this the most dangerous list in the interface.
    fn confirm_selected_restore(&mut self) {
        let Some(record) = self.history.as_ref().and_then(History::selected).cloned() else {
            return;
        };

        // Closed first, so the confirmation is not drawn over a list it is
        // about — and so answering `no` returns to the tree rather than to a
        // view whose selection would then be meaningless.
        self.history = None;

        self.pending_restore = Some(record.clone());
        self.confirm = Some(
            Confirm::new(
                self.lang.render(&Msg::ConfirmRestoreTitle {
                    path: record.path.clone(),
                }),
                self.lang.render(&Msg::ConfirmRestoreBody {
                    task: record.task.to_owned(),
                    path: record.path.clone(),
                }),
            )
            .with_warning(self.lang.render(&Msg::ConfirmLockoutWarning)),
        );
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
    }
    /// Handles a key press while the parameter form is open.
    ///
    /// Every printable character is literal here. Only `Tab`, `Enter`, `Esc`,
    /// the arrows and the `Ctrl-*` bindings stay commands.
    fn on_form_key(&mut self, key: KeyEvent) -> Option<ParamValues> {
        // The options list is modal over the form, so it answers first — the
        // same precedence the form itself has over the tree. Without this,
        // `Esc` would close the form underneath an open list.
        if self.options_at.is_some() {
            self.on_options_key(key);
            return None;
        }

        let form = self.form.as_mut()?;
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        match key.code {
            KeyCode::Esc => {
                // Discarding a form with work in it on a single keystroke is
                // how typed values get lost; an untouched one has nothing to
                // lose, so it closes outright.
                if form.is_untouched() || form.cancel_armed() {
                    self.form = None;
                    // The list belongs to a field of this form; leaving it set
                    // would reopen it over the next form that is opened.
                    self.options_at = None;
                } else {
                    form.arm_cancel();
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
        // `↑↓` step through what the host offers where there is anything to
        // step through, and move between fields where there is not. `Tab` and
        // `BackTab` always move between fields, so the navigation the form had
        // before is never the thing that was taken away — a field with options
        // is still left with `Tab`, which the key bar names.
        //
        // Asked of the focused field rather than of the form: two fields of
        // one form differ, and `ssh.allow-users` has a shell-less list beside
        // an account field.
        let offers_options = form
            .focused_mut()
            .is_some_and(|field| !field.options().is_empty());

        let edit: fn(&mut Field) = match key.code {
            // Opens on the option the field already holds, so a list reached
            // from a filled field starts where the operator left it rather
            // than at the top.
            KeyCode::Char('l') if control && offers_options => {
                self.options_at = Some(form.focused_option_position().unwrap_or(0));
                return None;
            }
            KeyCode::Down if offers_options => Field::next_option,
            KeyCode::Up if offers_options => Field::previous_option,
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
    /// Handles a key press while the ports table is open.
    ///
    /// Two layers, because a cell being edited has to swallow letters: `d`
    /// removes a row while navigating and types a letter while editing, and a
    /// handler that could not tell those apart would delete a row every time
    /// somebody typed `udp`.
    fn on_ports_key(&mut self, key: KeyEvent) -> Option<ParamValues> {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        let table = self.ports.as_mut()?;

        // Any key means the operator carried on, so an explanation cannot
        // outlive the keystroke it belonged to.
        if key.code != KeyCode::Esc {
            table.forget_refusal();
        }

        if table.is_editing() {
            let edit: fn(&mut Field) = match key.code {
                // Discards the cell rather than the table: the row was there
                // before the cell was opened, and `Esc` inside an editor means
                // "not this value" everywhere else in this interface.
                KeyCode::Esc => {
                    table.discard_cell();
                    return None;
                }
                KeyCode::Enter => {
                    table.commit_cell();
                    return None;
                }
                KeyCode::Tab => {
                    table.edit_next_cell();
                    return None;
                }
                KeyCode::Down if table.focused_offers_options() => Field::next_option,
                KeyCode::Up if table.focused_offers_options() => Field::previous_option,
                // Readline's bindings win inside a text cell, exactly as they
                // do inside a form's field.
                KeyCode::Char('u') if control => Field::clear_before_cursor,
                KeyCode::Char('k') if control => Field::clear_after_cursor,
                KeyCode::Char('w') if control => Field::delete_word,
                KeyCode::Char('a') if control => Field::home,
                KeyCode::Char('e') if control => Field::end,
                KeyCode::Char(character) if !control => {
                    if let Some(field) = table.editing_field() {
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

            if let Some(field) = table.editing_field() {
                edit(field);
            }

            return None;
        }

        match key.code {
            KeyCode::Esc => {
                // A table nobody edited has nothing to lose and closes
                // outright; one with edits in it asks twice, the way a form
                // with typed values does.
                if table.is_untouched() || table.cancel_armed() {
                    self.ports = None;
                } else {
                    table.arm_cancel();
                }

                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                table.disarm_cancel();
                table.focus_next();
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                table.disarm_cancel();
                table.focus_previous();
                None
            }
            KeyCode::Char('a') => {
                table.disarm_cancel();
                table.add_row();
                None
            }
            KeyCode::Char('d') => {
                table.disarm_cancel();
                table.remove_row();
                None
            }
            KeyCode::Enter => {
                table.disarm_cancel();
                table.edit(Column::Port);
                None
            }
            // `Tab` applies rather than moving, which is the one binding here
            // that disagrees with the form. `Enter` opens what is under the
            // cursor everywhere in this interface — the tree, a category, a
            // field — and taking that away from the table to mean "apply"
            // would be the surprising half of the trade. `Tab` edits text
            // nowhere, so it is free to mean the thing that leaves.
            KeyCode::Tab => self.submit_ports(),
            _ => {
                table.disarm_cancel();
                None
            }
        }
    }

    /// Turns the table into the values the task runs with.
    ///
    /// The mirror of [`submit_form`](Self::submit_form), including pointing at
    /// the row that stopped it rather than refusing without saying which.
    fn submit_ports(&mut self) -> Option<ParamValues> {
        let table = self.ports.as_mut()?;

        if let Some((row, reason)) = table.refuses_to_submit() {
            table.refuse(row, reason);
            return None;
        }

        let mut values = ParamValues::new();
        values.set(ManagePorts::PORTS, table.value());
        // What the host admitted when this opened, so the task can tell a port
        // the operator removed from one that appeared while they decided.
        values.set(ManagePorts::PORTS_WERE, table.opened_on());

        self.ports = None;

        let asks = self
            .selected_task()
            .is_some_and(|task| task.confirmation() != Confirmation::None);

        if asks {
            self.pending_values = values;
            self.open_confirmation();
            return None;
        }

        Some(values)
    }

    /// Moves through the focused field's options, or takes one.
    ///
    /// Nothing is written to the field until `Enter`: moving the cursor here
    /// is reading the list, not answering it, so `Esc` leaves whatever was
    /// typed exactly as it was.
    fn on_options_key(&mut self, key: KeyEvent) {
        let Some(at) = self.options_at else {
            return;
        };

        let Some(form) = self.form.as_mut() else {
            // The list cannot outlive the form it belongs to.
            self.options_at = None;
            return;
        };

        let count = form.focused_option_count();

        if count == 0 {
            self.options_at = None;
            return;
        }

        match key.code {
            // Wrapping, like the tree and the search results: a list that
            // stops at its ends makes the operator reverse to reach what is
            // one press the other way.
            KeyCode::Down => self.options_at = Some((at + 1) % count),
            KeyCode::Up => {
                self.options_at = Some((at + count - 1) % count);
            }
            KeyCode::Home => self.options_at = Some(0),
            KeyCode::End => self.options_at = Some(count - 1),
            KeyCode::Enter => {
                form.take_focused_option(at);
                self.options_at = None;
            }
            KeyCode::Esc => self.options_at = None,
            _ => {}
        }
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
            return None;
        }

        let values = form.values();
        self.form = None;
        self.options_at = None;

        let asks = self
            .selected_task()
            .is_some_and(|task| task.confirmation() != Confirmation::None);

        if asks {
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
            // The warning scrolls where it carries a list — `users.lock-root`
            // names every account that keeps access, and a host with a dozen
            // administrators has more of them than the band can show. Up and
            // down rather than left and right, which already answer the
            // question.
            //
            // `j` and `k` are kept beside them although the tree no longer has
            // them: this dialog can hold more than it shows, a hand already on
            // them loses nothing by their being here, and neither letter means
            // anything else in this state. The comment used to justify them by
            // the tree, which stopped being true when the vim movement keys
            // were retired.
            //
            // `n` is not among these even though `j`/`k` are: it is the safe
            // answer, and a key that sometimes scrolls and sometimes cancels
            // is one nobody presses with confidence.
            KeyCode::Down | KeyCode::Char('j') => confirm.scroll_warning(1),
            KeyCode::Up | KeyCode::Char('k') => confirm.scroll_warning(-1),
            // `n` and `Esc` both mean the safe answer, so the reflex to back
            // out of something lands on it whichever key it reaches for.
            KeyCode::Esc | KeyCode::Char('n' | 'N') => self.cancel_confirmation(),
            // Uppercase only, the rule `K` and `R` already follow in the
            // verification window: the safe answers may be a single keystroke,
            // the one that changes the machine costs a deliberate Shift.
            // Lowercase `y` is also the copy-transcript key on the output pane,
            // so the reflex learned there landed on accept here.
            KeyCode::Char('Y') => return self.accept_confirmation(),
            // Asked for from wherever the operator is stuck — which includes
            // the dialog that is about to change the machine.
            KeyCode::Char('?') => self.help = Some(0),
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

        // A confirmed restore is not a task, so it never reaches the worker:
        // it is one file copy and one reload, done here and reported like any
        // other outcome. Intercepted before the values are yielded, since
        // yielding them would start whatever the tree's cursor happens to be
        // on — a restore confirmed from the history would run an unrelated
        // task, which is the worst thing this path could do.
        if let Some(record) = self.pending_restore.take() {
            // Same reason as in `cancel_confirmation`: these values are
            // abandoned rather than run, so whatever secret they hold has to be
            // overwritten instead of dropped.
            self.forget_pending_secrets();
            self.pending_values = ParamValues::new();
            self.restore_recorded(record);
            return None;
        }

        // Collected by the form before this dialog opened.
        Some(std::mem::take(&mut self.pending_values))
    }
    /// Closes the dialog, discarding anything collected for the task.
    ///
    /// Discarding a password means overwriting it, not dropping it: replacing
    /// `pending_values` would free the old buffer with the typed value intact.
    /// [`finish_bookkeeping`](super::App::finish_bookkeeping) closes the same
    /// hole for a task that *ran*, and `users.create` asks an ordinary
    /// `Confirmation::Change`, so filling the form and answering `n` is a
    /// path an operator takes without anything having gone wrong.
    fn cancel_confirmation(&mut self) {
        self.forget_pending_secrets();
        self.confirm = None;
        self.pending_restore = None;
        self.pending_values = ParamValues::new();
    }

    /// Overwrites any secret held in the values collected but never run.
    ///
    /// The task is the cursor's, which is where the values came from: the form
    /// opens on the selected row and the dialog is answered before it moves.
    fn forget_pending_secrets(&mut self) {
        if let Some(task) = self.selected_task() {
            let params = task.params();
            self.pending_values.forget_secrets(&params);
        }
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
            // state change: the detail pane states the reason and the tool
            // stays where it was.
            return None;
        }

        // A precondition the host is *measured* not to meet refuses here too,
        // and for the same reason the family check does: the detail pane
        // already names the task to run first, so the answer is on screen
        // before the key is pressed and the refusal changes nothing.
        //
        // Without this the row went the whole way — form, values, and the
        // lockout confirmation — before the guard inside `run` refused. Asking
        // an operator for a set of ports and then a red dialog about ending
        // their own session, to arrive at "run firewall.enable first", spends
        // their attention on a decision that was never available.
        //
        // Only `Blocked` refuses. `Unknown` means the check could not be run —
        // the probe has no privilege escalation, so that is an ordinary answer
        // rather than an edge case — and a row that could not be measured must
        // stay pressable: the guard inside `run` is still the barrier, and it
        // asks the host directly.
        if matches!(
            self.readiness.of(task.id()),
            super::probe::Readiness::Blocked { .. }
        ) {
            return None;
        }

        // Values first, then consent, then the work: the confirmation states
        // what will happen, and it cannot do that before it knows the values.
        // `params_here` rather than `params`: a field whose answer this host
        // would ignore is not worth asking for. This replaced a `needs_input`
        // that asked `params` — a task whose only field is filtered out here
        // needs no form at all, and an empty one would put a dialog with
        // nothing in it between the operator and the confirmation.
        let mut asked = task.params_here(self.backend.as_ref());

        // Before the form is built rather than after: a field takes its value
        // from `param.initial` when it is constructed, so replacing it here is
        // what makes the field *open* on the host's answer instead of being
        // overwritten a moment later.
        //
        // `firewall.enable` is why this exists. Its port field keeps the
        // operator's own session alive through a default-deny policy, and it
        // offered a compiled-in `22` to do that — so on a host whose SSH had
        // been moved, accepting the default admitted a port nothing listens on
        // and closed the one carrying the session. The field meant to prevent a
        // lockout was the thing causing it.
        for param in &mut asked {
            let Some(live) = param.live_default else {
                continue;
            };

            param.initial = match live {
                LiveDefault::SshPort => crate::tasks::sshd_config::effective_port(
                    self.executor.as_ref(),
                    self.backend.path_for(crate::backend::Capability::Ssh),
                )
                .to_string(),
                // The set the operator is about to edit starts as what the host
                // holds, so removing a row is the only way a port closes.
                //
                // A ruleset that could not be read stops this rather than
                // seeding the field with the empty set, which in a declarative
                // field means "close everything". The port *table* refuses for
                // the same reason a few lines below; this is the text field the
                // same value reaches on a task asking for it that way.
                LiveDefault::OpenPorts => {
                    let Ok(open) = crate::tasks::network::open_ports_value(
                        self.executor.as_ref(),
                        self.backend.as_ref(),
                    ) else {
                        self.output.push(OutputLine::new(
                            Stream::Stderr,
                            self.lang.render(&Msg::FirewallStateUnreadable),
                        ));

                        return None;
                    };

                    open
                }
            };
        }

        // A parameter holding a set of ports is collected in a table rather
        // than a text field. Keyed off the *kind* rather than the task id: a
        // field that declares a list wants a list, and the interface should
        // not have to be told which tasks those are.
        if asked.iter().any(|param| param.kind == ParamKind::PortList) {
            // Refused rather than opened empty. The table is *declarative* — a
            // row absent from it is a port asked to be closed — so a listing
            // that failed to read would be confirmed as "admit nothing", and
            // the port carrying the operator's own session is the likeliest
            // row missing from it.
            //
            // The unreadable case is the ordinary one rather than an edge:
            // `nft list` needs root, this executor may not prompt, and the
            // startup timestamp lapses while the session stays open. So the
            // message says how to get it back.
            let Some(admitted) = self.readable_admitted_ports() else {
                self.output.push(OutputLine::new(
                    Stream::Stderr,
                    self.lang.render(&Msg::FirewallStateUnreadable),
                ));

                return None;
            };

            self.ports = Some(PortTable::new(task.title(), &admitted));
            return None;
        }

        if !asked.is_empty() {
            let mut form = Form::new(task.title(), asked);
            self.offer_what_the_host_knows(&mut form);
            self.form = Some(form);
            return None;
        }

        if task.confirmation() != Confirmation::None {
            self.open_confirmation();
            return None;
        }

        Some(ParamValues::new())
    }

    /// What the host admits inbound, for the table to open on.
    ///
    /// Read here rather than in the table, and once rather than per keystroke:
    /// this is a command, and putting the executor in the path of an arrow
    /// press is the thing `offer_what_the_host_knows` exists to avoid.
    ///
    /// The rows carry their origin, which the parameter's own live default
    /// cannot: `open_ports_value` answers with specs because that is what a
    /// text field holds, and the table needs to know which rows it must refuse
    /// to remove.
    ///
    /// An empty answer where nothing can be read, for the same reason the
    /// suggestions are dropped rather than raised: the task refuses on its own
    /// terms with a better message than a dialog that would not open.
    /// The ports this host admits, or `None` where the ruleset could not be
    /// read.
    ///
    /// The distinction this returns used to be collapsed into an empty `Vec`,
    /// and the two halves call for opposite things. An empty list is a firewall
    /// admitting nothing; `None` is a firewall nobody could ask — `nft list`
    /// needs root, and this executor may not prompt for it. Rendered
    /// identically, the second reads as the first: on a host admitting SSH the
    /// table opened with no SSH row and no sign that anything had failed, which
    /// in a declarative table is a confirmation away from closing it.
    fn readable_admitted_ports(&self) -> Option<Vec<crate::domain::firewall::AllowedPort>> {
        let firewall =
            crate::backend::firewall_for(self.backend.as_ref(), self.executor.as_ref()).ok()??;

        firewall
            .state(self.executor.as_ref())
            .ok()
            .map(|state| state.allowed)
    }

    /// Fills each field with what the host says it could hold.
    ///
    /// Resolved once here rather than per keystroke: each answer is a command,
    /// and running `cat /etc/passwd` on every arrow press would put the
    /// executor in the path of a keystroke.
    ///
    /// Asked once per kind, not once per field. `ssh.allow-users` has two
    /// account fields, and the passwd database does not change between them.
    ///
    /// A failure is dropped rather than raised. These are suggestions: a host
    /// whose `/etc/shells` cannot be read is a host where the operator types
    /// the shell, which is what they did before there was anything to offer.
    /// Refusing to open the form over it would turn a convenience into a
    /// prerequisite.
    fn offer_what_the_host_knows(&mut self, form: &mut Form) {
        let mut accounts: Option<Vec<String>> = None;
        let mut shells: Option<Vec<String>> = None;

        for field in form.fields_mut() {
            // Read before the suggestions and independently of them: a field
            // whose value must *not* exist is offered nothing and still has to
            // know the accounts in order to refuse them, which is the case
            // this whole check exists for.
            if field.param.existence.is_some() {
                let known = accounts.get_or_insert_with(|| {
                    self.backend
                        .accounts()
                        .list(self.executor.as_ref())
                        .unwrap_or_default()
                });

                field.knows_accounts(known.clone());
            }

            let Some(source) = field.param.suggestions else {
                continue;
            };

            let options = match source {
                Suggestions::Accounts => accounts.get_or_insert_with(|| {
                    self.backend
                        .accounts()
                        .list(self.executor.as_ref())
                        .unwrap_or_default()
                }),
                Suggestions::Shells => shells.get_or_insert_with(|| {
                    self.backend
                        .account_writer()
                        .valid_shells(self.executor.as_ref())
                        .unwrap_or_default()
                }),
                // The one source that asks the host nothing: the releases are
                // compiled in, because the digest that makes a download
                // trustworthy has to be. Offered in declaration order, which is
                // newest first, so the field opens on the most recent version
                // this build can actually verify.
                Suggestions::Releases(releases) => {
                    field.offer(releases.iter().map(|r| r.version.to_owned()).collect());

                    continue;
                }
                // Compiled in like the releases, and for a stronger reason:
                // these are not what the host happens to hold but every value
                // the validator will accept, so there is nothing to ask it.
                Suggestions::Fixed(values) => {
                    field.offer(values.iter().map(|value| (*value).to_owned()).collect());

                    continue;
                }
            };

            field.offer(options.clone());
        }
    }

    /// Opens the confirmation for the selected task.
    ///
    /// `users.lock-root` states its own warning, because it is the only task
    /// with two accounts in play: the form collected the one that *survives*,
    /// and the generic warning would leave the operator's last look at an
    /// irreversible operation without either name on it.
    fn open_confirmation(&mut self) {
        let Some(task) = self.selected_task() else {
            return;
        };

        let confirm = Confirm::new(task.title(), task.description());

        // A warning only where one is true. Every task that writes asks now,
        // and attaching the lockout sentence to all of them would put "this
        // can lock you out of a server you reach over SSH" under installing a
        // shell — which is how a warning stops being read by the time it
        // reaches the task that means it.
        self.confirm = Some(match task.confirmation() {
            Confirmation::Lockout => {
                let warning = match task.id() {
                    LockRoot::ID => self.lockout_warning(),
                    DeleteUser::ID => self.deletion_warning(),
                    EnableFirewall::ID => self.firewall_warning(),
                    ManagePorts::ID => self.ports_warning(),
                    HardenSsh::ID => self.ssh_harden_warning(true),
                    HardenSshStrict::ID => self.ssh_harden_warning(false),
                    _ => self.lang.render(&Msg::ConfirmLockoutWarning),
                };

                confirm.with_warning(warning)
            }
            Confirmation::Change | Confirmation::None => confirm,
        });
    }

    /// Shows which accounts survive locking root, rather than asking for one.
    ///
    /// The second warning here that runs commands, and by far the more
    /// expensive: it scans every account on the host — 17 privileged commands
    /// on a stock `debian:13`, measured — where `deletion_warning` spends two.
    /// Paid at the
    /// moment the dialog opens rather than in the path of a keystroke, which is
    /// the rule that warning already follows, and paid at all because the
    /// alternative was asking the operator to type a name the machine already
    /// knew.
    ///
    /// Listing every account that passes rather than the first is what the
    /// scan exists for: the operator's decision is whether *their* account is
    /// among them, which a list of one cannot answer.
    ///
    /// A scan that cannot run falls back to the generic warning rather than to
    /// silence or to a claim. The task runs the same scan again and refuses on
    /// its own terms, which is a better place to fail than a dialog.
    pub(super) fn lockout_warning(&self) -> String {
        // Which direction the row is about, asked here because here it *can*
        // be asked: a dialog is a point of interaction, so this may escalate
        // where the probe thread drawing the tree may not. `/etc/shadow` is
        // mode `640` and answers nothing to anyone else.
        //
        // Three outcomes rather than two, and the third is the one that made
        // the single row workable. A state that could not be read is not
        // guessed at: proposing the forward direction on a failed read is how
        // an operator is offered a lock over a root already locked, and that
        // mistake is recovered through the hosting provider's rescue console.
        match self
            .backend
            .account_writer()
            .is_locked(self.executor.as_ref(), crate::tasks::users::ROOT)
        {
            Ok(true) => return self.lang.render(&Msg::ConfirmRootUnlock),
            Ok(false) => {}
            Err(_) => return self.lang.render(&Msg::ConfirmRootStateUnreadable),
        }

        let Ok(examined) = LockRoot::verify_a_way_back_in(
            self.executor.as_ref(),
            self.backend.as_ref(),
            &mut |_| {},
        ) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        let keeping: Vec<&Examined> = examined
            .iter()
            .filter(|account| account.keeps_access())
            .collect();

        let mut lines = vec![self.lang.render(&Msg::ConfirmRootLockout {
            keeping: keeping.len(),
        })];

        lines.extend(keeping.iter().filter_map(|account| {
            let Ok(Credentials { key, password }) = account.verdict else {
                return None;
            };

            Some(self.lang.render(&Msg::ConfirmKeepsAccess {
                user: account.user.clone(),
                key,
                password,
            }))
        }));

        // Only where nothing answers. `SUDO_USER` and `DOAS_USER` are the only
        // things that say who escalated into this session — every command
        // describes the process, which by then is root — and they are set by
        // the subject itself, so this is a warning and never a refusal.
        // Refusing on an unanswerable question would leave the provider's
        // rescue console, which arrives as root directly, unable to run the one
        // task it is there for.
        if escalated_from().is_none() {
            lines.push(self.lang.render(&Msg::ConfirmSessionAccountUnknown));
        }

        lines.join("\n")
    }

    /// States what deleting this account destroys, in the terms it destroys it.
    ///
    /// The one warning here that runs commands. Every other one is written
    /// from what the form already collected; this one needs the *host* — where
    /// the account's home is, and how much is in it — because the generic
    /// sentence would ask about "the home directory" and be answered by habit.
    ///
    /// Measured when the dialog opens rather than while the form is typed,
    /// which is the same rule `offer_what_the_host_knows` follows one step
    /// earlier: two commands at a deliberate moment, none in the path of a
    /// keystroke.
    ///
    /// A path that cannot be measured says so instead of reporting zero. An
    /// unreadable directory and an empty one are different facts, and "(0 B)"
    /// understates the stake by exactly the amount that matters.
    /// Names the port about to be the only one admitted, and what that means
    /// for a session reaching this host over SSH.
    ///
    /// The generic lockout sentence — "this can lock you out, make sure you
    /// have another way in" — is true here and useless: it says nothing about
    /// *which* port decides, and this dialog is the last place the operator can
    /// still change it. Reported as a task asking for a port with no stated
    /// reason, which the field's own hint answers in six words and the dialog
    /// has room to answer properly.
    ///
    /// The port comes from what was just typed rather than from the host, on
    /// purpose: the value being confirmed is the one that will be applied, and
    /// a warning quoting anything else would describe a different operation.
    pub(super) fn firewall_warning(&self) -> String {
        let Ok(port) = self.pending_values.port(EnableFirewall::SSH_PORT) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        // What the daemon is actually serving, so the warning can say whether
        // the two agree. A mismatch is the case that ends the session, and it
        // is invisible to an operator who has not thought about it.
        let listening = crate::tasks::sshd_config::effective_port(
            self.executor.as_ref(),
            self.backend.path_for(crate::backend::Capability::Ssh),
        );

        self.lang.render(&Msg::ConfirmFirewallLockout {
            port,
            listening,
            agrees: port == listening,
        })
    }

    /// Names the ports about to close, and says whether SSH is one of them.
    ///
    /// The inverse of the question [`firewall_warning`](Self::firewall_warning)
    /// asks. There the operator named one port to keep and the risk was naming
    /// the wrong one; here they left a row out of a table, and the row they
    /// left out may be the one carrying this session. Nothing about deleting a
    /// row announces that, which is why the dialog says it instead.
    ///
    /// Computed from the two parameters rather than by asking the host what is
    /// open: the difference between them *is* what will close, and the table
    /// that produced them was itself read from the host a moment ago. The one
    /// command spent here is the same one `firewall_warning` spends, for the
    /// same reason — the daemon's own port is the fact that decides.
    pub(super) fn ports_warning(&self) -> String {
        let (Ok(declared), Ok(were)) = (
            self.pending_values.get(ManagePorts::PORTS),
            self.pending_values.get(ManagePorts::PORTS_WERE),
        ) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        let declared: Vec<&str> = declared.split_whitespace().collect();

        let closing: Vec<&str> = were
            .split_whitespace()
            .filter(|spec| !declared.contains(spec))
            .collect();

        let opening = declared
            .iter()
            .filter(|spec| !were.split_whitespace().any(|was| was == **spec))
            .count();

        // Still framed as a lockout even when nothing closes: the tier belongs
        // to the task rather than to the values. But the sentence says plainly
        // that nothing is being closed, because a red frame over a batch that
        // only opens ports is how the warnings beside it stop being read.
        if closing.is_empty() {
            return self.lang.render(&Msg::ConfirmPortsOpeningOnly { opening });
        }

        let listening = crate::tasks::sshd_config::effective_port(
            self.executor.as_ref(),
            self.backend.path_for(crate::backend::Capability::Ssh),
        );

        // Matched on the port rather than on the whole spec: sshd serves TCP,
        // and a `22/udp` in the closing set is not the session's.
        let ssh = closing.iter().any(|spec| {
            spec.split_once('/')
                .is_some_and(|(port, protocol)| protocol == "tcp" && port == listening.to_string())
        });

        self.lang.render(&Msg::ConfirmPortsClosing {
            specs: closing.join(", "),
            listening,
            closes_ssh: ssh,
        })
    }

    /// Lists the accounts that still get in once the hardening is applied.
    ///
    /// The dialog runs the same scan the task does, so the operator sees the
    /// set the guard will judge them by rather than a claim about it. Paid at
    /// the moment the dialog opens rather than in the path of a keystroke,
    /// which is the rule `lockout_warning` and `deletion_warning` already
    /// follow — and cheaper than either, at one passwd lookup and one file read
    /// per account.
    ///
    /// `disables_root` is the tier: the safe one writes `PermitRootLogin no`,
    /// so it both excludes root from the scan and says so in the warning.
    ///
    /// Falls back to the generic warning where anything cannot be read, rather
    /// than to silence or to a claim. The task runs the same scan again and
    /// refuses on its own terms, which is a better place to fail than a dialog.
    pub(super) fn ssh_harden_warning(&self, disables_root: bool) -> String {
        let executor = self.executor.as_ref();
        let path = self.backend.path_for(crate::backend::Capability::Ssh);

        let Ok(contents) = self.backend.files().read(executor, path) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        let Ok(holders) = crate::tasks::ssh::accounts_keeping_ssh_access(
            executor,
            self.backend.as_ref(),
            &contents,
            disables_root,
        ) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        let keeps = crate::tasks::ssh::keeps_access(&holders);

        // Nothing to list means the task is about to refuse. Saying so here
        // would be a second wording of a refusal the task states better, and
        // promising a list this dialog cannot produce is worse than the generic
        // sentence, which is at least true.
        if keeps.is_empty() {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        }

        self.lang.render(&Msg::ConfirmSshHardenLockout {
            keeps_access: keeps.join(", "),
            disables_root,
        })
    }

    pub(super) fn deletion_warning(&self) -> String {
        let Ok(user) = self.pending_values.get(DeleteUser::USER) else {
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        let deleting = matches!(
            self.pending_values.get(DeleteUser::HOME),
            Ok(answer) if answer == DeleteUser::DELETE_HOME
        );

        let Ok(path) = self
            .backend
            .accounts()
            .home_dir(self.executor.as_ref(), user)
        else {
            // No path to name, so there is nothing this can say that the
            // generic warning does not. Dropped rather than reported: the
            // account may simply not exist yet, which the task itself refuses
            // with a better message than a dialog could.
            return self.lang.render(&Msg::ConfirmLockoutWarning);
        };

        if !deleting {
            return self.lang.render(&Msg::ConfirmKeepHome {
                user: user.to_owned(),
                path,
            });
        }

        match self
            .backend
            .accounts()
            .size_of(self.executor.as_ref(), &path)
        {
            Ok(Some(bytes)) => self.lang.render(&Msg::ConfirmDeleteHome {
                user: user.to_owned(),
                path,
                size: human_size(bytes),
            }),
            Ok(None) | Err(_) => self.lang.render(&Msg::ConfirmDeleteHomeUnmeasured {
                user: user.to_owned(),
                path,
            }),
        }
    }
}

/// Bytes as a person reads them.
///
/// Binary units, matching what `du -h` and every file manager on the host
/// report: a number that disagreed with what the operator sees elsewhere would
/// undermine the sentence it appears in.
///
/// One decimal place above a kibibyte and none below. "2.4 GB" is the
/// precision the decision needs — the difference between 2.4 and 2.5 changes
/// nothing, and "2 GB" for anything between 2.0 and 2.9 understates by
/// almost half.
///
/// Not in the catalogue, because it is arithmetic rather than words: the
/// units are the same in every language this tool will render, and a `Msg`
/// per magnitude would be four variants that only ever say a suffix.
fn human_size(bytes: u64) -> String {
    /// Suffixes, smallest first. Each step is 1024 of the one before.
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    /// What separates one unit from the next.
    const STEP: f64 = 1024.0;

    let mut size = bytes as f64;
    let mut unit = 0;

    // `UNITS.len() - 1` so the loop cannot walk past the last suffix: a
    // petabyte home is not a case worth a variant, and reporting it in
    // tebibytes is right rather than absent.
    while size >= STEP && unit < UNITS.len() - 1 {
        size /= STEP;
        unit += 1;
    }

    let suffix = UNITS.get(unit).copied().unwrap_or("B");

    if unit == 0 {
        // Whole bytes: a fractional byte is not a thing, and "512.0 B" reads
        // as a rounding of something larger.
        format!("{bytes} {suffix}")
    } else {
        format!("{size:.1} {suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::human_size;

    #[test]
    fn a_size_is_reported_in_the_units_the_host_uses() {
        // Binary units, matching `du -h`: a number disagreeing with what the
        // operator sees elsewhere undermines the sentence carrying it.
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(2_576_980_378), "2.4 GiB");
    }

    #[test]
    fn bytes_are_whole_and_everything_above_them_is_not() {
        // "512.0 B" reads as a rounding of something larger, and a fractional
        // byte is not a thing. Above that the decimal is what makes 2.4 and
        // 2.0 distinguishable — the difference an operator is deciding on.
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1), "1 B");
        assert_eq!(human_size(1536), "1.5 KiB");
    }

    #[test]
    fn a_size_beyond_the_last_unit_is_reported_rather_than_lost() {
        // The loop stops at the largest suffix instead of walking off the end
        // of the table. A petabyte home does not deserve a unit of its own,
        // and reporting it in tebibytes is right rather than absent.
        assert_eq!(human_size(u64::MAX), "16777216.0 TiB");
    }
}
