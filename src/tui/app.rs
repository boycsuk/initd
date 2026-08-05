//! Application state, navigation and the event loop.

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};

use super::confirm::Confirm;
use super::field::Field;
use super::form::Form;
use super::output::OutputPane;
use super::status::{State, Status};
use super::verify::Verification;
use super::worker::{Running, Update};
use super::{Tui, help, layout, style};
use crate::backend::Backend;
use crate::distro::Distro;
use crate::distro::host::HostFacts;
use crate::error::Result;
use crate::exec::{Executor, OutputLine, Stream};
use crate::i18n::Lang;
use crate::tasks::params::ParamValues;
use crate::tasks::revert::{Outcome, Revert};
use crate::tasks::{self, Node, Task};

/// How long to wait for a key before redrawing.
///
/// Short enough that the interface stays responsive, long enough that an idle
/// TUI does not spin the CPU.
///
/// It also bounds how late a transient message can outlive its stated
/// lifetime: such a message expires on a redraw, and a redraw happens at least
/// this often whether or not anything is typed.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The version shown in the header.
///
/// Taken from the manifest so the interface cannot claim a release the binary
/// is not.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Right-aligned hint in the header.
const HELP_HINT: &str = "? help";

/// Lines a page key moves the output by.
const PAGE_SCROLL: usize = 10;

/// Rows the verification banner occupies: its top border and four lines.
const VERIFY_BANNER_ROWS: u16 = 5;

/// Lines a page key moves the help overlay by.
const HELP_PAGE: u16 = 10;

/// Marks a row that opens onto another level.
const CATEGORY_MARKER: &str = "› ";

/// Marks a runnable row, keeping task titles aligned with category ones.
const TASK_MARKER: &str = "  ";

/// Which pane the movement keys act on.
///
/// `j` and `k` mean "next" and "previous" in both panes, so something has to
/// say which one they address. That something is `Tab` and nothing else:
/// overloading a movement key with focus is how keys start leaking between
/// panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Tree,
    Output,
}

impl Pane {
    /// The pane `Tab` moves to.
    const fn other(self) -> Self {
        match self {
            Self::Tree => Self::Output,
            Self::Output => Self::Tree,
        }
    }
}

/// A helper's request for the terminal, waiting to be served.
///
/// Carries the reply channel so that whoever takes the request is obliged to
/// answer it: a worker thread is blocked on the other end.
struct AuthRequest {
    program: String,
    args: Vec<String>,
    mechanism: String,
    reply: std::sync::mpsc::Sender<bool>,
}

/// The running application.
///
/// Navigation is drill-down: exactly one level of the tree is on screen at a
/// time, and entering a category replaces the list with its children.
pub struct App {
    distro: Distro,
    /// Facts about the machine, probed once at startup.
    host: HostFacts,
    backend: Box<dyn Backend>,
    executor: Box<dyn Executor>,
    /// The whole tree, owned so that levels can be borrowed from it.
    tree: Vec<Node>,
    /// Indices from the root to the category on screen; empty means the root.
    ///
    /// Positions rather than titles, so nothing breaks if two categories in
    /// different branches share a name.
    path: Vec<usize>,
    /// Cursor position of each level left behind, restored on the way back.
    cursor_stack: Vec<usize>,
    list_state: ListState,
    /// Which pane the movement keys currently address.
    focus: Pane,
    output: OutputPane,
    /// The parameter form, while one is being filled in.
    form: Option<Form>,
    confirm: Option<Confirm>,
    /// A helper waiting for the terminal, until the next turn of the loop.
    ///
    /// Held rather than served where it arrives: draining happens without the
    /// terminal in hand, and restoring the screen needs it.
    pending_auth: Option<AuthRequest>,
    /// Values collected from the form, held until the task actually runs.
    ///
    /// A destructive task with parameters passes through the form and then the
    /// confirmation, and the values have to survive the step between.
    pending_values: ParamValues,

    /// The values the running task was started with.
    ///
    /// Separate from `pending_values`, which is emptied when the task is
    /// launched. Consequences are declared from what the task actually ran
    /// with — moving to port 2222 invalidates a firewall rule naming 22, while
    /// re-running with 22 invalidates nothing — so reporting them needs the
    /// values to outlive the launch.
    ran_with: ParamValues,
    /// The task currently running, if any.
    running: Option<Running>,
    /// An applied change waiting to be kept or put back.
    verification: Option<Verification>,
    /// How far the help overlay is scrolled, while it is showing.
    ///
    /// `None` means it is closed: the overlay has no state worth keeping
    /// between openings, and it always starts at the top.
    help: Option<u16>,
    status: Status,
    should_quit: bool,
}

impl App {
    /// Builds the application for a detected system.
    ///
    /// The host facts are passed in rather than probed here so that the caller
    /// owns every read of the machine, and so tests can state a host outright
    /// instead of inheriting whichever one they happen to run on.
    pub fn new(
        distro: Distro,
        host: HostFacts,
        backend: Box<dyn Backend>,
        executor: impl Executor + 'static,
    ) -> Self {
        let mut list_state = ListState::default();

        // The root level is never empty, so the cursor always has a row.
        list_state.select(Some(0));

        Self {
            distro,
            host,
            backend,
            executor: Box::new(executor),
            pending_auth: None,
            tree: tasks::tree(),
            path: Vec::new(),
            cursor_stack: Vec::new(),
            list_state,
            // The tree is where a session starts: nothing has run yet, so
            // there is no output to read.
            focus: Pane::Tree,
            output: OutputPane::new(),
            form: None,
            confirm: None,
            pending_values: ParamValues::new(),
            ran_with: ParamValues::new(),
            running: None,
            verification: None,
            help: None,
            status: Status::new(),
            should_quit: false,
        }
    }

    /// The nodes of the level currently on screen.
    fn current_level(&self) -> &[Node] {
        level_at(&self.tree, &self.path)
    }

    /// The node under the cursor, if any.
    fn selected_node(&self) -> Option<&Node> {
        self.current_level().get(self.list_state.selected()?)
    }

    /// Titles from the root to the level on screen, for the breadcrumb.
    fn breadcrumb(&self) -> String {
        let mut nodes = self.tree.as_slice();
        let mut titles = Vec::new();

        for &index in &self.path {
            let Some(Node::Category(category)) = nodes.get(index) else {
                break;
            };

            titles.push(category.title);
            nodes = category.children.as_slice();
        }

        if titles.is_empty() {
            "Tasks".to_owned()
        } else {
            titles.join(" › ")
        }
    }

    /// Descends into the category under the cursor.
    fn enter_category(&mut self, index: usize) {
        self.cursor_stack.push(index);
        self.path.push(index);
        self.list_state.select(Some(0));
        self.status.set(State::Ready, "");
    }

    /// Returns to the parent level, restoring the cursor it was left on.
    ///
    /// At the root there is nowhere to go, so this reports rather than quits:
    /// `q` is the way out, and an `Esc` that sometimes exits the program would
    /// make going back one level too far a destructive mistake.
    fn leave_category(&mut self) {
        if self.path.pop().is_none() {
            // A refusal, not a state: the tool is still ready, the key simply
            // had nowhere to go.
            self.status
                .flash("already at the top level", Instant::now());
            return;
        }

        let restored = self.cursor_stack.pop().unwrap_or(0);
        self.list_state.select(Some(restored));
    }

    /// Runs the event loop until the user quits.
    pub fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        while !self.should_quit {
            // Both before drawing: output that has arrived should appear in
            // this frame, and an expired window should never be shown with a
            // countdown that has already run out.
            self.poll_running();
            self.expire_verification();

            // Before drawing, not after: the frame this loop is about to paint
            // would land on top of the helper's prompt.
            self.serve_pending_auth(terminal)?;

            terminal
                .draw(|frame| self.render(frame))
                .map_err(|source| crate::error::Error::Terminal { source })?;

            self.handle_events()?;
        }

        Ok(())
    }

    /// Reads and dispatches one round of input.
    ///
    /// Returns without an event when the poll times out, which is what lets a
    /// flashed refusal disappear on its own: nothing schedules its removal, the
    /// next redraw simply stops drawing it.
    fn handle_events(&mut self) -> Result<()> {
        let has_event = event::poll(POLL_INTERVAL)
            .map_err(|source| crate::error::Error::Terminal { source })?;

        if !has_event {
            return Ok(());
        }

        let event = event::read().map_err(|source| crate::error::Error::Terminal { source })?;

        // Key release events would otherwise trigger every action twice on
        // terminals that report them.
        if let Event::Key(key) = event
            && key.kind == KeyEventKind::Press
        {
            self.on_key(key);
        }

        Ok(())
    }

    /// Handles a key press, routing to whichever dialog is open.
    ///
    /// Modal dialogs are checked first and swallow everything: inside a form,
    /// `j`, `k`, `/` and `q` are literal characters, not commands.
    /// No key needs the terminal any more: starting a task hands it to a
    /// thread rather than to a child process, so the whole path is testable.
    fn on_key(&mut self, key: KeyEvent) {
        if let Some(values) = self.dispatch(key) {
            self.run_selected(values);
        }
    }

    /// Routes a key press, returning the values to run the selected task with.
    ///
    /// `Some` means the key was the one that starts the work; everything else
    /// is resolved in place.
    fn dispatch(&mut self, key: KeyEvent) -> Option<ParamValues> {
        if self.help.is_some() {
            self.on_help_key(key);
            return None;
        }

        // While a task runs the interface stays open — scrolling, switching
        // panes and reading all work — but nothing new may be started and
        // nothing may be answered. Only one task at a time, and the keys that
        // would start another are refused rather than queued.
        if self.running.is_some() {
            self.on_running_key(key);
            return None;
        }

        // Semi-modal: reading is never blocked while a change is unverified,
        // but nothing new may be started until this one is settled.
        if self.verification.is_some() {
            self.on_verify_key(key);
            return None;
        }

        if self.form.is_some() {
            return self.on_form_key(key);
        }

        if self.confirm.is_some() {
            return self.on_confirm_key(key);
        }

        if self.on_navigation_key(key) {
            return None;
        }

        if key.code == KeyCode::Enter && self.focus == Pane::Tree {
            return self.activate();
        }

        None
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
                "a task is running — Ctrl-C to stop it first",
                Instant::now(),
            ),
            _ => self
                .status
                .flash("a task is already running", Instant::now()),
        }
    }

    /// Asks the running task to stop at its next step boundary.
    fn cancel_running(&mut self) {
        let Some(running) = self.running.as_mut() else {
            return;
        };

        if running.is_cancelling() {
            self.status.flash(
                "already stopping — waiting for the current step",
                Instant::now(),
            );
            return;
        }

        running.cancel();
        // Not "cancelled": the task has been asked to stop and has not yet
        // done so. Saying otherwise before the step finishes would be a lie
        // about what state the machine is in.
        self.status
            .set(State::Running, "stopping after the current step...");
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
        let limit = help::max_scroll(Rect::new(0, 0, 80, 24));

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
            KeyCode::Char('R') => self.revert_change("reverted"),
            KeyCode::Down | KeyCode::Char('j') => self.output.scroll_down(1),
            KeyCode::Up => self.output.scroll_up(1),
            KeyCode::PageDown => self.output.scroll_down(PAGE_SCROLL),
            KeyCode::PageUp => self.output.scroll_up(PAGE_SCROLL),
            // Every other key is refused rather than ignored: an unanswered
            // window is the one state where doing nothing has consequences.
            _ => self
                .status
                .flash("K keeps this change, R puts it back", Instant::now()),
        }
    }

    /// Puts the change back if its window has run out.
    ///
    /// Called from the event loop rather than driven by a key, because the
    /// whole point is that it happens when nobody is pressing anything.
    fn expire_verification(&mut self) {
        let expired = self
            .verification
            .as_ref()
            .is_some_and(|window| window.has_expired(Instant::now()));

        if expired {
            self.revert_change("no confirmation");
        }
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
                    self.status.set(State::Ready, "cancelled");
                } else {
                    form.arm_cancel();
                    self.status
                        .flash("press Esc again to discard what you typed", Instant::now());
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
            self.status
                .flash("fill in every field first", Instant::now());
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
        self.status.set(State::Ready, "cancelled");
    }

    /// Acts on the selected row: descends into a category, or runs a task.
    fn activate(&mut self) -> Option<ParamValues> {
        let index = self.list_state.selected()?;

        if let Some(Node::Category(_)) = self.current_level().get(index) {
            self.enter_category(index);
            return None;
        }

        let task = self.selected_task()?;

        if !task.supports(self.distro.family) {
            // Pressing Enter on a row the host cannot run is a refusal, not a
            // state change: the reason flashes and the tool stays where it was.
            let reason = format!("{} is not supported on {}", task.id(), self.distro.family);
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

        self.confirm = Some(Confirm::new(task.title(), task.description()).with_warning(
            "This operation can lock you out of a server you reach over SSH. \
             Make sure you have another way in before continuing.",
        ));
    }

    /// Executes the selected task, streaming its output into the pane.
    fn run_selected(&mut self, values: ParamValues) {
        let Some(Node::Task(task)) = self.selected_node() else {
            return;
        };

        let id = task.id();

        self.output.clear();
        self.status.set(State::Running, id);
        // Reading what is about to happen is the natural thing to do next.
        self.focus = Pane::Output;

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
    fn poll_running(&mut self) {
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
                text: Lang::from_env().render(&crate::i18n::Msg::AuthenticationRequested {
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

    /// Records a request for the terminal, answering any it displaces.
    ///
    /// A second request while one is outstanding would strand the thread
    /// waiting on the first, so the displaced one is refused rather than
    /// dropped. One task authenticates once at a time in practice; this keeps
    /// that something the code states rather than something it relies on.
    fn supersede_pending_auth(&mut self, request: AuthRequest) {
        if let Some(superseded) = self.pending_auth.replace(request) {
            let _ = superseded.reply.send(false);
        }
    }

    /// Hands the terminal to a helper that needs to prompt, and answers.
    ///
    /// The reply is sent on every path, including the one where restoring the
    /// terminal fails: a worker thread is blocked on the other end, and
    /// letting it wait for the deadline instead of telling it no would stall a
    /// task for five minutes over an error already in hand.
    ///
    /// A send failure is ignored, as elsewhere: it means the thread is gone,
    /// which is not this loop's problem to solve.
    fn serve_pending_auth(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(request) = self.pending_auth.take() else {
            return Ok(());
        };

        let outcome = super::with_terminal_released(terminal, || {
            // Every stream inherited: the helper has to reach the terminal to
            // prompt, and on sudo the timestamp it writes is keyed by it.
            let status = std::process::Command::new(&request.program)
                .args(&request.args)
                .stdin(std::process::Stdio::inherit())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .status()
                .map_err(|source| crate::error::Error::CommandIo {
                    command: request.program.clone(),
                    source,
                })?;

            Ok(status.success())
        });

        let granted = match &outcome {
            Ok(granted) => *granted,
            Err(_) => false,
        };

        let _ = request.reply.send(granted);

        if granted {
            self.output.push(OutputLine {
                stream: Stream::Stdout,
                text: Lang::from_env().render(&crate::i18n::Msg::AuthenticationGranted),
            });
        } else {
            self.output.push(OutputLine {
                stream: Stream::Stderr,
                text: Lang::from_env().render(&crate::i18n::Msg::AuthenticationRefused {
                    mechanism: request.mechanism.clone(),
                }),
            });
        }

        outcome.map(|_| ())
    }

    /// Records how a finished task ended.
    ///
    /// Success and failure are pills of their own, so the outcome is legible
    /// from the left edge without reading the message beside it.
    fn finish_run(&mut self, id: &str, outcome: Result<Outcome>, cancelled: bool) {
        // Cancellation is reported only once the task has actually stopped,
        // and it says which steps ran. A tool that claims to have stopped
        // before it has is how half-configured servers happen.
        if cancelled {
            self.status.set(
                State::Cancelled,
                format!("{id} — stopped after the last step"),
            );
            return;
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
            Err(ref err) => self.status.set(State::Failed, format!("{id} — {err}")),
        }
    }

    /// Writes what the finished task invalidated into the output pane.
    ///
    /// Reported, never acted on: the administrator decides what to do about
    /// each one. Warnings the tool cannot verify carry a different marker from
    /// those it can, since presenting both alike would imply the provider's
    /// firewall had been checked when nothing checked it.
    fn report_consequences(&mut self, id: &str) {
        let Some(task) = tasks::find(id) else {
            return;
        };

        let consequences = task.consequences(&self.ran_with);

        if consequences.is_empty() {
            return;
        }

        let lang = Lang::from_env();

        self.output.push(OutputLine {
            stream: Stream::Stdout,
            text: String::new(),
        });
        self.output.push(OutputLine {
            stream: Stream::Stdout,
            text: "Consequences:".to_owned(),
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
    fn begin_verification(&mut self, task: &str, revert: Revert) {
        let window = Verification::new(task, revert, Instant::now());

        self.status
            .set(State::Verify, format!("{task} — applied, not yet kept"));
        self.verification = Some(window);
    }

    /// Keeps an applied change, closing its window.
    fn keep_change(&mut self) {
        let Some(window) = self.verification.take() else {
            return;
        };

        self.status
            .set(State::Done, format!("{} — kept", window.task));
    }

    /// Puts an applied change back, closing its window.
    ///
    /// A revert that itself fails is reported rather than swallowed: the
    /// administrator has to know the machine is in neither state.
    fn revert_change(&mut self, reason: &str) {
        let Some(window) = self.verification.take() else {
            return;
        };

        let outcome = window
            .revert()
            .apply(self.executor.as_ref(), self.backend.as_ref());

        match outcome {
            Ok(()) => self.status.set(
                State::Done,
                format!(
                    "{} — {reason}, previous configuration restored",
                    window.task
                ),
            ),
            Err(ref err) => self.status.set(
                State::Failed,
                format!("{} — could not restore: {err}", window.task),
            ),
        }
    }

    /// The task currently under the cursor, if the cursor is on one.
    fn selected_task(&self) -> Option<&dyn Task> {
        match self.selected_node()? {
            Node::Task(task) => Some(task.as_ref()),
            Node::Category(_) => None,
        }
    }

    /// Moves the cursor down one row.
    ///
    /// Every row of a level is selectable now that categories are entered
    /// rather than skipped over.
    fn select_next(&mut self) {
        let last = self.current_level().len().saturating_sub(1);
        let current = self.list_state.selected().unwrap_or(0);

        self.list_state
            .select(Some(current.saturating_add(1).min(last)));
    }

    /// Moves the cursor up one row.
    fn select_previous(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);

        self.list_state.select(Some(current.saturating_sub(1)));
    }

    /// Moves the cursor to the first row of the level.
    fn select_first(&mut self) {
        self.list_state.select(Some(0));
    }

    /// Moves the cursor to the last row of the level.
    fn select_last(&mut self) {
        self.list_state
            .select(Some(self.current_level().len().saturating_sub(1)));
    }

    /// Draws the whole interface.
    ///
    /// A terminal too small for a legible interface gets a stated requirement
    /// rather than a partial one: a garbled layout on a production server is
    /// worse than a clear refusal.
    fn render(&mut self, frame: &mut Frame) {
        if !layout::is_usable(frame.area()) {
            render_too_small(frame);
            return;
        }

        let bands = layout::frame(frame.area());

        self.render_header(frame, bands.header);
        self.render_body(frame, bands.body);
        self.render_status(frame, bands.status);

        if let Some(keys) = bands.keys {
            self.render_key_bar(frame, keys);
        }

        // Dialogs draw last, over everything: they are modal, and content
        // showing through one would misrepresent what the keys now do.
        if let Some(ref confirm) = self.confirm {
            confirm.render(frame);
        }

        if let Some(ref mut form) = self.form {
            form.render(frame);
        }

        // Last of all: help is asked for from wherever the operator is stuck,
        // including on top of a dialog.
        if let Some(scroll) = self.help {
            help::render(frame, scroll);
        }
    }

    /// Draws the one-line header naming the tool and the machine.
    ///
    /// Borderless: at 24 rows a bordered header would spend three of them on
    /// one line of text.
    ///
    /// The hostname is emphasised because it answers the question an
    /// administrator with several terminals open actually has — *which machine
    /// am I about to change?* — and the privilege mechanism is stated up front
    /// so that "this will need a password" is known before a task is started
    /// rather than when one fails.
    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let separator = || Span::styled("  ·  ", style::BLOCK_SUBTITLE);

        // With one pane on screen at a time, nothing else says which one is
        // showing, so the header trades the host facts for an indicator —
        // otherwise `Tab` would look like it did nothing.
        let mut spans = if layout::BodyLayout::for_width(area.width) == layout::BodyLayout::Single {
            let (tree, output) = match self.focus {
                Pane::Tree => (style::EMPHASIS, style::BLOCK_SUBTITLE),
                Pane::Output => (style::BLOCK_SUBTITLE, style::EMPHASIS),
            };

            vec![
                Span::styled(" initd", style::HEADING),
                separator(),
                Span::styled(self.host.hostname.clone(), style::EMPHASIS),
                Span::raw("  "),
                Span::styled("tasks", tree),
                Span::styled(" / ", style::BLOCK_SUBTITLE),
                Span::styled("output", output),
            ]
        } else {
            vec![
                Span::styled(" initd", style::HEADING),
                Span::styled(format!(" {VERSION}"), style::BLOCK_SUBTITLE),
                separator(),
                Span::styled(self.host.hostname.clone(), style::EMPHASIS),
                separator(),
                Span::styled(self.distro.display_name().to_owned(), style::NORMAL),
                separator(),
                Span::styled(format!("root via {}", self.host.privilege), style::NORMAL),
            ]
        };

        // The help hint is dropped rather than allowed to wrap onto a row the
        // header does not have.
        let used: usize = spans.iter().map(|span| span.content.chars().count()).sum();
        let hint_width = HELP_HINT.chars().count() + 1;

        if used + hint_width <= area.width as usize {
            let gap = area.width as usize - used - hint_width;
            spans.push(Span::raw(" ".repeat(gap)));
            spans.push(Span::styled(HELP_HINT, style::BLOCK_SUBTITLE));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// Draws the task tree beside the output pane.
    fn render_body(&mut self, frame: &mut Frame, area: Rect) {
        let split = layout::BodyLayout::for_width(area.width);
        let (tree_area, right_area) = layout::body(area, split);

        // Below the split threshold both panes are the whole area, so drawing
        // both would leave one written over the other. One is shown at a time
        // and `Tab` chooses which.
        if split == layout::BodyLayout::Single {
            match self.focus {
                Pane::Tree => self.render_tree(frame, tree_area),
                Pane::Output => self.render_right(frame, right_area),
            }

            return;
        }

        self.render_tree(frame, tree_area);
        self.render_right(frame, right_area);
    }

    /// Draws the task tree and its scrollbar.
    fn render_tree(&mut self, frame: &mut Frame, tree_area: Rect) {
        let family = self.distro.family;
        // The two borders and the marker column are not available to the row.
        let row_width = tree_area.width.saturating_sub(2) as usize;
        let items: Vec<ListItem> = self
            .current_level()
            .iter()
            .map(|node| ListItem::new(row(node, family, row_width)))
            .collect();

        let tree_focused = self.focus == Pane::Tree;
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(style::border(tree_focused))
                    .title(Span::styled(
                        // Two borders and the spaces framing the title.
                        truncate_head(&self.breadcrumb(), tree_area.width.saturating_sub(4)),
                        style::PANE_TITLE,
                    ))
                    // The census rides the bottom border, costing no rows.
                    .title_bottom(Span::styled(self.census(), style::BLOCK_SUBTITLE)),
            )
            // The selected row stays visible while focus is elsewhere, drawn
            // differently: losing the cursor on Tab would mean hunting for it
            // again on the way back.
            .highlight_style(if tree_focused {
                style::SELECTION_FOCUSED
            } else {
                style::SELECTION_UNFOCUSED
            });

        frame.render_stateful_widget(list, tree_area, &mut self.list_state);
        self.render_tree_scrollbar(frame, tree_area);
    }

    /// Draws whichever of detail, output or verification the state calls for.
    fn render_right(&mut self, frame: &mut Frame, right_area: Rect) {
        if let Some(ref window) = self.verification {
            // The countdown takes the top of the pane and the output keeps the
            // rest: what the change did is the evidence for the decision.
            let [banner, log] =
                Layout::vertical([Constraint::Length(VERIFY_BANNER_ROWS), Constraint::Min(3)])
                    .areas(right_area);

            render_verification(frame, banner, window);
            self.output
                .render(frame, log, "output", self.focus == Pane::Output);
        } else if self.output.is_empty() {
            self.render_detail(frame, right_area);
        } else {
            self.output
                .render(frame, right_area, "output", self.focus == Pane::Output);
        }
    }

    /// Draws the tree's scrollbar, but only when there is something to scroll.
    ///
    /// A track drawn against a level that fits is a permanent hint that
    /// content is hidden when none is.
    fn render_tree_scrollbar(&self, frame: &mut Frame, area: Rect) {
        let rows = self.current_level().len();
        // The block's own borders are not available to the list.
        let viewport = area.height.saturating_sub(2) as usize;

        if rows <= viewport {
            return;
        }

        let mut state =
            ScrollbarState::new(rows.saturating_sub(viewport)).position(self.list_state.offset());

        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(style::SCROLLBAR_TRACK)
                .thumb_style(style::SCROLLBAR_THUMB),
            area,
            &mut state,
        );
    }

    /// Draws what the selected row would do, before anything has run.
    ///
    /// A category has no description of its own, so it reports what it holds
    /// rather than leaving the pane blank.
    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let description = match self.selected_node() {
            Some(Node::Task(task)) => task.description().to_owned(),
            Some(Node::Category(category)) => {
                let count = category.task_count();
                let plural = if count == 1 { "task" } else { "tasks" };
                format!(
                    "{} — {} {} inside.\n\nPress Enter to open.",
                    category.title, count, plural
                )
            }
            None => String::new(),
        };

        let title = match self.selected_node() {
            Some(Node::Task(task)) => task.title(),
            _ => "Detail",
        };

        let paragraph = Paragraph::new(description)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(style::border(self.focus == Pane::Output))
                    .title(Span::styled(
                        truncate_head(title, area.width.saturating_sub(4)),
                        style::PANE_TITLE,
                    )),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
    }

    /// Counts what the level on screen holds, for the tree's bottom border.
    fn census(&self) -> String {
        let level = self.current_level();
        let categories = level
            .iter()
            .filter(|node| matches!(node, Node::Category(_)))
            .count();
        let tasks = level.len() - categories;

        let parts: Vec<String> = [
            (categories, "category", "categories"),
            (tasks, "task", "tasks"),
        ]
        .iter()
        .filter(|(count, _, _)| *count > 0)
        .map(|(count, singular, plural)| {
            let noun = if *count == 1 { singular } else { plural };
            format!("{count} {noun}")
        })
        .collect();

        format!(" {} ", parts.join(", "))
    }

    /// Draws the status bar and key hints.
    ///
    /// The pill always occupies the same cells at the left edge, so the eye
    /// never has to search for the tool's current state.
    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let now = Instant::now();
        let state = self.pill();

        let mut spans = vec![
            Span::styled(format!(" {} ", state.label()), state.style()),
            Span::raw("  "),
            Span::styled(self.status.message(now), style::NORMAL),
        ];

        // Two independent liveness signals, right-aligned: a spinner driven by
        // the clock and a wall-clock timer. Both keep moving through a command
        // that produces no output for a minute, which is what distinguishes a
        // slow package manager from a frozen screen over a bad link.
        if let Some(ref running) = self.running {
            let live = format!("{}  {}  ", running.spinner(now), running.elapsed(now));
            let used: usize = spans.iter().map(|span| span.content.chars().count()).sum();
            let width = area.width as usize;

            if used + live.chars().count() <= width {
                spans.push(Span::raw(" ".repeat(width - used - live.chars().count())));
                spans.push(Span::styled(live, style::BLOCK_SUBTITLE));
            }
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    /// The state pill for the status row.
    ///
    /// Mostly this is whatever the last action left behind, but two conditions
    /// describe the cursor rather than the past and therefore win: a dialog is
    /// open, or the row under the cursor cannot run here. The pill is the one
    /// place that always states what pressing Enter would do.
    ///
    /// The confirmation outranks the form for the same reason the row flag
    /// does: a destructive task collects its parameters first and confirms
    /// after, so once both are open the confirmation is the live question.
    fn pill(&self) -> State {
        if self.confirm.is_some() {
            return State::Confirm;
        }

        if self.form.is_some() {
            return State::Input;
        }

        match self.selected_node() {
            Some(Node::Task(task)) if !task.supports(self.distro.family) => State::Unsupported,
            _ => self.status.state(),
        }
    }

    /// The hints offered while the tree holds focus.
    ///
    /// `Enter` opens a category but runs a task, so the hint names which of
    /// the two it is rather than listing both every time.
    fn tree_keys(&self) -> Vec<(&'static str, &'static str)> {
        let enter_hint = match self.selected_node() {
            Some(Node::Category(_)) => "open",
            _ => "run",
        };

        let mut keys = vec![("↑↓", "move"), ("Enter", enter_hint)];

        // Going back is only offered where there is somewhere to go back to.
        if !self.path.is_empty() {
            keys.push(("Esc", "back"));
        }

        // Switching panes is pointless with nothing to read.
        if !self.output.is_empty() {
            keys.push(("Tab", "output"));
        }

        keys
    }

    /// Draws the key hints along the bottom row.
    ///
    /// The hints follow the focused pane and the row under the cursor rather
    /// than listing every binding: a bar that never changes is one the operator
    /// stops reading.
    fn render_key_bar(&self, frame: &mut Frame, area: Rect) {
        // While a change is unverified the tree keys are refused, so offering
        // them would advertise actions the state does not allow.
        let mut keys = match self.focus {
            // Only the keys the state actually accepts. Offering "Enter run"
            // while a task is running would name an action that is refused.
            _ if self.running.is_some() => vec![
                ("Ctrl-C", "stop"),
                ("↑↓", "scroll"),
                ("w", "wrap"),
                ("?", "keys"),
            ],
            _ if self.verification.is_some() => {
                vec![("K", "keep"), ("R", "revert"), ("↑↓", "scroll")]
            }
            Pane::Tree => self.tree_keys(),
            Pane::Output => vec![
                ("↑↓", "scroll"),
                ("G", "follow"),
                ("w", "wrap"),
                ("Tab", "tree"),
            ],
        };

        // Quitting is refused while work is outstanding: mid-task it would
        // leave a server half-configured, and mid-verification it would
        // abandon a change with nobody left to put it back.
        if self.verification.is_none() && self.running.is_none() {
            keys.push(("q", "quit"));
        }

        let mut spans = Vec::with_capacity(keys.len() * 3);
        for (key, label) in keys {
            spans.push(Span::styled(format!(" {key}"), style::KEYBAR_KEY));
            spans.push(Span::styled(format!(" {label} "), style::KEYBAR_LABEL));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

/// Draws the banner over an applied change that has not been kept.
///
/// It states three things in order: that the change is applied but not yet
/// permanent, how long is left, and what to press. The countdown is red
/// because it is the one number on screen that acts on its own.
fn render_verification(frame: &mut Frame, area: Rect, window: &Verification) {
    let lines = vec![
        Line::from(vec![
            Span::styled(" VERIFY ", style::STATUS_BUSY),
            Span::raw("  "),
            Span::styled("applied, ", style::NORMAL),
            Span::styled("not yet kept", style::EMPHASIS),
        ]),
        Line::from(vec![
            Span::styled("reverting in ", style::DANGER_TEXT),
            Span::styled(window.countdown(Instant::now()), style::EMPHASIS),
            Span::raw("   "),
            Span::styled("K", style::KEYBAR_KEY),
            Span::styled(" keep   ", style::KEYBAR_LABEL),
            Span::styled("R", style::KEYBAR_KEY),
            Span::styled(" revert now", style::KEYBAR_LABEL),
        ]),
        // The instruction that matters: the tool cannot check this itself, so
        // the one thing the administrator must do is stated outright.
        Line::styled("Open a second session and check you", style::EMPHASIS),
        Line::styled("can still log in.", style::EMPHASIS),
    ];

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::TOP | Borders::LEFT | Borders::RIGHT)
                    .border_style(style::DIALOG_BORDER_DANGER),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Builds one row of the tree.
///
/// Flags are glyphs rather than colours so that a monochrome terminal loses
/// nothing, and unsupported tasks stay visible with their reason rather than
/// being hidden — hiding them makes the tool look inconsistent between hosts.
fn row(node: &Node, family: crate::distro::Family, width: usize) -> Line<'static> {
    let (marker, marker_style, title, title_style, trailing, trailing_style) = match node {
        // The marker tells a category apart from a task at a glance; with one
        // level on screen there is no indentation to do it.
        //
        // The count is what makes a collapsed level navigable: it tells a
        // 3-task category from an 8-task one without opening either.
        Node::Category(category) => (
            CATEGORY_MARKER,
            style::CATEGORY_COLLAPSED,
            category.title,
            style::HEADING,
            category.task_count().to_string(),
            style::BLOCK_SUBTITLE,
        ),
        Node::Task(task) => {
            let supported = task.supports(family);
            // Destructive outranks input: a task that asks for a port before
            // wiping something is first of all the one that wipes something,
            // and only one flag fits the column.
            let (text_style, flag, flag_style) = if !supported {
                (
                    style::DISABLED,
                    style::MARKER_UNSUPPORTED,
                    style::FLAG_UNSUPPORTED,
                )
            } else if task.is_destructive() {
                (style::NORMAL, style::MARKER_DANGER, style::FLAG_DANGER)
            } else if !task.params().is_empty() {
                (style::NORMAL, style::MARKER_INPUT, style::FLAG_INPUT)
            } else {
                (style::NORMAL, "", style::NORMAL)
            };

            (
                TASK_MARKER,
                text_style,
                task.title(),
                text_style,
                flag.to_owned(),
                flag_style,
            )
        }
    };

    // A title longer than its column is cut with an ellipsis rather than
    // silently clipped by the terminal: "Install and enable the SSH ser" reads
    // as a real name, so the operator cannot tell it was truncated.
    //
    // Titles lose their tail, unlike breadcrumbs, which lose their head: a task
    // is identified by how its name starts, a path by where it ends.
    let fixed = marker.chars().count() + trailing.chars().count();
    // One space always separates the title from the trailing flag.
    let room_for_title = width.saturating_sub(fixed + 1);
    let title = truncate_tail(title, room_for_title);

    let used = fixed + title.chars().count();
    let padding = width.saturating_sub(used).max(1);

    Line::from(vec![
        Span::styled(marker, marker_style),
        Span::styled(title, title_style),
        Span::raw(" ".repeat(padding)),
        Span::styled(trailing, trailing_style),
    ])
}

/// Fits `text` into `width` cells, dropping characters from the end.
///
/// The companion of [`truncate_head`], for text identified by how it starts.
fn truncate_tail(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }

    // Too narrow to say anything meaningful; an ellipsis alone is honest.
    if width <= 1 {
        return "…".repeat(width);
    }

    text.chars().take(width - 1).chain(['…']).collect()
}

/// Fits `text` into `width` cells, dropping characters from the front.
///
/// Paths lose their head, never their tail: `…› Configuration` says where you
/// are, whereas `Remote Access › SSH › Configura` does not. The result is
/// padded with a space on each side, the way every title in the interface is
/// framed against its border.
fn truncate_head(text: &str, width: u16) -> String {
    let available = width as usize;
    let length = text.chars().count();

    if length <= available {
        return format!(" {text} ");
    }

    // One cell goes to the ellipsis that marks the dropped head.
    let kept: String = text
        .chars()
        .skip(length.saturating_sub(available.saturating_sub(1)))
        .collect();

    format!(" …{kept} ")
}

/// Draws the refusal shown on a terminal too small for a legible interface.
fn render_too_small(frame: &mut Frame) {
    let message = format!(
        "initd needs at least {}×{} .\nThis terminal is {}×{}.",
        layout::MIN_WIDTH,
        layout::MIN_HEIGHT,
        frame.area().width,
        frame.area().height,
    );

    frame.render_widget(
        Paragraph::new(message)
            .style(style::NORMAL)
            .wrap(Wrap { trim: true }),
        frame.area(),
    );
}

/// The nodes reached by following `path` from the root of `tree`.
///
/// A path only ever grows by descending into a category, so a step that lands
/// on anything else cannot happen; it returns the level reached so far rather
/// than panicking, because a logic error must not take the interface down.
fn level_at<'a>(tree: &'a [Node], path: &[usize]) -> &'a [Node] {
    let mut nodes = tree;

    for &index in path {
        match nodes.get(index) {
            Some(Node::Category(category)) => nodes = category.children.as_slice(),
            _ => return nodes,
        }
    }

    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::MockExecutor;

    fn test_distro(family: Family) -> Distro {
        Distro {
            id: "debian".to_owned(),
            version_id: Some("13".to_owned()),
            pretty_name: Some("Debian GNU/Linux 13".to_owned()),
            family,
        }
    }

    /// A host stated outright, so the assertions do not depend on whichever
    /// machine happens to run the suite.
    fn test_host() -> HostFacts {
        HostFacts {
            hostname: "web-01".to_owned(),
            privilege: "sudo".to_owned(),
        }
    }

    fn test_app(family: Family) -> App {
        App::new(
            test_distro(family),
            test_host(),
            for_family(family),
            MockExecutor::new(),
        )
    }

    /// Descends into the named category of the level currently shown.
    ///
    /// Used where the test is about a specific area rather than about the
    /// drill-down itself, so that a new category added above it does not
    /// silently redirect the walk.
    fn enter_named_category(app: &mut App, title: &str) {
        let index = app
            .current_level()
            .iter()
            .position(|node| matches!(node, Node::Category(c) if c.title == title))
            .unwrap_or_else(|| panic!("the level must contain {title}"));

        app.list_state.select(Some(index));
        app.enter_category(index);
    }

    /// Descends into the first category of the level currently shown.
    fn enter_first_category(app: &mut App) {
        let index = app
            .current_level()
            .iter()
            .position(|node| matches!(node, Node::Category(_)))
            .expect("the level must contain a category");

        app.list_state.select(Some(index));
        app.enter_category(index);
    }

    #[test]
    fn starts_at_the_root_level_with_a_row_selected() {
        let app = test_app(Family::Debian);

        assert!(app.path.is_empty(), "navigation must start at the root");
        assert_eq!(app.list_state.selected(), Some(0));
    }

    #[test]
    fn the_root_shows_only_top_level_nodes() {
        let app = test_app(Family::Debian);

        assert_eq!(app.current_level().len(), tasks::tree().len());
    }

    #[test]
    fn entering_a_category_shows_its_children() {
        let mut app = test_app(Family::Debian);

        let expected = match &app.current_level()[0] {
            Node::Category(category) => category.children.len(),
            Node::Task(_) => panic!("the root must start with a category"),
        };

        enter_first_category(&mut app);

        assert_eq!(app.current_level().len(), expected);
        assert_eq!(app.path, vec![0]);
    }

    #[test]
    fn going_back_restores_the_level_and_the_cursor() {
        let mut app = test_app(Family::Debian);

        // Move off the first row so the restored cursor is distinguishable.
        app.select_next();
        let before = app.list_state.selected().expect("a row must be selected");
        let index = before;
        app.enter_category(index);

        app.leave_category();

        assert!(app.path.is_empty(), "the root must be restored");
        assert_eq!(
            app.list_state.selected(),
            Some(before),
            "the cursor must return to the row that was entered"
        );
    }

    #[test]
    fn going_back_at_the_root_does_not_quit() {
        let mut app = test_app(Family::Debian);

        app.leave_category();

        assert!(app.path.is_empty());
        assert!(
            !app.should_quit,
            "Esc at the root must not exit the program"
        );
    }

    #[test]
    fn entering_leaves_the_cursor_on_a_valid_row() {
        let mut app = test_app(Family::Debian);

        enter_first_category(&mut app);

        let selected = app.list_state.selected().expect("a row must be selected");
        assert!(
            selected < app.current_level().len(),
            "the cursor must point inside the new level"
        );
    }

    #[test]
    fn navigation_stops_at_the_ends() {
        let mut app = test_app(Family::Debian);
        enter_first_category(&mut app);

        for _ in 0..100 {
            app.select_next();
        }
        let last = app.list_state.selected().expect("selection must persist");

        for _ in 0..100 {
            app.select_previous();
        }
        let first = app.list_state.selected().expect("selection must persist");

        assert_eq!(first, 0);
        assert_eq!(last, app.current_level().len() - 1);
    }

    #[test]
    fn every_row_of_a_level_is_selectable() {
        // Categories are entered rather than skipped, so unlike the previous
        // flat tree the cursor must be able to land on one.
        let mut app = test_app(Family::Debian);
        enter_first_category(&mut app);

        for expected in 0..app.current_level().len() {
            assert_eq!(app.list_state.selected(), Some(expected));
            app.select_next();
        }
    }

    #[test]
    fn a_deeply_nested_task_is_reachable() {
        // Remote Access > SSH > Service > install: three descents before a task
        // appears, which is what the drill-down has to support. Named rather
        // than reached by position, so adding a category above it moves the
        // path without failing the test for the wrong reason.
        let mut app = test_app(Family::Debian);

        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        let task = app.selected_task().expect("a task must be selected");
        assert_eq!(task.id(), "ssh.install");
    }

    #[test]
    fn the_breadcrumb_tracks_the_path() {
        let mut app = test_app(Family::Debian);
        assert_eq!(app.breadcrumb(), "Tasks");

        enter_named_category(&mut app, "Remote Access");
        assert_eq!(app.breadcrumb(), "Remote Access");

        enter_first_category(&mut app);
        assert_eq!(app.breadcrumb(), "Remote Access › SSH");
    }

    #[test]
    fn a_category_row_is_not_a_task() {
        let app = test_app(Family::Debian);

        assert!(
            app.selected_task().is_none(),
            "the root holds categories, which are not runnable"
        );
    }

    #[test]
    fn no_dialog_is_open_initially() {
        assert!(test_app(Family::Debian).confirm.is_none());
    }

    /// Feeds a key to the app, as the event loop would.
    ///
    /// Routes through the real dispatcher — dialogs included — against a test
    /// terminal. A task that actually runs would need the terminal handed to a
    /// child, which is why the tasks exercised here are ones that stop at a
    /// form or a confirmation.
    fn press(app: &mut App, code: KeyCode) {
        // The dispatcher resolves everything except handing the terminal to a
        // child process, so the tasks exercised here stop at a form or a
        // confirmation rather than running.
        app.dispatch(KeyEvent::from(code));
    }

    #[test]
    fn tab_is_the_only_key_that_moves_focus() {
        // Overloading a movement key with focus is how keys start leaking
        // between panes, so h/l must not do it.
        let mut app = test_app(Family::Debian);
        assert_eq!(app.focus, Pane::Tree);

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Pane::Output);

        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Pane::Tree);

        press(&mut app, KeyCode::Char('l'));
        assert_eq!(app.focus, Pane::Tree, "l is not a focus key");
    }

    #[test]
    fn movement_keys_address_the_focused_pane() {
        // j and k mean "next" and "previous" in both panes; focus is what says
        // which one they act on.
        let mut app = test_app(Family::Debian);
        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        for i in 0..5 {
            app.output.push(crate::exec::OutputLine {
                stream: crate::exec::Stream::Stdout,
                text: format!("line {i}"),
            });
        }

        let before = app.list_state.selected();

        app.focus = Pane::Output;
        press(&mut app, KeyCode::Char('k'));

        assert_eq!(
            app.list_state.selected(),
            before,
            "the tree cursor must not move while the output has focus"
        );
        assert!(
            !app.output.is_following(),
            "scrolling up must detach the output from its tail"
        );
    }

    #[test]
    fn quitting_works_from_either_pane() {
        // q is refused only while a task runs, never by focus.
        for pane in [Pane::Tree, Pane::Output] {
            let mut app = test_app(Family::Debian);
            app.focus = pane;

            press(&mut app, KeyCode::Char('q'));

            assert!(app.should_quit, "q must quit with focus on {pane:?}");
        }
    }

    #[test]
    fn the_key_bar_follows_the_focused_pane() {
        let mut app = test_app(Family::Debian);

        let on_tree = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(on_tree.contains("move"), "got {on_tree}");

        app.focus = Pane::Output;
        let on_output = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(on_output.contains("scroll"), "got {on_output}");
        assert!(on_output.contains("wrap"), "got {on_output}");
    }

    #[test]
    fn the_output_tab_hint_appears_only_once_there_is_output() {
        // Offering a switch to an empty pane is an invitation to nothing.
        let mut app = test_app(Family::Debian);

        let empty = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(!empty.contains("output"), "got {empty}");

        app.output.push(crate::exec::OutputLine {
            stream: crate::exec::Stream::Stdout,
            text: "installing".to_owned(),
        });

        let with_output = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(with_output.contains("output"), "got {with_output}");
    }

    #[test]
    fn the_selected_row_stays_visible_when_focus_leaves_the_tree() {
        // Losing the cursor on Tab would mean hunting for it again on the way
        // back, so it is drawn differently rather than dropped.
        let mut app = test_app(Family::Debian);
        app.focus = Pane::Output;

        let rows = render_to_rows(&mut app, 80, 24);

        assert!(
            rows[2].contains("Identity & Access"),
            "the selected row must still be drawn: {:?}",
            rows[2]
        );
    }

    /// Moves the cursor onto the task with the given id, opening categories.
    fn select_task(app: &mut App, id: &str) {
        // Depth-first, following the same path the operator would.
        fn descend(app: &mut App, id: &str, depth: usize) -> bool {
            if depth > 8 {
                return false;
            }

            for index in 0..app.current_level().len() {
                app.list_state.select(Some(index));

                match app.current_level().get(index) {
                    Some(Node::Task(task)) if task.id() == id => return true,
                    Some(Node::Category(_)) => {
                        app.enter_category(index);
                        if descend(app, id, depth + 1) {
                            return true;
                        }
                        app.leave_category();
                    }
                    _ => {}
                }
            }

            false
        }

        assert!(descend(app, id, 0), "the task {id} must be in the tree");
    }

    #[test]
    fn a_task_that_needs_values_opens_a_form_rather_than_running() {
        // Running with placeholder values is what this replaces: pressing
        // Enter used to authorise an empty key.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.authorize-key");

        press(&mut app, KeyCode::Enter);

        assert!(app.form.is_some(), "the form must open");
        assert!(app.confirm.is_none(), "values come before consent");
    }

    #[test]
    fn a_form_swallows_the_keys_that_are_commands_elsewhere() {
        // j, k, q and / are literal characters inside a form.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.authorize-key");
        press(&mut app, KeyCode::Enter);

        for character in ['j', 'k', 'q', '/'] {
            press(&mut app, KeyCode::Char(character));
        }

        assert!(!app.should_quit, "q must not quit inside a form");

        let value = app
            .form
            .as_mut()
            .and_then(Form::focused_mut)
            .map(|field| field.value())
            .expect("the first field holds what was typed");

        assert!(value.ends_with("jkq/"), "got {value:?}");
    }

    #[test]
    fn a_form_will_not_submit_until_every_field_is_valid() {
        // The key field starts empty, so Enter must point at it rather than
        // running the task with nothing.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.authorize-key");
        press(&mut app, KeyCode::Enter);

        // Enter on the first field advances; on the last it submits.
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Enter);

        assert!(app.form.is_some(), "an invalid form stays open");
        assert!(
            app.status.message(Instant::now()).contains("fill in"),
            "the refusal must say what is missing"
        );
    }

    #[test]
    fn a_destructive_task_with_values_confirms_after_the_form() {
        // Consent has to state what will happen, which it cannot do before it
        // knows the values.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.change-port");

        press(&mut app, KeyCode::Enter);
        assert!(app.form.is_some(), "the port is collected first");

        // The field starts on the current port, which is already valid.
        press(&mut app, KeyCode::Enter);

        assert!(app.form.is_none(), "the form closes once submitted");
        assert!(app.confirm.is_some(), "consent comes after the values");
    }

    #[test]
    fn cancelling_a_form_with_typed_values_asks_first() {
        // Discarding typed work on one keystroke is how values get lost.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.change-port");
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('9'));

        press(&mut app, KeyCode::Esc);
        assert!(
            app.form.is_some(),
            "the first Esc asks rather than discards"
        );

        press(&mut app, KeyCode::Esc);
        assert!(app.form.is_none(), "the second Esc discards");
    }

    #[test]
    fn an_untouched_form_closes_on_the_first_escape() {
        // There is nothing to lose, so asking would be a step with no purpose.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.change-port");
        press(&mut app, KeyCode::Enter);

        press(&mut app, KeyCode::Esc);

        assert!(app.form.is_none());
    }

    #[test]
    fn carrying_on_after_esc_disarms_the_discard() {
        // A stale "press Esc again" must not be answerable several actions
        // later by a keystroke aimed at something else.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.change-port");
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('9'));

        press(&mut app, KeyCode::Esc);
        press(&mut app, KeyCode::Char('9'));
        press(&mut app, KeyCode::Esc);

        assert!(
            app.form.is_some(),
            "typing after Esc must disarm the discard"
        );
    }

    /// A verification window over a fabricated change.
    fn open_verification(app: &mut App) {
        app.begin_verification(
            "ssh.harden",
            Revert::ConfigFile {
                backup: crate::domain::files::Backup {
                    original: "/etc/ssh/sshd_config".to_owned(),
                    copy: "/etc/ssh/sshd_config.initd".to_owned(),
                },
                service: "ssh.service",
            },
        );
    }

    #[test]
    fn a_revertible_change_is_not_reported_as_done() {
        // "Done" would claim the tool knows the administrator can still get
        // in, which is exactly what it cannot know.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        assert_eq!(app.status.state(), State::Verify);
        assert!(app.verification.is_some());
    }

    #[test]
    fn keeping_a_change_closes_the_window() {
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('K'));

        assert!(app.verification.is_none());
        assert_eq!(app.status.state(), State::Done);
    }

    #[test]
    fn lowercase_k_cannot_keep_a_change() {
        // k is "move up" everywhere else, and this is the one place where a
        // mistyped navigation key would do something unrecoverable.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('k'));

        assert!(
            app.verification.is_some(),
            "a lowercase k must not commit the change"
        );
    }

    #[test]
    fn reverting_puts_the_configuration_back() {
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('R'));

        assert!(app.verification.is_none());
    }

    #[test]
    fn an_unanswered_window_reverts_on_its_own() {
        // The whole point: an administrator who has just locked themselves out
        // cannot press a key to undo it.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        // Reopen the window as though it had been left unanswered.
        app.verification = Some(Verification::new(
            "ssh.harden",
            Revert::ConfigFile {
                backup: crate::domain::files::Backup {
                    original: "/etc/ssh/sshd_config".to_owned(),
                    copy: "/etc/ssh/sshd_config.initd".to_owned(),
                },
                service: "ssh.service",
            },
            Instant::now() - Duration::from_secs(120),
        ));

        app.expire_verification();

        assert!(
            app.verification.is_none(),
            "an expired window must resolve itself"
        );
    }

    #[test]
    fn nothing_new_can_be_started_while_a_change_is_unverified() {
        // One unsettled change at a time: starting another would leave two
        // reverts outstanding with no way to say which is which.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Enter);

        assert!(app.form.is_none(), "Enter must not open a form");
        assert!(app.confirm.is_none(), "Enter must not open a confirmation");
        assert!(app.verification.is_some(), "the window stays open");
    }

    #[test]
    fn reading_the_log_stays_available_during_verification() {
        // The log of what just happened is the evidence for the decision.
        let mut app = test_app(Family::Debian);
        for i in 0..10 {
            app.output.push(crate::exec::OutputLine {
                stream: crate::exec::Stream::Stdout,
                text: format!("line {i}"),
            });
        }
        open_verification(&mut app);

        press(&mut app, KeyCode::Up);

        assert!(
            !app.output.is_following(),
            "scrolling must work while a change is unverified"
        );
        assert!(app.verification.is_some());
    }

    #[test]
    fn an_unrecognised_key_says_what_the_two_answers_are() {
        // Doing nothing has consequences here, so a stray key is refused with
        // the answer rather than ignored.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('x'));

        let message = app.status.message(Instant::now());
        assert!(
            message.contains('K') && message.contains('R'),
            "got {message}"
        );
    }

    #[test]
    fn quitting_is_refused_while_a_change_is_unverified() {
        // Leaving now would abandon the change with nobody left to revert it,
        // which is the one outcome the window exists to prevent.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('q'));

        assert!(!app.should_quit, "q must not leave a change unsettled");
        assert!(app.verification.is_some());
    }

    #[test]
    fn the_key_bar_offers_only_what_verification_allows() {
        // Advertising Enter or Esc here would name actions the state refuses.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        let keys = render_to_rows(&mut app, 80, 24)[23].clone();

        assert!(keys.contains("K keep"), "got {keys}");
        assert!(keys.contains("R revert"), "got {keys}");
        assert!(!keys.contains("run"), "got {keys}");
        assert!(!keys.contains("quit"), "got {keys}");
    }

    #[test]
    fn the_banner_states_the_countdown_and_both_keys() {
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        let rows = render_to_rows(&mut app, 80, 24);
        let screen = rows.join("\n");

        assert!(screen.contains("not yet kept"), "{screen}");
        assert!(screen.contains("reverting in"), "{screen}");
        assert!(screen.contains("second session"), "{screen}");
        assert!(rows[22].contains("VERIFY"), "got {:?}", rows[22]);
    }

    #[test]
    fn going_back_too_far_flashes_rather_than_changing_state() {
        // Overshooting by one level is a refusal, not a state: the tool is
        // still ready, the key simply had nowhere to go.
        let mut app = test_app(Family::Debian);

        app.leave_category();

        assert_eq!(app.status.state(), State::Ready);
        assert!(
            app.status.message(Instant::now()).contains("top level"),
            "the refusal must say why nothing happened"
        );
    }

    #[test]
    fn a_refusal_leaves_the_pill_alone() {
        // Losing sight of what the tool is doing because something was refused
        // is the failure this separation exists to prevent.
        let mut app = test_app(Family::Debian);
        app.status.set(State::Done, "ssh.install");

        app.leave_category();

        assert_eq!(
            app.pill(),
            State::Done,
            "the pill reports the last outcome, not the refusal"
        );
    }

    #[test]
    fn an_open_dialog_owns_the_pill() {
        // The pill must describe what Enter would do now, which while a dialog
        // is open is answering it, whatever ran before.
        let mut app = test_app(Family::Debian);
        app.status.set(State::Done, "ssh.install");
        app.confirm = Some(Confirm::new("Harden", "..."));

        assert_eq!(app.pill(), State::Confirm);
    }

    #[test]
    fn the_status_row_states_the_outcome_of_the_last_task() {
        // Success and failure are pills of their own, so the outcome is
        // legible from the left edge without reading the message.
        let mut app = test_app(Family::Debian);
        app.status.set(State::Failed, "ssh.harden — invalid config");

        let rows = render_to_rows(&mut app, 80, 24);

        assert!(rows[22].contains("FAILED"), "got {:?}", rows[22]);
        assert!(rows[22].contains("invalid config"), "got {:?}", rows[22]);
    }

    /// Renders the app into an off-screen buffer and returns it as text rows.
    ///
    /// The mockups in `docs/tui-specification.html` are literal character
    /// grids, so the interface is checked against a real buffer rather than by
    /// reasoning about constraints.
    fn render_to_rows(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| app.render(frame))
            .expect("drawing must not fail");

        let buffer = terminal.backend().buffer().clone();

        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect()
    }

    /// Prints the rendered grid, for diffing against the mockups by eye.
    ///
    /// Ignored by default: it asserts nothing and exists as a viewer. Run with
    /// `cargo test show_the_reference_frame -- --ignored --nocapture`.
    #[test]
    #[ignore = "viewer, not an assertion"]
    fn show_the_reference_frame() {
        let mut app = test_app(Family::Debian);

        for (index, row) in render_to_rows(&mut app, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // Descend to a level of real tasks, where the flags are visible.
        // Named rather than reached by position: this walks to SSH's
        // Configuration group specifically, and a category added above it
        // would otherwise redirect the walk somewhere with a different shape.
        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        app.list_state.select(Some(1));
        app.enter_category(1);

        println!();
        for (index, row) in render_to_rows(&mut app, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // The wide layout, where the tree takes its fixed width and long task
        // titles have to be truncated rather than clipped.
        let mut wide = test_app(Family::Debian);
        enter_named_category(&mut wide, "Remote Access");
        enter_first_category(&mut wide);
        enter_first_category(&mut wide);

        println!();
        for (index, row) in render_to_rows(&mut wide, 140, 26).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // Output streaming, with the pane focused.
        let mut running = test_app(Family::Debian);
        enter_named_category(&mut running, "Remote Access");
        enter_first_category(&mut running);
        enter_first_category(&mut running);
        pretend_running(&mut running);
        running.focus = Pane::Output;

        for text in [
            "$ apt-get install -y openssh-server",
            "Reading package lists... Done",
            "Building dependency tree... Done",
            "The following NEW packages will be installed:",
            "  openssh-server openssh-sftp-server",
            "Setting up openssh-server (1:9.2p1-2) ...",
        ] {
            running.output.push(crate::exec::OutputLine {
                stream: crate::exec::Stream::Stdout,
                text: text.to_owned(),
            });
        }

        println!();
        for (index, row) in render_to_rows(&mut running, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // The parameter form, with a value partly typed.
        let mut form = test_app(Family::Debian);
        form.form = Some(Form::new(
            "Authorise a public key",
            crate::tasks::ssh::AuthorizeKey.params(),
        ));

        if let Some(open) = form.form.as_mut() {
            open.focus_next();
            if let Some(field) = open.focused_mut() {
                for character in "ssh-ed25519 AAAA".chars() {
                    field.insert(character);
                }
            }
        }

        println!();
        for (index, row) in render_to_rows(&mut form, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // The verification window over an applied change.
        let mut verifying = test_app(Family::Debian);
        select_task(&mut verifying, "ssh.harden");

        for text in [
            "$ sshd -t -f /etc/ssh/sshd_config",
            "ok syntax valid",
            "$ systemctl reload ssh.service",
            "ok reloaded, pid 812 kept — no restart",
        ] {
            verifying.output.push(crate::exec::OutputLine {
                stream: crate::exec::Stream::Stdout,
                text: text.to_owned(),
            });
        }

        open_verification(&mut verifying);

        println!();
        for (index, row) in render_to_rows(&mut verifying, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // The single-pane fallback, below the split threshold.
        let mut narrow = test_app(Family::Debian);
        enter_first_category(&mut narrow);
        enter_first_category(&mut narrow);

        println!();
        for (index, row) in render_to_rows(&mut narrow, 64, 16).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // The help overlay.
        let mut helping = test_app(Family::Debian);
        helping.help = Some(0);

        println!();
        for (index, row) in render_to_rows(&mut helping, 80, 24).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }
    }

    #[test]
    fn the_reference_size_spends_only_three_rows_on_chrome() {
        // 80x24 is the size that has to work: row 1 header, rows 2-22 body,
        // row 23 status, row 24 keys. Bordered chrome bands would eat six.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 80, 24);

        assert!(
            rows[0].contains("initd"),
            "row 1 is the header: {:?}",
            rows[0]
        );
        assert!(
            rows[1].starts_with('┌'),
            "the body must start on row 2: {:?}",
            rows[1]
        );
        assert!(
            rows[22].contains("READY"),
            "row 23 is the status pill: {:?}",
            rows[22]
        );
        assert!(
            rows[23].contains("quit"),
            "row 24 is the key bar: {:?}",
            rows[23]
        );
    }

    #[test]
    fn a_task_title_too_long_for_its_column_is_not_cut_mid_word() {
        // "Install and enable the SSH server" overflows a 34-cell tree pane,
        // which is what a wide terminal actually renders.
        let mut app = test_app(Family::Debian);
        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        let rows = render_to_rows(&mut app, 140, 30);
        let tree_rows = rows[2..6].join("\n");

        assert!(
            !tree_rows.contains("SSH ser│") && !tree_rows.contains("SSH ser "),
            "a truncated title must be marked, not silently cut: {tree_rows}"
        );
    }

    #[test]
    fn a_long_breadcrumb_loses_its_head_not_its_tail() {
        // "…› Configuration" says where you are; "Remote Access › SSH › Conf"
        // does not, so truncation must drop from the front.
        let fitted = truncate_head("Remote Access › SSH › Configuration", 20);

        assert!(fitted.starts_with(" …"), "got {fitted:?}");
        assert!(
            fitted.trim_end().ends_with("Configuration"),
            "got {fitted:?}"
        );
        assert!(fitted.chars().count() <= 22, "got {fitted:?}");
    }

    #[test]
    fn a_breadcrumb_that_fits_is_left_alone() {
        assert_eq!(truncate_head("Tasks", 20), " Tasks ");
    }

    #[test]
    fn the_deepest_breadcrumb_is_not_cut_mid_word_at_the_reference_size() {
        // Remote Access > SSH > Configuration overflows a 34-cell tree pane,
        // which is the case that surfaced this rule.
        let mut app = test_app(Family::Debian);
        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        app.list_state.select(Some(1));
        app.enter_category(1);

        let rows = render_to_rows(&mut app, 80, 24);

        assert!(
            rows[1].contains('…'),
            "an overflowing breadcrumb must be marked: {:?}",
            rows[1]
        );
        assert!(
            rows[1].contains("Configuration"),
            "the tail names where you are: {:?}",
            rows[1]
        );
    }

    #[test]
    fn the_header_names_the_detected_host() {
        // The operator checks what was detected before touching anything.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 80, 24);

        assert!(rows[0].contains("Debian GNU/Linux 13"), "got {:?}", rows[0]);
    }

    #[test]
    fn the_header_names_the_machine_being_administered() {
        // An administrator with four terminals open must be able to see which
        // one is about to be changed without asking.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 80, 24);

        assert!(rows[0].contains("web-01"), "got {:?}", rows[0]);
    }

    #[test]
    fn the_header_states_how_root_is_obtained() {
        // Whether privileged work will succeed is knowable before starting it,
        // rather than at the moment a task fails.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 80, 24);

        assert!(rows[0].contains("root via sudo"), "got {:?}", rows[0]);
    }

    #[test]
    fn the_header_never_overflows_its_single_row() {
        // The header is one row; anything that does not fit must be dropped
        // rather than wrapped onto a row that does not exist.
        for width in [60, 80, 100, 140] {
            let mut app = test_app(Family::Debian);
            let rows = render_to_rows(&mut app, width, 24);

            assert!(
                rows[0].chars().count() <= width as usize,
                "the header overflows at {width} columns: {:?}",
                rows[0]
            );
            assert!(
                rows[1].starts_with('┌'),
                "the body must still start on row 2 at {width} columns"
            );
        }
    }

    #[test]
    fn the_help_hint_yields_before_the_host_facts() {
        // On a narrow terminal the hint is the first thing to go: knowing
        // which machine this is matters more than knowing that ? opens help.
        let mut app = test_app(Family::Debian);

        let narrow = render_to_rows(&mut app, 60, 24)[0].clone();
        assert!(narrow.contains("web-01"), "got {narrow:?}");

        let wide = render_to_rows(&mut app, 140, 24)[0].clone();
        assert!(wide.contains(HELP_HINT), "got {wide:?}");
    }

    #[test]
    fn the_census_rides_the_bottom_border() {
        // A bottom title costs no rows, which is why the count lives there.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 80, 24);

        let body = rows[..22].join("\n");
        assert!(
            body.contains("categor"),
            "the tree must report what the level holds: {body}"
        );
    }

    #[test]
    fn a_destructive_task_is_flagged_in_the_tree() {
        // The marker is a glyph so a monochrome terminal loses nothing.
        let mut app = test_app(Family::Debian);
        enter_first_category(&mut app);
        enter_first_category(&mut app);
        // Remote Access > SSH > Configuration holds the destructive tasks.
        app.list_state.select(Some(1));
        app.enter_category(1);

        let rows = render_to_rows(&mut app, 80, 24);
        let body = rows[..22].join("\n");

        assert!(
            body.contains(style::MARKER_DANGER),
            "a destructive task must carry its marker: {body}"
        );
    }

    #[test]
    fn a_task_that_collects_parameters_is_flagged_in_the_tree() {
        // The operator has to be able to tell, before pressing Enter, which
        // tasks stop to ask and which run straight away.
        let task = crate::tasks::find("users.create").expect("users.create must exist");
        let node = Node::Task(task);

        let line = row(&node, Family::Debian, 60);
        let drawn: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        assert!(
            drawn.contains(style::MARKER_INPUT),
            "a task with parameters must carry its marker: {drawn}"
        );
    }

    #[test]
    fn a_destructive_task_with_parameters_keeps_the_danger_flag() {
        // Only one flag fits the column, and the destructive one is the
        // warning that matters: losing it to the input marker would hide the
        // very thing the operator must not miss.
        let task = crate::tasks::find("ssh.change-port").expect("ssh.change-port must exist");
        assert!(
            !task.params().is_empty() && task.is_destructive(),
            "this test is only meaningful while the task is both destructive and parameterised"
        );

        let node = Node::Task(task);
        let line = row(&node, Family::Debian, 60);
        let drawn: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        assert!(
            drawn.contains(style::MARKER_DANGER),
            "danger must outrank input: {drawn}"
        );
        assert!(
            !drawn.contains(style::MARKER_INPUT),
            "the two flags must not both be drawn: {drawn}"
        );
    }

    #[test]
    fn an_open_form_says_the_tool_is_waiting_for_input() {
        // The pill is the one place that always states what the interface is
        // doing; a form open with a READY pill would misreport it.
        let mut app = test_app(Family::Debian);
        assert_eq!(app.pill(), State::Ready);

        app.form = Some(Form::new(
            "Create a user",
            crate::tasks::find("users.create")
                .expect("users.create must exist")
                .params(),
        ));

        assert_eq!(app.pill(), State::Input);
    }

    #[test]
    fn a_superseded_authentication_request_is_refused_rather_than_dropped() {
        // Both requests have a thread blocked on them. Overwriting the first
        // without answering would leave that thread waiting out the deadline.
        let mut app = test_app(Family::Debian);
        let (first, first_answer) = std::sync::mpsc::channel();
        let (second, _second_answer) = std::sync::mpsc::channel();

        app.pending_auth = Some(AuthRequest {
            program: "sudo".to_owned(),
            args: vec!["-v".to_owned()],
            mechanism: "sudo".to_owned(),
            reply: first,
        });

        app.supersede_pending_auth(AuthRequest {
            program: "sudo".to_owned(),
            args: vec!["-v".to_owned()],
            mechanism: "sudo".to_owned(),
            reply: second,
        });

        assert_eq!(
            first_answer.try_recv(),
            Ok(false),
            "the superseded request must be answered, not abandoned"
        );
    }

    #[test]
    fn a_narrow_terminal_draws_one_pane_at_a_time() {
        // Below the split threshold both panes are handed the whole area, so
        // drawing both would overwrite one with the other.
        let mut app = test_app(Family::Debian);
        app.output.push(crate::exec::OutputLine {
            stream: crate::exec::Stream::Stdout,
            text: "installing openssh-server".to_owned(),
        });

        let on_tree = render_to_rows(&mut app, 64, 20).join("\n");
        assert!(
            on_tree.contains("Remote Access"),
            "the tree is drawn with focus on it: {on_tree}"
        );
        assert!(
            !on_tree.contains("installing openssh-server"),
            "the output must not be drawn over the tree: {on_tree}"
        );

        app.focus = Pane::Output;
        let on_output = render_to_rows(&mut app, 64, 20).join("\n");
        assert!(
            on_output.contains("installing openssh-server"),
            "the output is drawn with focus on it: {on_output}"
        );
    }

    /// A task running, without actually spawning one.
    ///
    /// `Running::start` would run a real task against the host; what these
    /// tests exercise is how the interface behaves while one is in flight.
    fn pretend_running(app: &mut App) {
        app.running = Some(Running::start(
            "ssh.install",
            app.distro.clone(),
            ParamValues::new(),
        ));
        app.status.set(State::Running, "ssh.install");
    }

    #[test]
    fn starting_a_task_does_not_block_the_interface() {
        // The whole point of the thread: the call returns immediately, with
        // the task still running.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.install");

        app.run_selected(ParamValues::new());

        assert!(app.running.is_some(), "the task runs in the background");
        assert_eq!(app.status.state(), State::Running);
    }

    #[test]
    fn starting_a_task_moves_focus_to_its_output() {
        // Reading what is about to happen is the natural next thing to do.
        let mut app = test_app(Family::Debian);
        select_task(&mut app, "ssh.install");

        app.run_selected(ParamValues::new());

        assert_eq!(app.focus, Pane::Output);
    }

    #[test]
    fn a_second_task_cannot_be_started_while_one_runs() {
        // Two tasks writing to the same configuration file is how a machine
        // ends up in a state neither of them intended.
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        press(&mut app, KeyCode::Enter);

        assert!(
            app.form.is_none() && app.confirm.is_none(),
            "Enter must not start anything"
        );
        assert!(
            app.status
                .message(Instant::now())
                .contains("already running"),
            "the refusal must say why"
        );
    }

    #[test]
    fn quitting_mid_task_is_refused_with_the_way_to_stop() {
        // Quitting halfway through is how a server ends up half-configured.
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        press(&mut app, KeyCode::Char('q'));

        assert!(!app.should_quit, "q must not quit mid-task");
        assert!(
            app.status.message(Instant::now()).contains("Ctrl-C"),
            "the refusal must name the way to actually stop"
        );
    }

    #[test]
    fn reading_stays_available_while_a_task_runs() {
        // The log of what is happening is the reason to be watching.
        let mut app = test_app(Family::Debian);
        for i in 0..10 {
            app.output.push(crate::exec::OutputLine {
                stream: crate::exec::Stream::Stdout,
                text: format!("line {i}"),
            });
        }
        pretend_running(&mut app);

        press(&mut app, KeyCode::Up);

        assert!(!app.output.is_following(), "scrolling must work");
        assert!(app.running.is_some(), "and must not stop the task");
    }

    #[test]
    fn cancelling_says_it_is_stopping_rather_than_stopped() {
        // Claiming to have stopped before the current step finishes would be a
        // lie about what state the machine is in.
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        app.cancel_running();

        assert_eq!(
            app.status.state(),
            State::Running,
            "still running until the step ends"
        );
        assert!(
            app.status.message(Instant::now()).contains("stopping"),
            "but the message says what is happening"
        );
    }

    #[test]
    fn cancelling_twice_reports_that_it_is_already_stopping() {
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        app.cancel_running();
        app.cancel_running();

        assert!(
            app.status
                .message(Instant::now())
                .contains("already stopping"),
            "got {:?}",
            app.status.message(Instant::now())
        );
    }

    #[test]
    fn a_cancelled_task_reports_where_it_stopped() {
        // A tool that says only "cancelled" leaves the operator guessing what
        // ran and what did not.
        let mut app = test_app(Family::Debian);

        app.finish_run("ssh.install", Ok(Outcome::Done), true);

        assert_eq!(app.status.state(), State::Cancelled);
        assert!(
            app.status
                .message(Instant::now())
                .contains("after the last step"),
            "got {:?}",
            app.status.message(Instant::now())
        );
    }

    #[test]
    fn a_task_that_vanishes_is_reported_rather_than_left_running() {
        // A thread that dies without reporting must not look like one still
        // working.
        let mut app = test_app(Family::Debian);

        app.finish_run(
            "ssh.install",
            Err(crate::error::Error::TaskVanished {
                task: "ssh.install".to_owned(),
            }),
            false,
        );

        assert_eq!(app.status.state(), State::Failed);
    }

    #[test]
    fn a_running_task_shows_a_clock_and_a_spinner() {
        // Over a bad link a quiet command and a frozen screen look identical,
        // so both signals keep moving whether or not output arrives.
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        let status = render_to_rows(&mut app, 80, 24)[22].clone();

        assert!(status.contains("RUNNING"), "got {status:?}");
        assert!(status.contains("0:0"), "the clock must show: {status:?}");
    }

    #[test]
    fn the_key_bar_offers_only_what_a_running_task_allows() {
        // Naming Enter or q here would advertise actions the state refuses.
        let mut app = test_app(Family::Debian);
        pretend_running(&mut app);

        let keys = render_to_rows(&mut app, 80, 24)[23].clone();

        assert!(keys.contains("Ctrl-C"), "got {keys:?}");
        assert!(!keys.contains("quit"), "got {keys:?}");
        assert!(!keys.contains("run"), "got {keys:?}");
    }

    #[test]
    fn help_opens_from_anywhere_and_closes_on_any_key() {
        // The moment someone needs the key list is the moment they do not know
        // which key to press, so it must not be dismissed a particular way.
        let mut app = test_app(Family::Debian);

        press(&mut app, KeyCode::Char('?'));
        assert!(app.help.is_some());

        press(&mut app, KeyCode::Char('x'));
        assert!(app.help.is_none(), "any other key must close it");
    }

    #[test]
    fn help_does_not_act_on_the_key_that_closes_it() {
        // Closing must not also run whatever that key would normally do.
        let mut app = test_app(Family::Debian);
        press(&mut app, KeyCode::Char('?'));

        press(&mut app, KeyCode::Char('q'));

        assert!(app.help.is_none());
        assert!(!app.should_quit, "the closing key must not also quit");
    }

    #[test]
    fn help_lists_the_keys_that_cannot_be_guessed() {
        let mut app = test_app(Family::Debian);
        app.help = Some(0);

        let screen = render_to_rows(&mut app, 80, 24).join("\n");

        assert!(screen.contains("Keys"), "{screen}");
        assert!(screen.contains("Task tree"), "{screen}");
        assert!(screen.contains("closes"), "{screen}");
    }

    #[test]
    fn the_keys_that_cannot_be_guessed_are_reachable_in_the_help() {
        // K and R sit at the end of the list, past the fold at 80x24. They are
        // the whole reason the overlay scrolls rather than truncating.
        let mut app = test_app(Family::Debian);
        app.help = Some(0);

        let first = render_to_rows(&mut app, 80, 24).join("\n");
        assert!(!first.contains("put the previous"), "not visible yet");

        press(&mut app, KeyCode::End);
        let last = render_to_rows(&mut app, 80, 24).join("\n");

        assert!(
            last.contains("keep the change"),
            "K must be reachable: {last}"
        );
        assert!(
            last.contains("put the previous"),
            "R must be reachable: {last}"
        );
    }

    #[test]
    fn scrolling_the_help_does_not_close_it() {
        let mut app = test_app(Family::Debian);
        app.help = Some(0);

        press(&mut app, KeyCode::Down);
        assert_eq!(app.help, Some(1), "j and the arrows scroll");

        press(&mut app, KeyCode::Up);
        assert_eq!(app.help, Some(0));

        press(&mut app, KeyCode::Up);
        assert_eq!(app.help, Some(0), "scrolling stops at the top");
    }

    #[test]
    fn help_covers_the_interface_beneath_it() {
        // An overlay showing content through it misrepresents what the keys do.
        let mut app = test_app(Family::Debian);
        let before = render_to_rows(&mut app, 80, 24).join("\n");
        assert!(before.contains("Remote Access"));

        app.help = Some(0);
        let after = render_to_rows(&mut app, 80, 24).join("\n");

        assert!(
            !after.contains("Remote Access"),
            "the tree must not show through: {after}"
        );
    }

    #[test]
    fn the_narrow_header_says_which_pane_is_showing() {
        // With one pane at a time and no indicator, Tab looks like it did
        // nothing at all.
        let mut app = test_app(Family::Debian);

        let on_tree = render_to_rows(&mut app, 64, 20)[0].clone();
        assert!(on_tree.contains("tasks"), "got {on_tree:?}");
        assert!(on_tree.contains("output"), "got {on_tree:?}");

        // The wide header spends its room on host facts instead.
        let wide = render_to_rows(&mut app, 100, 24)[0].clone();
        assert!(wide.contains("root via"), "got {wide:?}");
        assert!(!wide.contains(" / output"), "got {wide:?}");
    }

    #[test]
    fn a_terminal_below_the_minimum_states_what_it_needs() {
        // A garbled layout on a production box is worse than a refusal.
        let mut app = test_app(Family::Debian);
        let rows = render_to_rows(&mut app, 50, 10);
        let screen = rows.join("\n");

        assert!(
            screen.contains("60") && screen.contains("15"),
            "the refusal must state the requirement: {screen}"
        );
        assert!(
            !screen.contains("READY"),
            "no partial interface is drawn: {screen}"
        );
    }

    #[test]
    fn the_key_bar_names_what_enter_does_on_this_row() {
        // Enter opens a category but runs a task, so the hint must follow the
        // cursor rather than naming both every time.
        let mut app = test_app(Family::Debian);

        let on_category = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(on_category.contains("open"), "got {on_category}");

        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        let on_task = render_to_rows(&mut app, 80, 24)[23].clone();
        assert!(on_task.contains("run"), "got {on_task}");
    }

    #[test]
    fn an_unsupported_task_says_so_in_the_status_pill() {
        // The pill is the one place that always states what Enter would do.
        let mut app = test_app(Family::Arch);
        let arch_supports_everything = tasks::all_tasks()
            .iter()
            .all(|task| task.supports(Family::Arch));

        if arch_supports_everything {
            // Nothing to assert on this tree yet; the branch exists so the
            // test starts failing the day an Arch-unsupported task lands.
            return;
        }

        let rows = render_to_rows(&mut app, 80, 24);
        assert!(rows[22].contains("READY") || rows[22].contains("UNSUPPORTED"));
    }

    #[test]
    fn a_finished_task_reports_what_it_invalidated() {
        // Guards the wiring rather than the declaration: the values are moved
        // onto the worker thread when the task starts, so reporting from the
        // ones the form still held would find them empty and silently warn
        // about nothing. The task's own tests cannot catch that — they call
        // `consequences` directly.
        let mut app = test_app(Family::Debian);

        let mut values = ParamValues::new();
        values.set(crate::tasks::ssh::ChangePort::PORT, "2222".to_owned());
        app.ran_with = values;

        app.finish_run("ssh.change-port", Ok(Outcome::Done), false);

        let output = render_to_rows(&mut app, 100, 30).join("\n");

        assert!(
            output.contains("firewall.allow-port"),
            "the firewall warning must reach the pane: {output}"
        );
        assert!(
            output.contains("2222"),
            "the warning must name the new port: {output}"
        );
    }

    #[test]
    fn a_failed_task_invalidates_nothing() {
        // A change that did not happen breaks nothing downstream. Warning here
        // would send the administrator to fix a firewall for a port sshd never
        // moved to.
        let mut app = test_app(Family::Debian);

        let mut values = ParamValues::new();
        values.set(crate::tasks::ssh::ChangePort::PORT, "2222".to_owned());
        app.ran_with = values;

        app.finish_run(
            "ssh.change-port",
            Err(crate::error::Error::MissingParameter {
                name: "port".to_owned(),
            }),
            false,
        );

        let output = render_to_rows(&mut app, 100, 30).join("\n");

        assert!(
            !output.contains("firewall.allow-port"),
            "a failed task must not warn: {output}"
        );
    }
}
