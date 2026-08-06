//! Application state, navigation and the event loop.

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::widgets::ListState;

use super::auth::AuthRequest;
use super::confirm::Confirm;
use super::cursor::TreeCursor;
use super::form::Form;
use super::output::OutputPane;
use super::search::Search;
use super::signals::Hangup;
use super::status::{State, Status};
use super::verify::Verification;
use super::worker::Running;
use super::{Tui, render};
use crate::backend::Backend;
use crate::distro::Distro;
use crate::distro::host::HostFacts;
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::{Lang, Msg};
use crate::tasks::params::ParamValues;
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
pub(super) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lines a page key moves the output by.
pub(super) const PAGE_SCROLL: usize = 10;

/// Rows the verification banner occupies: its top border and four lines.
pub(super) const VERIFY_BANNER_ROWS: u16 = 5;

/// Lines a page key moves the help overlay by.
pub(super) const HELP_PAGE: u16 = 10;

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
    pub(super) const fn other(self) -> Self {
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
/// Which of the interface's states is in effect, in precedence order.
///
/// Derived from [`App::mode`] rather than stored, so there is exactly one
/// definition of what wins and the compiler requires every reader to answer
/// for each state. Borrows what it names, since every caller only reads.
pub(super) enum Mode<'a> {
    /// The help overlay is open, above everything else.
    Help,
    /// A task is running; nothing new may be started.
    ///
    /// Carries nothing: what the interface needs to draw about a running task
    /// — its spinner, its clock — is read from `running` where the borrow can
    /// be mutable, and every decision made from the mode is about *which*
    /// state this is rather than what is in it.
    Running,
    /// A change is applied and waiting to be kept or put back.
    Verifying,
    /// A parameter form is collecting values.
    ///
    /// Also carries nothing: `Form::render` needs `&mut self` for its scroll
    /// state, which a mode borrowing the rest of `App` could not lend.
    Filling,
    /// A destructive task is waiting to be confirmed.
    Confirming(&'a Confirm),
    /// A search is open over the task tree.
    Searching(&'a Search),
    /// The tree, with nothing modal on top of it.
    Browsing,
}

/// The running application.
///
/// Navigation is drill-down: exactly one level of the tree is on screen at a
/// time, and entering a category replaces the list with its children.
pub struct App {
    pub(super) distro: Distro,
    /// Facts about the machine, probed once at startup.
    pub(super) host: HostFacts,
    pub(super) backend: Box<dyn Backend>,
    pub(super) executor: Box<dyn Executor>,
    /// Where the operator is in the tree, and which row is under the cursor.
    ///
    /// Its own type because it depends on nothing else here — no executor, no
    /// backend, no terminal — and because the two stacks inside it have to
    /// move together. Keeping them in one place means the only code that can
    /// desynchronise them is the code whose job they are.
    pub(super) cursor: TreeCursor,
    /// Which pane the movement keys currently address.
    pub(super) focus: Pane,
    pub(super) output: OutputPane,
    /// The parameter form, while one is being filled in.
    pub(super) form: Option<Form>,
    pub(super) confirm: Option<Confirm>,
    /// A helper waiting for the terminal, until the next turn of the loop.
    ///
    /// Held rather than served where it arrives: draining happens without the
    /// terminal in hand, and restoring the screen needs it.
    pub(super) pending_auth: Option<AuthRequest>,
    /// Values collected from the form, held until the task actually runs.
    ///
    /// A destructive task with parameters passes through the form and then the
    /// confirmation, and the values have to survive the step between.
    pub(super) pending_values: ParamValues,

    /// The values the running task was started with.
    ///
    /// Separate from `pending_values`, which is emptied when the task is
    /// launched. Consequences are declared from what the task actually ran
    /// with — moving to port 2222 invalidates a firewall rule naming 22, while
    /// re-running with 22 invalidates nothing — so reporting them needs the
    /// values to outlive the launch.
    pub(super) ran_with: ParamValues,
    /// The task currently running, if any.
    pub(super) running: Option<Running>,
    /// An applied change waiting to be kept or put back.
    pub(super) verification: Option<Verification>,
    /// The open search, while one is being typed.
    ///
    /// Semi-modal like the verification window rather than fully modal like a
    /// form: it takes the keyboard, but the pane beside it keeps rendering, so
    /// a task's output stays readable while looking for the next one to run.
    pub(super) search: Option<Search>,
    /// Raised when the session this interface runs in is going away.
    ///
    /// Default in tests and where registration was declined: a flag nothing
    /// ever raises simply never fires, which is the behaviour that preceded it.
    hangup: Hangup,
    /// How far the help overlay is scrolled, while it is showing.
    ///
    /// `None` means it is closed: the overlay has no state worth keeping
    /// between openings, and it always starts at the top.
    pub(super) help: Option<u16>,
    pub(super) status: Status,
    /// The locale every user-facing string is rendered through.
    ///
    /// Resolved once here rather than per message. Errors reach the catalogue
    /// rarely enough that `Lang::from_env()` at the call site cost nothing, but
    /// the interface's own chrome is rendered on every frame — a key bar alone
    /// is a dozen labels — and reading the environment that often is a new hot
    /// path for an answer that cannot change while the process runs.
    pub(super) lang: Lang,
    pub(super) should_quit: bool,
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
            cursor: TreeCursor::new(tasks::tree()),
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
            search: None,
            hangup: Hangup::default(),
            lang: Lang::from_env(),
            should_quit: false,
        }
    }

    /// Gives the interface a flag raised when the session is going away.
    ///
    /// Separate from `new` so that a caller which could not register — and a
    /// test, which has no session to lose — gets an interface that behaves
    /// exactly as it did before, rather than one that must pretend.
    #[must_use]
    pub fn watching_for_hangup(mut self, hangup: Hangup) -> Self {
        self.hangup = hangup;
        self
    }

    /// What the interface is doing, as one answer rather than six flags.
    ///
    /// The modal state is held as six independent `Option`s, which between them
    /// can represent far more combinations than are reachable — a form open
    /// while a task runs, a countdown beside a confirmation. None of those
    /// happen, because the transitions never build them; but *nothing in the
    /// type says so*, and four separate places used to decide which one wins by
    /// testing the same fields in their own order.
    ///
    /// They had already drifted. `dispatch` refused a key to everything below
    /// `running`, while `pill` asked about `confirm` first and would have named
    /// a dialog during a task; `render` drew `confirm` and `form` with
    /// independent `if`s, so both would appear at once if both existed. No bug
    /// today, since the states cannot arise — but the correctness rested on
    /// four readings agreeing, and two of them no longer did.
    ///
    /// So precedence is stated once, here, and everything else matches on the
    /// answer. Deriving it rather than replacing the fields keeps the change
    /// to what it is worth: an `enum` holding the payloads would touch every
    /// site that reads or sets one, for the same guarantee this already gives
    /// the four readers that matter.
    pub(super) fn mode(&self) -> Mode<'_> {
        // Help sits above everything: it is asked for from wherever the
        // operator is stuck, including on top of a dialog.
        if self.help.is_some() {
            return Mode::Help;
        }

        self.mode_under_help()
    }

    /// The mode ignoring the help overlay, for the renderer.
    ///
    /// Help draws *over* another state rather than instead of it, so what it
    /// was opened on top of still has to be painted underneath. Every other
    /// caller wants [`Self::mode`], which reports the state that owns the
    /// keyboard.
    pub(super) fn mode_under_help(&self) -> Mode<'_> {
        // Then the two that refuse to start anything new, running first: a
        // task in flight outranks a window over a change already applied.
        if self.running.is_some() {
            return Mode::Running;
        }

        if self.verification.is_some() {
            return Mode::Verifying;
        }

        // Then the ways of starting something, innermost first. Search opens
        // over the tree and a form opens over what search found, so a form
        // takes the keyboard from the search that led to it.
        if self.form.is_some() {
            return Mode::Filling;
        }

        if let Some(ref confirm) = self.confirm {
            return Mode::Confirming(confirm);
        }

        if let Some(ref search) = self.search {
            return Mode::Searching(search);
        }

        Mode::Browsing
    }

    /// The nodes of the level currently on screen.
    pub(super) fn current_level(&self) -> &[Node] {
        self.cursor.current_level()
    }

    /// The node under the cursor, if any.
    pub(super) fn selected_node(&self) -> Option<&Node> {
        self.cursor.selected_node()
    }

    /// Titles from the root to the level on screen, for the breadcrumb.
    pub(super) fn breadcrumb(&self) -> String {
        self.cursor.breadcrumb()
    }

    /// Descends into the category under the cursor.
    pub(super) fn enter_category(&mut self, index: usize) {
        self.cursor.enter_category(index);
        self.status.set(State::Ready, "");
    }

    /// Returns to the parent level, restoring the cursor it was left on.
    ///
    /// At the root there is nowhere to go, so this reports rather than quits:
    /// `q` is the way out, and an `Esc` that sometimes exits the program would
    /// make going back one level too far a destructive mistake. The cursor
    /// answers whether it moved; phrasing the refusal is the interface's job.
    pub(super) fn leave_category(&mut self) {
        if !self.cursor.leave_category() {
            // A refusal, not a state: the tool is still ready, the key simply
            // had nowhere to go.
            self.status.flash(
                self.lang.render(&Msg::StatusAlreadyAtTopLevel),
                Instant::now(),
            );
        }
    }

    /// Runs the event loop until the user quits.
    pub fn run(&mut self, terminal: &mut Tui) -> Result<()> {
        while !self.should_quit {
            // First of all: a session that is ending takes the interface with
            // it, so anything still owed to the operator is owed now.
            if self.hangup.received() {
                self.resolve_on_hangup();
                break;
            }

            // Both before drawing: output that has arrived should appear in
            // this frame, and an expired window should never be shown with a
            // countdown that has already run out.
            self.poll_running();
            self.expire_verification();

            // Before drawing, not after: the frame this loop is about to paint
            // would land on top of the helper's prompt.
            self.serve_pending_auth(terminal)?;

            terminal
                .draw(|frame| render::all(frame, self))
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

    /// The task currently under the cursor, if the cursor is on one.
    pub(super) fn selected_task(&self) -> Option<&dyn Task> {
        self.cursor.selected_task()
    }

    /// Whether pressing Enter on the selected row would do anything.
    ///
    /// A category always would — it opens. A task only where this host
    /// supports it. Categories answer `true` rather than being excluded, so a
    /// row that *is* actionable is never drawn as if it were not.
    pub(super) fn selected_is_runnable(&self) -> bool {
        self.selected_task()
            .is_none_or(|task| task.supports(self.distro.family))
    }

    /// Moves the cursor down one row.
    ///
    /// Every row of a level is selectable now that categories are entered
    /// rather than skipped over.
    pub(super) fn select_next(&mut self) {
        self.cursor.select_next();
    }

    /// Moves the cursor up one row.
    pub(super) fn select_previous(&mut self) {
        self.cursor.select_previous();
    }

    /// Moves the cursor to the first row of the level.
    pub(super) fn select_first(&mut self) {
        self.cursor.select_first();
    }

    /// Moves the cursor to the last row of the level.
    pub(super) fn select_last(&mut self) {
        self.cursor.select_last();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The rendering tests stayed here rather than moving with the code they
    // exercise: they share `test_app` and the navigation helpers with the
    // tests that drive the keys, and splitting them would mean keeping two
    // copies of the fixtures in step. `render` is a sibling module, so
    // reaching into it costs nothing.
    use super::super::render::{self, row, truncate_head};
    use super::super::{layout, style};
    use crate::distro::Family;
    use crate::tui::fixtures::{enter_first_category, enter_named_category, test_app, test_distro};
    // Named here rather than at the top of the file: the production code that
    // used these moved to the sibling modules, and only the tests still reach
    // for them from here.
    use crate::error::Error;
    use crate::tasks::revert::{Outcome, Revert};
    use crossterm::event::{KeyCode, KeyEvent};
    use ratatui::layout::Rect;

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

        let before = app.cursor.selected();

        app.focus = Pane::Output;
        press(&mut app, KeyCode::Char('k'));

        assert_eq!(
            app.cursor.selected(),
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
                app.cursor.list_state().select(Some(index));

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
    fn losing_the_session_puts_an_unconfirmed_change_back() {
        // The case the window exists for, and the one it used to miss. The
        // countdown lived only in this process, so an `ssh.harden` that severed
        // the administrator's own connection took the interface down with it —
        // and the configuration that locked them out was the one left in place,
        // the screen having promised that silence would restore it.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        app.hangup.raise();
        app.resolve_on_hangup();

        assert!(
            app.verification.is_none(),
            "a change nobody confirmed must go back when the session ends"
        );
        assert!(
            app.status
                .message(Instant::now())
                .contains("the session ended"),
            "the report must say why it went back: {:?}",
            app.status.message(Instant::now())
        );
    }

    #[test]
    fn losing_the_session_with_nothing_pending_reverts_nothing() {
        // The other direction: a hangup is not itself a reason to undo work,
        // only a reason to stop waiting for a confirmation that cannot arrive.
        let mut app = test_app(Family::Debian);

        app.hangup.raise();
        app.resolve_on_hangup();

        assert_eq!(app.status.state(), State::Ready);
    }

    #[test]
    fn a_kept_change_survives_the_session_ending() {
        // Keeping is a confirmation, so it closes the window outright. Nothing
        // is left for a hangup to put back, and a later signal must not undo a
        // change the administrator explicitly accepted.
        let mut app = test_app(Family::Debian);
        open_verification(&mut app);

        press(&mut app, KeyCode::Char('K'));
        assert!(app.verification.is_none(), "keeping must close the window");

        app.hangup.raise();
        app.resolve_on_hangup();

        assert_ne!(
            app.status.state(),
            State::Failed,
            "a kept change must not be reverted by a later hangup"
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
            render::pill(&app),
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

        assert_eq!(render::pill(&app), State::Confirm);
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
    /// The interface is checked against a real buffer rather than by reasoning
    /// about constraints: a layout that satisfies every constraint on paper can
    /// still put a row somewhere nobody can read it.
    fn render_to_rows(app: &mut App, width: u16, height: u16) -> Vec<String> {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| render::all(frame, app))
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

    /// Renders and returns the colour pair the selected tree row was drawn with.
    ///
    /// The companion of [`render_to_rows`], which keeps only the symbols. A
    /// selection style carries no text of its own, so a row's *appearance* is
    /// unassertable from the grid alone — and the difference between a cursor
    /// that invites Enter and one that does not is entirely appearance.
    ///
    /// The cell is read two columns in. One is the border itself, which is
    /// drawn in the pane's own style and would answer `BORDER_FOCUSED` for
    /// every row — the reading that made the first version of this helper
    /// report cyan regardless of what the highlight had done.
    fn selected_row_style(
        app: &mut App,
        width: u16,
        height: u16,
    ) -> (Option<ratatui::style::Color>, Option<ratatui::style::Color>) {
        // Below the split width only one pane is drawn, and the tree's
        // rectangle is then whichever pane holds focus — so reading it with
        // focus elsewhere would report the output pane's style as if it were a
        // row's, plausibly and wrongly. Refused here rather than left to
        // produce a colour pair that looks like an answer.
        assert_eq!(
            app.focus,
            Pane::Tree,
            "this reads the tree's rectangle, so the tree must be drawn in it"
        );

        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| render::all(frame, app))
            .expect("drawing must not fail");

        let buffer = terminal.backend().buffer().clone();

        // The tree's own rectangle, asked of the same layout the renderer used,
        // rather than guessed. Computing the row from the list offset alone
        // lands on the pane title and reports the *border's* style for every
        // row — which is what the first version of this helper did, and why it
        // answered cyan whatever the highlight had done.
        let body = layout::frame(Rect::new(0, 0, width, height)).body;
        let (tree, _) = layout::body(body, layout::BodyLayout::for_width(body.width));
        let selected = app
            .cursor
            .list_state()
            .selected()
            .expect("a row must be selected");
        let offset = app.cursor.offset();

        // One row down for the pane's top border, one column in for its left.
        let y = tree.y + 1 + u16::try_from(selected - offset).expect("a visible row");

        // The colour pair alone. A rendered cell also carries whatever the row
        // beneath the highlight contributed — `underline_color`, and the `DIM`
        // an unsupported row's own text style adds — so comparing whole
        // `Style`s would fail on differences the highlight did not make.
        let cell = buffer[(tree.x + 1, y)].style();

        (cell.fg, cell.bg)
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
        app.cursor.list_state().select(Some(1));
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
        app.cursor.list_state().select(Some(1));
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
        assert!(
            wide.contains(&Lang::En.render(&Msg::HeaderHelpHint)),
            "got {wide:?}"
        );
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
        app.cursor.list_state().select(Some(1));
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
        assert_eq!(render::pill(&app), State::Ready);

        app.form = Some(Form::new(
            "Create a user",
            crate::tasks::find("users.create")
                .expect("users.create must exist")
                .params(),
        ));

        assert_eq!(render::pill(&app), State::Input);
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
        // ran and what did not, so the command it stopped before is named.
        let mut app = test_app(Family::Debian);

        app.finish_run(
            "ssh.install",
            Err(Error::Cancelled {
                before: "systemctl restart ssh.service".to_owned(),
            }),
            true,
        );

        assert_eq!(app.status.state(), State::Cancelled);
        assert!(
            app.status
                .message(Instant::now())
                .contains("systemctl restart ssh.service"),
            "got {:?}",
            app.status.message(Instant::now())
        );
    }

    /// Types a query into an open search, one key at a time.
    fn type_query(app: &mut App, query: &str) {
        for character in query.chars() {
            press(app, KeyCode::Char(character));
        }
    }

    #[test]
    fn one_state_owns_the_keyboard_even_when_several_are_set() {
        // The states below cannot arise together through any transition — but
        // nothing in the type says so, and four places used to decide which
        // one wins by testing the same fields in their own order. Two had
        // already drifted: `pill` asked about `confirm` before `running`, and
        // `render` drew `confirm` and `form` with independent `if`s.
        //
        // Setting them by hand is the only way to ask what the readers would
        // do if they ever disagreed. They now all read `mode`, so the answer
        // is one answer.
        let mut app = test_app(Family::Debian);

        app.confirm = Some(Confirm::new("Harden", "dangerous"));
        app.form = Some(Form::new(
            "Change the port",
            vec![crate::tasks::params::Param::new(
                "port",
                "Port",
                crate::tasks::params::ParamKind::Port,
            )],
        ));

        assert!(
            matches!(app.mode(), Mode::Filling),
            "a form outranks the confirmation it was opened from"
        );

        app.running = Some(Running::start(
            "ssh.install",
            test_distro(Family::Debian),
            ParamValues::new(),
        ));

        assert!(
            matches!(app.mode(), Mode::Running),
            "a running task outranks every way of starting another"
        );

        app.help = Some(0);

        assert!(
            matches!(app.mode(), Mode::Help),
            "help is asked for from wherever the operator is stuck"
        );
        assert!(
            matches!(app.mode_under_help(), Mode::Running),
            "and the state underneath still has to be drawn"
        );
    }

    #[test]
    fn the_key_bar_names_only_what_the_current_state_accepts() {
        // The bar is derived from the same `mode` the dispatcher routes on, so
        // it cannot advertise a key the state would refuse. `q` is the one
        // worth pinning: it is refused while work is outstanding, and a bar
        // offering it there names the one action that cannot be taken.
        let mut app = test_app(Family::Debian);

        assert!(
            rendered_keys(&mut app).contains("q"),
            "browsing may be quit: {:?}",
            rendered_keys(&mut app)
        );

        app.running = Some(Running::start(
            "ssh.install",
            test_distro(Family::Debian),
            ParamValues::new(),
        ));

        let keys = rendered_keys(&mut app);

        assert!(!keys.contains(" q "), "a running task refuses q: {keys:?}");
        assert!(keys.contains("Ctrl-C"), "and offers the way out: {keys:?}");
    }

    /// The key bar as one string, for asserting what it offers.
    ///
    /// Drawn through the whole interface rather than in isolation, since the
    /// bar is one of the things a narrow terminal drops and asserting on it
    /// out of context would not notice.
    fn rendered_keys(app: &mut App) -> String {
        render_to_rows(app, 100, 30).join("\n")
    }

    #[test]
    fn search_jumps_the_cursor_to_the_task_it_found() {
        // The point of searching: reaching a task without knowing which of the
        // six areas holds it. A result that cannot be jumped to is a list.
        let mut app = test_app(Family::Debian);

        press(&mut app, KeyCode::Char('/'));
        type_query(&mut app, "wireguard.install");
        press(&mut app, KeyCode::Enter);

        assert!(app.search.is_none(), "jumping must close the search");
        assert_eq!(
            app.selected_task().map(Task::id),
            Some("wireguard.install"),
            "the cursor must land on the task, in its own level"
        );
    }

    #[test]
    fn a_search_result_is_reached_by_the_same_route_as_any_other_task() {
        // Navigating rather than running: a jump that started the task would
        // skip the confirmation and the parameter form, making a mistyped
        // query the most dangerous key in the interface.
        let mut app = test_app(Family::Debian);

        press(&mut app, KeyCode::Char('/'));
        type_query(&mut app, "wireguard.install");
        press(&mut app, KeyCode::Enter);

        assert!(app.running.is_none(), "the jump must not start anything");
        assert!(app.form.is_none(), "nor open the form on its own");

        // And the breadcrumb reflects where the cursor actually is, so leaving
        // the category goes somewhere that makes sense.
        assert!(
            app.breadcrumb().contains("WireGuard"),
            "got {:?}",
            app.breadcrumb()
        );
    }

    #[test]
    fn a_slash_typed_into_a_query_is_literal() {
        // `/` opens search; inside one it is an ordinary character, and a task
        // id could contain it. Reopening would discard what had been typed.
        let mut app = test_app(Family::Debian);

        press(&mut app, KeyCode::Char('/'));
        type_query(&mut app, "ssh/");

        let query = app.search.as_ref().map(Search::query);

        assert_eq!(query, Some("ssh/"), "the slash belongs in the query");
    }

    #[test]
    fn escape_closes_the_search_without_moving_the_cursor() {
        let mut app = test_app(Family::Debian);
        let before = app.cursor.selected();

        press(&mut app, KeyCode::Char('/'));
        type_query(&mut app, "wireguard");
        press(&mut app, KeyCode::Esc);

        assert!(app.search.is_none());
        assert_eq!(
            app.cursor.selected(),
            before,
            "abandoning a search must leave the cursor where it was"
        );
    }

    #[test]
    fn search_is_refused_while_a_task_is_running() {
        // Only one task at a time, so the keys that would start another are
        // refused rather than queued — search exists to start one.
        let mut app = test_app(Family::Debian);
        app.running = Some(Running::start(
            "ssh.install",
            test_distro(Family::Debian),
            ParamValues::new(),
        ));

        press(&mut app, KeyCode::Char('/'));

        assert!(app.search.is_none(), "a running task must refuse search");
    }

    #[test]
    fn a_failure_is_readable_in_the_pane_rather_than_only_in_the_status_row() {
        // The status row is one line and is not truncated with an ellipsis, so
        // a package manager's stderr arriving through `CommandFailed` was cut
        // mid-sentence with nowhere to read the rest. The pane can be scrolled
        // and pasted into a bug report; the row keeps the summary.
        let mut app = test_app(Family::Debian);

        app.finish_run(
            "ssh.install",
            Err(Error::CommandFailed {
                command: "apt-get install -y openssh-server".to_owned(),
                code: 100,
                stderr: "E: Unable to locate package openssh-server".to_owned(),
            }),
            false,
        );

        assert_eq!(app.status.state(), State::Failed);
        assert!(
            app.output
                .lines()
                .iter()
                .any(|line| line.text.contains("Unable to locate package")),
            "the detail must be readable in the pane: {:?}",
            app.output.lines()
        );
    }

    #[test]
    fn a_task_that_finished_before_stopping_is_not_called_cancelled() {
        // The bug this guards: the interface used to report CANCELLED from the
        // operator having *asked*, so a task that ran to completion was shown
        // as stopped. Acting on that belief is how a change gets applied twice.
        let mut app = test_app(Family::Debian);

        app.finish_run("ssh.install", Ok(Outcome::Done), true);

        assert_eq!(
            app.status.state(),
            State::Done,
            "a task that finished must be reported as done, not cancelled"
        );
    }

    #[test]
    fn a_near_miss_is_said_out_loud_rather_than_dropped() {
        // The operator pressed a key and is owed an answer, even when the task
        // beat them to the finish.
        let mut app = test_app(Family::Debian);

        app.finish_run("ssh.install", Ok(Outcome::Done), true);

        assert!(
            app.output
                .lines()
                .iter()
                .any(|line| line.text.contains("finished before it could be stopped")),
            "got {:?}",
            app.output.lines()
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
        // Driven onto a task that is genuinely refused rather than hoping the
        // cursor lands on one: the old version returned early when the family
        // supported everything, so it could pass having rendered nothing.
        let mut app = test_app(Family::Rhel);

        jump_to_unsupported(&mut app, Family::Rhel);

        let rows = render_to_rows(&mut app, 80, 24);

        assert!(
            rows.iter().any(|row| row.contains("UNSUPPORTED")),
            "the pill must name the refusal: {rows:#?}"
        );
    }

    #[test]
    fn the_cursor_on_an_unsupported_task_is_not_drawn_as_an_invitation() {
        // The blue cursor reads as "press Enter", and pressing it here does
        // nothing — which looks like the interface dropping the key rather than
        // the host refusing the task. The pill and the detail pane both say so,
        // but only after the eye has moved off the row.
        //
        // Colour is not carrying this alone: the same row already shows
        // `MARKER_UNSUPPORTED` in its flag column, so a monochrome terminal
        // loses nothing.
        let mut app = test_app(Family::Rhel);

        jump_to_unsupported(&mut app, Family::Rhel);

        assert_eq!(
            selected_row_style(&mut app, 80, 24),
            (style::SELECTION_DISABLED.fg, style::SELECTION_DISABLED.bg),
            "a row that cannot run must not wear the cursor that invites Enter"
        );
    }

    #[test]
    fn the_cursor_on_a_runnable_task_still_invites_enter() {
        // The other direction, and the reason it is a separate test: a
        // predicate stuck at `false` would satisfy the assertion above while
        // drawing every row in the tree as refused. Neither scenario catches
        // that alone.
        let mut app = test_app(Family::Debian);

        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);

        assert_eq!(
            selected_row_style(&mut app, 80, 24),
            (style::SELECTION_FOCUSED.fg, style::SELECTION_FOCUSED.bg),
            "a runnable row must keep the ordinary cursor"
        );
    }

    #[test]
    fn an_unsupported_task_explains_itself_rather_than_only_refusing() {
        // The reason used to live in a test table, where the operator being
        // told "unsupported" could never see it — while the comment above the
        // tree claimed unsupported tasks stayed visible *with their reason*.
        // Dimming a row says that it is refused; only this says why, which is
        // the difference between a missing package, a policy, and a bug.
        let mut app = test_app(Family::Rhel);

        let expected = jump_to_unsupported(&mut app, Family::Rhel);
        let rows = render_to_rows(&mut app, 100, 30).join(" ");

        // The first few words, since the panel wraps and the reasons are long.
        let opening: String = expected
            .split_whitespace()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            rows.contains("Not available on"),
            "the detail must say the task cannot run here: {rows}"
        );
        assert!(
            rows.contains(&opening),
            "and must carry the reason ({opening:?}): {rows}"
        );
    }

    /// Puts the cursor on a task this family refuses, and returns the reason.
    ///
    /// Panics rather than skipping if every task is supported: a helper that
    /// quietly did nothing would make both tests above pass on a tree where
    /// they assert nothing.
    fn jump_to_unsupported(app: &mut App, family: Family) -> &'static str {
        let (location, reason) = tasks::located_tasks(&tasks::tree())
            .into_iter()
            .find_map(|(location, task)| {
                task.unsupported_reason(family)
                    .map(|reason| (location, reason))
            })
            .expect("some task must be unsupported on this family");

        app.cursor.jump_to(&location.path, location.index);
        reason
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
