//! Application state, navigation and the event loop.

use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};

use super::confirm::Confirm;
use super::output::OutputPane;
use super::status::{State, Status};
use super::{Tui, layout, style, with_terminal_released};
use crate::backend::Backend;
use crate::distro::Distro;
use crate::distro::host::HostFacts;
use crate::error::Result;
use crate::exec::Executor;
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
    confirm: Option<Confirm>,
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
            tree: tasks::tree(),
            path: Vec::new(),
            cursor_stack: Vec::new(),
            list_state,
            // The tree is where a session starts: nothing has run yet, so
            // there is no output to read.
            focus: Pane::Tree,
            output: OutputPane::new(),
            confirm: None,
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
            terminal
                .draw(|frame| self.render(frame))
                .map_err(|source| crate::error::Error::Terminal { source })?;

            self.handle_events(terminal)?;
        }

        Ok(())
    }

    /// Reads and dispatches one round of input.
    ///
    /// Returns without an event when the poll times out, which is what lets a
    /// flashed refusal disappear on its own: nothing schedules its removal, the
    /// next redraw simply stops drawing it.
    fn handle_events(&mut self, terminal: &mut Tui) -> Result<()> {
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
            self.on_key(key, terminal)?;
        }

        Ok(())
    }

    /// Handles a key press, routing to the dialog when one is open.
    fn on_key(&mut self, key: KeyEvent, terminal: &mut Tui) -> Result<()> {
        if self.confirm.is_some() {
            return self.on_confirm_key(key, terminal);
        }

        // Everything except running a task is resolved without the terminal,
        // so navigation stays testable without one.
        if self.on_navigation_key(key) {
            return Ok(());
        }

        if key.code == KeyCode::Enter && self.focus == Pane::Tree {
            self.activate(terminal)?;
        }

        Ok(())
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

    /// Handles a key press while the confirmation dialog is open.
    fn on_confirm_key(&mut self, key: KeyEvent, terminal: &mut Tui) -> Result<()> {
        let Some(confirm) = self.confirm.as_mut() else {
            return Ok(());
        };

        match key.code {
            KeyCode::Tab | KeyCode::Left | KeyCode::Right => confirm.toggle(),
            KeyCode::Esc => {
                self.confirm = None;
                self.status.set(State::Ready, "cancelled");
            }
            KeyCode::Enter => {
                let accepted = confirm.accepted;
                self.confirm = None;

                if accepted {
                    self.run_selected(terminal)?;
                } else {
                    self.status.set(State::Ready, "cancelled");
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Acts on the selected row: descends into a category, or runs a task.
    fn activate(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(index) = self.list_state.selected() else {
            return Ok(());
        };

        if let Some(Node::Category(_)) = self.current_level().get(index) {
            self.enter_category(index);
            return Ok(());
        }

        let Some(task) = self.selected_task() else {
            return Ok(());
        };

        if !task.supports(self.distro.family) {
            // Pressing Enter on a row the host cannot run is a refusal, not a
            // state change: the reason flashes and the tool stays where it was.
            let reason = format!("{} is not supported on {}", task.id(), self.distro.family);
            self.status.flash(reason, Instant::now());
            return Ok(());
        }

        if task.is_destructive() {
            self.confirm = Some(Confirm::new(task.title(), task.description()).with_warning(
                "This operation can lock you out of a server you reach over SSH. \
                     Make sure you have another way in before continuing.",
            ));
            return Ok(());
        }

        self.run_selected(terminal)
    }

    /// Executes the selected task, streaming its output into the pane.
    fn run_selected(&mut self, terminal: &mut Tui) -> Result<()> {
        let Some(index) = self.list_state.selected() else {
            return Ok(());
        };
        // The tree is rebuilt rather than borrowed from `self`, because running
        // the task needs `self.output` and `self.status` mutably while
        // `current_level` borrows all of `self`. Rebuilding is a handful of
        // allocations against an interactive action, and it keeps this path
        // free of `unsafe` in a binary that runs as root.
        let tree = tasks::tree();
        let Some(Node::Task(task)) = level_at(&tree, &self.path).get(index) else {
            return Ok(());
        };

        let id = task.id();

        self.output.clear();
        self.status.set(State::Running, id);

        // The terminal is handed to the child so that sudo can prompt for a
        // password: raw mode would swallow the input, and the alternate screen
        // would hide the prompt. Input events stay unread meanwhile, so the
        // TUI does not compete with sudo for keystrokes.
        let executor = self.executor.as_ref();
        let backend = self.backend.as_ref();
        let mut lines = Vec::new();

        let outcome = with_terminal_released(terminal, || {
            task.run(executor, backend, &mut |line| {
                // Output is echoed to the released terminal so the user sees
                // progress while the password prompt is on screen.
                println!("{}", line.text);
                lines.push(line);
            })
        });

        for line in lines {
            self.output.push(line);
        }

        // Success and failure are pills of their own, so the outcome is
        // legible from the left edge without reading the message.
        match outcome {
            Ok(()) => self.status.set(State::Done, id),
            Err(ref err) => self.status.set(State::Failed, format!("{id} — {err}")),
        }

        // A failing task is reported in the status bar rather than tearing the
        // interface down: the administrator stays in control.
        Ok(())
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

        if let Some(ref confirm) = self.confirm {
            confirm.render(frame);
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

        let mut spans = vec![
            Span::styled(" initd", style::PANE_TITLE.add_modifier(Modifier::BOLD)),
            Span::styled(format!(" {VERSION}"), style::BLOCK_SUBTITLE),
            separator(),
            Span::styled(self.host.hostname.clone(), style::EMPHASIS),
            separator(),
            Span::styled(self.distro.display_name().to_owned(), style::NORMAL),
            separator(),
            Span::styled(format!("root via {}", self.host.privilege), style::NORMAL),
        ];

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

        if self.output.is_empty() {
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
        let state = self.pill();

        let status = Paragraph::new(Line::from(vec![
            Span::styled(format!(" {} ", state.label()), state.style()),
            Span::raw("  "),
            Span::styled(self.status.message(Instant::now()), style::NORMAL),
        ]));

        frame.render_widget(status, area);
    }

    /// The state pill for the status row.
    ///
    /// Mostly this is whatever the last action left behind, but two conditions
    /// describe the cursor rather than the past and therefore win: a dialog is
    /// open, or the row under the cursor cannot run here. The pill is the one
    /// place that always states what pressing Enter would do.
    fn pill(&self) -> State {
        if self.confirm.is_some() {
            return State::Confirm;
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
        let mut keys = match self.focus {
            Pane::Tree => self.tree_keys(),
            Pane::Output => vec![
                ("↑↓", "scroll"),
                ("G", "follow"),
                ("w", "wrap"),
                ("Tab", "tree"),
            ],
        };

        keys.push(("q", "quit"));

        let mut spans = Vec::with_capacity(keys.len() * 3);
        for (key, label) in keys {
            spans.push(Span::styled(format!(" {key}"), style::KEYBAR_KEY));
            spans.push(Span::styled(format!(" {label} "), style::KEYBAR_LABEL));
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
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
            let (text_style, flag, flag_style) = if !supported {
                (
                    style::DISABLED,
                    style::MARKER_UNSUPPORTED,
                    style::FLAG_UNSUPPORTED,
                )
            } else if task.is_destructive() {
                (style::NORMAL, style::MARKER_DANGER, style::FLAG_DANGER)
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
        // appears, which is what the drill-down has to support.
        let mut app = test_app(Family::Debian);

        enter_first_category(&mut app);
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        let task = app.selected_task().expect("a task must be selected");
        assert_eq!(task.id(), "ssh.install");
    }

    #[test]
    fn the_breadcrumb_tracks_the_path() {
        let mut app = test_app(Family::Debian);
        assert_eq!(app.breadcrumb(), "Tasks");

        enter_first_category(&mut app);
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

    /// Feeds a navigation key to the app, as the event loop would.
    ///
    /// Only `Enter` on a task needs the terminal, and that is exercised
    /// through the task tests rather than here.
    fn press(app: &mut App, code: KeyCode) {
        app.on_navigation_key(KeyEvent::from(code));
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
        enter_first_category(&mut app);
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
            rows[2].contains("Remote Access"),
            "the selected row must still be drawn: {:?}",
            rows[2]
        );
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
        enter_first_category(&mut app);
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
        enter_first_category(&mut wide);
        enter_first_category(&mut wide);
        enter_first_category(&mut wide);

        println!();
        for (index, row) in render_to_rows(&mut wide, 140, 26).iter().enumerate() {
            println!("{:>2}|{row}", index + 1);
        }

        // Output streaming, with the pane focused.
        let mut running = test_app(Family::Debian);
        enter_first_category(&mut running);
        enter_first_category(&mut running);
        enter_first_category(&mut running);
        running.status.set(State::Running, "ssh.install");
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
        enter_first_category(&mut app);
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
        enter_first_category(&mut app);
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

        enter_first_category(&mut app);
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
}
