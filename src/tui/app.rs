//! Application state, navigation and the event loop.

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use super::confirm::Confirm;
use super::output::OutputPane;
use super::{Tui, with_terminal_released};
use crate::backend::Backend;
use crate::distro::Distro;
use crate::error::Result;
use crate::exec::Executor;
use crate::tasks::{self, Node, Task};

/// How long to wait for a key before redrawing.
///
/// Short enough that the interface stays responsive, long enough that an idle
/// TUI does not spin the CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Marks a row that opens onto another level.
const CATEGORY_MARKER: &str = "› ";

/// Marks a runnable row, keeping task titles aligned with category ones.
const TASK_MARKER: &str = "  ";

/// The running application.
///
/// Navigation is drill-down: exactly one level of the tree is on screen at a
/// time, and entering a category replaces the list with its children.
pub struct App {
    distro: Distro,
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
    output: OutputPane,
    confirm: Option<Confirm>,
    status: String,
    should_quit: bool,
}

impl App {
    /// Builds the application for a detected system.
    pub fn new(
        distro: Distro,
        backend: Box<dyn Backend>,
        executor: impl Executor + 'static,
    ) -> Self {
        let mut list_state = ListState::default();

        // The root level is never empty, so the cursor always has a row.
        list_state.select(Some(0));

        Self {
            distro,
            backend,
            executor: Box::new(executor),
            tree: tasks::tree(),
            path: Vec::new(),
            cursor_stack: Vec::new(),
            list_state,
            output: OutputPane::new(),
            confirm: None,
            status: "Ready".to_owned(),
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
        self.status = "Ready".to_owned();
    }

    /// Returns to the parent level, restoring the cursor it was left on.
    ///
    /// At the root there is nowhere to go, so this reports rather than quits:
    /// `q` is the way out, and an `Esc` that sometimes exits the program would
    /// make going back one level too far a destructive mistake.
    fn leave_category(&mut self) {
        if self.path.pop().is_none() {
            self.status = "Already at the top level".to_owned();
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

        match key.code {
            // `q` quits from any level; `Esc` means "go back", so that leaving
            // one level too many cannot drop the user out of the program.
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                self.leave_category();
            }
            KeyCode::Down | KeyCode::Char('j') => self.select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.select_previous(),
            KeyCode::PageUp => self.output.scroll_up(10),
            KeyCode::PageDown => self.output.scroll_down(10),
            KeyCode::Enter => self.activate(terminal)?,
            _ => {}
        }

        Ok(())
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
                self.status = "Cancelled".to_owned();
            }
            KeyCode::Enter => {
                let accepted = confirm.accepted;
                self.confirm = None;

                if accepted {
                    self.run_selected(terminal)?;
                } else {
                    self.status = "Cancelled".to_owned();
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
            self.status = format!("{} is not supported on {}", task.id(), self.distro.family);
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
        self.status = format!("Running {id}...");

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

        self.status = match outcome {
            Ok(()) => format!("{id} finished"),
            Err(ref err) => format!("{id} failed: {err}"),
        };

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

    /// Draws the whole interface.
    fn render(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_header(frame, chunks[0]);
        self.render_body(frame, chunks[1]);
        self.render_status(frame, chunks[2]);

        if let Some(ref confirm) = self.confirm {
            confirm.render(frame);
        }
    }

    /// Draws the header naming the detected system.
    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let header = Paragraph::new(Line::from(vec![
            Span::styled("initd", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("  —  "),
            Span::raw(self.distro.display_name().to_owned()),
            Span::raw("  ("),
            Span::raw(self.backend.family().to_string()),
            Span::raw(")"),
        ]))
        .block(Block::default().borders(Borders::ALL));

        frame.render_widget(header, area);
    }

    /// Draws the task tree beside the output pane.
    fn render_body(&mut self, frame: &mut Frame, area: Rect) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        let items: Vec<ListItem> = self
            .current_level()
            .iter()
            .map(|node| match node {
                // The marker tells a category apart from a task at a glance;
                // with one level on screen there is no indentation to do it.
                Node::Category(category) => ListItem::new(Line::styled(
                    format!("{}{}", CATEGORY_MARKER, category.title),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Node::Task(task) => {
                    // Unsupported tasks stay visible but greyed out, with the
                    // reason, rather than being hidden.
                    let supported = task.supports(self.distro.family);
                    let style = if supported {
                        Style::default()
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let suffix = if supported {
                        String::new()
                    } else {
                        format!("  (not supported on {})", self.distro.family)
                    };

                    ListItem::new(Line::styled(
                        format!("{}{}{}", TASK_MARKER, task.title(), suffix),
                        style,
                    ))
                }
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.breadcrumb()),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, columns[0], &mut self.list_state);

        if self.output.is_empty() {
            // With no output yet, the pane describes what the selection does.
            // A category has no description of its own, so it reports what it
            // holds rather than leaving the pane blank.
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

            let paragraph = Paragraph::new(description)
                .block(Block::default().borders(Borders::ALL).title("Description"))
                .wrap(Wrap { trim: true });

            frame.render_widget(paragraph, columns[1]);
        } else {
            self.output.render(frame, columns[1], "Output");
        }
    }

    /// Draws the status bar and key hints.
    ///
    /// What `Enter` does depends on the row under the cursor, so the hint says
    /// which of the two it is rather than naming both every time.
    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let bold = Style::default().add_modifier(Modifier::BOLD);

        let enter_hint = match self.selected_node() {
            Some(Node::Category(_)) => " open  ",
            _ => " run  ",
        };

        let mut spans = vec![
            Span::raw(self.status.clone()),
            Span::raw("   |   "),
            Span::styled("↑↓", bold),
            Span::raw(" navigate  "),
            Span::styled("Enter", bold),
            Span::raw(enter_hint),
        ];

        // Going back is only offered where there is somewhere to go back to.
        if !self.path.is_empty() {
            spans.push(Span::styled("Esc", bold));
            spans.push(Span::raw(" back  "));
        }

        spans.push(Span::styled("q", bold));
        spans.push(Span::raw(" quit"));

        let status =
            Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL));

        frame.render_widget(status, area);
    }
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

    fn test_app(family: Family) -> App {
        App::new(test_distro(family), for_family(family), MockExecutor::new())
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
}
