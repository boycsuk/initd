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
use crate::tasks::{self, Task};

/// How long to wait for a key before redrawing.
///
/// Short enough that the interface stays responsive, long enough that an idle
/// TUI does not spin the CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A flattened entry of the task tree: either a group heading or a task.
enum Entry {
    Group(&'static str),
    Task(Box<dyn Task>),
}

/// The running application.
pub struct App {
    distro: Distro,
    backend: Box<dyn Backend>,
    executor: Box<dyn Executor>,
    entries: Vec<Entry>,
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
        let entries = flatten_tree();
        let mut list_state = ListState::default();

        // Start on the first selectable row rather than on a heading.
        list_state.select(first_task_index(&entries));

        Self {
            distro,
            backend,
            executor: Box::new(executor),
            entries,
            list_state,
            output: OutputPane::new(),
            confirm: None,
            status: "Ready".to_owned(),
            should_quit: false,
        }
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
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
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

    /// Runs the selected task, asking for confirmation when it is destructive.
    fn activate(&mut self, terminal: &mut Tui) -> Result<()> {
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
        let Some(Entry::Task(task)) = self.entries.get(index) else {
            return Ok(());
        };

        self.output.clear();
        self.status = format!("Running {}...", task.id());

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
            Ok(()) => format!("{} finished", task.id()),
            Err(ref err) => format!("{} failed: {err}", task.id()),
        };

        // A failing task is reported in the status bar rather than tearing the
        // interface down: the administrator stays in control.
        Ok(())
    }

    /// The task currently under the cursor, if the cursor is on one.
    fn selected_task(&self) -> Option<&dyn Task> {
        match self.entries.get(self.list_state.selected()?) {
            Some(Entry::Task(task)) => Some(task.as_ref()),
            _ => None,
        }
    }

    /// Moves the cursor to the next task, skipping headings.
    fn select_next(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);
        let next = ((current + 1)..self.entries.len())
            .find(|&i| matches!(self.entries[i], Entry::Task(_)));

        if let Some(next) = next {
            self.list_state.select(Some(next));
        }
    }

    /// Moves the cursor to the previous task, skipping headings.
    fn select_previous(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);
        let previous = (0..current)
            .rev()
            .find(|&i| matches!(self.entries[i], Entry::Task(_)));

        if let Some(previous) = previous {
            self.list_state.select(Some(previous));
        }
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
            .entries
            .iter()
            .map(|entry| match entry {
                Entry::Group(title) => ListItem::new(Line::styled(
                    (*title).to_owned(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Entry::Task(task) => {
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

                    ListItem::new(Line::styled(format!("  {}{}", task.title(), suffix), style))
                }
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Tasks"))
            .highlight_style(
                Style::default()
                    .bg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, columns[0], &mut self.list_state);

        if self.output.is_empty() {
            // With no output yet, the pane describes what the selection does.
            let description = self
                .selected_task()
                .map_or_else(String::new, |task| task.description().to_owned());

            let paragraph = Paragraph::new(description)
                .block(Block::default().borders(Borders::ALL).title("Description"))
                .wrap(Wrap { trim: true });

            frame.render_widget(paragraph, columns[1]);
        } else {
            self.output.render(frame, columns[1], "Output");
        }
    }

    /// Draws the status bar and key hints.
    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let status = Paragraph::new(Line::from(vec![
            Span::raw(self.status.clone()),
            Span::raw("   |   "),
            Span::styled("↑↓", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" navigate  "),
            Span::styled("Enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" run  "),
            Span::styled("q", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" quit"),
        ]))
        .block(Block::default().borders(Borders::ALL));

        frame.render_widget(status, area);
    }
}

/// Flattens the task tree into rows for the list widget.
fn flatten_tree() -> Vec<Entry> {
    tasks::tree()
        .into_iter()
        .flat_map(|group| {
            std::iter::once(Entry::Group(group.title))
                .chain(group.tasks.into_iter().map(Entry::Task))
        })
        .collect()
}

/// Index of the first task row, skipping group headings.
fn first_task_index(entries: &[Entry]) -> Option<usize> {
    entries
        .iter()
        .position(|entry| matches!(entry, Entry::Task(_)))
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

    #[test]
    fn starts_on_a_task_not_a_heading() {
        let app = test_app(Family::Debian);
        let selected = app
            .list_state
            .selected()
            .expect("something must be selected");

        assert!(matches!(app.entries[selected], Entry::Task(_)));
    }

    #[test]
    fn navigation_skips_group_headings() {
        let mut app = test_app(Family::Debian);

        for _ in 0..app.entries.len() {
            app.select_next();
            let selected = app.list_state.selected().expect("selection must persist");
            assert!(
                matches!(app.entries[selected], Entry::Task(_)),
                "the cursor must never land on a heading"
            );
        }
    }

    #[test]
    fn navigation_stops_at_the_ends() {
        let mut app = test_app(Family::Debian);

        // Past the end: the selection must stay on the last task.
        for _ in 0..100 {
            app.select_next();
        }
        let last = app.list_state.selected().expect("selection must persist");

        for _ in 0..100 {
            app.select_previous();
        }
        let first = app.list_state.selected().expect("selection must persist");

        assert!(first < last, "the cursor must move between the two ends");
        assert!(matches!(app.entries[first], Entry::Task(_)));
        assert!(matches!(app.entries[last], Entry::Task(_)));
    }

    #[test]
    fn the_tree_contains_every_task() {
        let app = test_app(Family::Debian);
        let tasks = app
            .entries
            .iter()
            .filter(|entry| matches!(entry, Entry::Task(_)))
            .count();

        assert_eq!(
            tasks,
            tasks::tree()
                .into_iter()
                .map(|g| g.tasks.len())
                .sum::<usize>()
        );
    }

    #[test]
    fn no_dialog_is_open_initially() {
        assert!(test_app(Family::Debian).confirm.is_none());
    }
}
