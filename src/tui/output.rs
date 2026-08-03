//! Live output pane.
//!
//! Holds the lines a running task produces and renders them as they arrive.
//! State is kept separate from drawing so it can be tested without a terminal.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::exec::{OutputLine, Stream};

/// Maximum lines retained.
///
/// A package installation can emit thousands of lines; keeping them all would
/// grow without bound on a long-running session.
const MAX_LINES: usize = 2_000;

/// Accumulated output of the current task.
#[derive(Debug, Default)]
pub struct OutputPane {
    lines: Vec<OutputLine>,
    /// How far the view is scrolled from the bottom, in lines.
    scroll_offset: usize,
}

impl OutputPane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a line, trimming the oldest once the cap is reached.
    pub fn push(&mut self, line: OutputLine) {
        self.lines.push(line);

        if self.lines.len() > MAX_LINES {
            self.lines.remove(0);
        }
    }

    /// Discards all output, for when a new task starts.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.scroll_offset = 0;
    }

    /// Whether anything has been produced yet.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Number of retained lines.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Scrolls towards older output.
    pub fn scroll_up(&mut self, amount: usize) {
        self.scroll_offset = (self.scroll_offset + amount).min(self.lines.len().saturating_sub(1));
    }

    /// Scrolls back towards the newest output.
    pub fn scroll_down(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    /// Renders the pane, following the newest output unless scrolled away.
    pub fn render(&self, frame: &mut Frame, area: Rect, title: &str) {
        let text: Vec<Line> = self
            .lines
            .iter()
            .map(|line| {
                // stderr is highlighted so warnings stand out from progress.
                let style = match line.stream {
                    Stream::Stdout => Style::default(),
                    Stream::Stderr => Style::default().fg(Color::Yellow),
                };
                Line::styled(line.text.clone(), style)
            })
            .collect();

        // The visible height excludes the block's top and bottom borders.
        let viewport = area.height.saturating_sub(2) as usize;
        let scroll = self
            .lines
            .len()
            .saturating_sub(viewport)
            .saturating_sub(self.scroll_offset);

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title.to_owned()),
            )
            .wrap(Wrap { trim: false })
            .scroll((scroll as u16, 0));

        frame.render_widget(paragraph, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> OutputLine {
        OutputLine {
            stream: Stream::Stdout,
            text: text.to_owned(),
        }
    }

    #[test]
    fn starts_empty() {
        assert!(OutputPane::new().is_empty());
    }

    #[test]
    fn accumulates_lines() {
        let mut pane = OutputPane::new();
        pane.push(line("one"));
        pane.push(line("two"));

        assert_eq!(pane.len(), 2);
    }

    #[test]
    fn caps_retained_lines() {
        // A long install must not grow memory without bound.
        let mut pane = OutputPane::new();
        for i in 0..MAX_LINES + 100 {
            pane.push(line(&format!("line {i}")));
        }

        assert_eq!(pane.len(), MAX_LINES);
    }

    #[test]
    fn clearing_resets_scroll_as_well() {
        let mut pane = OutputPane::new();
        pane.push(line("one"));
        pane.scroll_up(1);
        pane.clear();

        assert!(pane.is_empty());
        assert_eq!(pane.scroll_offset, 0);
    }

    #[test]
    fn scrolling_stays_within_bounds() {
        let mut pane = OutputPane::new();
        for i in 0..5 {
            pane.push(line(&format!("line {i}")));
        }

        pane.scroll_up(100);
        assert!(
            pane.scroll_offset < pane.len(),
            "cannot scroll past the top"
        );

        pane.scroll_down(100);
        assert_eq!(pane.scroll_offset, 0, "cannot scroll past the bottom");
    }
}
