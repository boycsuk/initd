//! Live output pane.
//!
//! Holds the lines a running task produces and renders them as they arrive.
//! State is kept separate from drawing so it can be tested without a terminal.
//!
//! Two properties matter beyond showing text:
//!
//! 1. **Appending is O(1).** A package manager emits thousands of lines; a ring
//!    buffer drops the oldest without moving the rest.
//! 2. **The view follows the tail until the operator scrolls.** Watching a
//!    command run and reading back through what it did are different jobs, and
//!    the pane must not fight whichever one is in progress.

use std::collections::VecDeque;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use super::style;
use crate::exec::{OutputLine, Stream};

/// Maximum lines retained.
///
/// A package installation can emit thousands of lines; keeping them all would
/// grow without bound on a long-running session. The full transcript is not
/// lost by this — the pane is a window, not the record.
const MAX_LINES: usize = 5_000;

/// Marks the position the next line will be written at.
///
/// A visible write position distinguishes "the command is quiet" from "the
/// screen has stopped updating", which over a slow link look identical.
const WRITE_CURSOR: &str = "▌";

/// Accumulated output of the current task.
#[derive(Debug)]
pub struct OutputPane {
    /// The retained lines, oldest first.
    ///
    /// A `VecDeque` rather than a `Vec`: dropping the oldest line from a `Vec`
    /// shifts every remaining element, which at this cap means thousands of
    /// moves per line once the buffer is full.
    lines: VecDeque<OutputLine>,
    /// How far the view is scrolled from the bottom, in lines.
    scroll_offset: usize,
    /// Whether the view is pinned to the newest output.
    ///
    /// Set false by any scroll key and restored by jumping to the tail, so
    /// reading back through a log is never interrupted by new arrivals.
    follow: bool,
    /// Whether long lines wrap or run off the right edge.
    wrap: bool,
}

impl Default for OutputPane {
    fn default() -> Self {
        Self {
            lines: VecDeque::new(),
            scroll_offset: 0,
            // Watching is the common case: a task is started and then read.
            follow: true,
            wrap: true,
        }
    }
}

impl OutputPane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a line, dropping the oldest once the cap is reached.
    pub fn push(&mut self, line: OutputLine) {
        if self.lines.len() == MAX_LINES {
            self.lines.pop_front();
        }

        self.lines.push_back(line);
    }

    /// Discards all output, for when a new task starts.
    ///
    /// Follow mode is restored: a new task is something to watch, whatever the
    /// operator was doing with the previous one's output.
    pub fn clear(&mut self) {
        self.lines.clear();
        self.scroll_offset = 0;
        self.follow = true;
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

    /// Whether the view is pinned to the newest output.
    #[cfg(test)]
    pub const fn is_following(&self) -> bool {
        self.follow
    }

    /// Scrolls towards older output, detaching from the tail.
    pub fn scroll_up(&mut self, amount: usize) {
        self.follow = false;
        self.scroll_offset = (self.scroll_offset + amount).min(self.lines.len().saturating_sub(1));
    }

    /// Scrolls back towards the newest output.
    ///
    /// Reaching the bottom re-attaches: the operator has caught up, and having
    /// to press another key to resume following would be a step with no
    /// purpose.
    pub fn scroll_down(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);

        if self.scroll_offset == 0 {
            self.follow = true;
        }
    }

    /// Jumps to the newest output and follows it again.
    pub fn scroll_to_tail(&mut self) {
        self.scroll_offset = 0;
        self.follow = true;
    }

    /// Toggles wrapping of long lines.
    pub const fn toggle_wrap(&mut self) {
        self.wrap = !self.wrap;
    }

    /// Renders the pane, following the newest output unless scrolled away.
    ///
    /// The title states whether the view is pinned, because a pane that has
    /// silently stopped updating and one that is following a quiet command
    /// look the same.
    pub fn render(&self, frame: &mut Frame, area: Rect, title: &str, focused: bool) {
        let mut text: Vec<Line> = self.lines.iter().map(render_line).collect();

        // The cursor marks where the next line lands, so a quiet command is
        // distinguishable from a frozen screen.
        if self.follow {
            text.push(Line::from(Span::styled(WRITE_CURSOR, style::OUTPUT_CURSOR)));
        }

        let status = if self.follow { "follow" } else { "detached" };

        // The visible height excludes the block's top and bottom borders.
        let viewport = area.height.saturating_sub(2) as usize;
        let scroll = text
            .len()
            .saturating_sub(viewport)
            .saturating_sub(self.scroll_offset);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(style::border(focused))
            .title(Span::styled(format!(" {title} "), style::PANE_TITLE))
            .title_bottom(Span::styled(format!(" {status} "), style::BLOCK_SUBTITLE));

        let mut paragraph = Paragraph::new(text).block(block).scroll((scroll as u16, 0));

        if self.wrap {
            paragraph = paragraph.wrap(Wrap { trim: false });
        }

        frame.render_widget(paragraph, area);
    }
}

/// Styles one line according to the stream it came from.
fn render_line(line: &OutputLine) -> Line<'static> {
    let style = match line.stream {
        Stream::Stdout => style::NORMAL,
        // stderr is highlighted so warnings stand out from progress. It is not
        // treated as an error: plenty of tools report progress on stderr.
        Stream::Stderr => style::OUTPUT_WARN,
    };

    Line::styled(line.text.clone(), style)
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
    fn starts_empty_and_following() {
        let pane = OutputPane::new();

        assert!(pane.is_empty());
        assert!(pane.is_following(), "a new task is something to watch");
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
    fn the_oldest_line_is_the_one_dropped() {
        // Dropping from the wrong end would discard the output the operator is
        // currently watching rather than the history behind it.
        let mut pane = OutputPane::new();
        for i in 0..MAX_LINES + 1 {
            pane.push(line(&format!("line {i}")));
        }

        assert_eq!(
            pane.lines.front().expect("a line must remain").text,
            "line 1"
        );
        assert_eq!(
            pane.lines.back().expect("a line must remain").text,
            format!("line {MAX_LINES}")
        );
    }

    #[test]
    fn clearing_resets_scroll_and_resumes_following() {
        let mut pane = OutputPane::new();
        pane.push(line("one"));
        pane.scroll_up(1);
        pane.clear();

        assert!(pane.is_empty());
        assert_eq!(pane.scroll_offset, 0);
        assert!(pane.is_following());
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

    #[test]
    fn scrolling_up_detaches_from_the_tail() {
        // Reading back through a log must not be interrupted by new arrivals.
        let mut pane = OutputPane::new();
        for i in 0..10 {
            pane.push(line(&format!("line {i}")));
        }

        pane.scroll_up(3);

        assert!(!pane.is_following());
    }

    #[test]
    fn reaching_the_bottom_re_attaches() {
        // The operator has caught up; needing another key to resume following
        // would be a step with no purpose.
        let mut pane = OutputPane::new();
        for i in 0..10 {
            pane.push(line(&format!("line {i}")));
        }

        pane.scroll_up(3);
        pane.scroll_down(3);

        assert!(pane.is_following());
    }

    #[test]
    fn jumping_to_the_tail_resumes_following() {
        let mut pane = OutputPane::new();
        for i in 0..10 {
            pane.push(line(&format!("line {i}")));
        }

        pane.scroll_up(5);
        pane.scroll_to_tail();

        assert!(pane.is_following());
        assert_eq!(pane.scroll_offset, 0);
    }

    #[test]
    fn wrapping_toggles() {
        let mut pane = OutputPane::new();
        assert!(pane.wrap, "wrapping is on by default");

        pane.toggle_wrap();
        assert!(!pane.wrap);

        pane.toggle_wrap();
        assert!(pane.wrap);
    }
}
