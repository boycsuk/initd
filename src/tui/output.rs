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
use crate::i18n::{Lang, Msg};

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
}

impl Default for OutputPane {
    fn default() -> Self {
        Self {
            lines: VecDeque::new(),
            scroll_offset: 0,
            // Watching is the common case: a task is started and then read.
            follow: true,
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

    /// Number of retained lines, for assertions about the ring buffer.
    ///
    /// Production had one reader — the line reporting how many lines a copy
    /// sent — and that report is gone: OSC 52 cannot confirm a copy, and the
    /// line landed in the transcript the next copy would send.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// The retained lines, for assertions about what was reported.
    #[cfg(test)]
    pub fn lines(&self) -> &VecDeque<OutputLine> {
        &self.lines
    }

    /// Whether the view is pinned to the newest output.
    #[cfg(test)]
    pub const fn is_following(&self) -> bool {
        self.follow
    }

    /// The retained output as text, for the clipboard.
    ///
    /// Whole lines, not the window on screen: what the pane draws is truncated
    /// by its own width, and a transcript pasted into a bug report with every
    /// long line cut is worse than none — it looks complete.
    ///
    /// Both streams, in the order they arrived. Dropping stderr would lose the
    /// error the transcript is usually being copied for, and separating them
    /// would put the failure somewhere other than after the command that
    /// caused it.
    pub fn transcript(&self) -> String {
        let mut text =
            self.lines
                .iter()
                .fold(String::new(), |mut text, OutputLine { text: line, .. }| {
                    text.push_str(line);
                    text.push('\n');
                    text
                });

        // A transcript that does not end in a newline concatenates with
        // whatever it is pasted before.
        if text.is_empty() {
            text.push('\n');
        }

        text
    }

    /// Scrolls towards older output, detaching from the tail.
    ///
    /// `saturating_add` rather than `+`, because `g` scrolls to the top by
    /// asking for `usize::MAX` and the sum overflowed before the clamp below
    /// could bound it — a panic in debug, and in release a silent wrap to a
    /// small offset, which is the same key jumping somewhere arbitrary. The
    /// clamp cannot save an addition that has already overflowed; it has to
    /// not overflow.
    pub fn scroll_up(&mut self, amount: usize) {
        self.follow = false;
        self.scroll_offset = self
            .scroll_offset
            .saturating_add(amount)
            .min(self.lines.len().saturating_sub(1));
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

    /// Renders the pane, following the newest output unless scrolled away.
    ///
    /// The title is resolved here rather than passed in. It named the one pane
    /// this type draws, so a caller supplying it could only ever supply the
    /// same word — and every caller doing so is a call site the catalogue does
    /// not reach.
    ///
    /// Nothing rides the bottom border. The `follow`/`detached` word that used
    /// to sit there went with the status line: the write cursor already
    /// distinguishes the two, being drawn only while the view is pinned, so its
    /// absence is what says the log is being read back.
    pub fn render(&self, frame: &mut Frame, area: Rect, lang: Lang, focused: bool) {
        let title = lang.render(&Msg::OutputTitle);

        // The visible height excludes the block's top and bottom borders.
        let viewport = area.height.saturating_sub(2) as usize;

        // The cursor occupies a row of its own, so it counts towards the total
        // the scroll offset is measured against.
        let total = self.lines.len() + usize::from(self.follow);
        let scroll = total
            .saturating_sub(viewport)
            .saturating_sub(self.scroll_offset);

        // Wrapped here rather than by ratatui's `Wrap`, which returns every
        // continuation to column zero. That is right for a command's output and
        // wrong for a failure's fields: `stderr  Failed to disable unit:` broke
        // to `docker.service not loaded.` at the left margin, where it read as
        // another label in the column above it. The width only exists at draw
        // time, which is why this cannot be done where the lines are pushed.
        //
        // Applied to indented lines alone, so a package manager's output is
        // still wrapped by the widget as before.
        let width = area.width.saturating_sub(2) as usize;
        let mut text: Vec<Line> = self
            .lines
            .iter()
            .flat_map(|line| wrap_indented(line, width))
            .collect();

        // The cursor marks where the next line lands, so a quiet command is
        // distinguishable from a frozen screen.
        if self.follow {
            text.push(Line::from(Span::styled(WRITE_CURSOR, style::OUTPUT_CURSOR)));
        }

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(style::border(focused))
            .title(Span::styled(format!(" {title} "), style::PANE_TITLE));

        let paragraph = Paragraph::new(text)
            .block(block)
            .scroll((scroll as u16, 0))
            .wrap(Wrap { trim: false });

        frame.render_widget(paragraph, area);
    }
}

/// Wraps a line, keeping continuations under where its text began.
///
/// Only a line whose text is a label and a value — two columns separated by
/// more than one space, which is what `Msg::OutputErrorField` renders — is
/// treated this way. Everything else is handed back whole for the widget's own
/// `Wrap` to break at column zero, which is correct for a command's output.
///
/// The indent is measured from the text rather than agreed with the catalogue.
/// A locale whose labels are wider pads them further, and a constant here would
/// have to be kept in step with a number in another module — the kind of pair
/// that stays right until somebody adds a language.
///
/// Wrapping on characters rather than words, deliberately: the values are
/// paths, commands and digests, and breaking a path at a space it does not
/// contain is not possible while breaking it mid-token is exactly what a
/// terminal does. `chars` rather than bytes, so a multi-byte character is not
/// split into invalid UTF-8.
fn wrap_indented(line: &OutputLine, width: usize) -> Vec<Line<'static>> {
    let Some(indent) = field_indent(&line.text) else {
        return vec![render_line(line)];
    };

    // Below this the continuations have no room left to say anything, and a
    // column two cells wide is worse than an unindented wrap.
    const MIN_VALUE_WIDTH: usize = 8;

    if width <= indent + MIN_VALUE_WIDTH {
        return vec![render_line(line)];
    }

    let characters: Vec<char> = line.text.chars().collect();

    if characters.len() <= width {
        return vec![render_line(line)];
    }

    let mut rows = Vec::new();
    let mut taken = 0;

    while taken < characters.len() {
        // A break that lands on a space would otherwise carry it into the next
        // row, where it adds to the indent and moves that row one cell right of
        // the column — visible from the third row of a long value onwards.
        while !rows.is_empty() && characters.get(taken) == Some(&' ') {
            taken += 1;
        }

        if taken >= characters.len() {
            break;
        }

        // The first row carries the label, so it gets the full width; every
        // continuation gives up `indent` cells to sit under the value.
        let room = if rows.is_empty() {
            width
        } else {
            width - indent
        };
        let end = (taken + room).min(characters.len());
        let chunk: String = characters[taken..end].iter().collect();

        rows.push(if rows.is_empty() {
            chunk
        } else {
            format!("{:indent$}{chunk}", "")
        });

        taken = end;
    }

    rows.into_iter()
        .map(|text| Line::styled(text, style_of(line.stream)))
        .collect()
}

/// Where a label-and-value line's value starts, if it is one.
///
/// Two or more spaces are what separates the two columns, which no ordinary
/// command output contains at the head of a line — and a line that is only
/// indentation has no value to hang.
fn field_indent(text: &str) -> Option<usize> {
    let gap = text.find("  ")?;

    // A leading gap means the line is already a continuation or a blank, not a
    // label followed by a value.
    if gap == 0 {
        return None;
    }

    let value_at = text[gap..]
        .find(|character: char| character != ' ')
        .map(|offset| gap + offset)?;

    // Measured in columns, and `find` answers in bytes: a label rendered in a
    // locale with multi-byte characters would otherwise indent too far.
    Some(text[..value_at].chars().count())
}

/// Styles one line according to the stream it came from.
///
/// A command is prefixed with `$` and dimmed: it is the structure of the
/// transcript rather than its content, and an administrator scanning for what
/// a task did reads the commands, not every line each one printed.
fn render_line(line: &OutputLine) -> Line<'static> {
    match line.stream {
        Stream::Command => Line::styled(format!("$ {}", line.text), style::OUTPUT_COMMAND),
        stream => Line::styled(line.text.clone(), style_of(stream)),
    }
}

/// The style a stream's text is drawn in.
///
/// Split out of [`render_line`] so a wrapped continuation is drawn the same as
/// the row it continues: two sources for one answer is how a continuation ends
/// up a different colour from its own first line.
const fn style_of(stream: Stream) -> ratatui::style::Style {
    match stream {
        Stream::Stdout => style::NORMAL,
        // stderr is highlighted so warnings stand out from progress. It is not
        // treated as an error: plenty of tools report progress on stderr.
        Stream::Stderr => style::OUTPUT_WARN,
        // The prefix belongs to the first row alone, so a wrapped command's
        // continuations are styled without being prefixed again.
        Stream::Command => style::OUTPUT_COMMAND,
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
    fn the_transcript_carries_whole_lines_and_both_streams() {
        // The reason this exists rather than letting the mouse do it: the pane
        // truncates to its own width, and a transcript pasted into a bug
        // report with every long line cut looks complete. Dropping stderr
        // would lose the error it is usually being copied for.
        let mut pane = OutputPane::new();
        pane.push(line("$ usermod -s /usr/bin/fish cosmin"));
        pane.push(OutputLine {
            stream: Stream::Stderr,
            text: "usermod: no changes".to_owned(),
        });

        let transcript = pane.transcript();

        assert_eq!(
            transcript,
            "$ usermod -s /usr/bin/fish cosmin\nusermod: no changes\n"
        );
    }

    #[test]
    fn a_wrapped_field_keeps_its_continuations_under_the_value() {
        // The defect this exists for was visible only on a rendered frame:
        // ratatui's own `Wrap` returns every continuation to column zero, so
        // `stderr  Failed to disable unit:` broke to `docker.service not
        // loaded.` at the left margin, where it read as another label in the
        // column above it — the alignment being the whole point of the block.
        let line = OutputLine {
            stream: Stream::Stderr,
            text: "stderr        Failed to disable unit: Unit not loaded.".to_owned(),
        };

        let rows = wrap_indented(&line, 30);

        assert!(rows.len() > 2, "must wrap more than once at 30: {rows:?}");

        // Every continuation, not only the first. A break landing on a space
        // carried it into the next row, where it added to the indent and moved
        // that row one cell right of the column — invisible until the third row
        // of a long value, which is why this asserts across all of them.
        for (index, row) in rows.iter().enumerate().skip(1) {
            let text = row
                .spans
                .first()
                .expect("a continuation has content")
                .content
                .clone();

            assert_eq!(
                text.len() - text.trim_start().len(),
                14,
                "row {index} must hang in the value's column: {text:?}"
            );
            assert!(
                !text.trim().is_empty(),
                "row {index} must carry text rather than only padding: {text:?}"
            );
        }

        // Nothing lost to the wrap: every word of the value survives, which a
        // break that swallowed a character either side would fail.
        let rejoined: String = rows
            .iter()
            .flat_map(|row| row.spans.iter())
            .map(|span| span.content.trim().to_owned())
            .collect::<Vec<_>>()
            .join(" ");

        assert!(
            rejoined.contains("Unit not loaded."),
            "the value must survive the wrap: {rejoined:?}"
        );
    }

    #[test]
    fn command_output_is_left_for_the_widget_to_wrap() {
        // A package manager's line has no label to hang under, and indenting
        // its continuations would misreport its output as structured.
        let line = OutputLine {
            stream: Stream::Stdout,
            text: "Removed /home/cosmin/.config/systemd/user/docker.service.".to_owned(),
        };

        assert_eq!(
            wrap_indented(&line, 20).len(),
            1,
            "one line, handed to the widget whole"
        );
    }

    #[test]
    fn a_field_narrower_than_its_own_indent_is_not_wrapped_here() {
        // Below the minimum the continuations have no room to say anything, and
        // a two-cell column is worse than an unindented wrap. Reached on a
        // genuinely narrow terminal rather than hypothetically.
        let line = OutputLine {
            stream: Stream::Stderr,
            text: "architecture  x86_64-unknown-linux-musl".to_owned(),
        };

        assert_eq!(
            wrap_indented(&line, 16).len(),
            1,
            "hand it over rather than indenting into nothing"
        );
    }

    #[test]
    fn the_indent_is_measured_in_columns_rather_than_bytes() {
        // A locale whose labels carry multi-byte characters would otherwise
        // indent by their byte length and push the value off the column.
        assert_eq!(field_indent("código        5"), Some(14));
    }

    #[test]
    fn a_line_that_only_looks_indented_is_not_treated_as_a_field() {
        // A continuation already written by something else, and a blank line,
        // both have no label to measure from.
        assert_eq!(field_indent("    already indented"), None);
        assert_eq!(field_indent(""), None);
        assert_eq!(field_indent("no double space here"), None);
    }

    #[test]
    fn the_transcript_ends_in_a_newline() {
        // Otherwise it concatenates with whatever it is pasted before.
        let mut pane = OutputPane::new();
        pane.push(line("only line"));

        assert!(pane.transcript().ends_with('\n'));
    }

    #[test]
    fn scrolling_to_the_top_does_not_overflow() {
        // `g` scrolls to the top by asking for `usize::MAX`, and the offset was
        // added to it before being clamped: a panic in debug, and in release a
        // silent wrap that jumps somewhere arbitrary. Reached with one
        // keystroke on a running task, in a program that runs as root.
        let mut pane = OutputPane::new();
        for i in 0..10 {
            pane.push(line(&format!("line {i}")));
        }

        pane.scroll_up(3);
        pane.scroll_up(usize::MAX);

        assert_eq!(pane.scroll_offset, 9, "the oldest of ten lines");
    }

    #[test]
    fn scrolling_to_the_top_of_an_empty_pane_is_not_a_crash() {
        // `g` before anything has run: the clamp reads `len() - 1` on an empty
        // pane, which is the other end of the same arithmetic.
        let mut pane = OutputPane::new();

        pane.scroll_up(usize::MAX);

        assert_eq!(pane.scroll_offset, 0);
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
}
