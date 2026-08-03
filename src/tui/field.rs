//! A single-line text field.
//!
//! `ratatui` has no input widget, so this composes one from a buffer, a cursor
//! and a horizontal scroll offset. Three properties it has to get right:
//!
//! 1. **The cursor is a character index, not a byte index.** A byte index into
//!    a key comment containing an accented character panics on the first
//!    slice; this codebase does not panic on user input.
//! 2. **Long values scroll rather than wrap.** A 380-character public key
//!    cannot be verified by reading it anyway, so the field shows a window
//!    onto it and proves correctness by parsing instead.
//! 3. **Validation runs on every keystroke.** The consequences of a value are
//!    visible before Enter, not after.

use crate::tasks::params::{Param, ParamKind};

/// Marks that text has scrolled off the left edge.
const SCROLLED_MARKER: char = '…';

/// One editable value.
#[derive(Debug, Clone)]
pub struct Field {
    /// What this field collects.
    pub param: Param,
    /// The characters typed so far.
    ///
    /// A `Vec<char>` rather than a `String`: every cursor operation is an
    /// index, and indexing a `String` by character means walking it each time.
    buffer: Vec<char>,
    /// Where the next character lands, in characters from the start.
    cursor: usize,
    /// First visible character, for values wider than the field.
    scroll: usize,
}

impl Field {
    /// Builds a field from its declaration, starting at the initial value.
    ///
    /// The cursor starts at the end, so a starting value can be extended or
    /// cleared without first having to move.
    pub fn new(param: Param) -> Self {
        let buffer: Vec<char> = param.initial.chars().collect();
        let cursor = buffer.len();

        Self {
            param,
            buffer,
            cursor,
            scroll: 0,
        }
    }

    /// The value typed so far.
    pub fn value(&self) -> String {
        self.buffer.iter().collect()
    }

    /// Whether the field holds anything at all.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// What is wrong with the value, if anything.
    ///
    /// Recomputed rather than cached: it is a comparison of a short string
    /// against a rule, and a cache is one more thing that can disagree with
    /// the buffer.
    pub fn error(&self) -> Option<String> {
        self.param.kind.validate(&self.value()).err()
    }

    /// Whether the value would be accepted.
    pub fn is_valid(&self) -> bool {
        self.error().is_none()
    }

    /// Inserts a character, if this kind of value can contain one.
    ///
    /// Rejecting the keystroke rather than accepting and then complaining
    /// means a port field cannot be made to hold letters at all.
    pub fn insert(&mut self, character: char) {
        if !self.param.kind.accepts(character) {
            return;
        }

        self.buffer.insert(self.cursor, character);
        self.cursor += 1;
    }

    /// Deletes the character before the cursor.
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }

        self.cursor -= 1;
        self.buffer.remove(self.cursor);
    }

    /// Deletes the character under the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
        }
    }

    /// Moves the cursor one character left.
    pub const fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Moves the cursor one character right.
    pub const fn right(&mut self) {
        if self.cursor < self.buffer.len() {
            self.cursor += 1;
        }
    }

    /// Moves the cursor to the start.
    pub const fn home(&mut self) {
        self.cursor = 0;
    }

    /// Moves the cursor to the end.
    pub const fn end(&mut self) {
        self.cursor = self.buffer.len();
    }

    /// Clears everything before the cursor.
    pub fn clear_before_cursor(&mut self) {
        self.buffer.drain(..self.cursor);
        self.cursor = 0;
    }

    /// Clears everything from the cursor onwards.
    pub fn clear_after_cursor(&mut self) {
        self.buffer.truncate(self.cursor);
    }

    /// Deletes the word before the cursor.
    ///
    /// Readline's convention, which wins over any other meaning of Ctrl-W
    /// inside a text field.
    pub fn delete_word(&mut self) {
        // Skip the run of spaces immediately behind the cursor, then the word
        // itself; deleting only up to the first space would leave the operator
        // pressing it twice for one word.
        let mut start = self.cursor;

        while start > 0 && self.buffer[start - 1].is_whitespace() {
            start -= 1;
        }

        while start > 0 && !self.buffer[start - 1].is_whitespace() {
            start -= 1;
        }

        self.buffer.drain(start..self.cursor);
        self.cursor = start;
    }

    /// The slice of the value visible in a field of the given width, and where
    /// the cursor sits within it.
    ///
    /// Recomputing the scroll here rather than storing it on every keystroke
    /// keeps the window a function of the cursor and the width, which is what
    /// it actually is — the width is not known until the frame is drawn.
    pub fn visible(&mut self, width: usize) -> (String, usize) {
        if width == 0 {
            return (String::new(), 0);
        }

        // Keep the cursor inside the window, scrolling only as far as needed
        // so that the text does not jump around while typing in the middle.
        //
        // The cursor may sit one past the last character, so the window has to
        // admit that position too — otherwise typing at the end scrolls on
        // every keystroke.
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if self.cursor >= self.scroll + width {
            self.scroll = self.cursor - width + 1;
        }

        let mut visible: Vec<char> = self
            .buffer
            .iter()
            .skip(self.scroll)
            .take(width)
            .copied()
            .collect();

        // A marker replaces the first visible character to say text was
        // dropped from the left, which is otherwise invisible. It costs that
        // character, so the window starts one later to make room for it.
        if self.scroll > 0 {
            visible.remove(0);
            visible.insert(0, SCROLLED_MARKER);
        }

        (visible.into_iter().collect(), self.cursor - self.scroll)
    }

    /// What the value parses as, for the note shown beneath the field.
    ///
    /// A 380-character key cannot be checked by reading it, so the field
    /// echoes what it understood: the type and comment an administrator can
    /// actually compare against their own machine.
    pub fn parsed_summary(&self) -> Option<String> {
        if self.param.kind != ParamKind::PublicKey || !self.is_valid() {
            return None;
        }

        let value = self.value();
        let mut parts = value.split_whitespace();
        let key_type = parts.next()?;
        // Everything after the base64 body is the comment, which may itself
        // contain spaces.
        let comment: Vec<&str> = parts.skip(1).collect();

        if comment.is_empty() {
            return Some(key_type.to_owned());
        }

        Some(format!("{key_type}  {}", comment.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port_field() -> Field {
        Field::new(Param::new("port", "Port", ParamKind::Port))
    }

    fn key_field() -> Field {
        Field::new(Param::new("key", "Public key", ParamKind::PublicKey))
    }

    #[test]
    fn starts_at_the_end_of_its_initial_value() {
        // A starting value must be extendable without first pressing End.
        let field = Field::new(Param::new("port", "Port", ParamKind::Port).with_initial("22"));

        assert_eq!(field.value(), "22");
        assert_eq!(field.cursor, 2);
    }

    #[test]
    fn a_port_field_refuses_letters_outright() {
        // Accepting and then complaining would let the field hold a value it
        // can never accept.
        let mut field = port_field();

        field.insert('2');
        field.insert('a');
        field.insert('2');

        assert_eq!(field.value(), "22");
    }

    #[test]
    fn typing_in_the_middle_inserts_rather_than_overwrites() {
        let mut field = port_field();
        for character in "223".chars() {
            field.insert(character);
        }

        field.left();
        field.insert('2');

        assert_eq!(field.value(), "2223");
    }

    #[test]
    fn backspace_deletes_behind_the_cursor() {
        let mut field = port_field();
        for character in "2222".chars() {
            field.insert(character);
        }

        field.backspace();

        assert_eq!(field.value(), "222");
    }

    #[test]
    fn backspace_at_the_start_does_nothing() {
        let mut field = port_field();
        field.insert('2');
        field.home();

        field.backspace();

        assert_eq!(field.value(), "2");
    }

    #[test]
    fn the_cursor_stops_at_both_ends() {
        let mut field = port_field();
        field.insert('2');

        for _ in 0..10 {
            field.left();
        }
        assert_eq!(field.cursor, 0);

        for _ in 0..10 {
            field.right();
        }
        assert_eq!(field.cursor, 1);
    }

    #[test]
    fn deleting_a_word_takes_its_trailing_spaces_with_it() {
        // Stopping at the first space would mean pressing Ctrl-W twice for one
        // word.
        let mut field = key_field();
        for character in "ssh-ed25519 AAAAC3 admin@laptop".chars() {
            field.insert(character);
        }

        field.delete_word();

        assert_eq!(field.value(), "ssh-ed25519 AAAAC3 ");
    }

    #[test]
    fn clearing_before_and_after_the_cursor() {
        let mut field = key_field();
        for character in "abcdef".chars() {
            field.insert(character);
        }
        field.left();
        field.left();
        field.left();

        let mut after = field.clone();
        after.clear_after_cursor();
        assert_eq!(after.value(), "abc");

        field.clear_before_cursor();
        assert_eq!(field.value(), "def");
    }

    #[test]
    fn a_value_wider_than_the_field_scrolls_with_the_cursor() {
        let mut field = key_field();
        for character in "0123456789".chars() {
            field.insert(character);
        }

        let (visible, cursor) = field.visible(4);

        assert!(
            visible.chars().count() <= 4,
            "the window must not exceed the field: {visible:?}"
        );
        assert!(
            visible.starts_with(SCROLLED_MARKER),
            "dropped text must be marked: {visible:?}"
        );
        assert!(cursor < 4, "the cursor must stay inside the window");
        assert!(
            visible.ends_with('9'),
            "the newest characters stay visible: {visible:?}"
        );
    }

    #[test]
    fn a_value_that_fits_is_shown_whole() {
        let mut field = port_field();
        for character in "22".chars() {
            field.insert(character);
        }

        let (visible, cursor) = field.visible(10);

        assert_eq!(visible, "22");
        assert_eq!(cursor, 2);
    }

    #[test]
    fn moving_back_scrolls_the_window_with_the_cursor() {
        let mut field = key_field();
        for character in "0123456789".chars() {
            field.insert(character);
        }

        field.visible(4);
        field.home();
        let (visible, cursor) = field.visible(4);

        assert_eq!(visible, "0123", "the window follows the cursor back");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn a_non_ascii_comment_does_not_panic() {
        // Byte indices would slice through the middle of a character here.
        let mut field = key_field();
        for character in "ssh-ed25519 AAAAC3 admin@münchen".chars() {
            field.insert(character);
        }

        field.home();
        field.right();
        field.visible(8);
        field.end();
        field.backspace();

        assert!(field.value().ends_with("münche"));
    }

    #[test]
    fn validation_states_what_is_wrong_as_it_is_typed() {
        let mut field = port_field();
        assert!(field.error().is_some(), "an empty port is not valid");

        for character in "70000".chars() {
            field.insert(character);
        }
        assert!(field.error().is_some(), "70000 is above the maximum");

        field.clear_before_cursor();
        for character in "2222".chars() {
            field.insert(character);
        }
        assert!(field.is_valid(), "2222 is a usable port");
    }

    #[test]
    fn a_key_echoes_what_it_parsed_as() {
        // A 380-character key is verified by what it parses to, not by reading
        // it: the type and comment are what the operator can compare.
        let mut field = key_field();
        for character in "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ admin@laptop".chars() {
            field.insert(character);
        }

        let summary = field.parsed_summary().expect("a valid key parses");

        assert!(summary.contains("ssh-ed25519"), "got {summary}");
        assert!(summary.contains("admin@laptop"), "got {summary}");
    }

    #[test]
    fn an_invalid_key_has_nothing_to_echo() {
        let mut field = key_field();
        field.insert('x');

        assert!(field.parsed_summary().is_none());
    }
}
