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
    /// What the host says this field could hold.
    ///
    /// Empty where the host was not asked or had no answer, which is the same
    /// thing to every reader here: a field with nothing to offer behaves
    /// exactly as it did before there was anything to offer.
    options: Vec<String>,
    /// Which option was last stepped to, for stepping on from it.
    ///
    /// `None` until one is, so that the first press offers the first option
    /// rather than the second. Cleared by typing: once the value is no longer
    /// the option that was chosen, counting from it would step somewhere the
    /// operator cannot predict.
    at_option: Option<usize>,
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
            options: Vec::new(),
            at_option: None,
        }
    }

    /// Offers the values the host says this field could hold.
    ///
    /// Set after construction rather than passed to it, because resolving them
    /// runs commands and `Field::new` is called from tests that have no
    /// executor. A field that is never given any behaves as it always did.
    pub fn offer(&mut self, options: Vec<String>) {
        self.options = options;
    }

    /// What the host says this field could hold.
    pub fn options(&self) -> &[String] {
        &self.options
    }

    /// Which option the value currently is, if it is one of them.
    ///
    /// Recomputed from the buffer rather than trusted from `at_option`: the
    /// operator may have typed a value that happens to be an option, and a
    /// position that disagrees with what is on screen is worse than none.
    pub fn option_position(&self) -> Option<usize> {
        let value = self.value();

        self.options.iter().position(|option| *option == value)
    }

    /// Replaces the value with the next option, wrapping at the end.
    pub fn next_option(&mut self) {
        self.step_option(1);
    }

    /// Replaces the value with the previous option, wrapping at the start.
    pub fn previous_option(&mut self) {
        self.step_option(-1);
    }

    /// Moves `delta` options along and takes that value.
    ///
    /// Counts from where the value already is when it matches an option, so
    /// that stepping continues from what is on screen rather than from
    /// whatever was last stepped to — the two differ once the operator has
    /// typed. Falling back to `at_option` covers the case where they typed
    /// something that is not an option at all and then pressed a key: the walk
    /// resumes where it left off instead of restarting.
    fn step_option(&mut self, delta: isize) {
        if self.options.is_empty() {
            return;
        }

        let count = self.options.len();

        let next = match self.option_position().or(self.at_option) {
            // `rem_euclid` rather than `%`: the remainder of a negative number
            // is negative in Rust, so stepping back from the first option
            // would index out of the list rather than wrapping to its end.
            Some(current) => (current as isize + delta).rem_euclid(count as isize) as usize,
            // Stepping into an untouched field offers the first option going
            // forwards and the last going back, which is what the arrow
            // pressed said to do.
            None if delta > 0 => 0,
            None => count - 1,
        };

        self.take_option(next);
    }

    /// Fills the field with the option at `index`.
    pub fn take_option(&mut self, index: usize) {
        let Some(option) = self.options.get(index) else {
            return;
        };

        self.buffer = option.chars().collect();
        self.cursor = self.buffer.len();
        self.at_option = Some(index);
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
        // The value is no longer the option that was stepped to, so counting
        // from it would step somewhere the operator cannot predict.
        self.at_option = None;
    }

    /// Deletes the character before the cursor.
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }

        self.cursor -= 1;
        self.buffer.remove(self.cursor);
        self.at_option = None;
    }

    /// Deletes the character under the cursor.
    pub fn delete(&mut self) {
        if self.cursor < self.buffer.len() {
            self.buffer.remove(self.cursor);
            self.at_option = None;
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
        self.at_option = None;
    }

    /// Clears everything from the cursor onwards.
    pub fn clear_after_cursor(&mut self) {
        self.buffer.truncate(self.cursor);
        self.at_option = None;
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
        self.at_option = None;
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

    fn shell_field() -> Field {
        let mut field = Field::new(Param::new("shell", "Shell", ParamKind::Path));
        field.offer(vec![
            "/bin/sh".to_owned(),
            "/bin/bash".to_owned(),
            "/usr/bin/fish".to_owned(),
        ]);

        field
    }

    #[test]
    fn the_first_step_forwards_offers_the_first_option() {
        // Not the second: an untouched field has no position to count from,
        // and skipping the first option would hide it behind a full cycle.
        let mut field = shell_field();

        field.next_option();

        assert_eq!(field.value(), "/bin/sh");
    }

    #[test]
    fn the_first_step_backwards_offers_the_last_option() {
        // Which is what the arrow pressed said to do; starting both
        // directions at the first option would make one of the two arrows lie.
        let mut field = shell_field();

        field.previous_option();

        assert_eq!(field.value(), "/usr/bin/fish");
    }

    #[test]
    fn stepping_past_the_end_wraps_to_the_start() {
        let mut field = shell_field();

        // The first press takes the first option rather than stepping past it,
        // so four presses over three options land back on the first.
        for _ in 0..4 {
            field.next_option();
        }

        assert_eq!(field.value(), "/bin/sh");
    }

    #[test]
    fn stepping_back_from_the_first_option_does_not_index_out_of_the_list() {
        // The remainder of a negative number is negative in Rust, so `%` here
        // would index past the start rather than wrapping to the end.
        let mut field = shell_field();

        field.next_option();
        field.previous_option();

        assert_eq!(field.value(), "/usr/bin/fish");
    }

    #[test]
    fn stepping_counts_from_a_value_that_was_typed_rather_than_stepped_to() {
        // Typing "/bin/sh" by hand and pressing Down must offer "/bin/bash",
        // not restart at the top — the two differ, and the one the operator
        // can predict is the one that follows what is on screen.
        let mut field = shell_field();

        for character in "/bin/sh".chars() {
            field.insert(character);
        }
        field.next_option();

        assert_eq!(field.value(), "/bin/bash");
    }

    #[test]
    fn a_field_with_nothing_offered_is_unchanged_by_stepping() {
        // Most fields have no options at all, and pressing an arrow in one
        // must not clear what was typed.
        let mut field = port_field();
        field.insert('2');
        field.insert('2');

        field.next_option();
        field.previous_option();

        assert_eq!(field.value(), "22");
    }

    #[test]
    fn taking_an_option_leaves_the_cursor_where_more_can_be_typed() {
        // A shell stepped to and then corrected by hand is the case: a cursor
        // left at the start would insert the correction backwards.
        let mut field = shell_field();

        field.next_option();

        assert_eq!(field.cursor, "/bin/sh".chars().count());
    }

    #[test]
    fn an_index_past_the_end_is_refused_rather_than_panicking() {
        // This runs as root on someone's server; an out-of-range index must
        // not take the interface down.
        let mut field = shell_field();

        field.take_option(99);

        assert_eq!(field.value(), "");
    }

    #[test]
    fn the_position_reported_is_the_one_on_screen() {
        let mut field = shell_field();

        assert_eq!(field.option_position(), None, "an empty field is no option");

        field.next_option();
        field.next_option();

        assert_eq!(field.option_position(), Some(1));

        field.insert('x');

        assert_eq!(
            field.option_position(),
            None,
            "an edited value is no longer the option it came from"
        );
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
