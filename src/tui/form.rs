//! The modal form that collects a task's parameters.
//!
//! Parameters are collected in a modal dialog, never inline in the tree: the
//! form has to swallow `j`, `k`, `/` and `q` as literal characters, and a
//! modal frame is the only honest way to show that a key means something
//! different here.
//!
//! Validation runs on every keystroke and is drawn directly beneath the field
//! it belongs to, so the consequences of a value are visible before Enter
//! rather than after.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::field::Field;
use super::{layout, style};
use crate::tasks::params::{Param, ParamValues};

/// Width the dialog is drawn at, before clamping to the terminal.
const DIALOG_WIDTH: u16 = 64;

/// Rows one field occupies: its label, the boxed input, and a note beneath.
const ROWS_PER_FIELD: u16 = 5;

/// Rows spent on the dialog's own frame and its footer.
const CHROME_ROWS: u16 = 4;

/// A form being filled in.
#[derive(Debug)]
pub struct Form {
    /// What the form is collecting values for.
    pub title: String,
    fields: Vec<Field>,
    /// Which field the keystrokes go to.
    focus: usize,
    /// Whether a second `Esc` would discard what has been typed.
    ///
    /// Cleared by any other key, so the confirmation cannot be answered by a
    /// keystroke aimed at something else several actions later.
    cancel_armed: bool,
}

impl Form {
    /// Builds a form for a task's declared parameters.
    pub fn new(title: impl Into<String>, params: Vec<Param>) -> Self {
        Self {
            title: title.into(),
            fields: params.into_iter().map(Field::new).collect(),
            focus: 0,
            cancel_armed: false,
        }
    }

    /// Arms cancellation, so a second `Esc` discards the form.
    pub const fn arm_cancel(&mut self) {
        self.cancel_armed = true;
    }

    /// Whether `Esc` has already been pressed once with work in the form.
    pub const fn cancel_armed(&self) -> bool {
        self.cancel_armed
    }

    /// Cancels the arming, for any key that is not `Esc`.
    pub const fn disarm_cancel(&mut self) {
        self.cancel_armed = false;
    }

    /// The field currently receiving keystrokes.
    pub fn focused_mut(&mut self) -> Option<&mut Field> {
        self.fields.get_mut(self.focus)
    }

    /// Moves to the next field, wrapping at the end.
    pub fn focus_next(&mut self) {
        if self.fields.is_empty() {
            return;
        }

        self.focus = (self.focus + 1) % self.fields.len();
    }

    /// Moves to the previous field, wrapping at the start.
    pub fn focus_previous(&mut self) {
        if self.fields.is_empty() {
            return;
        }

        self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
    }

    /// Whether the focused field is the last one.
    pub fn on_last_field(&self) -> bool {
        self.focus + 1 >= self.fields.len()
    }

    /// Whether every field holds a value that would be accepted.
    pub fn is_valid(&self) -> bool {
        self.fields.iter().all(Field::is_valid)
    }

    /// Whether anything has been typed into any field.
    ///
    /// Cancelling a form with work in it asks first; cancelling an untouched
    /// one does not, because there is nothing to lose.
    pub fn is_untouched(&self) -> bool {
        self.fields
            .iter()
            .all(|field| field.value() == field.param.initial)
    }

    /// The first field whose value would be rejected.
    ///
    /// Submitting moves to it rather than merely refusing, so the operator
    /// does not have to hunt for which field is the problem.
    pub fn first_invalid(&self) -> Option<usize> {
        self.fields.iter().position(|field| !field.is_valid())
    }

    /// Moves focus to a field by index.
    pub const fn focus_on(&mut self, index: usize) {
        self.focus = index;
    }

    /// The collected values, keyed by the names the task declared.
    pub fn values(&self) -> ParamValues {
        let mut values = ParamValues::new();

        for field in &self.fields {
            values.set(field.param.name, field.value());
        }

        values
    }

    /// Renders the dialog centred over the interface.
    pub fn render(&mut self, frame: &mut Frame) {
        let height = CHROME_ROWS + ROWS_PER_FIELD * self.fields.len() as u16;
        let area = layout::centred(DIALOG_WIDTH, height, frame.area());

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(style::DIALOG_BORDER_INPUT)
            .title(Span::styled(format!(" {} ", self.title), style::EMPHASIS));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        self.render_fields(frame, inner);
    }

    /// Draws each field, its validation note, and the footer.
    fn render_fields(&mut self, frame: &mut Frame, area: Rect) {
        // Two cells of the box's own border are not available to the text.
        let field_width = area.width.saturating_sub(4) as usize;
        let focus = self.focus;
        let total = self.fields.len();

        let mut lines: Vec<Line> = Vec::new();
        // Where the real terminal cursor goes, so screen readers and remote
        // clients follow it rather than a drawn imitation.
        let mut cursor_at = None;

        for (index, field) in self.fields.iter_mut().enumerate() {
            let focused = index == focus;
            let (visible, cursor) = field.visible(field_width);

            let counter = if total > 1 {
                format!("{} of {total}  ", index + 1)
            } else {
                String::new()
            };

            lines.push(Line::from(vec![
                Span::styled(counter, style::BLOCK_SUBTITLE),
                Span::styled(
                    field.param.label,
                    if focused {
                        style::EMPHASIS
                    } else {
                        style::NORMAL
                    },
                ),
                Span::styled(
                    field
                        .param
                        .hint
                        .as_ref()
                        .map(|hint| format!("   {hint}"))
                        .unwrap_or_default(),
                    style::BLOCK_SUBTITLE,
                ),
            ]));

            lines.push(Line::styled(
                format!("┌{}┐", "─".repeat(field_width)),
                style::border(focused),
            ));

            if focused {
                // Row within the dialog: the two lines already pushed for this
                // field, plus the three each previous field occupies.
                cursor_at = Some((area.x + 2 + cursor as u16, area.y + lines.len() as u16));
            }

            lines.push(Line::from(vec![
                Span::styled("│", style::border(focused)),
                Span::styled(format!("{visible:<field_width$}"), style::NORMAL),
                Span::styled("│", style::border(focused)),
            ]));

            lines.push(Line::styled(
                format!("└{}┘", "─".repeat(field_width)),
                style::border(focused),
            ));

            lines.push(note_line(field));
        }

        lines.push(Line::from(vec![
            Span::styled("Tab", style::KEYBAR_KEY),
            Span::styled(" field   ", style::KEYBAR_LABEL),
            Span::styled("Enter", style::KEYBAR_KEY),
            Span::styled(
                if self.is_valid() {
                    " continue   "
                } else {
                    " (fill every field)   "
                },
                style::KEYBAR_LABEL,
            ),
            Span::styled("Esc", style::KEYBAR_KEY),
            Span::styled(" cancel", style::KEYBAR_LABEL),
        ]));

        frame.render_widget(Paragraph::new(lines), area);

        if let Some((x, y)) = cursor_at {
            frame.set_cursor_position((x, y));
        }
    }
}

/// The note under a field: what is wrong, or what the value parsed as.
///
/// A warning the tool then ignores is worse than no warning, so this states
/// the problem rather than merely that there is one.
fn note_line(field: &Field) -> Line<'static> {
    if let Some(error) = field.error() {
        // An empty required field is not yet a mistake — the operator has not
        // finished — so it reads as a prompt rather than a failure.
        let style = if field.is_empty() {
            style::BLOCK_SUBTITLE
        } else {
            style::OUTPUT_ERROR
        };

        return Line::styled(format!("  {error}"), style);
    }

    field.parsed_summary().map_or_else(
        || Line::styled("  ✓", style::RESULT_OK),
        |summary| Line::styled(format!("  ✓ {summary}"), style::RESULT_OK),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::params::ParamKind;

    fn port_form() -> Form {
        Form::new(
            "Change the SSH port",
            vec![Param::new("port", "Port", ParamKind::Port).with_initial("22")],
        )
    }

    fn key_form() -> Form {
        Form::new(
            "Authorise a public key",
            vec![
                Param::new("user", "Username", ParamKind::Username).with_initial("root"),
                Param::new("key", "Public key", ParamKind::PublicKey),
            ],
        )
    }

    #[test]
    fn focus_starts_on_the_first_field() {
        assert_eq!(key_form().focus, 0);
    }

    #[test]
    fn focus_wraps_in_both_directions() {
        let mut form = key_form();

        form.focus_next();
        assert_eq!(form.focus, 1);

        form.focus_next();
        assert_eq!(form.focus, 0, "focus wraps past the last field");

        form.focus_previous();
        assert_eq!(form.focus, 1, "focus wraps back past the first");
    }

    #[test]
    fn a_form_with_an_empty_required_field_is_not_valid() {
        // The key field starts empty, so the form cannot be submitted yet.
        assert!(!key_form().is_valid());
    }

    #[test]
    fn a_form_becomes_valid_once_every_field_holds_a_usable_value() {
        let mut form = key_form();
        form.focus_next();

        let field = form.focused_mut().expect("the key field");
        for character in
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ admin@laptop".chars()
        {
            field.insert(character);
        }

        assert!(form.is_valid());
    }

    #[test]
    fn submitting_points_at_the_first_field_that_is_wrong() {
        // Refusing without saying which field is the problem makes the
        // operator hunt for it.
        let form = key_form();

        assert_eq!(form.first_invalid(), Some(1));
    }

    #[test]
    fn values_are_keyed_by_the_names_the_task_declared() {
        let mut form = port_form();
        let field = form.focused_mut().expect("the port field");
        field.clear_before_cursor();
        for character in "2222".chars() {
            field.insert(character);
        }

        let values = form.values();

        assert_eq!(values.get("port").expect("the port was collected"), "2222");
    }

    #[test]
    fn an_initial_value_is_carried_through_untouched() {
        // The common case is confirming what is already there.
        let values = port_form().values();

        assert_eq!(values.get("port").expect("the port field"), "22");
    }

    #[test]
    fn a_form_nobody_typed_into_is_untouched() {
        let mut form = port_form();
        assert!(form.is_untouched());

        form.focused_mut().expect("the port field").insert('2');
        assert!(!form.is_untouched(), "a typed value is work to lose");
    }

    #[test]
    fn the_last_field_is_where_enter_submits() {
        let mut form = key_form();
        assert!(!form.on_last_field());

        form.focus_next();
        assert!(form.on_last_field());
    }
}
