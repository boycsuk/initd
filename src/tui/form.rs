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
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use super::field::Field;
use super::{layout, style};
use crate::i18n::{Lang, Msg};
use crate::tasks::params::{Param, ParamValues};

/// Width the dialog is drawn at, before clamping to the terminal.
///
/// Sized by its footer rather than by its fields, which is what sets the
/// floor: the longest one is `Tab field   Ctrl-L list   Enter (fill every
/// field)   Esc cancel`, and it is drawn as adjacent spans that neither wrap
/// nor truncate — a footer one cell too wide simply loses `cancel`, leaving
/// the key that abandons the form unnamed. `centred` clamps this to the
/// terminal, so a narrow one shrinks the dialog rather than overflowing.
const DIALOG_WIDTH: u16 = 72;

/// Rows one field occupies: its label, the boxed input, and a note beneath.
const ROWS_PER_FIELD: u16 = 5;

/// Rows spent on the dialog's own frame and its footer.
const CHROME_ROWS: u16 = 4;

/// Rows the options overlay spends on its border and footer.
const OPTIONS_CHROME_ROWS: u16 = 2;

/// Tallest the options overlay is drawn, before the terminal clamps it.
///
/// Forty accounts do not fit a 24-row terminal and are not meant to: the list
/// scrolls. The ceiling is what keeps the overlay from claiming the whole
/// screen on a tall one, where the form underneath is the context for the
/// choice being made.
const OPTIONS_MAX_HEIGHT: u16 = 14;

/// How the key that opens the full list of options is written in the footer.
///
/// `Ctrl-L` for *list*, and free: the readline bindings this field honours are
/// `u`, `k`, `w`, `a` and `e`, so it takes nothing an operator's fingers
/// already expect to do something else here.
pub const LIST_KEY_LABEL: &str = "Ctrl-L";

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

    /// Every field, for filling in what the host can offer them.
    ///
    /// Mutable access to the whole set, which the rest of this type avoids on
    /// purpose. It exists for one caller: the interface resolves what each
    /// field could hold once, when the form opens, because doing it per
    /// keystroke would run `cat /etc/passwd` on every arrow press.
    pub fn fields_mut(&mut self) -> &mut [Field] {
        &mut self.fields
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

    /// Where this dialog is drawn inside the terminal.
    ///
    /// Resolved here rather than at each call site so that the options overlay
    /// can be placed against the same rectangle the form occupies. Two call
    /// sites computing it separately is how the two would drift apart after a
    /// change to either.
    fn area(&self, terminal: Rect) -> Rect {
        let height = CHROME_ROWS + ROWS_PER_FIELD * self.fields.len() as u16;

        layout::centred(DIALOG_WIDTH, height, terminal)
    }

    /// Draws every option the focused field offers, over the form.
    ///
    /// Stepping with `↑↓` covers the three shells `/etc/shells` usually holds;
    /// this covers the forty accounts `/etc/passwd` does, where stepping one
    /// at a time is not reading a list, it is guessing more slowly.
    ///
    /// `chosen` is where the cursor sits in the overlay, which is not the
    /// field's own position: the operator moves through the list before
    /// deciding, and the field is only written when they press `Enter`.
    pub fn render_options(&mut self, frame: &mut Frame, chosen: usize, lang: Lang) {
        let Some(field) = self.fields.get(self.focus) else {
            return;
        };

        if field.options().is_empty() {
            return;
        }

        let label = field.param.label.to_owned();
        let options = field.options();

        // Sized to the content up to a ceiling, so three shells do not get the
        // same box as forty accounts. Two rows go to the border and one to the
        // footer.
        let height = (options.len() as u16 + OPTIONS_CHROME_ROWS).min(OPTIONS_MAX_HEIGHT);

        // Below the form rather than centred over it, which is where centring
        // put it: on top of the very field it answers. A chooser that hides
        // the question makes the operator dismiss it to remember what they
        // were filling in.
        let area = below(self.area(frame.area()), height, frame.area());

        // Clear first, or the form underneath shows through.
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(style::DIALOG_BORDER_INPUT)
            .title(Span::styled(
                lang.render(&Msg::FormOptionsTitle { label }),
                style::EMPHASIS,
            ))
            // The spaces framing it are what hold the border off the words;
            // without them the footer reads as the frame having been drawn
            // through it.
            .title_bottom(Line::from(vec![
                Span::raw(" "),
                Span::styled("Enter", style::KEYBAR_KEY),
                Span::styled(lang.render(&Msg::FormOptionsChoose), style::KEYBAR_LABEL),
                Span::styled("Esc", style::KEYBAR_KEY),
                Span::styled(lang.render(&Msg::FormKeyCancel), style::KEYBAR_LABEL),
                Span::raw(" "),
            ]));

        let items: Vec<ListItem> = options
            .iter()
            .map(|option| ListItem::new(format!(" {option}")))
            .collect();

        let mut state = ListState::default().with_selected(Some(chosen));

        frame.render_stateful_widget(
            List::new(items)
                .block(block)
                .highlight_style(style::SELECTION_FOCUSED),
            area,
            &mut state,
        );
    }

    /// How many options the focused field offers.
    pub fn focused_option_count(&self) -> usize {
        self.fields
            .get(self.focus)
            .map_or(0, |field| field.options().len())
    }

    /// Fills the focused field with the option at `index`.
    pub fn take_focused_option(&mut self, index: usize) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.take_option(index);
        }
    }

    /// Where the focused field's value sits among its options.
    pub fn focused_option_position(&self) -> Option<usize> {
        self.fields.get(self.focus).and_then(Field::option_position)
    }

    /// Renders the dialog centred over the interface.
    ///
    /// The title arrives as text because it is the task's own, chosen before
    /// the form opened; `lang` renders only the chrome the dialog itself owns
    /// — the field counter and the key hints.
    pub fn render(&mut self, frame: &mut Frame, lang: Lang) {
        let area = self.area(frame.area());

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(style::DIALOG_BORDER_INPUT)
            .title(Span::styled(format!(" {} ", self.title), style::EMPHASIS));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        self.render_fields(frame, inner, lang);
    }

    /// Draws each field, its validation note, and the footer.
    fn render_fields(&mut self, frame: &mut Frame, area: Rect, lang: Lang) {
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
                lang.render(&Msg::FormFieldCounter {
                    index: index + 1,
                    total,
                })
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

            lines.push(note_line(field, lang));
        }

        // The key glyphs stay literals for the reason `help.rs` states: `Tab`
        // and `Esc` name keys on a keyboard rather than words in a language.
        let mut keys = vec![
            Span::styled("Tab", style::KEYBAR_KEY),
            Span::styled(lang.render(&Msg::FormKeyField), style::KEYBAR_LABEL),
        ];

        // Offered only where the focused field has something to list, since a
        // hint naming a key that does nothing is worse than no hint. `↑↓` are
        // not named here: they are stated beside the field itself, where the
        // count says how many there are to step through.
        if self
            .fields
            .get(focus)
            .is_some_and(|field| !field.options().is_empty())
        {
            keys.push(Span::styled(LIST_KEY_LABEL, style::KEYBAR_KEY));
            keys.push(Span::styled(
                lang.render(&Msg::FormKeyList),
                style::KEYBAR_LABEL,
            ));
        }

        keys.push(Span::styled("Enter", style::KEYBAR_KEY));
        keys.push(Span::styled(
            lang.render(&if self.is_valid() {
                Msg::FormKeyContinue
            } else {
                Msg::FormKeyIncomplete
            }),
            style::KEYBAR_LABEL,
        ));
        keys.push(Span::styled("Esc", style::KEYBAR_KEY));
        keys.push(Span::styled(
            lang.render(&Msg::FormKeyCancel),
            style::KEYBAR_LABEL,
        ));

        lines.push(Line::from(keys));

        frame.render_widget(Paragraph::new(lines), area);

        if let Some((x, y)) = cursor_at {
            frame.set_cursor_position((x, y));
        }
    }
}

/// Places a box of at most `wanted` rows against `anchor`, inside `terminal`.
///
/// Below the anchor by preference, above it when the room below is smaller,
/// and **shrunk to whatever that side actually has** — never merely moved. A
/// box placed at its full height where the room is shorter runs off the
/// terminal, which on a 24-row screen means it is drawn over the key bar and
/// through the frame's bottom border: the list looks like it broke the
/// interface rather than like it has more rows than fit.
///
/// Shrinking costs nothing the list does not already handle. It scrolls, so
/// fewer rows means fewer visible at once rather than options that cannot be
/// reached.
///
/// It keeps the anchor's width and left edge, so the two boxes read as one
/// stack rather than as two unrelated dialogs.
fn below(anchor: Rect, wanted: u16, terminal: Rect) -> Rect {
    let under = anchor.y + anchor.height;
    let bottom = terminal.y + terminal.height;

    let room_below = bottom.saturating_sub(under);
    let room_above = anchor.y.saturating_sub(terminal.y);

    // The taller side wins, so the list is drawn where most of it is legible.
    // Below is preferred on a tie: the eye is already travelling downwards
    // through the fields.
    let (y, room) = if room_below >= room_above {
        (under, room_below)
    } else {
        (terminal.y, room_above)
    };

    let height = wanted.min(room);

    Rect {
        x: anchor.x,
        // Sitting the box against the anchor rather than against the terminal
        // edge when it goes above: the gap belongs at the far end, not between
        // the list and the field it answers.
        y: if y == terminal.y {
            anchor.y - height
        } else {
            y
        },
        width: anchor.width,
        height,
    }
}

/// The note under a field: what is wrong, or what the value parsed as.
///
/// A warning the tool then ignores is worse than no warning, so this states
/// the problem rather than merely that there is one.
fn note_line(field: &Field, lang: Lang) -> Line<'static> {
    let mut spans = if let Some(error) = field.error() {
        // An empty required field is not yet a mistake — the operator has not
        // finished — so it reads as a prompt rather than a failure.
        let style = if field.is_empty() {
            style::BLOCK_SUBTITLE
        } else {
            style::OUTPUT_ERROR
        };

        vec![Span::styled(format!("  {error}"), style)]
    } else {
        match field.parsed_summary() {
            Some(summary) => vec![Span::styled(format!("  ✓ {summary}"), style::RESULT_OK)],
            None => vec![Span::styled("  ✓", style::RESULT_OK)],
        }
    };

    // What the host offers, on the row the operator is already reading for the
    // validation note. A row of its own would cost one per field, which on a
    // three-field form is the difference between fitting a 24-row terminal and
    // not.
    if !field.options().is_empty() {
        spans.push(Span::styled(
            lang.render(&Msg::FormOptionCount {
                position: field.option_position().map(|index| index + 1),
                total: field.options().len(),
            }),
            style::BLOCK_SUBTITLE,
        ));
    }

    Line::from(spans)
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

    /// A terminal 24 rows tall, the size the interface is measured against.
    fn terminal() -> Rect {
        Rect::new(0, 0, 80, 24)
    }

    #[test]
    fn an_options_box_that_fits_below_is_drawn_below() {
        let anchor = Rect::new(4, 5, 72, 8);

        let placed = below(anchor, 6, terminal());

        assert_eq!(placed.y, 13, "immediately under the anchor");
        assert_eq!(placed.height, 6, "at the height it asked for");
    }

    #[test]
    fn an_options_box_never_runs_off_the_bottom_of_the_terminal() {
        // Drawn at full height where the room is shorter, it lands on the key
        // bar and through the frame's bottom border — which reads as the list
        // having broken the interface rather than as having more rows than
        // fit.
        let anchor = Rect::new(4, 5, 72, 16);

        let placed = below(anchor, 7, terminal());

        assert!(
            placed.y + placed.height <= 24,
            "got y={} height={}",
            placed.y,
            placed.height
        );
    }

    #[test]
    fn an_options_box_goes_above_when_that_side_has_more_room() {
        // The form sits low enough that below it is two rows and above it is
        // eighteen; a chooser drawn into the two would show one option.
        let anchor = Rect::new(4, 18, 72, 4);

        let placed = below(anchor, 8, terminal());

        assert!(placed.y < anchor.y, "got y={}", placed.y);
        assert_eq!(
            placed.y + placed.height,
            anchor.y,
            "it must sit against the field it answers, not against the screen edge"
        );
    }

    #[test]
    fn an_options_box_is_shrunk_rather_than_moved_when_neither_side_fits() {
        // Both sides are short, so it takes the taller one at whatever height
        // that side has. The list scrolls, so fewer rows means fewer visible
        // at once rather than options that cannot be reached.
        let anchor = Rect::new(4, 9, 72, 12);

        let placed = below(anchor, 10, terminal());

        assert!(placed.height < 10, "got height={}", placed.height);
        assert!(placed.height > 0, "it must still be drawn");
        assert!(placed.y + placed.height <= 24);
    }

    #[test]
    fn an_options_box_keeps_the_width_and_left_edge_of_the_form() {
        // The two boxes read as one stack rather than as two dialogs.
        let anchor = Rect::new(4, 5, 72, 8);

        let placed = below(anchor, 6, terminal());

        assert_eq!(placed.x, anchor.x);
        assert_eq!(placed.width, anchor.width);
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
