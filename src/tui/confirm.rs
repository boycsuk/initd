//! Confirmation dialog for destructive operations.
//!
//! Hardening the configuration and changing the port can both lock an
//! administrator out of a remote server, so neither runs without an explicit
//! confirmation.

use ratatui::Frame;
use ratatui::layout::Alignment;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::{layout, style};
use crate::i18n::{Lang, Msg};

/// The dialog's share of the screen, as `docs/ui.md` specifies it.
const WIDTH_PERCENT: u16 = 60;
const HEIGHT_PERCENT: u16 = 40;

/// Rows held back for the lockout warning.
///
/// Two, because the warnings are a sentence rather than a phrase and wrap once
/// at the dialog's width. A band too small truncates the sentence; one too
/// large steals rows from a description that is merely useful.
const WARNING_ROWS: u16 = 2;

/// A pending confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub title: String,
    pub body: String,
    /// Extra warning shown in red, for operations that risk a lockout.
    pub warning: Option<String>,
    /// Whether "yes" is currently selected.
    pub accepted: bool,
}

impl Confirm {
    /// Builds a confirmation defaulting to "no".
    ///
    /// Defaulting to the safe answer means a stray Enter cannot trigger a
    /// destructive operation.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            warning: None,
            accepted: false,
        }
    }

    /// Attaches a lockout warning.
    #[must_use]
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warning = Some(warning.into());
        self
    }

    /// Moves the selection between yes and no.
    pub fn toggle(&mut self) {
        self.accepted = !self.accepted;
    }

    /// Renders the dialog centred over the interface.
    ///
    /// The title, body and warning arrive as text because they are the task's
    /// own words, chosen before the dialog opened; `lang` renders only the
    /// chrome the dialog itself owns — the two answers and the key hint.
    pub fn render(&self, frame: &mut Frame, lang: Lang) {
        let area = layout::centred_percent(WIDTH_PERCENT, HEIGHT_PERCENT, frame.area());

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.clone())
            .border_style(style::DIALOG_BORDER_DANGER);
        let inner = block.inner(area);

        frame.render_widget(block, area);

        // The choice is laid out before the prose rather than appended after
        // it. Stacked in one paragraph, a body long enough to fill the dialog
        // pushed `Yes` and `No` past the bottom border and they simply vanished
        // — leaving a destructive operation asking a question with no visible
        // answers. Found on Rocky, whose longer `PRETTY_NAME` narrowed the
        // dialog enough to wrap `ssh.harden`'s description one line further,
        // but the description was always one terminal size away from doing it
        // on any family.
        let (above, choice_area) = layout::split_off_last_row(inner);

        // The warning is given a band of its own too, below the description and
        // above the choice, because it is the one line here that must be read.
        // Appended to the description it was the first thing a long body pushed
        // out of sight — and a dialog that has lost its warning still looks
        // like a dialog, so nothing reports it. The description is what yields
        // instead: by the time this is on screen the operator has chosen the
        // task and can scroll back to its detail pane, whereas the risk of
        // losing the machine is stated only here.
        let (body_area, warning_area) = match self.warning {
            Some(_) => {
                let (body, warning) = layout::split_off_last_rows(above, WARNING_ROWS);
                (body, Some(warning))
            }
            None => (above, None),
        };

        let body = Paragraph::new(self.body.clone())
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        frame.render_widget(body, body_area);

        if let (Some(warning), Some(warning_area)) = (self.warning.as_ref(), warning_area) {
            frame.render_widget(
                Paragraph::new(warning.clone())
                    .style(style::DANGER_TEXT)
                    .wrap(Wrap { trim: true })
                    .alignment(Alignment::Left),
                warning_area,
            );
        }

        frame.render_widget(
            Paragraph::new(self.choice_line(lang)).alignment(Alignment::Left),
            choice_area,
        );
    }

    /// The yes/no line, with the current selection highlighted.
    fn choice_line(&self, lang: Lang) -> Line<'static> {
        let (yes, no) = if self.accepted {
            (style::CHOICE_SELECTED, style::CHOICE_NORMAL)
        } else {
            (style::CHOICE_NORMAL, style::CHOICE_SELECTED)
        };

        Line::from(vec![
            Span::styled(lang.render(&Msg::ConfirmYes), yes),
            Span::raw("   "),
            Span::styled(lang.render(&Msg::ConfirmNo), no),
            Span::raw(lang.render(&Msg::ConfirmKeyHint)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders a dialog and returns the screen as text.
    fn rendered(confirm: &Confirm, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))
                .expect("the test backend must build");

        terminal
            .draw(|frame| confirm.render(frame, Lang::En))
            .expect("the dialog must draw");

        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One of the answers, as it is drawn.
    ///
    /// Trimmed of the badge padding the catalogue carries: what the assertions
    /// are about is whether the word survived being laid out, and a screen
    /// dumped row by row has already lost the spaces around it to the cells
    /// beside it.
    fn answer(message: &Msg) -> String {
        Lang::En.render(message).trim().to_owned()
    }

    /// A description long enough to fill the dialog at any usable size.
    ///
    /// `ssh.harden`'s own, which is what exposed this: it wraps to more lines
    /// than the dialog has rows, so whatever is laid out after it is what gets
    /// lost.
    const LONG_BODY: &str = "Disables root login, password authentication, agent and X11 \
         forwarding, tunnelling and user environments; limits authentication attempts to 3 \
         and the login grace period to 30 seconds; disconnects idle sessions after 10 \
         minutes; and turns on verbose logging so the key each login used is recorded.";

    #[test]
    fn a_body_too_long_for_the_dialog_cannot_push_the_choice_off_screen() {
        // The failure this guards against is silent: the dialog still looks
        // like a dialog, and a destructive operation is left asking a question
        // with no visible answers.
        let confirm = Confirm::new("Harden the SSH configuration", LONG_BODY);

        let screen = rendered(&confirm, 80, 24);

        assert!(
            screen.contains(&answer(&Msg::ConfirmYes)),
            "the choice must be drawn: {screen}"
        );
        assert!(
            screen.contains(&answer(&Msg::ConfirmNo)),
            "the choice must be drawn: {screen}"
        );
    }

    #[test]
    fn a_body_too_long_for_the_dialog_cannot_push_the_warning_off_screen() {
        // The warning outranks the description: by the time this is on screen
        // the operator has chosen the task, but the risk of losing the machine
        // is stated only here.
        let confirm = Confirm::new("Harden the SSH configuration", LONG_BODY)
            .with_warning("This can lock you out of a remote server.");

        let screen = rendered(&confirm, 80, 24);

        assert!(
            screen.contains("lock you out"),
            "the warning must survive a long body: {screen}"
        );
        assert!(
            screen.contains(&answer(&Msg::ConfirmYes)),
            "and so must the choice: {screen}"
        );
    }

    #[test]
    fn the_warning_and_choice_survive_a_narrow_terminal() {
        // Narrower means the body wraps to more lines, which is what crowds the
        // rest out — the Rocky failure was a wider `PRETTY_NAME` doing exactly
        // this by one line.
        let confirm = Confirm::new("Harden the SSH configuration", LONG_BODY)
            .with_warning("This can lock you out of a remote server.");

        let screen = rendered(&confirm, layout::MIN_WIDTH, layout::MIN_HEIGHT);

        assert!(
            screen.contains("lock you out"),
            "the warning must survive the smallest usable terminal: {screen}"
        );
        assert!(
            screen.contains(&answer(&Msg::ConfirmYes)),
            "and so must the choice: {screen}"
        );
    }

    #[test]
    fn defaults_to_the_safe_answer() {
        // A stray Enter must never run a destructive operation.
        assert!(!Confirm::new("Harden SSH", "Continue?").accepted);
    }

    #[test]
    fn toggling_switches_the_selection() {
        let mut confirm = Confirm::new("Harden SSH", "Continue?");

        confirm.toggle();
        assert!(confirm.accepted);

        confirm.toggle();
        assert!(!confirm.accepted);
    }

    #[test]
    fn carries_an_optional_lockout_warning() {
        let confirm = Confirm::new("Change port", "Continue?")
            .with_warning("You may lose access to this server.");

        assert!(confirm.warning.is_some());
    }

    /// The columns the dialog's border occupies, read back from a real buffer.
    ///
    /// Asserting on the constants would only compare them with themselves; what
    /// has to hold is that the drawn dialog is the size `docs/ui.md` states,
    /// which is a property of `render` rather than of the numbers it reads.
    fn drawn_bounds(width: u16, height: u16) -> (u16, u16) {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| Confirm::new("Change port", "Continue?").render(frame, Lang::En))
            .expect("drawing must not fail");

        let buffer = terminal.backend().buffer().clone();
        let drawn: Vec<(u16, u16)> = (0..height)
            .flat_map(|y| (0..width).map(move |x| (x, y)))
            .filter(|&(x, y)| buffer[(x, y)].symbol() != " ")
            .collect();

        let columns = drawn.iter().map(|&(x, _)| x);
        let rows = drawn.iter().map(|&(_, y)| y);

        let span = |values: &mut dyn Iterator<Item = u16>| {
            let (min, max) = values.fold((u16::MAX, 0), |(lo, hi), v| (lo.min(v), hi.max(v)));
            max - min + 1
        };

        (span(&mut columns.into_iter()), span(&mut rows.into_iter()))
    }

    #[test]
    fn the_dialog_takes_the_share_of_the_screen_the_contract_states() {
        // `docs/ui.md` specifies 60% x 40%. Measured on the buffer, so a render
        // that stopped threading these constants through would be caught.
        let (width, height) = drawn_bounds(100, 50);

        assert_eq!(width, 60, "60% of 100 columns");
        assert_eq!(height, 20, "40% of 50 rows");
    }

    #[test]
    fn the_dialog_stays_inside_a_small_terminal() {
        // Centring clamps rather than overflowing; a dialog wider than the
        // screen would render as nothing.
        let (width, height) = drawn_bounds(40, 12);

        assert!(width <= 40, "got {width}");
        assert!(height <= 12, "got {height}");
    }
}
