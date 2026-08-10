//! Confirmation dialog for destructive operations.
//!
//! Hardening the configuration and changing the port can both lock an
//! administrator out of a remote server, so neither runs without an explicit
//! confirmation.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::{layout, style};
use crate::i18n::{Lang, Msg};

/// Rows the dialog spends beyond its wrapped body: the chrome every modal
/// shares, plus the rule above the answers and the row the answers sit on.
///
/// Sized from its content rather than as a share of the screen, which is what
/// this was and what put a 40%-tall block around two lines of text. That
/// mattered little while nine tasks confirmed; it matters now that all but
/// three do, because the dialog an operator sees most is the one whose empty
/// half they read past every time.
const CHROME_ROWS: u16 = layout::DIALOG_CHROME_ROWS + 3;

/// Rows the warning needs, and a blank one separating it from the description.
///
/// Measured rather than fixed. It was two — the width at which the sentences
/// happened to wrap once — and a fixed band is wrong in both directions: too
/// small it truncates the one line here that must be read, too large it steals
/// rows from a description that is merely useful. Widening the dialog was
/// enough to make the old constant draw the second half of the warning over
/// the rule below it.
fn warning_rows(warning: &str, width: usize) -> u16 {
    layout::wrapped_rows(warning, width) + 1
}

/// Rows the warning may occupy before it starts scrolling instead of growing.
///
/// A ceiling rather than a share of the screen, and it exists because one
/// warning now carries a list: `users.lock-root` names every account that keeps
/// access, and a host with twenty administrators would otherwise size a dialog
/// taller than the terminal — at which point centring clamps it and the choice
/// at the bottom is what gets cut off, leaving an irreversible operation asking
/// a question with no visible answers.
///
/// Eight rows is a heading and roughly six accounts, which fits inside
/// [`layout::MIN_HEIGHT`] alongside a description. Beyond that the band stops
/// growing and scrolls, so no account is hidden with no way to reach it — the
/// one thing this dialog must not do.
const WARNING_MAX_ROWS: u16 = 8;

/// A pending confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirm {
    pub title: String,
    pub body: String,
    /// Extra warning shown in red, for operations that risk a lockout.
    pub warning: Option<String>,
    /// Whether "yes" is currently selected.
    pub accepted: bool,
    /// First visible row of the warning, when it is taller than its band.
    ///
    /// Held here rather than computed while drawing, for the reason `Form`
    /// keeps its own: a scroll position is state, and the alternative is
    /// `render` mutating what it was handed. Zero for every warning short
    /// enough to fit, which is all of them but one.
    pub warning_scroll: u16,
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
            warning_scroll: 0,
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

    /// Rows the warning needs, and the band it is allowed to have.
    ///
    /// Returned together because the second is derived from the first and the
    /// caller needs both: how far it can scroll is the difference.
    fn warning_extent(&self, width: usize) -> (u16, u16) {
        let needed = self
            .warning
            .as_deref()
            .map_or(0, |warning| warning_rows(warning, width));

        (needed, needed.min(WARNING_MAX_ROWS))
    }

    /// Scrolls the warning by a row, where it has more than it can show.
    ///
    /// Clamped at both ends rather than wrapping: a list that jumped back to
    /// the top on the last keypress would read as having lost rows, and the
    /// operator is counting accounts here.
    pub fn scroll_warning(&mut self, delta: i16) {
        let text_width = layout::DIALOG_WIDTH as usize - 2 - layout::DIALOG_GUTTER * 2;
        let (needed, band) = self.warning_extent(text_width);
        let max = needed.saturating_sub(band);

        self.warning_scroll = self.warning_scroll.saturating_add_signed(delta).min(max);
    }

    /// Whether the warning holds more than its band can show.
    ///
    /// Asked by the key bar, so the scroll keys are offered only where they do
    /// something — a hint for a key that moves nothing is one that teaches the
    /// operator to distrust the bar.
    pub fn warning_scrolls(&self) -> bool {
        let text_width = layout::DIALOG_WIDTH as usize - 2 - layout::DIALOG_GUTTER * 2;
        let (needed, band) = self.warning_extent(text_width);

        needed > band
    }

    /// Renders the dialog centred over the interface.
    ///
    /// The title, body and warning arrive as text because they are the task's
    /// own words, chosen before the dialog opened; `lang` renders only the
    /// chrome the dialog itself owns — the two answers and the key hint.
    pub fn render(&self, frame: &mut Frame, lang: Lang) {
        // Measured at the width the body will actually be drawn at: the two
        // borders and the gutter each side are gone by the time it wraps.
        let text_width = layout::DIALOG_WIDTH as usize - 2 - layout::DIALOG_GUTTER * 2;
        let body_rows = layout::wrapped_rows(&self.body, text_width);
        // The band it gets rather than the rows it wants. A warning carrying a
        // list of accounts is unbounded — one per administrator on the host —
        // and a dialog sized to all of them grows past the terminal, where
        // centring clamps it and the choice at the bottom is what disappears.
        let (_, warning_rows) = self.warning_extent(text_width);

        let area = layout::centred(
            layout::DIALOG_WIDTH,
            CHROME_ROWS + body_rows + warning_rows,
            frame.area(),
        );

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        // Red only where a warning was attached, which is where the change can
        // end the session applying it. Almost every task confirms now, and a
        // red frame around all of them says nothing about any — the colour is
        // what distinguishes `users.lock-root` from installing a shell.
        //
        // Derived from the warning rather than passed separately: two fields
        // that must agree are two fields that can disagree, and the one that
        // would go wrong is a danger frame over a dialog with nothing to warn
        // about.
        let border = if self.warning.is_some() {
            style::DIALOG_BORDER_DANGER
        } else {
            style::DIALOG_BORDER_INPUT
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border)
            // Styled like the parameter form's title, and for the same reason:
            // it names the task rather than the panel. It was the one title in
            // the interface drawn with no role at all, which left the dialog
            // that asks before a destructive change looking less deliberate
            // than the form that asks for a port.
            .title(Span::styled(format!(" {} ", self.title), style::EMPHASIS));
        // The gutter and the inset the parameter form uses, applied here so a
        // dialog reads the same whichever one it is: text a cell in from the
        // frame, a blank row at each end of the content. Without them the body
        // sat against the top border while the height below it went unused,
        // which is the shape an operator reported.
        let inner = layout::inset(block.inner(area), layout::DIALOG_GUTTER as u16, 1);

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

        // The rule the parameter form draws above its footer, for the reason it
        // draws one: the row below acts on the dialog rather than on anything
        // above it, and a blank row cannot say that where blank rows are also
        // what separate content. It spans the full inner width — the gutter is
        // a margin for text, and a rule stopping short of the frame reads as a
        // line somebody left unfinished.
        let (_, rule_row) = layout::split_off_last_row(above);
        let rule = Rect {
            x: area.x + 1,
            width: area.width.saturating_sub(2),
            ..rule_row
        };

        frame.render_widget(
            Paragraph::new("─".repeat(rule.width as usize)).style(border),
            rule,
        );

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
                let (body, warning) = layout::split_off_last_rows(above, warning_rows);
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
                    // Scrolled rather than truncated. Where the warning is a
                    // list of the accounts that survive locking root, a row
                    // held back is an account the operator cannot see — and
                    // theirs may be the one below the fold.
                    .scroll((self.warning_scroll, 0))
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

        let mut spans = vec![
            Span::styled(lang.render(&Msg::ConfirmYes), yes),
            Span::raw("   "),
            Span::styled(lang.render(&Msg::ConfirmNo), no),
            Span::raw(lang.render(&Msg::ConfirmKeyHint)),
        ];

        // Only where it moves something. A hint for a key that does nothing is
        // how a bar stops being read — and this one appears on exactly one
        // dialog, where the rows below the fold are accounts the operator is
        // checking for their own.
        if self.warning_scrolls() {
            spans.push(Span::raw(lang.render(&Msg::ConfirmScrollHint)));
        }

        Line::from(spans)
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

    /// A warning shaped like `users.lock-root`'s on a host with many
    /// administrators: a heading and one row per account that keeps access.
    fn account_list(accounts: usize) -> String {
        let mut warning = format!("{accounts} accounts can still get in:");

        for n in 0..accounts {
            warning.push_str(&format!("\n  admin{n} — key + password"));
        }

        warning
    }

    #[test]
    fn a_warning_longer_than_its_band_scrolls_rather_than_growing() {
        // The failure this prevents is the one the choice-off-screen tests
        // already describe, reached by a new route: this warning is unbounded —
        // one row per administrator on the host — so a dialog sized to all of
        // them grows past the terminal, centring clamps it, and the answers at
        // the bottom are what get cut off.
        let confirm =
            Confirm::new("Lock the root account", "Continue?").with_warning(account_list(20));

        let (_, height) = bounds_of(&confirm, 100, 50);
        let screen = rendered(&confirm, 100, 50);

        assert!(
            height <= 50,
            "a twenty-account list must not outgrow the terminal: {height}"
        );
        assert!(
            screen.contains(&answer(&Msg::ConfirmYes)),
            "and the choice must survive it: {screen}"
        );
    }

    #[test]
    fn scrolling_reaches_the_accounts_below_the_fold() {
        // Decision 7, and the whole reason the band scrolls rather than
        // truncating: a row held back is an account the operator cannot see,
        // and theirs may be the one below the fold. Asserted by reading the
        // last account off the screen, which no amount of clamping produces.
        let mut confirm =
            Confirm::new("Lock the root account", "Continue?").with_warning(account_list(20));

        assert!(
            !rendered(&confirm, 100, 50).contains("admin19"),
            "the fixture must actually overflow, or this proves nothing"
        );

        for _ in 0..40 {
            confirm.scroll_warning(1);
        }

        assert!(
            rendered(&confirm, 100, 50).contains("admin19"),
            "every account must be reachable: {}",
            rendered(&confirm, 100, 50)
        );
    }

    #[test]
    fn scrolling_stops_at_both_ends_rather_than_wrapping() {
        // A list that jumped back to the top on the last keypress would read as
        // having lost rows, and the operator is counting accounts here.
        let mut confirm =
            Confirm::new("Lock the root account", "Continue?").with_warning(account_list(20));

        confirm.scroll_warning(-5);
        assert_eq!(confirm.warning_scroll, 0, "it cannot scroll above the top");

        for _ in 0..100 {
            confirm.scroll_warning(1);
        }
        let bottom = confirm.warning_scroll;

        confirm.scroll_warning(1);
        assert_eq!(
            confirm.warning_scroll, bottom,
            "nor past the last row it has"
        );
    }

    #[test]
    fn a_warning_that_fits_offers_no_scrolling() {
        // The hint appears on one dialog and must not appear on the others: a
        // key that does nothing is how a bar stops being read.
        let short = Confirm::new("Change port", "Continue?")
            .with_warning("This can lock you out of a remote server.");

        assert!(!short.warning_scrolls());
        assert!(
            Confirm::new("Lock the root account", "Continue?")
                .with_warning(account_list(20))
                .warning_scrolls(),
            "and it must appear where there is something below the fold"
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
        bounds_of(&Confirm::new("Change port", "Continue?"), width, height)
    }

    /// The rectangle `confirm` actually paints, in cells.
    fn bounds_of(confirm: &Confirm, width: u16, height: u16) -> (u16, u16) {
        let backend = ratatui::backend::TestBackend::new(width, height);
        let mut terminal = ratatui::Terminal::new(backend).expect("test terminal");

        terminal
            .draw(|frame| confirm.render(frame, Lang::En))
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
    fn the_dialog_is_as_tall_as_what_it_holds() {
        // It was a share of the screen — 60% x 40% — which put a block that
        // size around two lines of text and left the operator reading past an
        // empty half of it. Sized from the content instead, and pinned on the
        // buffer so a render that stopped measuring would be caught.
        //
        // Asserted on a terminal far larger than the dialog, which is where a
        // proportional one grew and a measured one does not.
        let (width, height) = drawn_bounds(100, 50);

        assert_eq!(width, layout::DIALOG_WIDTH, "one width for every modal");
        assert!(
            height < 12,
            "a two-line question must not reserve half the screen: {height}"
        );

        // And taller where there is more to say, or "measured" would just be
        // another fixed size.
        let long = Confirm::new(
            "Harden",
            "A description long enough to wrap several times over the dialog's \
             width, which is what a task with something to explain actually \
             carries when it opens one of these.",
        );
        let (_, taller) = bounds_of(&long, 100, 50);

        assert!(taller > height, "{taller} must exceed {height}");
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
