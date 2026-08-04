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

/// The dialog's share of the screen, as `docs/ui.md` specifies it.
const WIDTH_PERCENT: u16 = 60;
const HEIGHT_PERCENT: u16 = 40;

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
    pub fn render(&self, frame: &mut Frame) {
        let area = layout::centred_percent(WIDTH_PERCENT, HEIGHT_PERCENT, frame.area());

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        let mut lines = vec![Line::from(self.body.clone()), Line::from("")];

        if let Some(ref warning) = self.warning {
            lines.push(Line::styled(warning.clone(), style::DANGER_TEXT));
            lines.push(Line::from(""));
        }

        lines.push(self.choice_line());

        let dialog = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.title.clone())
                    .border_style(style::DIALOG_BORDER_DANGER),
            )
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        frame.render_widget(dialog, area);
    }

    /// The yes/no line, with the current selection highlighted.
    fn choice_line(&self) -> Line<'static> {
        let (yes, no) = if self.accepted {
            (style::CHOICE_SELECTED, style::CHOICE_NORMAL)
        } else {
            (style::CHOICE_NORMAL, style::CHOICE_SELECTED)
        };

        Line::from(vec![
            Span::styled(" Yes ", yes),
            Span::raw("   "),
            Span::styled(" No ", no),
            Span::raw("      (Tab to switch, Enter to confirm, Esc to cancel)"),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn the_dialog_keeps_the_proportions_the_contract_states() {
        // `docs/ui.md` specifies 60% x 40%; the styles and the centring are
        // shared, but these two numbers belong to this dialog.
        assert_eq!(WIDTH_PERCENT, 60);
        assert_eq!(HEIGHT_PERCENT, 40);
    }
}
