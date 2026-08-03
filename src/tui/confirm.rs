//! Confirmation dialog for destructive operations.
//!
//! Hardening the configuration and changing the port can both lock an
//! administrator out of a remote server, so neither runs without an explicit
//! confirmation.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

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
        let area = centred_rect(60, 40, frame.area());

        // Clear first, or the interface underneath shows through the dialog.
        frame.render_widget(Clear, area);

        let mut lines = vec![Line::from(self.body.clone()), Line::from("")];

        if let Some(ref warning) = self.warning {
            lines.push(Line::styled(
                warning.clone(),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::from(""));
        }

        lines.push(self.choice_line());

        let dialog = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(self.title.clone())
                    .border_style(Style::default().fg(Color::Yellow)),
            )
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left);

        frame.render_widget(dialog, area);
    }

    /// The yes/no line, with the current selection highlighted.
    fn choice_line(&self) -> Line<'static> {
        let selected = Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD);

        let (yes, no) = if self.accepted {
            (selected, Style::default())
        } else {
            (Style::default(), selected)
        };

        Line::from(vec![
            Span::styled(" Yes ", yes),
            Span::raw("   "),
            Span::styled(" No ", no),
            Span::raw("      (Tab to switch, Enter to confirm, Esc to cancel)"),
        ])
    }
}

/// Computes a centred rectangle occupying the given percentage of the area.
fn centred_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
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
    fn centred_rect_stays_inside_its_area() {
        let area = Rect::new(0, 0, 100, 50);
        let centred = centred_rect(60, 40, area);

        assert!(centred.width <= area.width);
        assert!(centred.height <= area.height);
        assert!(centred.x + centred.width <= area.x + area.width);
        assert!(centred.y + centred.height <= area.y + area.height);
    }
}
