//! The help overlay.
//!
//! The key bar shows what is available *here*; this shows everything, grouped
//! by where it applies. It is the answer to "what else can this do", which a
//! bar four hints wide cannot give.
//!
//! The movement keys scroll it; any other key closes it, including the one
//! that opened it. An overlay that has to be dismissed a particular way traps
//! whoever opened it by accident.
//!
//! It scrolls rather than dropping what will not fit, because the section
//! worth reading most — the keys that cannot be guessed from anywhere else —
//! is the one at the end.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::{layout, style};

/// Width the overlay is drawn at, before clamping to the terminal.
const WIDTH: u16 = 70;

/// Height the overlay is drawn at, before clamping.
const HEIGHT: u16 = 24;

/// One group of bindings, as it appears in the overlay.
struct Section {
    title: &'static str,
    keys: &'static [(&'static str, &'static str)],
}

/// Every binding the interface has, grouped by where it applies.
///
/// Stated here rather than derived from the key handlers: a handler says what
/// a key does, not what it is *for*, and the grouping is the part that makes a
/// list of forty bindings readable.
const SECTIONS: &[Section] = &[
    Section {
        title: "Anywhere",
        keys: &[
            ("Tab", "move focus between the tree and the output"),
            ("?", "this help"),
            ("q", "quit"),
        ],
    },
    Section {
        title: "Task tree",
        keys: &[
            ("↑ k", "previous row"),
            ("↓ j", "next row"),
            ("g G", "first / last row"),
            ("Enter", "open a category, or run a task"),
            ("/", "find a task anywhere in the tree"),
            ("Esc ← h", "back to the parent level"),
        ],
    },
    Section {
        title: "Search",
        keys: &[
            ("(type)", "filter by title or task id"),
            ("↑ ↓", "move between results"),
            ("Enter", "go to the task, without running it"),
            ("Esc", "close, leaving the cursor where it was"),
        ],
    },
    // Listed because this is when somebody most needs it: a task three minutes
    // in is exactly when `?` gets pressed, and the key bar that also shows
    // Ctrl-C is dropped on a terminal under 24 rows.
    Section {
        title: "While a task runs",
        keys: &[
            ("Ctrl-C", "stop after the current command"),
            ("↑ ↓", "scroll the output"),
            ("Tab", "move focus to the output"),
        ],
    },
    Section {
        title: "Output",
        keys: &[
            ("↑ k / ↓ j", "scroll a line"),
            ("PageUp/Down", "scroll a page"),
            ("g", "oldest retained line"),
            ("G f", "newest output, and follow it"),
            ("w", "wrap long lines"),
        ],
    },
    Section {
        title: "Forms",
        keys: &[
            ("Tab", "next field"),
            ("Enter", "next field, or submit on the last"),
            ("Ctrl-A/E", "start / end of the value"),
            ("Ctrl-U/K", "clear before / after the cursor"),
            ("Ctrl-W", "delete the previous word"),
            ("Esc", "cancel (twice, if anything is typed)"),
        ],
    },
    Section {
        title: "Confirmation",
        keys: &[
            ("y", "apply"),
            ("n Esc", "cancel"),
            ("← →", "move between the answers"),
        ],
    },
    Section {
        title: "After a change that could lock you out",
        keys: &[
            ("K", "keep the change"),
            ("R", "put the previous configuration back"),
            ("(wait)", "puts it back on its own after 60s"),
        ],
    },
];

/// Draws the overlay over the interface.
///
/// `scroll` is how far down the list has been moved, in lines.
pub fn render(frame: &mut Frame, scroll: u16) {
    let area = layout::centred(WIDTH, HEIGHT, frame.area());

    // Clear first, or the interface underneath shows through.
    frame.render_widget(Clear, area);

    let all = lines();
    let visible_height = area.height.saturating_sub(2);
    let max_scroll = (all.len() as u16).saturating_sub(visible_height);
    let scroll = scroll.min(max_scroll);

    // The hint says which keys move the list, but only while there is
    // something below the fold to move to.
    let footer = if max_scroll > 0 {
        format!(
            " ↑↓ more · any other key closes  ({}%) ",
            percentage(scroll, max_scroll)
        )
    } else {
        " any key closes ".to_owned()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(style::BORDER_FOCUSED)
        .title(Span::styled(" Keys ", style::PANE_TITLE))
        .title_bottom(Span::styled(footer, style::BLOCK_SUBTITLE));

    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(all).scroll((scroll, 0)), inner);
}

/// How far through the list the view has reached.
const fn percentage(scroll: u16, max_scroll: u16) -> u16 {
    if max_scroll == 0 {
        return 100;
    }

    (scroll as u32 * 100 / max_scroll as u32) as u16
}

/// How far the list can be scrolled inside a given frame.
///
/// The caller clamps its own offset with this, so pressing down at the bottom
/// does nothing rather than scrolling into blank space.
pub fn max_scroll(area: Rect) -> u16 {
    let height = layout::centred(WIDTH, HEIGHT, area)
        .height
        .saturating_sub(2);

    (lines().len() as u16).saturating_sub(height)
}

/// The overlay's full contents.
///
/// Every section is built whether or not it fits: the list scrolls rather than
/// dropping what will not fit, because the sections most worth reading — the
/// keys that cannot be guessed from anywhere else — are the ones at the end.
fn lines() -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for section in SECTIONS {
        lines.push(Line::styled(section.title, style::HEADING));

        for (key, description) in section.keys {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key:<12}"), style::KEYBAR_KEY),
                Span::styled(*description, style::NORMAL),
            ]));
        }

        lines.push(Line::raw(""));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_section_states_at_least_one_key() {
        for section in SECTIONS {
            assert!(
                !section.keys.is_empty(),
                "section {} lists nothing",
                section.title
            );
            assert!(!section.title.is_empty());
        }
    }

    #[test]
    fn the_dangerous_keys_are_documented_in_their_own_section() {
        // K and R are the two keys whose meaning cannot be guessed from the
        // rest of the interface, so they must be findable here.
        let verify = SECTIONS
            .iter()
            .find(|section| section.title.contains("lock you out"))
            .expect("the verification keys must have a section");

        let keys: Vec<&str> = verify.keys.iter().map(|(key, _)| *key).collect();

        assert!(keys.contains(&"K"), "got {keys:?}");
        assert!(keys.contains(&"R"), "got {keys:?}");
    }

    #[test]
    fn every_section_is_built_whether_or_not_it_fits() {
        // The sections most worth reading are the ones at the end, so the list
        // scrolls rather than dropping what will not fit.
        let all = lines();

        for section in SECTIONS {
            assert!(
                all.iter().any(|line| line.to_string() == section.title),
                "section {} must be present",
                section.title
            );
        }
    }

    #[test]
    fn the_list_scrolls_when_it_is_taller_than_its_frame() {
        // At the reference size the overlay does not fit, which is exactly the
        // case that used to lose the verification keys.
        assert!(
            max_scroll(Rect::new(0, 0, 80, 24)) > 0,
            "the reference size must offer scrolling"
        );
    }

    #[test]
    fn the_overlay_never_grows_past_its_own_height() {
        // It is an overlay, not a screen: on a large terminal it stays the
        // same size and scrolls, rather than covering everything.
        let huge = layout::centred(WIDTH, HEIGHT, Rect::new(0, 0, 200, 200));

        assert_eq!(huge.height, HEIGHT);
        assert_eq!(huge.width, WIDTH);
        assert!(
            max_scroll(Rect::new(0, 0, 200, 200)) > 0,
            "the list is longer than the overlay at any terminal size"
        );
    }

    #[test]
    fn the_overlay_fits_the_smallest_usable_terminal() {
        // It is clamped rather than allowed to overflow into nothing.
        let area = layout::centred(WIDTH, HEIGHT, Rect::new(0, 0, 60, 15));

        assert!(area.width <= 60);
        assert!(area.height <= 15);
        assert!(!lines().is_empty(), "something must still be shown");
    }

    #[test]
    fn progress_reads_as_a_percentage_of_the_way_down() {
        assert_eq!(percentage(0, 20), 0);
        assert_eq!(percentage(10, 20), 50);
        assert_eq!(percentage(20, 20), 100);
        assert_eq!(percentage(0, 0), 100, "a list that fits is fully shown");
    }
}
