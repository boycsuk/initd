//! The interface's style table.
//!
//! Every style used anywhere in the TUI is named here and nowhere else. A
//! `Style` built at a call site drifts from its siblings the moment either is
//! edited, so call sites reference these constants instead.
//!
//! Two properties the table is designed around:
//!
//! 1. **Colour is semantic, never decorative.** The terminal theme owns the
//!    hues; `Color::Reset` means "whatever the user's foreground is".
//! 2. **No signal is carried by colour alone.** Every coloured state is also
//!    marked by a glyph or a word, so the interface survives `NO_COLOR`,
//!    monochrome themes and colour-blind operators. `DIM` in particular renders
//!    identically to normal under some themes, which is why disabled rows carry
//!    [`MARKER_UNSUPPORTED`] rather than relying on [`DISABLED`].
//!
//! The table is declared whole rather than grown entry by entry, so that the
//! roles stay a single readable reference and a new call site picks one instead
//! of inventing a colour. Entries the interface does not draw yet — the gauge,
//! result glyphs, the search highlight — are therefore allowed to be unused;
//! the alternative is scattering their definitions across later commits, which
//! is exactly the drift this module exists to prevent.
#![allow(dead_code)]

use ratatui::style::{Color, Modifier, Style};

/// Builds a style from a foreground colour alone.
///
/// `const fn` so the whole table is resolved at compile time.
const fn fg(color: Color) -> Style {
    Style::new().fg(color)
}

/// Builds a style from a foreground colour and a modifier.
const fn fg_mod(color: Color, modifier: Modifier) -> Style {
    Style::new().fg(color).add_modifier(modifier)
}

/// Builds a style from an explicit foreground/background pair.
const fn pair(foreground: Color, background: Color) -> Style {
    Style::new().fg(foreground).bg(background)
}

// --- Structure -------------------------------------------------------------

/// Expanded category rows.
pub const HEADING: Style = fg_mod(Color::Cyan, Modifier::BOLD);

/// Collapsed category rows; the `›` marker carries the meaning too.
pub const CATEGORY_COLLAPSED: Style = fg(Color::Cyan);

/// `Block` titles: the task title and the breadcrumb.
pub const PANE_TITLE: Style = fg(Color::Cyan);

/// Bottom titles and section headers inside the detail pane.
pub const BLOCK_SUBTITLE: Style = fg_mod(Color::White, Modifier::DIM);

/// Task rows, detail body text and child stdout.
pub const NORMAL: Style = fg(Color::Reset);

// --- Selection -------------------------------------------------------------

/// The selected row while its pane holds focus.
///
/// An explicit background/foreground pair rather than `REVERSED`, which is the
/// usual ratatui idiom: REVERSED swaps per cell, so a red destructive marker on
/// a reversed row renders as a red block and the row's meaning inverts with it.
/// The `▸` cursor glyph covers terminals that mangle backgrounds entirely.
pub const SELECTION_FOCUSED: Style = pair(Color::White, Color::Blue).add_modifier(Modifier::BOLD);

/// The selected row while focus is elsewhere.
pub const SELECTION_UNFOCUSED: Style =
    fg_mod(Color::White, Modifier::BOLD).add_modifier(Modifier::UNDERLINED);

/// The selected row when the task under it cannot run on this host.
pub const SELECTION_DISABLED: Style = pair(Color::Black, Color::White);

/// Unsupported rows and inert hints.
pub const DISABLED: Style = fg_mod(Color::White, Modifier::DIM);

// --- Row flags -------------------------------------------------------------

/// The `!` marker on a destructive task.
pub const FLAG_DANGER: Style = fg_mod(Color::Red, Modifier::BOLD);

/// The `…` marker on a task that needs input first.
pub const FLAG_INPUT: Style = fg(Color::Yellow);

/// The `·` marker on a task this host cannot run.
pub const FLAG_UNSUPPORTED: Style = fg_mod(Color::White, Modifier::DIM);

/// The `✓` glyph and `ok` lines.
pub const RESULT_OK: Style = fg(Color::Green);

/// The `✗` glyph on a failed task.
pub const RESULT_FAIL: Style = fg_mod(Color::Red, Modifier::BOLD);

/// A consequence the tool can inspect, and verify when asked.
pub const CONSEQUENCE: Style = fg(Color::Yellow);

/// A consequence beyond this machine, which the tool cannot check.
///
/// Distinct from [`CONSEQUENCE`] because the difference is the point: the
/// administrator has to be able to tell which warnings the tool can settle and
/// which are theirs to chase. Colour alone does not carry that, so the marker
/// differs too — the same reason the status pills stay readable without it.
pub const CONSEQUENCE_EXTERNAL: Style = fg_mod(Color::Yellow, Modifier::BOLD);

// --- Chrome ----------------------------------------------------------------

/// Depth guides, pinned rows and horizontal rules.
pub const TREE_GUIDE: Style = fg_mod(Color::White, Modifier::DIM);

/// Scrollbar track and arrows.
pub const SCROLLBAR_TRACK: Style = fg_mod(Color::White, Modifier::DIM);

/// Scrollbar thumb.
pub const SCROLLBAR_THUMB: Style = fg(Color::White);

/// The border of the focused pane.
pub const BORDER_FOCUSED: Style = fg(Color::Cyan);

/// The border of every other pane.
pub const BORDER_UNFOCUSED: Style = fg_mod(Color::White, Modifier::DIM);

/// The border of a pane, according to whether it holds focus.
pub const fn border(focused: bool) -> Style {
    if focused {
        BORDER_FOCUSED
    } else {
        BORDER_UNFOCUSED
    }
}

// --- Command output --------------------------------------------------------

/// The `$` prefix and the echoed command itself.
pub const OUTPUT_COMMAND: Style = fg_mod(Color::White, Modifier::DIM);

/// `W:` lines and other non-fatal notes.
pub const OUTPUT_WARN: Style = fg(Color::Yellow);

/// stderr on failure and invalid configuration lines.
pub const OUTPUT_ERROR: Style = fg_mod(Color::Red, Modifier::BOLD);

/// The `▌` live write position.
pub const OUTPUT_CURSOR: Style = Style::new().add_modifier(Modifier::REVERSED);

// --- Dialogs ---------------------------------------------------------------

/// Dialog headlines and the rollback countdown.
pub const DANGER_TEXT: Style = fg_mod(Color::Red, Modifier::BOLD);

/// Values that change, and key words inside dialogs.
pub const EMPHASIS: Style = fg_mod(Color::White, Modifier::BOLD);

/// The double border reserved for confirmation dialogs.
pub const DIALOG_BORDER_DANGER: Style = fg_mod(Color::Red, Modifier::BOLD);

/// The border of input forms and field boxes.
pub const DIALOG_BORDER_INPUT: Style = fg(Color::Blue);

/// The preselected safe answer in a y/N dialog.
pub const CHOICE_SELECTED: Style = Style::new()
    .add_modifier(Modifier::REVERSED)
    .add_modifier(Modifier::BOLD);

/// The other answer in a y/N dialog.
pub const CHOICE_NORMAL: Style = fg_mod(Color::White, Modifier::DIM);

/// The matched substring inside a filtered row.
pub const SEARCH_MATCH: Style = pair(Color::Black, Color::Yellow);

// --- Status row and key bar ------------------------------------------------
//
// Two families, because the status is drawn in two places that cannot share a
// style. A badge sits on a filled background; the status line rides a pane
// border, where a background would paint a block over the border it interrupts
// and read as damage rather than as emphasis. So the badges below set a pair
// and the `STATUS_*` roles set a foreground only.

/// The `VERIFY` badge inside the verification banner.
///
/// The one place a status word is still drawn on a filled background: the
/// banner is a block of its own, not a border it has to sit inside.
pub const BADGE_BUSY: Style = pair(Color::Black, Color::Yellow).add_modifier(Modifier::BOLD);

/// `READY` and `DONE` on the pane border.
pub const STATUS_READY: Style = fg_mod(Color::Green, Modifier::BOLD);

/// `RUNNING` and `VERIFY` on the pane border.
pub const STATUS_BUSY: Style = fg_mod(Color::Yellow, Modifier::BOLD);

/// `FAILED`, `CANCELLED` and `CONFIRM` on the pane border.
pub const STATUS_ERROR: Style = fg_mod(Color::Red, Modifier::BOLD);

/// `INPUT` on the pane border.
pub const STATUS_INPUT: Style = fg_mod(Color::Blue, Modifier::BOLD);

/// `UNSUPPORTED` on the pane border.
///
/// Dim rather than coloured: a host refusing a task is not an error, and
/// giving it a hue of its own would rank it alongside a failure.
pub const STATUS_INERT: Style = fg_mod(Color::White, Modifier::DIM);

/// The key glyph in the bottom key bar.
pub const KEYBAR_KEY: Style = fg_mod(Color::Reset, Modifier::BOLD);

/// The description beside a key glyph.
pub const KEYBAR_LABEL: Style = fg_mod(Color::White, Modifier::DIM);

/// One key and what it does, as the bar and the dialogs draw the pair.
///
/// The spacing belongs here rather than to either word. It used to live in
/// both places at once: `render.rs` wrapped the label in `format!(" {} ")`
/// with a comment saying a label carrying its own spaces could not be reused
/// where the spacing differs, while eight entries in the catalogue carried
/// exactly those spaces — `" cancel"`, `" choose   "`. A translator editing
/// one of those strings was changing the layout without being told, and the
/// trailing runs were invisible in a diff.
///
/// Returned as a pair rather than a `Line`, because callers assemble them
/// differently: the bar concatenates several, the option list puts two in a
/// `title_bottom`, and the form pushes them onto a vector it is already
/// building.
pub fn key_hint(glyph: &str, label: &str) -> [ratatui::text::Span<'static>; 2] {
    [
        ratatui::text::Span::styled(format!(" {glyph}"), KEYBAR_KEY),
        ratatui::text::Span::styled(format!(" {label} "), KEYBAR_LABEL),
    ]
}

/// The step-progress gauge.
pub const GAUGE: Style = pair(Color::Green, Color::Reset);

// --- Row markers -----------------------------------------------------------
//
// Glyphs rather than colours carry these meanings, so that a monochrome or
// NO_COLOR terminal loses nothing. They are single-cell and ASCII-adjacent:
// every one is present in the fonts a server console is likely to have.

/// Precedes a destructive task.
pub const MARKER_DANGER: &str = "!";

/// Precedes a task that collects parameters before it runs.
pub const MARKER_INPUT: &str = "…";

/// Precedes a task this host cannot run.
pub const MARKER_UNSUPPORTED: &str = "·";

/// Precedes a reversible row whose verb the host has not settled yet.
///
/// Transient — the probe answers within a few hundred milliseconds of startup
/// — and worth a glyph for that window: the row is showing "Install" because
/// nothing has been measured, not because anything was found absent, and a row
/// that may be about to change its verb is one to wait a moment before acting
/// on.
pub const MARKER_PROBING: &str = "?";

/// Marks a task that succeeded during this session.
pub const MARKER_OK: &str = "✓";

/// Marks a task that failed during this session.
pub const MARKER_FAIL: &str = "✗";

/// Precedes the selected row, alongside [`SELECTION_FOCUSED`].
pub const MARKER_CURSOR: &str = "▸";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_sets_an_explicit_pair_rather_than_reversing() {
        // REVERSED would invert the destructive marker's red into a block and
        // flip the row's meaning with it, so the selected row must name both
        // colours outright.
        assert_eq!(SELECTION_FOCUSED.fg, Some(Color::White));
        assert_eq!(SELECTION_FOCUSED.bg, Some(Color::Blue));
        assert!(!SELECTION_FOCUSED.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn normal_text_defers_to_the_terminal_theme() {
        // Hardcoding a foreground here would fight the user's colour scheme.
        assert_eq!(NORMAL.fg, Some(Color::Reset));
    }

    #[test]
    fn a_badge_sets_both_colours_of_its_pair() {
        // A badge differs from its surroundings by background, so it must also
        // set a foreground that contrasts; one with only a background inverts
        // unpredictably against whatever theme is underneath.
        assert!(BADGE_BUSY.fg.is_some(), "a badge must set its foreground");
        assert!(BADGE_BUSY.bg.is_some(), "a badge must set its background");
        assert!(BADGE_BUSY.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn no_status_style_paints_a_background_over_the_border() {
        // These are drawn on a pane's bottom border, where a background fills
        // the cells the border runs through — which reads as a gap in the
        // frame rather than as emphasis. Foreground only, so the border shows
        // through the spaces around the word.
        for status in [
            STATUS_READY,
            STATUS_BUSY,
            STATUS_ERROR,
            STATUS_INPUT,
            STATUS_INERT,
        ] {
            assert!(status.fg.is_some(), "a status must colour its text");
            assert_eq!(
                status.bg, None,
                "a background here would paint over the border"
            );
        }
    }

    #[test]
    fn the_status_styles_differ_from_one_another() {
        // Colour is redundant reinforcement here rather than the signal, but
        // two states sharing a hue would make the reinforcement misleading.
        let hues = [
            STATUS_READY.fg,
            STATUS_BUSY.fg,
            STATUS_ERROR.fg,
            STATUS_INPUT.fg,
        ];
        let mut seen: Vec<String> = hues.iter().map(|colour| format!("{colour:?}")).collect();
        seen.sort_unstable();
        seen.dedup();

        assert_eq!(seen.len(), hues.len(), "two states share a colour");
    }

    #[test]
    fn row_markers_are_single_cell() {
        // Row layout budgets two cells for flags; a double-width glyph would
        // push the columns out of alignment on every row that carries one.
        for marker in [
            MARKER_DANGER,
            MARKER_INPUT,
            MARKER_UNSUPPORTED,
            MARKER_PROBING,
            MARKER_OK,
            MARKER_FAIL,
            MARKER_CURSOR,
        ] {
            assert_eq!(
                marker.chars().count(),
                1,
                "marker {marker} must occupy one cell"
            );
        }
    }
}
