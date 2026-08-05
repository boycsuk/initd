//! Layout geometry, as constraint lists.
//!
//! Every screen shares one outer vertical layout; only the body's inner splits
//! change, and only by swapping a constraint list. No screen owns a layout tree
//! of its own, so a change to the frame is a change in one place.
//!
//! Terminal size is handled by branching on `area.width` or `area.height` at
//! draw time rather than by maintaining separate layouts per size.
//!
//! Like the style table beside it, the geometry is stated whole: the sizes a
//! screen may take are a single reference rather than numbers rediscovered at
//! each call site. [`detail_height`] describes a split the interface does not
//! draw yet — the detail/output division — and is unused until it does.
#![allow(dead_code)]

use ratatui::layout::{Constraint, Flex, Layout, Rect};

/// Width at or above which the tree pane takes a fixed width.
///
/// Its content has a fixed natural width — labels are capped by design — so
/// extra width belongs to the output, where lines are long and wrapping hurts.
const WIDE_LAYOUT_MIN_WIDTH: u16 = 100;

/// Width below which the two panes collapse into one, switched with `Tab`.
///
/// A 30-cell tree beside a 40-cell detail pane is the floor at which both stay
/// readable; below it a side-by-side split degrades into two unusable columns.
const SPLIT_LAYOUT_MIN_WIDTH: u16 = 72;

/// Fixed width of the tree pane in the wide layout.
///
/// Two cells of gutter, eight of indent, twenty of label, two of flags and two
/// of border.
const TREE_PANE_WIDTH: u16 = 34;

/// Minimum width left for the right pane in the wide layout.
const RIGHT_PANE_MIN_WIDTH: u16 = 46;

/// Height at or below which the detail pane gives up rows to the output.
const SHORT_TERMINAL_HEIGHT: u16 = 30;

/// Rows the detail pane occupies while browsing on a comfortable terminal.
const DETAIL_HEIGHT: u16 = 13;

/// Rows the detail pane occupies once the terminal is short.
const DETAIL_HEIGHT_SHORT: u16 = 9;

/// Rows the detail pane is squeezed to on the shortest terminals.
const DETAIL_HEIGHT_MINIMAL: u16 = 6;

/// Smallest terminal `initd` will draw a real interface on.
///
/// Below this it refuses and states what it needs: a garbled layout on a
/// production box is worse than a clear refusal.
pub const MIN_WIDTH: u16 = 60;
/// Companion of [`MIN_WIDTH`].
pub const MIN_HEIGHT: u16 = 15;

/// Rows the key bar needs; it is dropped on terminals shorter than this.
const KEYBAR_MIN_HEIGHT: u16 = 24;

/// How the body splits between the tree and the right pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLayout {
    /// Tree at a fixed width, right pane absorbing everything else.
    Wide,
    /// Tree and right pane sharing the width proportionally.
    Split,
    /// One pane at a time, switched with `Tab`.
    Single,
}

impl BodyLayout {
    /// Chooses the split for a given terminal width.
    pub const fn for_width(width: u16) -> Self {
        if width >= WIDE_LAYOUT_MIN_WIDTH {
            Self::Wide
        } else if width >= SPLIT_LAYOUT_MIN_WIDTH {
            Self::Split
        } else {
            Self::Single
        }
    }

    /// The constraints this split resolves to.
    fn constraints(self) -> Vec<Constraint> {
        match self {
            Self::Wide => vec![
                Constraint::Length(TREE_PANE_WIDTH),
                Constraint::Min(RIGHT_PANE_MIN_WIDTH),
            ],
            // 33 / 47 cells at the reference width of 80.
            Self::Split => vec![Constraint::Percentage(42), Constraint::Percentage(58)],
            Self::Single => vec![Constraint::Percentage(100)],
        }
    }
}

/// The four horizontal bands every screen is built from.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    /// One line naming the tool and the detected host.
    pub header: Rect,
    /// Everything between the header and the status row.
    pub body: Rect,
    /// The status pill and its message.
    pub status: Rect,
    /// The key hints, absent on terminals too short to afford them.
    pub keys: Option<Rect>,
}

/// Splits the whole terminal into its four bands.
///
/// The key bar is the first thing to go when rows run short: it is a
/// convenience, whereas the status row is the only authoritative place the
/// operator is told what the tool is doing.
pub fn frame(area: Rect) -> Frame {
    let keep_keybar = area.height >= KEYBAR_MIN_HEIGHT;

    let constraints: &[Constraint] = if keep_keybar {
        &[
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
            Constraint::Length(1),
        ]
    } else {
        &[
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
        ]
    };

    let bands = Layout::vertical(constraints).split(area);

    Frame {
        header: bands[0],
        body: bands[1],
        status: bands[2],
        keys: if keep_keybar { Some(bands[3]) } else { None },
    }
}

/// Splits the body into the tree pane and the right pane.
///
/// In the single-pane layout both rects are the whole area; the caller draws
/// one of them according to which pane holds focus.
pub fn body(area: Rect, layout: BodyLayout) -> (Rect, Rect) {
    if layout == BodyLayout::Single {
        return (area, area);
    }

    let columns = Layout::horizontal(layout.constraints()).split(area);

    (columns[0], columns[1])
}

/// Rows the detail pane gets before the output takes the rest.
///
/// The output is always the flexible constraint: in every state the spare space
/// goes to the thing being watched, never to descriptive text.
pub const fn detail_height(terminal_height: u16) -> u16 {
    if terminal_height >= SHORT_TERMINAL_HEIGHT {
        DETAIL_HEIGHT
    } else if terminal_height >= MIN_HEIGHT + DETAIL_HEIGHT_SHORT {
        DETAIL_HEIGHT_SHORT
    } else {
        DETAIL_HEIGHT_MINIMAL
    }
}

/// Whether the terminal is large enough to draw the interface at all.
pub const fn is_usable(area: Rect) -> bool {
    area.width >= MIN_WIDTH && area.height >= MIN_HEIGHT
}

/// Centres a rectangle of the given size inside `area`.
///
/// Used for every modal dialog, which is drawn over a `Clear`. The size is
/// clamped to the area so that a dialog on a small terminal shrinks rather than
/// overflowing into nothing.
pub fn centred(width: u16, height: u16, area: Rect) -> Rect {
    let [vertical] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);

    let [centred] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(vertical);

    centred
}

/// Centres a rectangle sized as a percentage of `area`.
///
/// The confirmation dialog is specified as a proportion of the screen rather
/// than a cell size, so that a short question does not occupy a fixed block on
/// a large terminal. Sizing in cells, the way the form and the help overlay do,
/// would be a change to the contract in `docs/ui.md`.
///
/// The arithmetic widens to `u32` before multiplying: a terminal 1093 columns
/// wide overflows `u16` at 60%, which panics in debug and wraps silently in
/// release — the profile this ships as. Wide terminals are what a proportional
/// dialog is for, so the overflow sits on the path the function exists to
/// serve.
pub fn centred_percent(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let scale = |extent: u16, percent: u16| {
        let scaled = u32::from(extent) * u32::from(percent) / 100;

        // The result is a fraction of `extent`, which is a `u16`, so it cannot
        // exceed one — except for a percentage above 100, which no caller has
        // and which the clamp in `centred` would absorb anyway.
        u16::try_from(scaled).unwrap_or(extent)
    };

    centred(
        scale(area.width, percent_x),
        scale(area.height, percent_y),
        area,
    )
}

/// Reserves the last row of `area`, returning what precedes it and that row.
///
/// For a dialog whose final line must be visible whatever the prose above it
/// does. Stacking both in one paragraph makes the choice the first thing lost:
/// a body long enough to fill the area pushes it past the bottom border, and it
/// does not wrap or truncate, it simply is not drawn — leaving a destructive
/// operation asking a question with no answers on screen.
///
/// An area one row tall yields an empty rect for the prose rather than
/// borrowing the row back: whatever else is missing, the choice is drawn.
pub fn split_off_last_row(area: Rect) -> (Rect, Rect) {
    split_off_last_rows(area, 1)
}

/// Reserves the last `rows` of `area`, returning what precedes them.
///
/// The generalisation of [`split_off_last_row`], for a dialog with more than one
/// band that must survive a body long enough to crowd it out. Where the area
/// cannot afford the reservation, the reserved band takes what there is and the
/// remainder is empty: the rows held back are the ones the caller judged more
/// important than the prose above them, so they are the last to be given up
/// rather than the first.
pub fn split_off_last_rows(area: Rect, rows: u16) -> (Rect, Rect) {
    let reserved = rows.min(area.height);

    let [above, last] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(reserved)]).areas(area);

    (above, last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn area(width: u16, height: u16) -> Rect {
        Rect::new(0, 0, width, height)
    }

    #[test]
    fn the_reference_size_uses_the_split_layout() {
        // 80x24 is the size that has to work; it sits between the single-pane
        // floor and the wide threshold.
        assert_eq!(BodyLayout::for_width(80), BodyLayout::Split);
    }

    #[test]
    fn layout_switches_at_its_thresholds() {
        assert_eq!(BodyLayout::for_width(120), BodyLayout::Wide);
        assert_eq!(BodyLayout::for_width(100), BodyLayout::Wide);
        assert_eq!(BodyLayout::for_width(99), BodyLayout::Split);
        assert_eq!(BodyLayout::for_width(72), BodyLayout::Split);
        assert_eq!(BodyLayout::for_width(71), BodyLayout::Single);
        assert_eq!(BodyLayout::for_width(64), BodyLayout::Single);
    }

    #[test]
    fn the_reference_frame_spends_two_rows_on_chrome() {
        // Rows 1, 23 and 24 are chrome; rows 2-22 are the body. Losing more
        // than that to borders is what the one-line bands exist to prevent.
        let frame = frame(area(80, 24));

        assert_eq!(frame.header.height, 1);
        assert_eq!(frame.status.height, 1);
        assert_eq!(frame.keys.expect("24 rows affords a key bar").height, 1);
        assert_eq!(frame.body.height, 21);
    }

    #[test]
    fn a_short_terminal_drops_the_key_bar_before_the_status_row() {
        // The status row is the only authoritative place; the key bar is a
        // convenience, so it goes first.
        let frame = frame(area(80, 16));

        assert!(frame.keys.is_none());
        assert_eq!(frame.status.height, 1);
        assert!(frame.body.height > 0);
    }

    #[test]
    fn the_wide_layout_gives_extra_width_to_the_output() {
        let (tree, right) = body(area(120, 20), BodyLayout::Wide);

        assert_eq!(tree.width, TREE_PANE_WIDTH);
        assert_eq!(
            right.width,
            120 - TREE_PANE_WIDTH,
            "the right pane absorbs everything the tree does not need"
        );
    }

    #[test]
    fn the_single_layout_hands_the_whole_area_to_both_panes() {
        // One is drawn at a time, chosen by focus, so both must be full-size.
        let whole = area(64, 16);
        let (tree, right) = body(whole, BodyLayout::Single);

        assert_eq!(tree, whole);
        assert_eq!(right, whole);
    }

    #[test]
    fn the_detail_pane_yields_rows_as_the_terminal_shrinks() {
        assert_eq!(detail_height(40), DETAIL_HEIGHT);
        assert_eq!(detail_height(30), DETAIL_HEIGHT);
        assert_eq!(detail_height(24), DETAIL_HEIGHT_SHORT);
        assert_eq!(detail_height(15), DETAIL_HEIGHT_MINIMAL);
    }

    #[test]
    fn usability_matches_the_stated_minimum() {
        assert!(is_usable(area(80, 24)));
        assert!(is_usable(area(MIN_WIDTH, MIN_HEIGHT)));
        assert!(!is_usable(area(MIN_WIDTH - 1, MIN_HEIGHT)));
        assert!(!is_usable(area(MIN_WIDTH, MIN_HEIGHT - 1)));
    }

    #[test]
    fn a_centred_dialog_sits_inside_its_area() {
        let dialog = centred(68, 19, area(80, 24));

        assert_eq!(dialog.width, 68);
        assert_eq!(dialog.height, 19);
        assert!(dialog.x + dialog.width <= 80);
        assert!(dialog.y + dialog.height <= 24);
    }

    #[test]
    fn a_dialog_larger_than_the_terminal_is_clamped() {
        // Clamping keeps the dialog drawable; overflowing would render nothing.
        let dialog = centred(68, 19, area(60, 15));

        assert_eq!(dialog.width, 60);
        assert_eq!(dialog.height, 15);
    }

    #[test]
    fn a_proportional_dialog_takes_its_share_of_the_screen() {
        // The confirmation dialog is specified as a proportion rather than a
        // cell size, so it must scale with the terminal.
        let dialog = centred_percent(60, 40, area(100, 50));

        assert_eq!(dialog.width, 60);
        assert_eq!(dialog.height, 20);
    }

    #[test]
    fn a_proportional_dialog_stays_inside_its_area() {
        let screen = area(37, 13);
        let dialog = centred_percent(60, 40, screen);

        assert!(dialog.x + dialog.width <= screen.width);
        assert!(dialog.y + dialog.height <= screen.height);
    }

    #[test]
    fn a_very_wide_terminal_does_not_overflow_the_arithmetic() {
        // 1093 columns x 60% exceeds `u16`, which panics in debug and wraps
        // silently in release. A wide terminal is precisely what a
        // proportional dialog is for, so the case is on the path, not at its
        // edge.
        let dialog = centred_percent(60, 40, area(2000, 1000));

        assert_eq!(dialog.width, 1200);
        assert_eq!(dialog.height, 400);
    }

    #[test]
    fn the_reserved_row_is_the_last_one_and_the_prose_takes_the_rest() {
        let (prose, choice) = split_off_last_row(area(60, 10));

        assert_eq!(prose.height, 9);
        assert_eq!(choice.height, 1);
        assert_eq!(
            choice.y,
            prose.y + prose.height,
            "the reserved row must sit below the prose, not overlap it"
        );
    }

    #[test]
    fn the_reserved_row_survives_an_area_with_no_room_to_spare() {
        // The row this reserves is the one the operator answers with, so it is
        // the last thing to give up rather than the first.
        let (prose, choice) = split_off_last_row(area(60, 1));

        assert_eq!(prose.height, 0);
        assert_eq!(choice.height, 1);
    }

    #[test]
    fn the_widest_possible_terminal_is_still_proportional() {
        let dialog = centred_percent(60, 40, area(u16::MAX, u16::MAX));

        assert_eq!(dialog.width, 39321);
        assert_eq!(dialog.height, 26214);
    }
}
