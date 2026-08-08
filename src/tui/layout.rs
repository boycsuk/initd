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

/// Width every modal dialog is drawn at, before clamping to the terminal.
///
/// One number rather than the three the dialogs had — 72, 70 and 64 — which
/// were each defensible alone and, side by side over the same interface, read
/// as three sizes chosen by nobody. The floor is the parameter form's footer,
/// the longest fixed string any of them draws: `Tab field   Ctrl-L list
/// Enter (fill every field)   Esc cancel`, rendered as adjacent spans that
/// neither wrap nor truncate, so a dialog one cell too narrow silently loses
/// `cancel` — the key out of a modal.
///
/// `centred` clamps it, so a terminal narrower than this shrinks the dialog
/// rather than overflowing.
pub const DIALOG_WIDTH: u16 = 72;

/// Cells of margin between a dialog's border and its text, on both sides.
///
/// Also the column a focus marker occupies in the parameter form, which is why
/// it is spent whether or not one is drawn: text that shifted sideways when a
/// row gained the focus would move under the cursor reading it.
pub const DIALOG_GUTTER: usize = 2;

/// Rows a dialog spends on itself: two borders and the blank row inset at each
/// end of its content.
///
/// The inset is the same row that separates a form's fields, so the spacing
/// reads as one rhythm rather than as content crowded against the frame at
/// both ends.
pub const DIALOG_CHROME_ROWS: u16 = 4;

/// Rows `text` occupies once wrapped to `width`, counting a blank line as one.
///
/// Ratatui wraps at draw time and reports nothing back, so a dialog that wants
/// to be as tall as its content has to do the arithmetic itself. Words are
/// broken on whitespace the way `Wrap { trim: true }` does; a word longer than
/// the width takes a row of its own rather than looping forever, which is what
/// a naive `while remaining > width` does on an unbreakable token.
///
/// Counted in characters rather than bytes: a description holding an accent
/// would otherwise be measured longer than it is drawn and the dialog would
/// reserve a row nothing lands on.
pub fn wrapped_rows(text: &str, width: usize) -> u16 {
    if width == 0 {
        return 0;
    }

    let mut rows: u16 = 0;

    for line in text.lines() {
        let mut used = 0usize;
        let mut rows_here: u16 = 1;

        for word in line.split_whitespace() {
            let word = word.chars().count();

            if used == 0 {
                // A word wider than the dialog is drawn broken across rows
                // rather than skipped, so it costs what it actually takes. The
                // row already counted holds the first `width` of it, hence the
                // subtraction — without it a word that exactly fills a whole
                // number of rows was charged one more than it draws.
                used = word % width;
                rows_here = rows_here.saturating_add((word.saturating_sub(1) / width) as u16);
            } else if used + 1 + word <= width {
                used += 1 + word;
            } else {
                rows_here = rows_here.saturating_add(1);
                used = word;
            }
        }

        rows = rows.saturating_add(rows_here);
    }

    rows.max(1)
}

/// Width at or above which the tree pane takes a fixed width.
///
/// Its content has a natural width — the longest task title plus a row's
/// chrome, which is what [`TREE_PANE_WIDTH`] is — so beyond that, extra width
/// belongs to the output, where lines are long and wrapping hurts. Giving the
/// tree a share of a wide terminal would spend it on padding.
///
/// Must stay at or above `TREE_PANE_WIDTH + RIGHT_PANE_MIN_WIDTH`, or the
/// layout promises the right pane a minimum it cannot be given; a test pins
/// that rather than the comment.
const WIDE_LAYOUT_MIN_WIDTH: u16 = 100;

/// Width below which the two panes collapse into one, switched with `Tab`.
///
/// A 30-cell tree beside a 40-cell detail pane is the floor at which both stay
/// readable; below it a side-by-side split degrades into two unusable columns.
const SPLIT_LAYOUT_MIN_WIDTH: u16 = 72;

/// Fixed width of the tree pane in the wide layout.
///
/// Measured against the tree rather than chosen: the longest title in it is
/// `Allow unprivileged binding to 80 and 443` at 40 cells, and a row spends
/// six more — two of border, two of marker, one of flag, and the space that
/// separates the title from it. So 46 is the width at which no task in the
/// tree is truncated, and it was 34, which cut nine of the twenty-eight.
///
/// This is the one number that has to grow with the content. A title longer
/// than this is still cut with an ellipsis rather than clipped, so the cost of
/// being wrong is legible rather than silent — `tree_rows_are_not_truncated`
/// is what makes it noticed.
const TREE_PANE_WIDTH: u16 = 46;

/// Cells a tree row spends on anything that is not the title.
///
/// Two of border, two of marker, one of flag, one separating the last two.
/// Stated here because [`TREE_PANE_WIDTH`] is derived from it and a test
/// checks that derivation; a literal in both places is a literal that drifts.
pub const TREE_ROW_CHROME: u16 = 6;

/// Minimum width left for the right pane in the wide layout.
///
/// The detail pane holds prose, which wraps, so it degrades gracefully where
/// the tree does not — a truncated title is a name the operator cannot read,
/// whereas narrower prose is the same prose on more lines.
const RIGHT_PANE_MIN_WIDTH: u16 = 46;

// Below this the layout would hand the right pane less than the minimum it
// declares, which is a promise the constraints cannot keep — ratatui resolves
// it by shrinking something, without saying so. All three are constants, so
// the compiler is the right place to check it: a test would only report at run
// time what is already knowable at build time.
const _: () = assert!(WIDE_LAYOUT_MIN_WIDTH >= TREE_PANE_WIDTH + RIGHT_PANE_MIN_WIDTH);

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

/// The three horizontal bands every screen is built from.
///
/// There were four. The status had a band of its own, and spent it saying
/// `READY` for most of a session; it rides the right pane's bottom border now,
/// the way the tree's census rides its own, and the row it cost went to the
/// body — where it is one more task visible without scrolling on the 24-row
/// terminal this interface is measured against.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    /// One line naming the tool and the detected host.
    pub header: Rect,
    /// Everything between the header and the key hints.
    pub body: Rect,
    /// The key hints, absent on terminals too short to afford them.
    pub keys: Option<Rect>,
}

/// Splits the whole terminal into its bands.
///
/// The key bar is the first thing to go when rows run short: it is a
/// convenience, and it is now the only band that can be given up at all. The
/// status costs no row to keep, so a short terminal no longer has to choose
/// between being told what the tool is doing and having somewhere to draw it.
pub fn frame(area: Rect) -> Frame {
    let keep_keybar = area.height >= KEYBAR_MIN_HEIGHT;

    let constraints: &[Constraint] = if keep_keybar {
        &[
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
        ]
    } else {
        &[Constraint::Length(1), Constraint::Min(8)]
    };

    let bands = Layout::vertical(constraints).split(area);

    Frame {
        header: bands[0],
        body: bands[1],
        keys: if keep_keybar { Some(bands[2]) } else { None },
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
/// Shrinks an area by `horizontal` cells on each side and `vertical` on each
/// end.
///
/// The margin every modal keeps between its frame and its content, in one
/// place so the four of them cannot drift apart. Saturating rather than
/// panicking: a terminal narrow enough to leave nothing inside yields an empty
/// rect, and an empty rect draws nothing — which is what should happen on a
/// screen with no room for the dialog anyway.
pub fn inset(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(horizontal),
        y: area.y.saturating_add(vertical),
        width: area.width.saturating_sub(horizontal.saturating_mul(2)),
        height: area.height.saturating_sub(vertical.saturating_mul(2)),
    }
}

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
    fn the_dialog_width_fits_the_longest_footer_any_modal_draws() {
        // The floor the shared width rests on. Footers are drawn as adjacent
        // spans that neither wrap nor truncate, so a dialog one cell too narrow
        // silently loses its last word — which in the parameter form is
        // `cancel`, the key out of a modal.
        const LONGEST_FOOTER: &str =
            " Tab field   Ctrl-L list   Enter (fill every field)   Esc cancel";

        assert!(
            LONGEST_FOOTER.chars().count() + 2 <= DIALOG_WIDTH as usize,
            "the footer needs {} cells plus two borders, and the width is {DIALOG_WIDTH}",
            LONGEST_FOOTER.chars().count()
        );
    }

    #[test]
    fn wrapping_counts_the_rows_a_paragraph_will_take() {
        assert_eq!(
            wrapped_rows("", 20),
            1,
            "an empty body still occupies a row"
        );
        assert_eq!(wrapped_rows("short", 20), 1);
        assert_eq!(
            wrapped_rows("exactly twenty chars", 20),
            1,
            "a full row is one"
        );
        assert_eq!(wrapped_rows("this one runs past twenty", 20), 2);
        assert_eq!(
            wrapped_rows("first\nsecond", 20),
            2,
            "an explicit newline breaks a row"
        );
    }

    #[test]
    fn a_word_wider_than_the_dialog_takes_the_rows_it_needs() {
        // The case a `while remaining > width` loop never leaves: a token with
        // no whitespace to break on. A path this size can appear in a
        // description, and a dialog that hung drawing one would take the
        // interface with it.
        assert_eq!(wrapped_rows(&"x".repeat(45), 20), 3);
        assert_eq!(wrapped_rows(&"x".repeat(40), 20), 2, "an exact multiple");
    }

    #[test]
    fn wrapping_measures_characters_rather_than_bytes() {
        // An accented description would otherwise be measured longer than it
        // is drawn, and the dialog would reserve a row nothing lands on.
        assert_eq!(wrapped_rows("ñññññ", 5), 1);
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
        // Row 1 and row 24 are chrome; rows 2-23 are the body. Losing more
        // than that to borders is what the one-line bands exist to prevent.
        let frame = frame(area(80, 24));

        assert_eq!(frame.header.height, 1);
        assert_eq!(frame.keys.expect("24 rows affords a key bar").height, 1);
        assert_eq!(frame.body.height, 22);
    }

    #[test]
    fn the_body_kept_the_row_the_status_band_used_to_cost() {
        // The status moved onto a border it was already drawing, so this is a
        // row the body gained rather than one the chrome merely stopped using.
        // Pinned at the reference size because that is where a row is worth
        // arguing about: 24 rows is the terminal the interface is measured on.
        assert_eq!(frame(area(80, 24)).body.height, 22);
    }

    #[test]
    fn a_short_terminal_drops_the_key_bar_and_keeps_the_body() {
        // The key bar is a convenience and is the only band left that can be
        // given up. What the tool is doing costs no row now, so a short
        // terminal is no longer asked to choose between being told and having
        // somewhere to draw it.
        let frame = frame(area(80, 16));

        assert!(frame.keys.is_none());
        assert_eq!(frame.header.height, 1);
        assert_eq!(frame.body.height, 15, "everything the header leaves");
    }

    #[test]
    fn the_tree_pane_fits_the_longest_title_in_the_tree() {
        // The pane was 34 cells and nine of the twenty-eight titles did not
        // fit, so the rows read `Create an administrative us…`. The number is
        // derived from the content rather than chosen, which means it has to
        // be checked against the content: a task added with a longer name is
        // the case this catches, and it is silent otherwise — a truncated
        // title still renders, it just cannot be read.
        let longest = crate::tasks::all_tasks()
            .iter()
            .map(|task| task.title().chars().count())
            .max()
            .expect("the tree has tasks in it");

        assert!(
            TREE_PANE_WIDTH as usize >= longest + TREE_ROW_CHROME as usize,
            "the longest title is {longest} cells and the pane offers {}",
            TREE_PANE_WIDTH - TREE_ROW_CHROME
        );
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
