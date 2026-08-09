//! Finding a task without knowing where it lives.
//!
//! The tree browses one level at a time, which is the right shape for reading
//! what a category holds and the wrong one for reaching a task whose category
//! you cannot remember. Twenty-eight tasks across six areas is past the number
//! anybody keeps a map of, and the only recourse was `docs/cli.md` — outside
//! the tool, on a server that may not have it.
//!
//! Three decisions worth stating:
//!
//! 1. **Search spans the whole tree, not the level on screen.** Filtering the
//!    current level answers "which of these" when the question is "where is
//!    it". A result therefore carries its breadcrumb, since a title alone does
//!    not say which area it came from.
//! 2. **Matching is case-insensitive and covers the id as well as the title.**
//!    The id is what `docs/cli.md` and every script name, so somebody arriving
//!    from either types `ssh.harden`; somebody who has only used the interface
//!    types "harden".
//! 3. **A match reports where it hit.** The interface underlines that range
//!    rather than merely listing the row, so a result that matched on its id
//!    does not look like an unexplained hit on its title.

use ratatui::Frame;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState};

use super::{layout, style};
use crate::i18n::{Lang, Msg};
use crate::tasks::{Node, TaskLocation, located_tasks};

/// Width of the overlay, in columns.
///
/// The width every modal shares, rather than one of its own: two dialogs the
/// operator opens in the same session at two widths read as an interface that
/// has not decided.
const WIDTH: u16 = layout::DIALOG_WIDTH;

/// Height of the overlay, in rows.
///
/// Tall enough to show a useful number of results without covering the whole
/// interface: the pane behind it keeps rendering, which is the point of search
/// being semi-modal.
const HEIGHT: u16 = 16;

/// A task that matched, and how to reach it.
pub struct Match {
    /// Identifier of the matching task.
    pub id: String,
    /// Title, as the row displays it.
    pub title: &'static str,
    /// Categories above it, outermost first.
    pub breadcrumb: Vec<&'static str>,
    /// Where the task sits, for jumping to it.
    pub location: TaskLocation,
    /// Range within `title` that matched, if the title is what matched.
    ///
    /// `None` when the query matched the id instead, which the interface shows
    /// by rendering the id rather than by underlining nothing.
    pub title_hit: Option<(usize, usize)>,
}

/// An open search: what has been typed, and what it currently finds.
pub struct Search {
    /// The query so far.
    query: String,
    /// Matches for `query`, in tree order.
    matches: Vec<Match>,
    /// Which match the cursor is on.
    selected: usize,
}

impl Search {
    /// Opens a search over `tree` with an empty query.
    ///
    /// An empty query matches everything rather than nothing: opening search
    /// shows the whole tree flattened, which is itself useful — it is the one
    /// view that lists all twenty-eight tasks with their areas.
    pub fn new(tree: &[Node]) -> Self {
        let mut search = Self {
            query: String::new(),
            matches: Vec::new(),
            selected: 0,
        };

        search.recompute(tree);
        search
    }

    /// The query typed so far.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The current matches, in tree order.
    pub fn matches(&self) -> &[Match] {
        &self.matches
    }

    /// Which match the cursor is on.
    pub const fn selected(&self) -> usize {
        self.selected
    }

    /// The match under the cursor, if any.
    pub fn selected_match(&self) -> Option<&Match> {
        self.matches.get(self.selected)
    }

    /// Appends a character and refilters.
    pub fn push(&mut self, character: char, tree: &[Node]) {
        self.query.push(character);
        self.recompute(tree);
    }

    /// Removes the last character and refilters.
    ///
    /// Reports whether anything was removed, so the interface can decide what
    /// a backspace on an empty query means — closing search is friendlier than
    /// ignoring it.
    pub fn backspace(&mut self, tree: &[Node]) -> bool {
        let removed = self.query.pop().is_some();

        if removed {
            self.recompute(tree);
        }

        removed
    }

    /// Moves the cursor to the next match, stopping at the end.
    ///
    /// Deliberately not wrapping. A list that jumps back to the top when the
    /// cursor runs off the bottom hides the fact that there was nothing more,
    /// and in a list of results that is the thing worth knowing.
    pub fn select_next(&mut self) {
        if self.selected + 1 < self.matches.len() {
            self.selected += 1;
        }
    }

    /// Moves the cursor to the previous match, stopping at the start.
    pub const fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Recomputes the matches for the current query.
    ///
    /// The cursor returns to the first result on every keystroke: after
    /// narrowing the list, the row that was under the cursor is rarely the one
    /// still wanted, and a cursor left pointing at whatever now occupies that
    /// index is worse than one that starts over.
    fn recompute(&mut self, tree: &[Node]) {
        let needle = self.query.to_lowercase();

        self.matches = located_tasks(tree)
            .into_iter()
            .filter_map(|(location, task)| {
                let title_hit = match_range(task.title(), &needle);
                let matched = title_hit.is_some() || task.id().to_lowercase().contains(&needle);

                matched.then(|| Match {
                    id: task.id().to_owned(),
                    title: task.title(),
                    breadcrumb: location.titles.clone(),
                    location,
                    title_hit,
                })
            })
            .collect();

        self.selected = 0;
    }
}

/// Where `needle` appears in `haystack`, as character offsets.
///
/// Characters rather than bytes, because the caller slices the title to
/// underline the hit and a byte offset into a multi-byte character panics.
/// An empty needle matches at the start with zero width, so opening search
/// underlines nothing rather than the whole title.
fn match_range(haystack: &str, needle: &str) -> Option<(usize, usize)> {
    if needle.is_empty() {
        return Some((0, 0));
    }

    let lowered: Vec<char> = haystack.to_lowercase().chars().collect();
    let wanted: Vec<char> = needle.chars().collect();

    lowered
        .windows(wanted.len())
        .position(|window| window == wanted.as_slice())
        .map(|start| (start, start + wanted.len()))
}

/// Draws the search overlay over the interface.
///
/// `lang` renders the chrome around the query only. The query itself is what
/// the operator typed, and the results are titles and ids the tasks own.
pub fn render(frame: &mut Frame, search: &Search, lang: Lang) {
    let area = layout::centred(WIDTH, HEIGHT, frame.area());

    // Clear first, or the interface underneath shows through.
    frame.render_widget(Clear, area);

    let items: Vec<ListItem> = search.matches().iter().map(row).collect();

    let footer = lang.render(&if search.matches().is_empty() {
        Msg::SearchNoMatches
    } else {
        Msg::SearchFooter {
            position: search.selected() + 1,
            total: search.matches().len(),
        }
    });

    // Titled through the catalogue's roles like every other overlay: the
    // heading in `PANE_TITLE` and the count beneath it in `BLOCK_SUBTITLE`,
    // which is what `help.rs` draws and what `history.rs` draws. Passing either
    // as a bare `String` inherits whatever the block's own style happens to be,
    // so this one modal rendered its chrome in the border's colour while the
    // six beside it did not.
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(style::BORDER_FOCUSED)
        .title(Span::styled(
            lang.render(&Msg::SearchTitle {
                query: search.query().to_owned(),
            }),
            style::PANE_TITLE,
        ))
        .title_bottom(Span::styled(footer, style::BLOCK_SUBTITLE));

    let mut state = ListState::default();
    state.select(Some(search.selected()));

    // The inset every modal keeps, applied vertically only. The horizontal
    // gutter is deliberately not: a selected row is drawn as a filled band,
    // and one stopping two cells short of each border would read as a
    // highlight that failed to paint rather than as a margin. `List` carries
    // the block itself so the rows can reach the frame.
    frame.render_widget(block.clone(), area);

    frame.render_stateful_widget(
        List::new(items).highlight_style(style::SELECTION_FOCUSED),
        layout::inset(block.inner(area), 0, 1),
        &mut state,
    );
}

/// One result: its title with the hit marked, and the area it came from.
fn row(found: &Match) -> ListItem<'static> {
    let mut spans = Vec::new();

    match found.title_hit {
        // Only the matched span is highlighted, so a long title does not
        // become a wall of colour and the reason this row matched is legible.
        Some((start, end)) if end > start => {
            let characters: Vec<char> = found.title.chars().collect();
            let slice = |range: std::ops::Range<usize>| -> String {
                characters.get(range).unwrap_or_default().iter().collect()
            };

            spans.push(Span::styled(slice(0..start), style::NORMAL));
            spans.push(Span::styled(slice(start..end), style::SEARCH_MATCH));
            spans.push(Span::styled(slice(end..characters.len()), style::NORMAL));
        }
        // Matched on the id, or matched everything with an empty query. The
        // title is drawn plain and the id below carries the explanation.
        _ => spans.push(Span::styled(found.title.to_owned(), style::NORMAL)),
    }

    let where_from = if found.breadcrumb.is_empty() {
        found.id.clone()
    } else {
        format!("{}  ·  {}", found.breadcrumb.join(" › "), found.id)
    };

    ListItem::new(vec![
        Line::from(spans),
        Line::styled(format!("  {where_from}"), style::BLOCK_SUBTITLE),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::tree;

    #[test]
    fn the_heading_and_the_count_are_drawn_in_the_roles_every_overlay_uses() {
        // Asserted on the style rather than on the text, because the text was
        // never what was wrong: this modal passed its title and footer as bare
        // `String`s while the six beside it styled theirs, so the heading came
        // out in the border's colour and the count with it. A screen dump would
        // have agreed with both versions.
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(WIDTH, 20))
            .expect("the test backend must build");

        let search = Search::new(&tree());

        terminal
            .draw(|frame| render(frame, &search, Lang::En))
            .expect("the overlay must draw");

        // Only the two frame rows the titles are drawn into. The result rows
        // between them carry `PANE_TITLE` and `BLOCK_SUBTITLE` of their own —
        // a hit is cyan and the breadcrumb beneath it is dim — so a search of
        // the whole buffer finds both roles whether the titles were styled or
        // not, and passes against the very code this is here to reject.
        let buffer = terminal.backend().buffer();
        let area = layout::centred(WIDTH, HEIGHT, buffer.area);

        let row_styles = |y: u16| -> Vec<_> {
            (area.x..area.x + area.width)
                .map(|x| {
                    let cell = &buffer[(x, y)];
                    (cell.fg, cell.modifier)
                })
                .collect()
        };

        let top = row_styles(area.y);
        let bottom = row_styles(area.y + area.height - 1);

        // A role's `fg` is an `Option` because a `Style` may leave the colour
        // to whatever it is drawn over; a cell's is resolved. Both roles set
        // one, so the unwrap is the assertion that they do.
        let role = |style: ratatui::style::Style| {
            (
                style.fg.expect("the role must set a colour"),
                style.add_modifier,
            )
        };

        let heading = role(style::PANE_TITLE);
        let count = role(style::BLOCK_SUBTITLE);

        assert!(
            top.contains(&heading),
            "the heading must be drawn in PANE_TITLE, not in the border's own style"
        );

        assert!(
            bottom.contains(&count),
            "the count must be drawn in BLOCK_SUBTITLE, not in the border's own style"
        );
    }

    #[test]
    fn an_empty_query_finds_every_task() {
        // Opening search is also the only view that lists the whole tree with
        // each task's area beside it.
        let search = Search::new(&tree());

        assert_eq!(search.matches().len(), crate::tasks::all_tasks().len());
    }

    #[test]
    fn a_query_matches_a_title_regardless_of_case() {
        let search_lower = {
            let mut search = Search::new(&tree());
            for character in "harden".chars() {
                search.push(character, &tree());
            }
            search
        };
        let search_upper = {
            let mut search = Search::new(&tree());
            for character in "HARDEN".chars() {
                search.push(character, &tree());
            }
            search
        };

        assert!(!search_lower.matches().is_empty());
        assert_eq!(
            search_lower.matches().len(),
            search_upper.matches().len(),
            "case must not change what is found"
        );
    }

    #[test]
    fn a_task_is_reachable_by_its_id() {
        // What `docs/cli.md` names and what a script would carry, so somebody
        // arriving from either types the id rather than the prose title.
        let mut search = Search::new(&tree());

        for character in "ssh.harden-strict".chars() {
            search.push(character, &tree());
        }

        let found: Vec<_> = search.matches().iter().map(|m| m.id.as_str()).collect();

        assert_eq!(found, ["ssh.harden-strict"], "{found:?}");
    }

    #[test]
    fn a_result_carries_the_area_it_came_from() {
        // A title alone does not say which area it belongs to, and the whole
        // point of searching is not knowing that already.
        let mut search = Search::new(&tree());

        for character in "wireguard.install".chars() {
            search.push(character, &tree());
        }

        let found = search.selected_match().expect("the task must be found");

        assert!(
            !found.breadcrumb.is_empty(),
            "a result must name its area: {:?}",
            found.breadcrumb
        );
    }

    #[test]
    fn a_query_matching_nothing_finds_nothing() {
        let mut search = Search::new(&tree());

        for character in "zzzznotataskzzzz".chars() {
            search.push(character, &tree());
        }

        assert!(search.matches().is_empty());
        assert!(search.selected_match().is_none());
    }

    #[test]
    fn backspace_widens_the_search_again() {
        let mut search = Search::new(&tree());

        for character in "hardenx".chars() {
            search.push(character, &tree());
        }
        assert!(search.matches().is_empty(), "the typo must match nothing");

        assert!(search.backspace(&tree()));

        assert!(
            !search.matches().is_empty(),
            "removing the typo must bring the results back"
        );
    }

    #[test]
    fn backspace_on_an_empty_query_reports_that_it_did_nothing() {
        let mut search = Search::new(&tree());

        assert!(!search.backspace(&tree()));
    }

    #[test]
    fn the_cursor_stops_at_the_ends_rather_than_wrapping() {
        // Wrapping hides that the list had run out, which in a result list is
        // the thing worth knowing.
        let mut search = Search::new(&tree());

        search.select_previous();
        assert_eq!(search.selected(), 0, "already at the top");

        for _ in 0..1000 {
            search.select_next();
        }

        assert_eq!(
            search.selected(),
            search.matches().len() - 1,
            "the cursor must stop on the last match"
        );
    }

    #[test]
    fn narrowing_the_query_returns_the_cursor_to_the_first_result() {
        let mut search = Search::new(&tree());

        search.select_next();
        search.select_next();
        assert_eq!(search.selected(), 2);

        search.push('s', &tree());

        assert_eq!(search.selected(), 0);
    }

    #[test]
    fn the_hit_is_reported_where_it_landed() {
        // The interface underlines this range, so a result that matched on its
        // id does not look like an unexplained hit on its title.
        assert_eq!(
            match_range("Harden the SSH configuration", "ssh"),
            Some((11, 14))
        );
        assert_eq!(match_range("Harden the SSH configuration", "nope"), None);
    }

    #[test]
    fn a_hit_is_measured_in_characters_rather_than_bytes() {
        // A byte offset into a multi-byte character panics when the caller
        // slices the title to underline it.
        let range = match_range("échange de clés", "clés");

        assert_eq!(range, Some((11, 15)));
    }
}
