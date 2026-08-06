//! Where the operator is in the task tree, and how they move through it.
//!
//! Split out of `app.rs` because it depends on none of what the rest of that
//! file does: no executor, no backend, no terminal. It is the tree, a path into
//! it, and a row — which makes it the one part of the interface testable
//! without constructing an interface.
//!
//! Two pieces of state that must move together, and one that must not:
//!
//! - `path` and `cursor_stack` are pushed and popped as a pair. They are held
//!   here rather than beside the rest of the application state so that the
//!   only code able to desynchronise them is in this file.
//! - The status row is *not* here. `leave_category` at the root has nothing to
//!   do, and the interface reports that as a flash — but a cursor that knew
//!   about the status row would be a cursor that knew about the interface, so
//!   it answers whether it moved and lets the caller phrase the refusal.

use ratatui::widgets::ListState;

use crate::tasks::{Node, Task};

/// The position in the tree: which level is shown, and which row is on.
pub struct TreeCursor {
    /// The whole tree, owned so that levels can be borrowed from it.
    tree: Vec<Node>,
    /// Indices from the root to the category on screen; empty means the root.
    ///
    /// Positions rather than titles, so nothing breaks if two categories in
    /// different branches share a name.
    path: Vec<usize>,
    /// Cursor position of each level left behind, restored on the way back.
    cursor_stack: Vec<usize>,
    /// Which row of the current level is selected.
    list_state: ListState,
}

impl TreeCursor {
    /// Places the cursor at the top of `tree`.
    pub fn new(tree: Vec<Node>) -> Self {
        let mut list_state = ListState::default();

        // The root level is never empty, so the cursor always has a row.
        list_state.select(Some(0));

        Self {
            tree,
            path: Vec::new(),
            cursor_stack: Vec::new(),
            list_state,
        }
    }

    /// The whole tree.
    pub fn tree(&self) -> &[Node] {
        &self.tree
    }

    /// The nodes of the level currently on screen.
    pub fn current_level(&self) -> &[Node] {
        level_at(&self.tree, &self.path)
    }

    /// The node under the cursor, if any.
    pub fn selected_node(&self) -> Option<&Node> {
        self.current_level().get(self.list_state.selected()?)
    }

    /// The task under the cursor, if the cursor is on one.
    pub fn selected_task(&self) -> Option<&dyn Task> {
        match self.selected_node()? {
            Node::Task(task) => Some(task.as_ref()),
            Node::Category(_) => None,
        }
    }

    /// Which row is selected.
    pub fn selected(&self) -> Option<usize> {
        self.list_state.selected()
    }

    /// The list state, for rendering.
    pub const fn list_state(&mut self) -> &mut ListState {
        &mut self.list_state
    }

    /// First visible row, for sizing the scrollbar.
    ///
    /// Written by the list widget as it renders, so it reflects where the view
    /// actually is rather than where the selection is.
    pub fn offset(&self) -> usize {
        self.list_state.offset()
    }

    /// Whether the cursor is at the root level.
    pub fn at_root(&self) -> bool {
        self.path.is_empty()
    }

    /// Indices from the root to the level on screen, for assertions.
    #[cfg(test)]
    pub fn path(&self) -> &[usize] {
        &self.path
    }

    /// Titles from the root to the level on screen, for the breadcrumb.
    pub fn breadcrumb(&self) -> String {
        let mut nodes = self.tree.as_slice();
        let mut titles = Vec::new();

        for &index in &self.path {
            let Some(Node::Category(category)) = nodes.get(index) else {
                break;
            };

            titles.push(category.title);
            nodes = category.children.as_slice();
        }

        if titles.is_empty() {
            "Tasks".to_owned()
        } else {
            titles.join(" › ")
        }
    }

    /// Descends into the category at `index`.
    pub fn enter_category(&mut self, index: usize) {
        self.cursor_stack.push(index);
        self.path.push(index);
        self.list_state.select(Some(0));
    }

    /// Returns to the parent level, restoring the cursor it was left on.
    ///
    /// Answers whether there was anywhere to go. At the root there is not, and
    /// the caller reports that — `q` is the way out of the program, and an
    /// `Esc` that sometimes quit would make going back one level too far a
    /// destructive mistake.
    pub fn leave_category(&mut self) -> bool {
        if self.path.pop().is_none() {
            return false;
        }

        let restored = self.cursor_stack.pop().unwrap_or(0);
        self.list_state.select(Some(restored));

        true
    }

    /// Puts the cursor on a task found elsewhere in the tree.
    ///
    /// The cursor stack is set from the path rather than preserved: the jump
    /// did not pass through those levels, so the rows it would restore are a
    /// guess. The path's own indices are the honest answer — leaving a
    /// category returns to the row holding it.
    pub fn jump_to(&mut self, path: &[usize], index: usize) {
        self.path.clear();
        self.path.extend_from_slice(path);
        self.cursor_stack.clear();
        self.cursor_stack.extend_from_slice(path);
        self.list_state.select(Some(index));
    }

    /// Moves the cursor down one row.
    ///
    /// Every row of a level is selectable, now that categories are entered
    /// rather than skipped over.
    pub fn select_next(&mut self) {
        let last = self.current_level().len().saturating_sub(1);
        let current = self.list_state.selected().unwrap_or(0);

        self.list_state
            .select(Some(current.saturating_add(1).min(last)));
    }

    /// Moves the cursor up one row.
    pub fn select_previous(&mut self) {
        let current = self.list_state.selected().unwrap_or(0);

        self.list_state.select(Some(current.saturating_sub(1)));
    }

    /// Moves the cursor to the first row of the level.
    pub fn select_first(&mut self) {
        self.list_state.select(Some(0));
    }

    /// Moves the cursor to the last row of the level.
    pub fn select_last(&mut self) {
        self.list_state
            .select(Some(self.current_level().len().saturating_sub(1)));
    }
}

/// The nodes reached by following `path` from the root of `tree`.
///
/// A path only ever grows by descending into a category, so a step that lands
/// on anything else cannot happen; it returns the level reached so far rather
/// than panicking, because a logic error must not take the interface down.
fn level_at<'a>(tree: &'a [Node], path: &[usize]) -> &'a [Node] {
    let mut nodes = tree;

    for &index in path {
        match nodes.get(index) {
            Some(Node::Category(category)) => nodes = category.children.as_slice(),
            _ => return nodes,
        }
    }

    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::tree;

    /// A cursor over the real task tree.
    fn cursor() -> TreeCursor {
        TreeCursor::new(tree())
    }

    #[test]
    fn a_new_cursor_starts_on_the_first_row_of_the_root() {
        let cursor = cursor();

        assert!(cursor.at_root());
        assert_eq!(cursor.selected(), Some(0));
        assert_eq!(cursor.breadcrumb(), "Tasks");
    }

    #[test]
    fn entering_a_category_shows_its_children() {
        let mut cursor = cursor();
        let before = cursor.current_level().len();

        cursor.enter_category(0);

        assert!(!cursor.at_root());
        assert_eq!(cursor.selected(), Some(0), "a new level starts at the top");
        assert_ne!(
            cursor.current_level().len(),
            before,
            "the level on screen must have changed"
        );
    }

    #[test]
    fn leaving_restores_the_row_the_level_was_left_on() {
        // The property the cursor stack exists for: coming back to a category
        // and finding the cursor at the top would lose the operator's place.
        let mut cursor = cursor();

        cursor.select_next();
        cursor.select_next();
        let left_on = cursor.selected();

        cursor.enter_category(2);
        assert!(cursor.leave_category());

        assert_eq!(cursor.selected(), left_on);
    }

    #[test]
    fn leaving_the_root_reports_that_it_could_not() {
        // Answered rather than acted on, so the interface phrases the refusal
        // and the cursor stays out of the status row.
        let mut cursor = cursor();

        assert!(!cursor.leave_category());
        assert!(cursor.at_root(), "a refused move must change nothing");
    }

    #[test]
    fn the_two_stacks_stay_the_same_depth() {
        // `path` and `cursor_stack` are pushed and popped as a pair, and this
        // is the file where they can be got wrong.
        let mut cursor = cursor();

        cursor.enter_category(1);
        cursor.enter_category(0);
        assert_eq!(cursor.path.len(), cursor.cursor_stack.len());

        cursor.leave_category();
        assert_eq!(cursor.path.len(), cursor.cursor_stack.len());

        cursor.leave_category();
        assert_eq!(cursor.path.len(), cursor.cursor_stack.len());
        assert!(cursor.at_root());
    }

    #[test]
    fn the_breadcrumb_names_the_levels_that_were_entered() {
        let mut cursor = cursor();

        cursor.enter_category(0);

        assert_ne!(cursor.breadcrumb(), "Tasks");
        assert!(!cursor.breadcrumb().is_empty());
    }

    #[test]
    fn the_cursor_stops_at_both_ends_of_a_level() {
        let mut cursor = cursor();
        let last = cursor.current_level().len() - 1;

        for _ in 0..1000 {
            cursor.select_next();
        }
        assert_eq!(cursor.selected(), Some(last));

        for _ in 0..1000 {
            cursor.select_previous();
        }
        assert_eq!(cursor.selected(), Some(0));
    }

    #[test]
    fn first_and_last_reach_the_ends_directly() {
        let mut cursor = cursor();
        let last = cursor.current_level().len() - 1;

        cursor.select_last();
        assert_eq!(cursor.selected(), Some(last));

        cursor.select_first();
        assert_eq!(cursor.selected(), Some(0));
    }

    #[test]
    fn jumping_lands_on_the_task_and_leaves_a_sensible_way_back() {
        // The route a search result takes. Nothing was entered on the way, so
        // the rows to restore are the ones holding each category.
        let mut cursor = cursor();

        cursor.jump_to(&[1, 0], 0);

        assert_eq!(cursor.selected(), Some(0));
        assert_eq!(
            cursor.path.len(),
            cursor.cursor_stack.len(),
            "a jump must leave the stacks agreeing"
        );

        assert!(cursor.leave_category());
        assert_eq!(
            cursor.selected(),
            Some(0),
            "leaving returns to the row holding the category"
        );
    }

    #[test]
    fn a_path_that_does_not_resolve_stops_where_it_got_to() {
        // A logic error must not take the interface down on a server, so a
        // step that cannot be followed yields the level reached so far.
        let nodes = tree();

        assert_eq!(
            level_at(&nodes, &[9999]).len(),
            nodes.len(),
            "an unfollowable first step leaves the root showing"
        );
        assert_eq!(
            level_at(&nodes, &[0, 9999]).len(),
            level_at(&nodes, &[0]).len(),
            "and a later one leaves the level it had reached"
        );
    }

    #[test]
    fn selected_task_is_none_on_a_category() {
        let cursor = cursor();

        // The root level holds categories only.
        assert!(cursor.selected_node().is_some());
        assert!(cursor.selected_task().is_none());
    }
}
