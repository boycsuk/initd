//! Walking the task tree: entering a category, going back, moving the cursor.
//!
//! Drill-down navigation is the interface's simplest behaviour and the one
//! everything else assumes works, which is why its tests are the one block
//! that needs no key presses, no rendering and no running task — just the
//! cursor and the level under it.

#[cfg(test)]
mod tests {
    use super::super::fixtures::{enter_first_category, enter_named_category, test_app};
    use crate::distro::Family;
    use crate::tasks::{self, Node};

    #[test]
    fn starts_at_the_root_level_with_a_row_selected() {
        let app = test_app(Family::Debian);

        assert!(app.cursor.at_root(), "navigation must start at the root");
        assert_eq!(app.cursor.selected(), Some(0));
    }

    #[test]
    fn the_root_shows_only_top_level_nodes() {
        let app = test_app(Family::Debian);

        assert_eq!(app.current_level().len(), tasks::tree().len());
    }

    #[test]
    fn entering_a_category_shows_its_children() {
        let mut app = test_app(Family::Debian);

        let expected = match &app.current_level()[0] {
            Node::Category(category) => category.children.len(),
            Node::Task(_) => panic!("the root must start with a category"),
        };

        enter_first_category(&mut app);

        assert_eq!(app.current_level().len(), expected);
        assert_eq!(app.cursor.path(), vec![0]);
    }

    #[test]
    fn going_back_restores_the_level_and_the_cursor() {
        let mut app = test_app(Family::Debian);

        // Move off the first row so the restored cursor is distinguishable.
        app.select_next();
        let before = app.cursor.selected().expect("a row must be selected");
        let index = before;
        app.enter_category(index);

        app.leave_category();

        assert!(app.cursor.at_root(), "the root must be restored");
        assert_eq!(
            app.cursor.selected(),
            Some(before),
            "the cursor must return to the row that was entered"
        );
    }

    #[test]
    fn going_back_at_the_root_does_not_quit() {
        let mut app = test_app(Family::Debian);

        app.leave_category();

        assert!(app.cursor.at_root());
        assert!(
            !app.should_quit,
            "Esc at the root must not exit the program"
        );
    }

    #[test]
    fn entering_leaves_the_cursor_on_a_valid_row() {
        let mut app = test_app(Family::Debian);

        enter_first_category(&mut app);

        let selected = app.cursor.selected().expect("a row must be selected");
        assert!(
            selected < app.current_level().len(),
            "the cursor must point inside the new level"
        );
    }

    #[test]
    fn navigation_stops_at_the_ends() {
        let mut app = test_app(Family::Debian);
        enter_first_category(&mut app);

        for _ in 0..100 {
            app.select_next();
        }
        let last = app.cursor.selected().expect("selection must persist");

        for _ in 0..100 {
            app.select_previous();
        }
        let first = app.cursor.selected().expect("selection must persist");

        assert_eq!(first, 0);
        assert_eq!(last, app.current_level().len() - 1);
    }

    #[test]
    fn every_row_of_a_level_is_selectable() {
        // Categories are entered rather than skipped, so unlike the previous
        // flat tree the cursor must be able to land on one.
        let mut app = test_app(Family::Debian);
        enter_first_category(&mut app);

        for expected in 0..app.current_level().len() {
            assert_eq!(app.cursor.selected(), Some(expected));
            app.select_next();
        }
    }

    #[test]
    fn a_deeply_nested_task_is_reachable() {
        // Remote Access > SSH > Service > install: three descents before a task
        // appears, which is what the drill-down has to support. Named rather
        // than reached by position, so adding a category above it moves the
        // path without failing the test for the wrong reason.
        let mut app = test_app(Family::Debian);

        enter_named_category(&mut app, "Remote Access");
        enter_first_category(&mut app);
        enter_first_category(&mut app);

        let task = app.selected_task().expect("a task must be selected");
        assert_eq!(task.id(), "ssh.install");
    }

    #[test]
    fn the_breadcrumb_tracks_the_path() {
        let mut app = test_app(Family::Debian);
        assert_eq!(app.breadcrumb(), "Tasks");

        enter_named_category(&mut app, "Remote Access");
        assert_eq!(app.breadcrumb(), "Remote Access");

        enter_first_category(&mut app);
        assert_eq!(app.breadcrumb(), "Remote Access › SSH");
    }

    #[test]
    fn a_category_row_is_not_a_task() {
        let app = test_app(Family::Debian);

        assert!(
            app.selected_task().is_none(),
            "the root holds categories, which are not runnable"
        );
    }

    #[test]
    fn no_dialog_is_open_initially() {
        assert!(test_app(Family::Debian).confirm.is_none());
    }
}
