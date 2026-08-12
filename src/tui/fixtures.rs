//! Fixtures the interface's tests share.
//!
//! `test_app` builds the whole `App`, so every test in `tui` needs it and it
//! cannot live inside any one of their modules. Shaped after
//! `exec::mock` and `tasks::ssh::fixtures`: a `#[cfg(test)]` module in a file
//! of its own rather than a `mod tests` a sibling reaches into.
//!
//! Only what more than one module needs is here. Helpers that drive a
//! particular corner of the interface — pressing keys, rendering to rows,
//! pretending a task is running — stay with the tests that use them.

#![cfg(test)]

use super::app::App;
use crate::backend::for_family;
use crate::distro::host::HostFacts;
use crate::distro::{Distro, Family};
use crate::exec::mock::MockExecutor;
use crate::tasks::Node;

pub fn test_distro(family: Family) -> Distro {
    Distro {
        id: "debian".to_owned(),
        version_id: Some("13".to_owned()),
        codename: Some("trixie".to_owned()),
        pretty_name: Some("Debian GNU/Linux 13".to_owned()),
        family,
    }
}

/// A host stated outright, so the assertions do not depend on whichever
/// machine happens to run the suite.
pub fn test_host() -> HostFacts {
    HostFacts {
        hostname: "web-01".to_owned(),
        privilege: "sudo".to_owned(),
    }
}

pub fn test_app(family: Family) -> App {
    App::new(
        test_distro(family),
        test_host(),
        for_family(family),
        MockExecutor::new(),
    )
}

/// Descends into the named category of the level currently shown.
///
/// Used where the test is about a specific area rather than about the
/// drill-down itself, so that a new category added above it does not
/// silently redirect the walk.
pub fn enter_named_category(app: &mut App, title: &str) {
    let index = app
        .current_level()
        .iter()
        .position(|node| matches!(node, Node::Category(c) if c.title == title))
        .unwrap_or_else(|| panic!("the level must contain {title}"));

    app.cursor.list_state().select(Some(index));
    app.enter_category(index);
}

/// Descends into the first category of the level currently shown.
pub fn enter_first_category(app: &mut App) {
    let index = app
        .current_level()
        .iter()
        .position(|node| matches!(node, Node::Category(_)))
        .expect("the level must contain a category");

    app.cursor.list_state().select(Some(index));
    app.enter_category(index);
}
