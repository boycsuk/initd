//! The task tree the TUI exposes.
//!
//! Tasks are native typed Rust rather than embedded shell scripts: they call
//! the domain traits, so they inherit the distro abstraction and are testable
//! without a container. A shell script could not call a trait.

pub mod algorithms;
pub mod consequence;
pub mod devtools;
pub mod network;
pub mod params;
pub mod revert;
pub mod services;
pub mod ssh;
pub mod sshd_config;
pub mod users;
pub mod wireguard;

use crate::backend::Backend;
use crate::distro::Family;
use crate::error::Result;
use crate::exec::{Executor, OutputLine};
use crate::tasks::consequence::Consequence;
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;

/// Somewhere a task reports its progress to.
///
/// The CLI prints these lines; the TUI streams them into its output pane.
pub type Progress<'a> = &'a mut dyn FnMut(OutputLine);

/// A unit of administration work.
///
/// Implementations must never branch on the distribution. If a task needs to
/// know which distro it runs on, the missing abstraction belongs in a domain
/// trait instead.
pub trait Task {
    /// Stable identifier, used by the CLI and as a key in the TUI.
    fn id(&self) -> &'static str;

    /// Short human-readable title.
    fn title(&self) -> &'static str;

    /// What the task does, shown in the TUI before running it.
    fn description(&self) -> &'static str;

    /// Whether the task changes system state irreversibly enough to warrant a
    /// confirmation prompt.
    fn is_destructive(&self) -> bool {
        false
    }

    /// Values the task needs before it can run.
    ///
    /// Declared rather than supplied at construction, so the tree can offer a
    /// task without inventing values for it. Whichever interface is driving
    /// collects them: the TUI in a form, the CLI from its arguments.
    ///
    /// Most tasks need nothing and inherit the empty default.
    fn params(&self) -> Vec<Param> {
        Vec::new()
    }

    /// Whether the task collects anything before it runs.
    fn needs_input(&self) -> bool {
        !self.params().is_empty()
    }

    /// What this task invalidates elsewhere, given the values it ran with.
    ///
    /// Declared rather than acted on: the interface states these and the
    /// administrator decides. Chaining the follow-up changes automatically
    /// would make a single keystroke reconfigure several subsystems, which is
    /// the opposite of what the verification window exists to provide.
    ///
    /// Takes the values because the consequence usually depends on them —
    /// moving SSH to 2222 invalidates a firewall rule naming 22, while
    /// re-running the same task with 22 invalidates nothing. A declaration that
    /// ignored them would warn every time and be learned to ignore.
    ///
    /// Most tasks affect nothing else and inherit the empty default.
    fn consequences(&self, values: &ParamValues) -> Vec<Consequence> {
        let _ = values;
        Vec::new()
    }

    /// Families this task supports.
    ///
    /// The TUI shows unsupported tasks greyed out with the reason, rather than
    /// hiding them.
    fn supported_families(&self) -> &'static [Family];

    /// Whether the task runs on the given family.
    fn supports(&self, family: Family) -> bool {
        self.supported_families().contains(&family)
    }

    /// Runs the task with the values collected for its parameters.
    ///
    /// A task that declared no parameters ignores `values`; one that did reads
    /// them back by the names it declared, and fails rather than substituting
    /// a default if the interface failed to collect one.
    ///
    /// Returning [`Outcome::Revertible`] hands the caller an undo for a change
    /// that has already been applied — the tool cannot tell whether the
    /// administrator can still reach the machine, so it applies, offers to put
    /// things back, and lets them prove it.
    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome>;
}

/// A node of the task tree: either a runnable task or a category of nodes.
///
/// The recursion lives here rather than in the interface so that `tree()`
/// remains the description of what the tool can do, at whatever depth an
/// administration area needs to express itself.
pub enum Node {
    Task(Box<dyn Task>),
    Category(Category),
}

/// A named group of nodes, which may itself contain further categories.
pub struct Category {
    pub title: &'static str,
    pub children: Vec<Node>,
}

impl Category {
    /// Builds a category from its title and children.
    pub fn new(title: &'static str, children: Vec<Node>) -> Self {
        Self { title, children }
    }

    /// Number of runnable tasks in this category, at any depth.
    pub fn task_count(&self) -> usize {
        self.children
            .iter()
            .map(|child| match child {
                Node::Task(_) => 1,
                Node::Category(category) => category.task_count(),
            })
            .sum()
    }
}

/// Builds the full task tree.
///
/// Each administration area owns how it subdivides itself, so adding one means
/// adding a line here and a module beside it — never restructuring the tree.
///
/// `Remote Access` is named for what its members do rather than for a protocol:
/// SSH grants shell access and WireGuard, once it lands, grants network access.
pub fn tree() -> Vec<Node> {
    vec![
        // Identity comes first because the rest depends on there being a safe
        // way in: authorising a key for an account that does not exist yet is
        // the wrong order, and locking root before either is how a machine
        // becomes unreachable.
        Node::Category(Category::new(
            "Identity & Access",
            vec![Node::Category(users::category())],
        )),
        Node::Category(Category::new(
            "Remote Access",
            vec![
                Node::Category(ssh::category()),
                Node::Category(wireguard::category()),
            ],
        )),
        // Its own top-level area rather than a child of Remote Access: the
        // firewall and the kernel parameters are what every other component
        // depends on, and belong to none of them.
        Node::Category(network::category()),
        Node::Category(services::category()),
        Node::Category(devtools::category()),
    ]
}

/// Finds a task by its identifier, at any depth of the tree.
pub fn find(id: &str) -> Option<Box<dyn Task>> {
    find_in(tree(), id)
}

/// Searches a forest of nodes for a task with the given identifier.
fn find_in(nodes: Vec<Node>, id: &str) -> Option<Box<dyn Task>> {
    for node in nodes {
        match node {
            Node::Task(task) if task.id() == id => return Some(task),
            Node::Task(_) => {}
            Node::Category(category) => {
                if let Some(found) = find_in(category.children, id) {
                    return Some(found);
                }
            }
        }
    }

    None
}

/// Collects every task in the tree, flattened, in tree order.
///
/// Callers that only need the tasks — support checks, uniqueness tests — use
/// this instead of walking the recursion themselves.
pub fn all_tasks() -> Vec<Box<dyn Task>> {
    let mut tasks = Vec::new();
    collect_tasks(tree(), &mut tasks);
    tasks
}

/// Appends every task under `nodes` to `out`, depth first.
fn collect_tasks(nodes: Vec<Node>, out: &mut Vec<Box<dyn Task>>) {
    for node in nodes {
        match node {
            Node::Task(task) => out.push(task),
            Node::Category(category) => collect_tasks(category.children, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_task_has_a_unique_id() {
        let ids: Vec<_> = all_tasks()
            .into_iter()
            .map(|task| task.id().to_owned())
            .collect();

        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(ids.len(), unique.len(), "duplicate task ids: {ids:?}");
    }

    #[test]
    fn every_task_supports_at_least_one_family() {
        for task in all_tasks() {
            assert!(
                !task.supported_families().is_empty(),
                "{} supports nothing",
                task.id()
            );
        }
    }

    #[test]
    fn tasks_can_be_found_by_id() {
        assert!(find("ssh.install").is_some());
        assert!(find("nonexistent").is_none());
    }

    #[test]
    fn finds_a_task_nested_several_levels_deep() {
        // Remote Access > SSH > Keys > authorize-key: the deepest node today,
        // and the one that proves the search is not single-level.
        let task = find("ssh.authorize-key").expect("the task must be reachable");
        assert_eq!(task.id(), "ssh.authorize-key");
    }

    #[test]
    fn a_category_title_is_not_a_runnable_id() {
        // Categories group tasks; they are not tasks. Resolving one by id would
        // let the CLI try to run something that has no `run`.
        assert!(find("SSH").is_none());
        assert!(find("Remote Access").is_none());
    }

    #[test]
    fn no_category_is_empty() {
        // An empty category renders as a row that opens onto nothing.
        fn check(nodes: &[Node]) {
            for node in nodes {
                if let Node::Category(category) = node {
                    assert!(
                        !category.children.is_empty(),
                        "category {} has no children",
                        category.title
                    );
                    check(&category.children);
                }
            }
        }

        check(&tree());
    }

    #[test]
    fn task_count_totals_every_depth() {
        // Summed across the roots rather than read off the first one: the tree
        // grew a second top-level category, and a count that only walked one
        // would report a shrinking total every time an area is added.
        let counted: usize = tree()
            .into_iter()
            .map(|node| match node {
                Node::Task(_) => 1,
                Node::Category(category) => category.task_count(),
            })
            .sum();

        assert_eq!(counted, all_tasks().len());
    }
}
