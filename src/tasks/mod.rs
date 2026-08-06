//! The task tree the TUI exposes.
//!
//! Tasks are native typed Rust rather than embedded shell scripts: they call
//! the domain traits, so they inherit the distro abstraction and are testable
//! without a container. A shell script could not call a trait.

pub mod algorithms;
pub mod consequence;
pub mod devtools;
pub mod hardening;
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
use crate::exec::{Executor, OutputLine, Stream};
use crate::tasks::consequence::Consequence;
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;

/// Somewhere a task reports its progress to.
///
/// The CLI prints these lines; the TUI streams them into its output pane.
pub type Progress<'a> = &'a mut dyn FnMut(OutputLine);

/// Reports a step to the caller as a normal output line.
///
/// Here rather than in each task module: the seven that report progress had
/// written this identically, so the shape of an output line was a decision
/// recorded in seven places and changeable in none of them alone.
pub(crate) fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Whether a task runs on a family, and the reason when it does not.
///
/// The reason is not optional, which is the point: an exception with no stated
/// cause is indistinguishable from an oversight, and every one of these was
/// established by measurement rather than assumption — which repository ships
/// what, which shipped `Include` wins, which installer publishes no digest.
///
/// It is `&'static str` rather than a message in the catalogue because it says
/// something about the world rather than about this program, and because these
/// sentences are the record of what was tried. Rendering them through i18n
/// would mean translating a citation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// The task runs here.
    Yes,
    /// The task does not run here, for the stated reason.
    No(&'static str),
}

/// Implements [`Task::support`] as `Yes` for every family.
///
/// Most tasks work everywhere, and writing four identical arms in each of them
/// would bury the ones that do not. The `match` still happens — it is written
/// once, here — so a new family fails to compile in this macro and every task
/// using it is corrected in one place.
macro_rules! supported_everywhere {
    () => {
        fn support(&self, family: $crate::distro::Family) -> $crate::tasks::Support {
            match family {
                $crate::distro::Family::Debian
                | $crate::distro::Family::Rhel
                | $crate::distro::Family::Arch
                | $crate::distro::Family::Alpine => $crate::tasks::Support::Yes,
            }
        }
    };
}

pub(crate) use supported_everywhere;

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
    /// Takes the backend for the same reason every other method does: a
    /// consequence that names a command must let the family spell it. A task
    /// writing `nft list table inet initd` itself is a distro branch wearing a
    /// string literal — correct on three families and wrong on RHEL, where the
    /// rule was written through firewalld and lives in a zone that listing
    /// never shows.
    ///
    /// Most tasks affect nothing else and inherit the empty default.
    fn consequences(&self, backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let _ = (backend, values);
        Vec::new()
    }

    /// Whether this task runs on `family`, and if not, why not.
    ///
    /// Written as an exhaustive `match` rather than returning a list of the
    /// families that work. A `&[Family]` cannot be checked for exhaustiveness,
    /// so adding a family and forgetting a task produced a task that was
    /// *silently* unsupported — the tool would start on the new distribution
    /// and grey out every row. A test used to invert that default and catch it;
    /// this makes the compiler catch it, in the file that has to decide.
    ///
    /// The reason travels with the refusal because it is the useful half. Every
    /// one of these was measured — which repository ships what, which shipped
    /// `Include` wins, which installer publishes no digest — and it used to
    /// live in a test table where the operator being told "unsupported" could
    /// never see it.
    fn support(&self, family: Family) -> Support;

    /// Whether the task runs on the given family.
    fn supports(&self, family: Family) -> bool {
        matches!(self.support(family), Support::Yes)
    }

    /// Why this task does not run here, if it does not.
    fn unsupported_reason(&self, family: Family) -> Option<&'static str> {
        match self.support(family) {
            Support::Yes => None,
            Support::No(reason) => Some(reason),
        }
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
/// SSH grants shell access and WireGuard grants network access. The name was
/// chosen before WireGuard existed and did not have to change when it arrived,
/// which is what it was chosen for.
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
        Node::Category(hardening::category()),
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

/// Where a task sits in the tree: the indices to reach it, and the categories
/// it sits under.
///
/// Separate from [`all_tasks`], which flattens the tree and discards the route
/// through it. Search needs the route — a result nobody can jump to is a list,
/// not a way of getting anywhere — and the titles, because "Install the SSH
/// server" means something different under `Remote Access › SSH` than the same
/// words would elsewhere.
pub struct TaskLocation {
    /// Index of the task within its own level.
    pub index: usize,
    /// Indices from the root to the category holding it.
    pub path: Vec<usize>,
    /// Titles of those categories, outermost first.
    pub titles: Vec<&'static str>,
}

/// Locates every task in the tree, in tree order, keeping the route to each.
pub fn located_tasks(nodes: &[Node]) -> Vec<(TaskLocation, &dyn Task)> {
    let mut found = Vec::new();
    locate_tasks(nodes, &mut Vec::new(), &mut Vec::new(), &mut found);
    found
}

/// Walks `nodes`, carrying the path and titles taken to reach them.
fn locate_tasks<'a>(
    nodes: &'a [Node],
    path: &mut Vec<usize>,
    titles: &mut Vec<&'static str>,
    out: &mut Vec<(TaskLocation, &'a dyn Task)>,
) {
    for (index, node) in nodes.iter().enumerate() {
        match node {
            Node::Task(task) => out.push((
                TaskLocation {
                    index,
                    path: path.clone(),
                    titles: titles.clone(),
                },
                task.as_ref(),
            )),
            Node::Category(category) => {
                path.push(index);
                titles.push(category.title);
                locate_tasks(&category.children, path, titles, out);
                titles.pop();
                path.pop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docs_cli_lists_exactly_the_tasks_the_tree_offers() {
        // `docs/cli.md` is the programmatic contract, and it went stale within
        // one phase of the tree growing — twenty-two tasks existed that it did
        // not mention. A reader of `docs/` alone must be able to answer "what
        // can this do", so the drift is checked rather than remembered.
        //
        // Both directions matter: a task missing from the table is one nobody
        // knows they can run, and a table naming a task that no longer exists
        // sends a script after something that will exit 2.
        let doc = include_str!("../../docs/cli.md");

        let documented: Vec<&str> = doc
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|rest| rest.split('`').next())
            // Section headings and the conventions table use the same pipe
            // syntax; a task id is what the tree would recognise.
            .filter(|id| id.contains('.'))
            .collect();

        let mut in_tree: Vec<String> = all_tasks()
            .into_iter()
            .map(|task| task.id().to_owned())
            .collect();
        in_tree.sort_unstable();

        let mut listed: Vec<String> = documented.iter().map(|id| (*id).to_owned()).collect();
        listed.sort_unstable();
        listed.dedup();

        let undocumented: Vec<&String> = in_tree.iter().filter(|id| !listed.contains(id)).collect();
        let stale: Vec<&String> = listed.iter().filter(|id| !in_tree.contains(id)).collect();

        assert!(
            undocumented.is_empty(),
            "these tasks are missing from docs/cli.md: {undocumented:?}"
        );
        assert!(
            stale.is_empty(),
            "docs/cli.md names tasks that no longer exist: {stale:?}"
        );
    }

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
        // A task supported nowhere is a row that can never be run. The
        // compiler cannot catch this: `No` on every arm type-checks.
        for task in all_tasks() {
            assert!(
                Family::ALL.iter().any(|&family| task.supports(family)),
                "{} supports nothing",
                task.id()
            );
        }
    }

    #[test]
    fn every_refusal_states_a_reason_worth_reading() {
        // `Support::No` cannot be constructed without a reason, so what is
        // left to check is that the reason says something. An exception with
        // no stated cause is indistinguishable from an oversight, and these
        // sentences are the record of what was measured — which repository
        // ships what, which shipped `Include` wins, which installer publishes
        // no digest.
        //
        // The floor is deliberately low and the point is the shape: a
        // placeholder like "n/a" or "TODO" fails, a sentence passes.
        for task in all_tasks() {
            for &family in Family::ALL {
                let Some(reason) = task.unsupported_reason(family) else {
                    continue;
                };

                assert!(
                    reason.len() > 30 && reason.contains(' '),
                    "{} refuses {family} without explaining why: {reason:?}",
                    task.id()
                );
                assert!(
                    !reason.to_lowercase().contains("todo"),
                    "{} refuses {family} with a placeholder: {reason:?}",
                    task.id()
                );
            }
        }
    }

    #[test]
    fn support_and_supports_cannot_disagree() {
        // `supports` is derived from `support`, and the interface uses one
        // while the CLI's refusal path uses the other. They answer the same
        // question and must not drift.
        for task in all_tasks() {
            for &family in Family::ALL {
                assert_eq!(
                    task.supports(family),
                    task.unsupported_reason(family).is_none(),
                    "{} disagrees with itself about {family}",
                    task.id()
                );
            }
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
