//! The task tree the TUI exposes.
//!
//! Tasks are native typed Rust rather than embedded shell scripts: they call
//! the domain traits, so they inherit the distro abstraction and are testable
//! without a container. A shell script could not call a trait.

pub mod algorithms;
pub mod consequence;
pub mod devtools;
pub mod gitconfig;
pub mod hardening;
pub mod network;
pub mod params;
pub mod revert;
pub mod services;
pub mod ssh;
pub mod sshd_config;
pub mod uninstall;
pub mod users;
pub mod wireguard;

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::error::Result;
use crate::exec::{Executor, OutputLine, Stream};
use crate::i18n::{Lang, Msg};
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
///
/// Takes a [`Msg`] rather than a string, which is what puts the tasks' own
/// narration inside the catalogue. The claim that user-facing text lives there
/// held for errors and for the interface's chrome while these ninety lines sat
/// as English literals in the task modules — enough that a second language
/// would have produced an output pane with translated headings above untouched
/// progress.
///
/// The rendering happens here rather than in each task because this is the one
/// place every line already passes through: a `Lang` threaded into `Task::run`
/// would be a parameter fifty implementations carry and one forgets.
pub(crate) fn report(progress: Progress<'_>, message: &Msg) {
    // Resolved per line, which is affordable here in a way it is not in the
    // interface: a task reports a handful of steps over seconds, where a key
    // bar is a dozen labels every frame.
    progress(OutputLine::new(
        Stream::Stdout,
        Lang::from_env().render(message),
    ));
}

/// Reports a line that is data rather than language.
///
/// The WireGuard client configuration a peer is meant to copy, and the blank
/// line separating it from what came before. Neither is a sentence: translating
/// `[Interface]` would produce a file `wg-quick` cannot read, and a blank line
/// has nothing to translate. Kept apart from [`report`] so the distinction is
/// visible at the call site rather than resting on which constructor somebody
/// reached for.
pub(crate) fn report_verbatim(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine::new(Stream::Stdout, text.into()));
}

/// Reports data the screen may show but the clipboard may not carry.
///
/// The peer configuration is the case: it holds a private key and a preshared
/// key, and it exists to be read off the screen and typed into a client. The
/// pane draws it unchanged. What this bounds is the transcript copy, which
/// crosses back to the operator's own machine and persists there — the same
/// disclosure `write_uncopied` refuses on disk, through a different door.
pub(crate) fn report_secret(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine::new(Stream::Stdout, text.into()).sensitive());
}

/// What the operator is asked before a task runs.
///
/// Three answers rather than the boolean this replaced, because that boolean
/// had drifted from what it was documented to mean. It read "irreversibly
/// enough to warrant a prompt" and was applied as "could lock you out", which
/// left nineteen of twenty-eight tasks installing packages, enabling daemons
/// and writing configuration without asking anything — `ssh.install` put an
/// SSH server on the machine and started it in silence, which is how this came
/// to be reported.
///
/// The distinction between the last two is what keeps either worth reading. A
/// dialog that appears for every task is answered without being read, and the
/// one it teaches people to dismiss is `users.lock-root`'s — the operation
/// whose recovery is the provider's rescue console. So a change that can end
/// the session applying it keeps the red frame and its warning, and everything
/// else asks plainly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Nothing is asked: the task only reads.
    ///
    /// Stated rather than defaulted to. A task that reads knows it does; a
    /// task that writes must not be able to stay quiet by omission, which is
    /// exactly what the old default allowed.
    None,
    /// The task changes the system, and says what it will do.
    Change,
    /// The change can end the session applying it.
    ///
    /// Drawn with the danger frame and the lockout warning. Reserved for the
    /// tasks that can strand an administrator on a remote machine, so that the
    /// frame still means something when it appears.
    Lockout,
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
                | $crate::distro::Family::Alpine
                | $crate::distro::Family::Suse => $crate::tasks::Support::Yes,
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

    /// What the operator is asked before this task runs.
    ///
    /// Defaults to [`Confirmation::Change`], which is the answer for every
    /// task that writes anything: only a task that reads is exempt, and a task
    /// that reads says so. The default used to be "ask nothing", and what that
    /// produced was `ssh.install` putting a network daemon on the machine and
    /// enabling it with no question asked — the operator's report that opened
    /// this. A default of silence is one every new task inherits by saying
    /// nothing at all.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Change
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

    /// The parameters this task collects **on this host**.
    ///
    /// Separate from [`params`](Self::params) because the two answer different
    /// questions. `params` is what the task takes — a fact about the task,
    /// asked by the CLI, which documents every argument whether or not this
    /// machine honours it. This is what is worth *asking an operator*, which
    /// depends on the machine.
    ///
    /// The two come apart wherever a value has one possible outcome here. A
    /// removal depth decides whether configuration survives, and it decides
    /// that through a package manager: where a capability is not a package on
    /// this family — Zellij and Caddy on Debian arrive as verified release
    /// binaries — the undo deletes a file and `remove` and `purge` name the
    /// same `rm`. RHEL is the same shape for a different reason, rpm having no
    /// purge at all.
    ///
    /// Filtering rather than refusing: a field with two options and one
    /// outcome invites a decision and then ignores it, which is the complaint
    /// that produced this method. The CLI still accepts the argument and says
    /// when it could not be honoured, because a script written against one
    /// host should not silently mean something else on another.
    fn params_here(&self, _backend: &dyn Backend) -> Vec<Param> {
        self.params()
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
    /// string literal — correct on four families and wrong on RHEL, where the
    /// rule was written through firewalld and lives in a zone that listing
    /// never shows.
    ///
    /// Most tasks affect nothing else and inherit the empty default.
    fn consequences(&self, backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let _ = (backend, values);
        Vec::new()
    }

    /// What the host is asked about to decide which verb this row shows.
    ///
    /// Declared by the task rather than by a table beside the tree, for the
    /// reason every other declaration here is: a table is the thing that goes
    /// stale when a task changes what it installs, and nothing would fail to
    /// compile when it did.
    ///
    /// `None` for a task with no inverse, which is every task that is not half
    /// of a [`Node::Reversible`] — a row that cannot change its verb has
    /// nothing to measure and must not cost a command at startup.
    fn subject(&self) -> Option<Capability> {
        None
    }

    /// What must already be true before this task is worth running.
    ///
    /// The inverse of [`consequence::Consequence::Invalidates`], and the edge
    /// that lets the interface say so *before* a key is pressed. Every guard in
    /// this tree lives inside a `run`, so the tree drew a row that would refuse
    /// exactly like one that would work: `firewall.manage-ports` on a host with
    /// no policy looks, from the tree, like any other runnable row.
    ///
    /// **The interface refuses `Enter` on a row measured unmet**, and the guard
    /// inside `run` remains the barrier behind that. Two barriers rather than
    /// one because they answer different questions: the interface asks what it
    /// last measured, and the task asks the host at the moment it would act.
    /// Only the second can be trusted to be current, so it is never removed.
    ///
    /// What the first buys is the operator's attention. Without it a blocked
    /// row went the whole way — form, values, and for `firewall.manage-ports` a
    /// red lockout dialog — before being refused, spending a sequence of
    /// decisions on an outcome that was never available.
    ///
    /// **A requirement that could not be measured refuses nothing.** A check
    /// costs a command and the probe does not escalate, so "could not ask" is
    /// its ordinary answer rather than an edge case; a row greyed out on that
    /// basis is one the operator can neither run nor explain.
    ///
    /// Most tasks require nothing of another task and inherit the empty
    /// default. What belongs here is a dependency on *this tool's own* tasks,
    /// not on the world: "the package I install must exist" is a support
    /// question, and "a token must be issued" is a consequence.
    /// Takes the backend for the reason [`Self::consequences`] does: the
    /// command that answers "is this already true" is spelled per family, and a
    /// task writing it directly would have to pick one. The firewall is the
    /// case that proves it — `nft list table inet initd` names a table that
    /// does not exist on RHEL, where the rules live in a firewalld zone.
    fn requires(&self, _backend: &dyn Backend) -> Vec<consequence::Requirement> {
        Vec::new()
    }

    /// Which reversible pairs this task's success may have changed.
    ///
    /// Named rather than "everything": re-probing all of them after every task
    /// would put a second of `fork`/`exec` between finishing and being able to
    /// read the result. A task names the pair it belongs to, and the rare one
    /// that disturbs another names that too.
    fn affects(&self) -> &'static [&'static str] {
        &[]
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
    /// Two opposed operations sharing a single row.
    ///
    /// One row rather than two because "Install Caddy" and "Uninstall Caddy"
    /// are not a choice an operator makes: exactly one of them is meaningful at
    /// any moment, and a tree offering both makes the reader work out which.
    /// The interface asks what the host measured and draws the one that applies.
    ///
    /// Two *tasks* rather than one task with a verb, because a task's identity
    /// is its id. `find` resolves an id, [`crate::tui::worker`] re-resolves it
    /// on its own thread, `initd run <id>` names it, and
    /// `docs_cli_lists_exactly_the_tasks_the_tree_offers` gates it. An id that
    /// meant two things depending on the host would be a task the worker cannot
    /// resolve, the CLI cannot name, and the contract file cannot describe —
    /// and `confirmation()` takes only `&self`, so the lockout classification of
    /// such an id could not be stated either.
    ///
    /// Both members reach [`all_tasks`], so every invariant already asserted
    /// over the tree covers the inverse without being taught to.
    Reversible {
        /// Run when the subject is absent: the task that puts it there.
        forward: Box<dyn Task>,
        /// Run when the subject is present: the task that takes it away.
        inverse: Box<dyn Task>,
    },
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
                // A pair counts once: the number beside a category tells the
                // operator how many rows are inside it, and a reversible pair
                // draws one row whichever verb it is showing.
                Node::Reversible { .. } => 1,
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
            // Both members are findable by their own id, which is what lets the
            // worker thread and `initd run` resolve an inverse without knowing
            // that it shares a row with anything.
            Node::Reversible { forward, inverse } => {
                if forward.id() == id {
                    return Some(forward);
                }
                if inverse.id() == id {
                    return Some(inverse);
                }
            }
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
            // Both members, so that every invariant asserted over `all_tasks`
            // — unique ids, a reason behind every refusal, the `docs/cli.md`
            // contract — covers an inverse the moment it joins the tree,
            // rather than when somebody remembers to teach a test about it.
            Node::Reversible { forward, inverse } => {
                out.push(forward);
                out.push(inverse);
            }
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
            // Both members are searchable, and both carry the same index: they
            // share a row, so jumping to either lands on it. Navigation
            // addresses rows, search addresses operations — which is why
            // searching "uninstall caddy" finds something the tree may be
            // drawing as "Install Caddy" at that moment. The row the operator
            // arrives at shows whichever verb the host justifies.
            Node::Reversible { forward, inverse } => {
                for task in [forward, inverse] {
                    out.push((
                        TaskLocation {
                            index,
                            path: path.clone(),
                            titles: titles.clone(),
                        },
                        task.as_ref(),
                    ));
                }
            }
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
    fn only_a_task_that_reads_may_stay_silent() {
        // The reported defect, pinned: `ssh.install` put an SSH server on the
        // machine and enabled it without asking, because the old default was
        // "ask nothing" and nineteen tasks had inherited it by saying nothing.
        //
        // The default is now `Change`, so this cannot regress by omission —
        // only by a task declaring `None` outright. That is the list to keep
        // honest, and it is short enough to write down: a task that names
        // itself here and then writes something is the failure this catches.
        const READ_ONLY: [&str; 3] = ["firewall.status", "wireguard.status", "caddy.validate"];

        for task in all_tasks() {
            let silent = task.confirmation() == Confirmation::None;
            let listed = READ_ONLY.contains(&task.id());

            assert_eq!(
                silent,
                listed,
                "{} {} — a task that changes the system must ask first",
                task.id(),
                if silent {
                    "asks nothing and is not a read-only task"
                } else {
                    "is listed as read-only but asks before running"
                }
            );
        }
    }

    #[test]
    fn categories_come_after_the_rows_that_run_something() {
        // Reported for `Developer environment`, where `Git` sat between
        // `Install the Rust toolchain` and `Install the GitHub CLI`. A folder
        // among tasks reads as one of them until it is opened — the marker
        // distinguishes them, and a marker is one cell against a title that
        // looks like every other title.
        //
        // Checked over every level rather than the two that were wrong: the
        // rule is cheap to state and easy to break by adding a category to a
        // list that already has tasks in it, which is exactly how both of these
        // came about.
        fn check(nodes: &[Node], path: &str) {
            let mut seen_category = false;

            for node in nodes {
                match node {
                    Node::Category(category) => {
                        seen_category = true;
                        check(&category.children, &format!("{path} › {}", category.title));
                    }
                    Node::Task(task) => {
                        assert!(
                            !seen_category,
                            "{path}: {} is listed after a category; \
                             folders belong below the rows that run something",
                            task.id()
                        );
                    }
                    Node::Reversible { forward, .. } => {
                        assert!(
                            !seen_category,
                            "{path}: {} is listed after a category; \
                             folders belong below the rows that run something",
                            forward.id()
                        );
                    }
                }
            }
        }

        check(&tree(), "root");
    }

    #[test]
    fn a_lockout_is_reserved_for_what_can_end_the_session() {
        // The distinction the two levels exist for. If everything drifted to
        // `Lockout` the red frame would mark every row and distinguish none,
        // and the dialog it teaches people to dismiss is the one before
        // `users.lock-root`, whose recovery is the provider's rescue console.
        const LOCKOUT: [&str; 10] = [
            "firewall.enable",
            // A declared set of ports is the quieter half of the same risk.
            // `firewall.enable` asks which port to keep and warns about naming
            // the wrong one; here the operator removes a row, and nothing about
            // deleting a row from a table announces that the row was the one
            // carrying this session.
            "firewall.manage-ports",
            "ssh.allow-users",
            "ssh.harden",
            "ssh.harden-strict",
            "ssh.change-port",
            "users.set-shell",
            // Deleting the account being escalated through ends the session,
            // and unlike every other lockout there is nothing to put back: the
            // account is gone, and with it whatever sudo rule named it.
            "users.delete",
            // Two uninstalls can end the session running them. An administrator
            // connected over the tunnel loses it when wg0 goes down; every
            // other inverse removes something the session does not depend on.
            "wireguard.uninstall",
            // And the one this list used to say did not exist. `ssh.install`
            // had no inverse deliberately, because removing the daemon over its
            // own connection is the single operation in this tool with no route
            // back — the session ends mid-removal and reinstalling needs the
            // network path that just closed. It was added on request; the
            // reasoning did not stop being true, so it carries the strongest
            // confirmation the interface has and says plainly that a console is
            // the only recovery.
            "ssh.uninstall",
        ];

        let declared: Vec<_> = all_tasks()
            .iter()
            .filter(|task| task.confirmation() == Confirmation::Lockout)
            .map(|task| task.id().to_owned())
            .collect();

        // `users.lock-root` is the seventh and is checked apart, because it is
        // the one this whole distinction protects.
        let mut expected: Vec<_> = LOCKOUT.iter().map(|id| (*id).to_owned()).collect();
        expected.push("users.lock-root".to_owned());
        expected.sort();

        let mut declared = declared;
        declared.sort();

        assert_eq!(declared, expected, "the lockout set has drifted");
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
    fn a_task_that_refuses_for_a_missing_dependency_declares_it() {
        // The list is written out rather than derived, because what it pins is
        // a pairing no signature carries: a guard inside `run` and a
        // declaration the tree reads are two separate pieces of code saying one
        // thing. Every task here refuses at run time when its dependency is
        // absent, naming the task that supplies it; each must also say so
        // *before* Enter, which is the whole point of the mechanism.
        //
        // A task added to this list without a `requires` fails here. One that
        // grows a guard and is never added is the case this cannot catch —
        // which is why the list names the error each guard raises, so a reader
        // adding a tenth has somewhere obvious to look.
        let backend = crate::backend::for_family(Family::Debian);

        for id in [
            // Error::SshdAbsent, from `write_validated`
            "ssh.harden",
            "ssh.harden-strict",
            "ssh.change-port",
            "ssh.allow-users",
            // Error::WireguardNotConfigured
            "wireguard.add-peer",
            // Error::DockerEngineAbsent
            "docker.rootless",
            // Error::CaddyAbsent
            "caddy.validate",
            "caddy.security-headers",
            // Error::FirewallNotEnabled
            "firewall.manage-ports",
        ] {
            let task = find(id).unwrap_or_else(|| panic!("{id} must be in the tree"));

            assert!(
                !task.requires(backend.as_ref()).is_empty(),
                "{id} refuses at run time for a missing dependency, so it must \
                 declare one — otherwise the row is drawn exactly like one that \
                 would work"
            );
        }
    }

    #[test]
    fn a_requirement_points_at_a_task_that_exists() {
        // Same property the consequences have, and for the same reason: a
        // requirement naming a task is an instruction, and one naming something
        // that is not in the tree sends the operator looking for a row nobody
        // built. `mise.activate` is what that costs when nothing checks.
        let backend = crate::backend::for_family(Family::Debian);

        for task in all_tasks() {
            for requirement in task.requires(backend.as_ref()) {
                assert!(
                    find(requirement.task).is_some(),
                    "{} requires `{}`, which is not a task in the tree",
                    task.id(),
                    requirement.task
                );

                // A requirement must not name the task that states it: the
                // sentence it produces is "run X first", and a row telling the
                // operator to run itself first is one they cannot act on. This
                // is where a requirement and a consequence differ — a
                // consequence naming itself is honest, because it is reporting
                // something no task can do.
                assert_ne!(
                    requirement.task,
                    task.id(),
                    "{} requires itself, which names no step the operator can take",
                    task.id()
                );
            }
        }
    }

    #[test]
    fn a_consequence_points_at_a_task_that_exists() {
        // A consequence naming a task is an instruction: it tells the operator
        // what to run to resolve what the task just invalidated. One naming a
        // task that does not exist sends them looking through the tree for a
        // row that was never built — and nothing checked, so `mise.install`
        // pointed at `mise.activate` for as long as it shipped, with a unit
        // test asserting the broken pointer rather than the property.
        //
        // A task naming *itself* is allowed and is not an oversight: `gh` needs
        // a token this tool cannot supply, so the row that installs it is the
        // honest place to say so. What is refused is naming something that is
        // not a row at all.
        for task in all_tasks() {
            let backend = crate::backend::for_family(Family::Debian);

            for consequence in task.consequences(backend.as_ref(), &ParamValues::new()) {
                let Some(named) = consequence.task() else {
                    continue;
                };

                assert!(
                    find(named).is_some(),
                    "{} names `{named}`, which is not a task in the tree",
                    task.id()
                );
            }
        }
    }

    #[test]
    fn a_field_asking_for_the_ssh_port_reads_it_from_the_host() {
        // A compiled-in `22` is a safe *starting* value only where being wrong
        // fails loudly. `fail2ban.install` is where it does not: a jail pointed
        // at a port nothing listens on installs, writes its jail, starts its
        // service and reports success while protecting nothing, and no later
        // task disagrees with it. It shipped with a fixed `22` for as long as it
        // existed, on a host where `ssh.change-port` had moved the daemon.
        //
        // Asserted over the tree rather than on the one task, so a fourth field
        // asking the same question inherits the requirement rather than
        // repeating the defect.
        for task in all_tasks() {
            for param in task.params() {
                let asks_for_the_ssh_port = param.kind == params::ParamKind::Port
                    && (param.name.contains("ssh") || param.label.to_lowercase().contains("ssh"));

                if !asks_for_the_ssh_port {
                    continue;
                }

                assert_eq!(
                    param.live_default,
                    Some(params::LiveDefault::SshPort),
                    "{}'s `{}` asks for the SSH port and must read it from the host",
                    task.id(),
                    param.name
                );
            }
        }
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
    fn a_task_that_creates_an_account_does_not_offer_the_ones_that_exist() {
        // The mistake this pins, found on screen rather than by a test:
        // suggestions were derived from `ParamKind`, so `users.create` offered
        // all twenty-four accounts on the host — precisely the values it
        // refuses, since it fails with "account exists" on every one of them.
        //
        // Asserted against the task rather than against the field's kind: the
        // kind is the same one `ssh.authorize-key` uses and wants suggestions
        // for, which is the whole reason the two cannot share an answer.
        let creators = ["users.create", "wireguard.add-peer"];

        for task in all_tasks() {
            if !creators.contains(&task.id()) {
                continue;
            }

            for param in task.params() {
                assert_eq!(
                    param.suggestions,
                    None,
                    "{} offers the host's accounts for {}, which it cannot accept",
                    task.id(),
                    param.name
                );
            }
        }
    }

    #[test]
    fn a_field_naming_an_existing_account_offers_them() {
        // The other direction, so the fix cannot be "suggest nothing
        // anywhere": a field that names an account which must already exist is
        // exactly the case the host's answer is worth reading.
        //
        // `users.lock-root` was here and is deliberately not any more. It asked
        // for an account it only ever *checked* — never locked, never modified,
        // never recorded — which is a question the machine can answer for
        // itself, so it now scans instead of asking. A task with no fields has
        // no field to offer accounts for.
        let expected = [
            "users.set-shell",
            "ssh.authorize-key",
            "containers.rootless",
            "devtools.install",
        ];

        for task in all_tasks() {
            if !expected.contains(&task.id()) {
                continue;
            }

            assert!(
                task.params()
                    .iter()
                    .any(|param| param.suggestions == Some(params::Suggestions::Accounts)),
                "{} names an existing account and offers nothing for it",
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
                Node::Task(_) | Node::Reversible { .. } => 1,
                Node::Category(category) => category.task_count(),
            })
            .sum();

        // Rows, not tasks — the two stopped being the same number when the
        // tree gained reversible pairs, and the count beside a category is a
        // promise about how many rows opening it shows. Every pair contributes
        // one row and two tasks, so the difference is exactly the pair count;
        // asserting the relation rather than equality is what keeps this test
        // meaningful instead of merely passing.
        let pairs = count_pairs(&tree());
        assert_eq!(counted + pairs, all_tasks().len());
    }

    #[test]
    fn the_tree_holds_the_number_of_tasks_the_prose_claims() {
        // The sibling above asserts the *relation* between rows, pairs and
        // tasks, which holds at any size — so the tree grew from thirty-nine
        // tasks to fifty and eleven pairs to sixteen without anything
        // objecting, while eight comments and `CLAUDE.md` went on stating the
        // old figures. Prose is where those numbers are read, and prose is the
        // one thing no test was watching.
        //
        // So this pins the absolutes. It is *meant* to fail when a task is
        // added: the failure is the reminder to update the sentences that
        // quote it, and the message names them. `docs/cli.md` is already
        // covered in both directions by
        // `docs_cli_lists_exactly_the_tasks_the_tree_offers`; what this adds
        // is the count itself, which that test does not state.
        assert_eq!(
            all_tasks().len(),
            52,
            "the task count changed; update it in CLAUDE.md's task-areas entry \
             and in the comments that restate it — `rg 'fifty-two tasks'`"
        );
        assert_eq!(
            count_pairs(&tree()),
            17,
            "the reversible-row count changed; update it in CLAUDE.md and in \
             `tui/execution.rs`, `tui/app.rs` and `tasks/uninstall.rs`"
        );
    }

    /// Number of reversible pairs anywhere in a forest.
    fn count_pairs(nodes: &[Node]) -> usize {
        nodes
            .iter()
            .map(|node| match node {
                Node::Task(_) => 0,
                Node::Reversible { .. } => 1,
                Node::Category(category) => count_pairs(&category.children),
            })
            .sum()
    }
}
