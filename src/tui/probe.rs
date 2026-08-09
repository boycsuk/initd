//! Asking the host what it already has, without blocking the interface.
//!
//! A reversible row shows one of two verbs, and which one is a fact about this
//! machine rather than about the tree. Somebody has to ask, and where that
//! asking happens is the whole of this module's design.
//!
//! **Not at render time.** `render::row` is `&App`-shaped and holds no
//! executor by construction, and the rule predates this module: running a
//! command on every arrow press puts the executor in the path of a keystroke,
//! which is why form suggestions are collected once and handed in rather than
//! looked up as the cursor moves.
//!
//! **Not at startup, inline.** The queries are unprivileged — `dpkg-query`,
//! `pacman -Q`, `apk info -e` and `rpm -q` all read a local database that is
//! world-readable, and `command -v` asks the shell — so none of them prompts.
//! They are not free: eleven `fork`/`exec` in series cost between 200 and 900
//! milliseconds on a slow VPS, with `rpm -q` the worst of them because opening
//! the rpm database dominates. That is a visibly slower start, paid before the
//! first frame, on exactly the constrained hardware this tool is most likely
//! to administer.
//!
//! So: a thread, a channel, and rows that begin as [`Presence::Unknown`] and
//! settle over the next few hundred milliseconds. Unknown draws the forward
//! verb, which is the safe half of the guess — offering to install something
//! already present wastes a keystroke and changes nothing, while offering to
//! remove something absent is a row that does nothing and explains nothing.
//!
//! Shaped like [`super::worker`] rather than reusing it. `Running` is a single
//! `Option` pinned by a test, and its `Update::Finished(Result<Outcome>)` is
//! the wrong shape for a probe, which produces a map rather than an outcome.
//! Widening that enum would make every arm of `poll_running` handle a variant
//! that cannot occur while a task runs.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::thread;

use crate::backend::Capability;
use crate::distro::Distro;
use crate::tasks::Node;

/// What the host said about one reversible pair.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Presence {
    /// Measured: the subject is installed.
    Present,
    /// Measured: it is not.
    Absent,
    /// Present, but not where this tool would have put it.
    ///
    /// Only a binary-installed capability can be in this state: a package is
    /// either registered with the package manager or it is not, while a
    /// program on `PATH` may have come from `cargo install`, from a vendor
    /// script, or from an administrator with a `curl`. The row shows the
    /// *forward* verb for it, because this tool has installed nothing here and
    /// the copy that exists is not its to remove.
    Foreign { found_at: String },
    /// Never measured, or the question failed.
    ///
    /// The starting state of every row and the resting state of any whose
    /// probe could not answer. Draws the forward verb, which is the half of
    /// the guess that costs a keystroke rather than confusion.
    #[default]
    Unknown,
}

impl Presence {
    /// Whether the row should offer to undo rather than to do.
    ///
    /// Only [`Present`](Self::Present) does. `Foreign` deliberately does not,
    /// which is the whole reason it is a separate state rather than being
    /// folded into `Present`.
    pub fn calls_for_the_inverse(&self) -> bool {
        matches!(self, Self::Present)
    }

    /// Whether the host has answered about this row yet.
    pub fn is_settled(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// What the last probe measured, keyed by the forward task's id.
///
/// Keyed on the forward id rather than on the capability because the row is
/// what is being described, and two rows could name one capability.
#[derive(Debug, Default)]
pub struct InstalledState {
    measured: HashMap<&'static str, Presence>,
}

impl InstalledState {
    /// What is known about the pair whose forward task has this id.
    pub fn of(&self, forward_id: &str) -> &Presence {
        self.measured.get(forward_id).unwrap_or(&Presence::Unknown)
    }

    /// Records what a probe measured.
    pub fn record(&mut self, forward_id: &'static str, presence: Presence) {
        self.measured.insert(forward_id, presence);
    }

    /// Forgets what is known about one pair, so the row falls back to its
    /// forward verb until a fresh probe answers.
    ///
    /// Used when a task finishes: the answer from before it ran describes a
    /// machine that no longer exists, and showing it until the new probe lands
    /// is showing something known to be stale.
    pub fn forget(&mut self, forward_id: &str) {
        self.measured.remove(forward_id);
    }
}

/// One measurement, on its way back to the interface.
#[derive(Debug)]
pub struct Measurement {
    /// The forward task whose row this describes.
    pub forward_id: &'static str,
    pub presence: Presence,
}

/// A probe running on its own thread.
pub struct Probe {
    results: Receiver<Measurement>,
}

impl Probe {
    /// Measures each named pair, on a thread of its own.
    ///
    /// Takes the ids and their subjects rather than the tree, because the tree
    /// is not `Send` and rebuilding it here would mean this module deciding
    /// which rows are reversible — a decision that belongs to the tree.
    ///
    /// Takes the whole `Distro` for the same reason [`super::worker::Running`]
    /// does: the thread outlives this call and builds its own backend, since
    /// neither `Backend` nor `Executor` crosses a thread boundary.
    pub fn start(distro: Distro, subjects: Vec<(&'static str, Capability)>) -> Self {
        let (sender, results) = channel();

        thread::spawn(move || {
            let backend = crate::backend::for_distro(&distro);
            // No broker, no cancel token, no observer. Every query here is
            // unprivileged, and without a broker a privileged one fails rather
            // than waiting for a terminal nobody will hand over — which is the
            // guarantee wanted: a probe must never raise a password prompt
            // over an operator who is reading the tree.
            let executor = crate::exec::local::LocalExecutor::new(crate::exec::privilege::detect());

            for (forward_id, capability) in subjects {
                let presence = measure(&executor, backend.as_ref(), capability);

                // A send failure means the interface moved on — a task was
                // started, or the tool is exiting. The loop stops rather than
                // measuring the rest for nobody.
                if sender
                    .send(Measurement {
                        forward_id,
                        presence,
                    })
                    .is_err()
                {
                    return;
                }
            }
        });

        Self { results }
    }

    /// Takes whatever has been measured since the last call.
    ///
    /// Never blocks: this runs inside the event loop's tick, and a probe that
    /// stalled the loop would cost exactly what running the queries inline
    /// would have.
    pub fn drain(&mut self) -> Vec<Measurement> {
        let mut measured = Vec::new();

        // Both ends of the channel stop the loop the same way, unlike the
        // worker's drain: a thread that died mid-task has to be reported,
        // while a probe that stopped early just leaves rows at `Unknown` —
        // a state the interface already draws correctly.
        while let Ok(measurement) = self.results.try_recv() {
            measured.push(measurement);
        }

        measured
    }

    /// Whether the thread has finished sending.
    pub fn is_finished(&self) -> bool {
        matches!(self.results.try_recv(), Err(TryRecvError::Disconnected))
    }
}

/// Asks the host about one capability.
///
/// The order of the two questions is what keeps a foreign copy safe. A
/// capability the family packages is answered by the package manager alone; one
/// it does not is answered by where the binary actually is, and "somewhere
/// else" is reported as such rather than as installed.
fn measure(
    executor: &dyn crate::exec::Executor,
    backend: &dyn crate::backend::Backend,
    capability: Capability,
) -> Presence {
    if backend.has_package_for(capability) {
        let package = backend.package_for(capability);

        return match backend.packages().is_installed(executor, package) {
            Ok(true) => Presence::Present,
            Ok(false) => Presence::Absent,
            // A failed query is not an answer. Left `Unknown` rather than
            // guessed at, so the row keeps offering to install — the outcome
            // that is harmless when wrong.
            Err(_) => Presence::Unknown,
        };
    }

    let Some(program) = program_for(capability) else {
        return Presence::Unknown;
    };

    match backend.binaries().is_installed_here(executor, program) {
        Ok(true) => Presence::Present,
        Ok(false) => match backend.binaries().location_of(executor, program) {
            Ok(Some(found_at)) => Presence::Foreign { found_at },
            Ok(None) => Presence::Absent,
            Err(_) => Presence::Unknown,
        },
        Err(_) => Presence::Unknown,
    }
}

/// The program a binary-installed capability puts on the machine.
///
/// Needed because `is_installed_here` takes the executable's name while the
/// rest of the backend speaks in capabilities, and the two differ: the
/// capability is `Capability::Rust` where the binary is `rustup`.
///
/// `&'static str` all the way down, which is what stops a value from a form
/// ever reaching the `sh -c` that `Command::locating` builds.
fn program_for(capability: Capability) -> Option<&'static str> {
    match capability {
        Capability::Zellij => Some("zellij"),
        Capability::Mise => Some("mise"),
        Capability::Caddy => Some("caddy"),
        Capability::Rust => Some("rustup"),
        // Everything else is packaged on every family this tool supports, so a
        // host that has no package for it has no other way to have got it
        // either. Written as an exhaustive match rather than a catch-all: a
        // future capability installed from a release must decide here, and
        // silence would leave its row permanently offering to install.
        Capability::Ssh
        | Capability::Wireguard
        | Capability::DockerRootless
        | Capability::Nftables
        | Capability::Fish
        | Capability::Fail2ban
        | Capability::Crowdsec
        | Capability::UnattendedUpgrades => None,
    }
}

/// Which half of a node the interface should act on and draw.
///
/// The one place that choice is made. Drawing and running resolve a row
/// through this same function, because a row that renders "Uninstall Caddy"
/// and starts `caddy.install` when pressed is the worst outcome this feature
/// can produce — and two copies of the rule is how that happens.
pub fn task_for<'a>(node: &'a Node, state: &InstalledState) -> Option<&'a dyn crate::tasks::Task> {
    match node {
        Node::Task(task) => Some(task.as_ref()),
        Node::Reversible { forward, inverse } => {
            if state.of(forward.id()).calls_for_the_inverse() {
                Some(inverse.as_ref())
            } else {
                Some(forward.as_ref())
            }
        }
        Node::Category(_) => None,
    }
}

/// Every reversible pair in a forest, as the ids and subjects a probe needs.
///
/// Walks the tree once at startup rather than being a list kept beside it: a
/// pair added to the tree is measured without anything else being edited.
pub fn subjects_in(nodes: &[Node]) -> Vec<(&'static str, Capability)> {
    let mut found = Vec::new();
    collect_subjects(nodes, &mut found);
    found
}

/// Appends the subjects under `nodes` to `out`.
fn collect_subjects(nodes: &[Node], out: &mut Vec<(&'static str, Capability)>) {
    for node in nodes {
        match node {
            // A lone task has no verb to choose, so nothing about it is worth
            // a command at startup even if it declared a subject.
            Node::Task(_) => {}
            Node::Reversible { forward, .. } => {
                if let Some(capability) = forward.subject() {
                    out.push((forward.id(), capability));
                }
            }
            Node::Category(category) => collect_subjects(&category.children, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn an_unmeasured_row_offers_to_install() {
        // The starting state of every row, and the resting state of one whose
        // probe failed. Offering to install what is already there wastes a
        // keystroke; offering to remove what is absent is a row that does
        // nothing and explains nothing.
        let state = InstalledState::default();

        assert_eq!(*state.of("caddy.install"), Presence::Unknown);
        assert!(!state.of("caddy.install").calls_for_the_inverse());
    }

    #[test]
    fn a_packaged_capability_is_answered_by_the_package_manager() {
        let present = MockExecutor::with_replies([Reply::ok("install ok installed")]);
        let backend = for_family(Family::Debian);

        assert_eq!(
            measure(&present, backend.as_ref(), Capability::Fail2ban),
            Presence::Present
        );

        let absent = MockExecutor::with_replies([Reply::failure(1, "")]);

        assert_eq!(
            measure(&absent, backend.as_ref(), Capability::Fail2ban),
            Presence::Absent
        );
    }

    #[test]
    fn a_binary_somebody_else_installed_is_reported_as_theirs() {
        // The failure the whole `Foreign` state exists for: Debian packages no
        // zellij, so the question falls to the binary installer, and a copy in
        // ~/.cargo/bin is not this tool's to remove. The row must keep saying
        // "install".
        let mock = MockExecutor::with_replies([
            // `test -f /usr/local/bin/zellij` — nothing there.
            Reply::failure(1, ""),
            // `command -v zellij` — but the shell finds one elsewhere.
            Reply::ok("/home/op/.cargo/bin/zellij\n"),
        ]);

        let presence = measure(
            &mock,
            for_family(Family::Debian).as_ref(),
            Capability::Zellij,
        );

        assert_eq!(
            presence,
            Presence::Foreign {
                found_at: "/home/op/.cargo/bin/zellij".to_owned()
            }
        );
        assert!(
            !presence.calls_for_the_inverse(),
            "a copy this tool did not install must not be offered for removal"
        );
    }

    #[test]
    fn this_tools_own_copy_is_offered_for_removal() {
        // `test -f /usr/local/bin/zellij` succeeds, so no lookup follows.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        let presence = measure(
            &mock,
            for_family(Family::Debian).as_ref(),
            Capability::Zellij,
        );

        assert_eq!(presence, Presence::Present);
        assert!(presence.calls_for_the_inverse());
    }

    #[test]
    fn a_capability_the_family_packages_never_asks_the_shell() {
        // Arch packages zellij, so the question is the package manager's and
        // the binary installer is not consulted at all — asking both would
        // report a package-managed program as foreign the moment it was
        // installed somewhere other than /usr/local/bin, which is everywhere.
        let mock = MockExecutor::with_replies([Reply::ok("zellij 0.44.0-1")]);

        assert_eq!(
            measure(&mock, for_family(Family::Arch).as_ref(), Capability::Zellij),
            Presence::Present
        );
        assert_eq!(mock.recorded_lines(), ["pacman -Q zellij"]);
    }

    #[test]
    fn a_query_that_could_not_run_never_offers_to_uninstall() {
        // `is_installed` folds "not installed" and "the query failed" into one
        // `false`, because a package manager reports both as a non-zero exit
        // and neither backend can tell them apart. So a probe that could not
        // ask lands on `Absent` rather than `Unknown`.
        //
        // Harmless, and worth pinning for what it guarantees rather than for
        // what it distinguishes: both roads lead to the forward verb, so a
        // machine whose package manager is missing offers to install rather
        // than offering to remove something nobody confirmed is there.
        let mock = MockExecutor::with_replies([Reply::failure(127, "dpkg-query: not found")]);

        let presence = measure(
            &mock,
            for_family(Family::Debian).as_ref(),
            Capability::Fail2ban,
        );

        assert!(
            !presence.calls_for_the_inverse(),
            "a question that could not be asked must not produce an uninstall row"
        );
    }

    #[test]
    fn what_a_finished_task_changed_is_forgotten_rather_than_kept() {
        // The answer from before a task ran describes a machine that no longer
        // exists. Showing it until the fresh probe lands is showing something
        // known to be stale.
        let mut state = InstalledState::default();
        state.record("caddy.install", Presence::Absent);

        state.forget("caddy.install");

        assert_eq!(*state.of("caddy.install"), Presence::Unknown);
    }

    /// A pair built from two real tasks, so the resolution can be exercised
    /// before any inverse exists in the tree.
    ///
    /// Which two does not matter — nothing here runs them — only that they are
    /// distinguishable by id.
    fn a_pair() -> Node {
        Node::Reversible {
            forward: crate::tasks::find("caddy.install").expect("caddy.install must exist"),
            inverse: crate::tasks::find("caddy.validate").expect("caddy.validate must exist"),
        }
    }

    #[test]
    fn a_row_offers_the_inverse_only_once_the_host_has_confirmed_the_subject() {
        let pair = a_pair();
        let mut state = InstalledState::default();

        // Unmeasured, then measured absent: the forward half both times.
        assert_eq!(
            task_for(&pair, &state).map(crate::tasks::Task::id),
            Some("caddy.install")
        );

        state.record("caddy.install", Presence::Absent);
        assert_eq!(
            task_for(&pair, &state).map(crate::tasks::Task::id),
            Some("caddy.install")
        );

        state.record("caddy.install", Presence::Present);
        assert_eq!(
            task_for(&pair, &state).map(crate::tasks::Task::id),
            Some("caddy.validate")
        );
    }

    #[test]
    fn a_foreign_copy_leaves_the_row_on_its_forward_verb() {
        // The state exists to be distinguishable from `Present` here and
        // nowhere else: folded into it, the row would offer to remove a binary
        // this tool never installed.
        let pair = a_pair();
        let mut state = InstalledState::default();

        state.record(
            "caddy.install",
            Presence::Foreign {
                found_at: "/usr/bin/caddy".to_owned(),
            },
        );

        assert_eq!(
            task_for(&pair, &state).map(crate::tasks::Task::id),
            Some("caddy.install")
        );
    }

    #[test]
    fn every_reversible_row_declares_what_to_measure() {
        // A pair whose forward task returns `None` from `subject` is a row that
        // can never learn which verb it should show: the probe would skip it
        // and it would offer to install for the whole session, including on a
        // host where the subject is plainly present. Silent, and indisputably
        // wrong — so the tree is walked rather than trusted.
        let mut pairs = 0;
        count_pairs(&crate::tasks::tree(), &mut pairs);

        assert_eq!(
            subjects_in(&crate::tasks::tree()).len(),
            pairs,
            "every reversible pair must declare a subject to measure"
        );
    }

    /// Counts reversible pairs in a forest, however deeply nested.
    fn count_pairs(nodes: &[Node], out: &mut usize) {
        for node in nodes {
            match node {
                Node::Task(_) => {}
                Node::Reversible { .. } => *out += 1,
                Node::Category(category) => count_pairs(&category.children, out),
            }
        }
    }
}
