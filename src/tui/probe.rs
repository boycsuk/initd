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

use crate::backend::{Capability, firewall_for};
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
    /// Whether the sending thread has been observed to have gone.
    ///
    /// Remembered rather than asked, because asking costs a `try_recv` and
    /// `try_recv` consumes — see [`drain`](Probe::drain).
    finished: bool,
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

        Self {
            results,
            finished: false,
        }
    }

    /// Takes whatever has been measured since the last call.
    ///
    /// Never blocks: this runs inside the event loop's tick, and a probe that
    /// stalled the loop would cost exactly what running the queries inline
    /// would have.
    pub fn drain(&mut self) -> Vec<Measurement> {
        let mut measured = Vec::new();

        loop {
            match self.results.try_recv() {
                Ok(measurement) => measured.push(measurement),
                Err(TryRecvError::Empty) => break,
                // Recorded here rather than answered by a second `try_recv`
                // later. `try_recv` *consumes*, so asking "are you finished?"
                // through one is asking a question that can eat the answer to
                // a different one: a measurement arriving between the last
                // drain and that call would be received, discarded, and its
                // row left at `Unknown` for the rest of the session.
                //
                // The window is narrow, and the case that lands in it is the
                // one that matters most: `refresh_presence_after` starts a
                // single-subject probe, so that thread sends once and returns
                // immediately — exactly the shape that races.
                Err(TryRecvError::Disconnected) => {
                    self.finished = true;
                    break;
                }
            }
        }

        measured
    }

    /// Whether the thread has finished sending.
    ///
    /// Reads what the last [`drain`](Self::drain) observed rather than asking
    /// the channel again, so answering it can never take a measurement out of
    /// the queue.
    pub const fn is_finished(&self) -> bool {
        self.finished
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
    // The one capability where "present" is not a question about software. `nft`
    // being installed says nothing about whether this host is filtering, and a
    // row that offered to *disable* a firewall on the strength of a package
    // being there would offer it on every Debian, none of which filter until
    // told to. What the row reports is the policy, so that is what is measured.
    if capability == Capability::Nftables {
        return match firewall_for(backend, executor) {
            Ok(Some(firewall)) => match firewall.state(executor) {
                Ok(state) if state.active => Presence::Present,
                Ok(_) => Presence::Absent,
                Err(_) => Presence::Unknown,
            },
            // Nothing installed is nothing filtering, which is the same answer
            // the row needs: it goes on offering to enable.
            Ok(None) => Presence::Absent,
            Err(_) => Presence::Unknown,
        };
    }

    if backend.has_package_for(capability) {
        let package = backend.package_for(capability);

        return match backend.packages().is_installed(executor, package) {
            Ok(true) => Presence::Present,
            // The package manager saying no is not the host saying no. A
            // capability whose program is on the machine by some other route —
            // a provider image, a different package, a build — is present, and
            // a row reporting it absent offers to install what is already
            // running. Reported for SSH, which a VPS ships preinstalled and
            // which the backend asks about by one package name.
            //
            // `Foreign` rather than `Present`, which is the distinction this
            // state exists for: the copy was not put there by this tool, so the
            // row keeps its forward verb and never offers to remove something
            // it did not install.
            Ok(false) => match program_for(capability) {
                Some(program) => match backend.binaries().location_of(executor, program) {
                    Ok(Some(found_at)) => Presence::Foreign { found_at },
                    Ok(None) => Presence::Absent,
                    Err(_) => Presence::Unknown,
                },
                None => Presence::Absent,
            },
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
        // The binary is `gh` on every family, including the two that package
        // it as `github-cli` — which is why this table exists separately from
        // the package names.
        Capability::GithubCli => Some("gh"),
        // Asked by name rather than by package, because the package is not the
        // question on every family: Alpine's `sysctl` is a busybox applet, so a
        // host with no `procps` of any spelling still has the binary. Asking
        // the executable is the one question true on all five.
        Capability::Sysctl => Some("sysctl"),
        // The daemon rather than the package, for a reason the package name
        // cannot cover: a provider's image ships SSH already running, and it
        // need not have arrived as the one package this backend asks about.
        // Reported as the tree not detecting the system's own SSH — true, and
        // it was asking the wrong question.
        //
        // `sshd` rather than `ssh`: the client is a separate package on RHEL,
        // which installs `openssh-server` alone, so asking for the client
        // answers "absent" on a host plainly serving SSH.
        Capability::Ssh => Some("sshd"),
        // Everything else is packaged on every family this tool supports, so a
        // host that has no package for it has no other way to have got it
        // either. Written as an exhaustive match rather than a catch-all: a
        // future capability installed from a release must decide here, and
        // silence would leave its row permanently offering to install.
        Capability::Wireguard
        | Capability::DockerRootless
        | Capability::Nftables
        | Capability::Fish
        // The one capability all five families package under one name.
        | Capability::Git
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
            // A lone task has no verb to choose, and for a long time that was
            // taken to mean it had nothing worth asking either. It does: a row
            // with one verb can still say whether the thing is already there,
            // and `ssh.install` is the case that surfaced it — reported as not
            // detecting an SSH server that was installed, because the tree
            // asked the host nothing and the answer arrived only once the task
            // had been run.
            //
            // It stays opt-in through `subject()`, so this costs one query per
            // task that has something to report rather than one per task.
            Node::Task(task) => {
                if let Some(capability) = task.subject() {
                    out.push((task.id(), capability));
                }
            }
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
    fn an_ssh_server_the_package_manager_did_not_install_is_still_found() {
        // Reported as the tree not detecting the system's own SSH. It asked
        // `dpkg-query` about `openssh-server` and stopped there, so a daemon
        // that arrived by any other route — a provider's image, a different
        // package, a build — read as absent and the row offered to install what
        // was already running.
        //
        // Two replies: the package manager says no, then `command -v sshd`
        // answers with a path.
        let mock = crate::exec::mock::MockExecutor::with_replies([
            crate::exec::mock::Reply::failure(1, ""),
            crate::exec::mock::Reply::ok("/usr/sbin/sshd\n"),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        let presence = measure(&mock, backend.as_ref(), Capability::Ssh);

        // `Foreign`, not `Present`: this tool did not install that copy, so the
        // row keeps its forward verb rather than offering to remove something
        // it never put there. Removing the SSH server is the one operation here
        // with no way back, which makes the distinction load-bearing rather
        // than tidy.
        assert!(
            matches!(presence, Presence::Foreign { .. }),
            "a daemon found outside the package manager must be reported as \
             foreign: {presence:?}"
        );
        assert!(
            !presence.calls_for_the_inverse(),
            "and must not offer to uninstall it"
        );
    }

    #[test]
    fn a_host_with_no_ssh_at_all_still_reads_as_absent() {
        // The other direction, and the reason the lookup is not simply assumed
        // to find something: a host with neither the package nor the binary
        // must go on offering to install.
        let mock = crate::exec::mock::MockExecutor::with_replies([
            crate::exec::mock::Reply::failure(1, ""),
            crate::exec::mock::Reply::failure(1, ""),
        ]);
        let backend = crate::backend::for_family(crate::distro::Family::Debian);

        assert_eq!(
            measure(&mock, backend.as_ref(), Capability::Ssh),
            Presence::Absent
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
    fn a_measurement_that_arrives_as_the_thread_exits_is_not_lost() {
        // `is_finished` used to answer through its own `try_recv`, which
        // consumes: a measurement sent between the last drain and that call
        // was received, discarded, and its row left at `Unknown` for the rest
        // of the session.
        //
        // The shape reproduced here is the one that matters. Every refresh
        // after a task is a single-subject probe, so the thread sends once and
        // returns immediately — the send and the disconnect land together, and
        // the drain sees both in one pass.
        let (sender, results) = channel();
        let mut probe = Probe {
            results,
            finished: false,
        };

        // The tick that finds nothing: the thread has not answered yet, so the
        // drain is empty and the probe is not finished. This is the call the
        // lost measurement used to arrive *after*.
        assert!(probe.drain().is_empty());
        assert!(!probe.is_finished(), "nothing has been measured yet");

        sender
            .send(Measurement {
                forward_id: "caddy.install",
                presence: Presence::Present,
            })
            .expect("the receiver is alive");
        drop(sender);

        // Ask in the order the event loop asks, which is what makes the defect
        // reachable: `poll_probe` drains and *then* asks whether to drop the
        // probe. With `is_finished` implemented as its own `try_recv`, the
        // first of those two calls is the one that lost the measurement.
        //
        // Interleaved deliberately rather than drained first: reading the
        // whole channel and then asking is the one order the old code
        // survived, and a test that only exercised it would have passed
        // against the bug.
        let finished_first = probe.is_finished();
        let measured = probe.drain();

        assert_eq!(
            measured.len(),
            1,
            "the measurement must survive being asked whether the probe ended"
        );
        assert_eq!(measured[0].forward_id, "caddy.install");
        assert!(
            probe.is_finished() || finished_first,
            "the disconnect must be observed"
        );
        assert!(
            probe.drain().is_empty(),
            "a finished probe has nothing left to give"
        );
    }

    #[test]
    fn both_halves_of_a_pair_name_the_row_they_change() {
        // The forward half declaring `affects` is not enough, and this is the
        // omission that made it obvious: `firewall.disable` did not, so after
        // disabling the firewall the interface re-probed nothing and the row
        // went on offering to disable a firewall that was already off. It
        // corrected itself on the next start, which is the worst kind of wrong
        // — right often enough that nobody reports it as a bug in the tree.
        //
        // Asserted over both halves rather than trusting a convention: the
        // default is an empty list, so an inverse gets this wrong by saying
        // nothing at all.
        let tree = crate::tasks::tree();
        let mut pairs = Vec::new();
        collect_pairs(&tree, &mut pairs);

        for (forward, inverse) in pairs {
            for (task, role) in [(forward, "forward"), (inverse, "inverse")] {
                assert!(
                    !task.affects().is_empty(),
                    "the {role} half of the pair, {}, must name the row its \
                     success changes, or the interface never re-measures it",
                    task.id()
                );
            }
        }
    }

    /// Both halves of every reversible pair in a forest.
    fn collect_pairs<'a>(
        nodes: &'a [Node],
        out: &mut Vec<(&'a dyn crate::tasks::Task, &'a dyn crate::tasks::Task)>,
    ) {
        for node in nodes {
            match node {
                Node::Task(_) => {}
                Node::Reversible { forward, inverse } => {
                    out.push((forward.as_ref(), inverse.as_ref()));
                }
                Node::Category(category) => collect_pairs(&category.children, out),
            }
        }
    }

    #[test]
    fn every_reversible_row_declares_what_to_measure() {
        // A pair whose forward task returns `None` from `subject` is a row that
        // can never learn which verb it should show: the probe would skip it
        // and it would offer to install for the whole session, including on a
        // host where the subject is plainly present. Silent, and indisputably
        // wrong — so the tree is walked rather than trusted.
        let tree = crate::tasks::tree();
        let mut pairs = Vec::new();
        collect_pair_ids(&tree, &mut pairs);

        let measured: Vec<&str> = subjects_in(&tree).iter().map(|(id, _)| *id).collect();

        // Every pair is measured. Compared by id rather than by count, which is
        // what the assertion used to do: lone tasks may now declare a subject
        // too, so a total that happened to match would no longer prove that the
        // *pairs* were the things in it.
        for id in &pairs {
            assert!(
                measured.contains(id),
                "{id} is a reversible pair and must declare a subject: {measured:?}"
            );
        }
    }

    #[test]
    fn a_one_verb_task_may_declare_a_subject_too() {
        // `ssh.install` has no inverse — removing the SSH server over SSH is
        // the one thing this tool refuses to offer — and for as long as the
        // probe skipped lone tasks, its row asked the host nothing. Reported as
        // the tool not detecting an SSH server that was plainly installed: the
        // answer existed and arrived only once the task had been run.
        let measured: Vec<&str> = subjects_in(&crate::tasks::tree())
            .iter()
            .map(|(id, _)| *id)
            .collect();

        assert!(
            measured.contains(&"ssh.install"),
            "a lone task that declares a subject must be measured: {measured:?}"
        );
    }

    /// Collects the ids of every reversible pair's forward task.
    fn collect_pair_ids(nodes: &[Node], out: &mut Vec<&'static str>) {
        for node in nodes {
            match node {
                Node::Task(_) => {}
                Node::Reversible { forward, .. } => out.push(forward.id()),
                Node::Category(category) => collect_pair_ids(&category.children, out),
            }
        }
    }
}
