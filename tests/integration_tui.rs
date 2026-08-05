//! The interface, driven as a user drives it.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`. Needs the
//! same privileged container the systemd scenarios do, and skips where the
//! host will not grant it.
//!
//! The interface has rendering tests against a `TestBackend` buffer, which
//! check that a given state draws the right cells. What they cannot check is
//! the part that only exists at runtime: that keys move between states, that a
//! destructive task actually stops for confirmation, and above all that
//! `Revert::apply` puts the file back.
//!
//! # Why Revert is only reachable here
//!
//! There is no `initd revert` subcommand — deliberately, since a revert
//! without a verification window is the kind of operation the CLI keeps out.
//! So the interface is the only route to it, and its three unit tests run
//! against a mock that cannot say whether the restored file is the one that
//! was there before.
//!
//! It also needs systemd: without it `ssh.harden` writes the file, fails at
//! `systemctl reload`, and the task ends FAILED. A failed task offers nothing
//! to keep or revert, so the window never opens at all.

mod common;

use common::tui::Tui;

/// The state the interface reports while a change is applied but not kept.
const VERIFY: &str = "VERIFY";

/// How long to wait for the verification window to open.
///
/// Deliberately well under the window's own 60-second countdown
/// (`src/tui/verify.rs`), which reverts on its own when it expires. A scenario
/// that waited longer could watch the window it was waiting for close, then
/// press `K` into a state that no longer accepts it and report the change as
/// not kept — a timing artefact wearing the costume of a bug.
const WINDOW_OPENS_WITHIN: u32 = 20;

/// Starts the interface or skips the test.
macro_rules! tui {
    ($image:expr, $label:expr, $prepare:expr) => {
        match Tui::start($image, $label, $prepare) {
            Some(tui) => tui,
            None => {
                eprintln!("skipping: this host will not boot a privileged systemd container");
                return;
            }
        }
    };
}

/// Authorises a key for root, so the lockout guard permits hardening, and
/// records the configuration for later comparison.
///
/// The daemon is waited for rather than assumed. `systemctl start` returns once
/// systemd has accepted the job, not once the unit is up, and `ssh.harden`
/// reloads — which systemd refuses outright on an inactive unit, with
/// `sshd.service is not active, cannot reload`. That fails the task, and a
/// failed task offers nothing to keep or revert, so the verification window
/// these scenarios exist to observe never opens. It surfaced on RHEL, where
/// installing the package leaves the unit enabled but stopped rather than
/// started, but the race was there for any family whose daemon was slow enough.
const PREPARE_FOR_HARDENING: &str = concat!(
    "initd authorize-key root 'ssh-ed25519 ",
    "AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd",
    "' >/dev/null 2>&1; \
     systemctl start ssh sshd >/dev/null 2>&1; \
     for _ in $(seq 30); do \
       systemctl is-active --quiet ssh sshd && break; \
       sleep 0.2; \
     done; \
     cp /etc/ssh/sshd_config /tmp/before"
);

/// Walks from the root of the tree to the hardening task and runs it.
///
/// Four levels down — Remote Access, SSH, Configuration — then Enter to run.
/// Written once because every verification-window scenario needs it, and a
/// scenario that got the path wrong would sit on the wrong task and still
/// look plausible.
///
/// The leading `Down` is Identity & Access, which sorts above Remote Access:
/// the tree grew that area after these scenarios were written, and the title
/// assertion below is what turned the silent misnavigation into a failure that
/// named itself.
fn run_hardening(tui: &Tui) {
    tui.press("Down"); // Identity & Access -> Remote Access
    tui.press("Enter"); // Remote Access
    tui.press("Enter"); // SSH
    tui.press("Down"); // Service -> Configuration
    tui.press("Enter");

    // The path is positional — one Down from the top of SSH, then the first
    // row — so reordering the tree would silently point these scenarios at a
    // different task, and one that also opens a dialog would let them keep
    // passing. Checking the title costs nothing and turns that into a failure
    // that names itself.
    let screen = tui.screen();
    assert!(
        screen.contains("Harden the SSH configuration"),
        "navigation must land on the hardening task; the tree may have been \
         reordered: {screen}"
    );

    tui.press("Enter"); // run it
}

/// Answers the destructive-operation dialog with Yes.
///
/// `No` holds the focus when the dialog opens — the safe default for something
/// that warns it can lock you out of a server — so Tab is required, and a
/// scenario that pressed Enter alone would quietly cancel and then assert
/// against a system nothing had happened to.
fn confirm_dialog(tui: &Tui) {
    tui.press("Tab");
    tui.press("Enter");
}

for_each_image! {
    /// The interface must start and draw its tree.
    ///
    /// The control for every scenario below: they all begin by navigating, and
    /// a failure to start would look like a navigation failure.
    fn the_interface_starts_and_draws_the_task_tree(image) {
        let tui = tui!(image, "start", "true");

        let screen = tui.screen();

        assert!(
            screen.contains("initd"),
            "the header must name the program: {screen}"
        );
        assert!(
            screen.contains("Remote Access"),
            "the task tree must be on screen: {screen}"
        );
    }

    /// Enter drills into a category and the breadcrumb follows.
    ///
    /// The tree is navigated one level at a time, and the panel title is the
    /// path — so the title is what proves the interface moved rather than
    /// merely redrew.
    fn enter_opens_a_category_and_the_breadcrumb_follows(image) {
        let tui = tui!(image, "drill", "true");

        // Identity & Access sorts first, so one Down reaches Remote Access.
        tui.press("Down");
        tui.press("Enter");
        let after_one = tui.screen();
        assert!(
            after_one.contains("Remote Access"),
            "the breadcrumb must name the level entered: {after_one}"
        );

        tui.press("Enter");
        let after_two = tui.screen();
        assert!(
            after_two.contains("SSH"),
            "a second level must open too: {after_two}"
        );
    }

    /// Esc goes back rather than quitting.
    ///
    /// A deliberate decision: overshooting by one level must not drop an
    /// administrator out of the program mid-session. Only a scenario that
    /// actually presses it can tell the two apart.
    fn escape_returns_to_the_parent_instead_of_quitting(image) {
        let tui = tui!(image, "escape", "true");

        // Down first so the descent starts from Remote Access, which has a
        // second level to overshoot into — the point of the scenario is two
        // levels down and two back.
        tui.press("Down");
        tui.press("Enter");
        tui.press("Enter");
        tui.press("Escape");
        tui.press("Escape");

        assert!(
            tui.is_running(),
            "Esc must not quit the program"
        );
        assert!(
            tui.screen().contains("Remote Access"),
            "Esc must return to the root of the tree: {}",
            tui.screen()
        );
    }

    /// A destructive task must stop and ask.
    ///
    /// The tree has no other guard: without the dialog, one Enter on a
    /// highlighted row would harden a live server.
    fn a_destructive_task_asks_before_it_runs(image) {
        let tui = tui!(image, "confirm", PREPARE_FOR_HARDENING);

        run_hardening(&tui);

        let screen = tui.screen();
        assert!(
            screen.contains("Yes") && screen.contains("No"),
            "a confirmation dialog must be on screen: {screen}"
        );
        assert!(
            screen.contains("lock you out"),
            "the dialog must state the risk: {screen}"
        );

        // Nothing may have happened yet.
        let applied = tui.exec("grep -c '^PermitRootLogin no' /etc/ssh/sshd_config || true");
        assert!(
            applied.trim().starts_with('0'),
            "the task must not have run before confirmation: {applied}"
        );
    }

    /// Confirming applies the change and opens the verification window.
    ///
    /// The window is the anti-lockout mechanism: the change is live but not
    /// yet kept, and an administrator who cannot get back in does nothing and
    /// gets it back. This is the state a mock cannot produce.
    fn confirming_applies_the_change_and_holds_it_open(image) {
        let tui = tui!(image, "window", PREPARE_FOR_HARDENING);

        run_hardening(&tui);
        confirm_dialog(&tui);

        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open: {}",
            tui.status()
        );

        let status = tui.status();
        assert!(
            status.contains("K keep") && status.contains("R revert"),
            "the window must offer both answers: {status}"
        );

        let applied = tui.exec("grep -c '^PermitRootLogin no' /etc/ssh/sshd_config");
        assert!(
            applied.trim().starts_with('1'),
            "the change must be live while the window is open: {applied}"
        );
    }

    /// R restores the configuration that was there before.
    ///
    /// The scenario this whole binary exists for. `Revert::apply` is reachable
    /// from nowhere else, and its unit tests assert on the commands a mock
    /// recorded — which cannot say whether the file that came back is the one
    /// that went away. This compares them.
    fn reverting_restores_the_previous_configuration(image) {
        let tui = tui!(image, "revert", PREPARE_FOR_HARDENING);

        run_hardening(&tui);
        confirm_dialog(&tui);
        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open before it can be declined: {}",
            tui.status()
        );

        tui.type_char('R');

        assert!(
            tui.wait_for("reverted", WINDOW_OPENS_WITHIN),
            "the interface must report the revert: {}",
            tui.status()
        );

        assert!(
            tui.files_match("/tmp/before", "/etc/ssh/sshd_config"),
            "the configuration must be byte-for-byte what it was; still set: {}",
            tui.exec("grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config")
        );
    }

    /// K keeps the change.
    ///
    /// The other half, and the one that proves the window is a real choice
    /// rather than a delayed rollback: after keeping, the change must survive.
    fn keeping_leaves_the_change_in_place(image) {
        let tui = tui!(image, "keep", PREPARE_FOR_HARDENING);

        run_hardening(&tui);
        confirm_dialog(&tui);
        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open: {}",
            tui.status()
        );

        tui.type_char('K');

        let applied = tui.exec("grep -c '^PermitRootLogin no' /etc/ssh/sshd_config");
        assert!(
            applied.trim().starts_with('1'),
            "the kept change must survive: {applied}"
        );

        // The hazard is sharper here than in the revert scenario: this asserts
        // the files *differ*, which a missing comparison tool satisfies for
        // free. It passed on Arch that way twice.
        assert!(
            !tui.files_match("/tmp/before", "/etc/ssh/sshd_config"),
            "keeping must not put the previous configuration back"
        );
    }

    /// The comparison the revert and keep scenarios rest on must work.
    ///
    /// Both read `files_match`, and a broken one is invisible in either
    /// direction: always-false passes the keep scenario for free, always-true
    /// passes the revert scenario. This pins it to a copy and a change, so a
    /// comparison that cannot tell them apart fails here first and by name —
    /// which is what a missing `diff`, and then a missing `cmp`, did not.
    fn the_file_comparison_distinguishes_identical_from_changed(image) {
        let tui = tui!(image, "compare", "true");

        tui.exec("printf 'one\\ntwo\\n' > /tmp/a; cp /tmp/a /tmp/b");
        assert!(
            tui.files_match("/tmp/a", "/tmp/b"),
            "a copy must compare equal"
        );

        tui.exec("printf 'three\\n' >> /tmp/b");
        assert!(
            !tui.files_match("/tmp/a", "/tmp/b"),
            "an appended line must compare unequal"
        );

        assert!(
            !tui.files_match("/tmp/a", "/tmp/does-not-exist"),
            "a missing file must never read as a match"
        );
    }

    /// q quits from anywhere.
    fn q_quits(image) {
        let tui = tui!(image, "quit", "true");

        tui.press("Enter");
        tui.type_char('q');
        std::thread::sleep(std::time::Duration::from_secs(2));

        assert!(!tui.is_running(), "q must quit the program");
    }
}
