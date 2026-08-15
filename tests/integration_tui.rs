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
use common::{TEST_KEY, admin_group, create_account, create_account_with_home};

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

/// Authorises a key for an ordinary account, so the lockout guard permits
/// hardening, and records the configuration for later comparison.
///
/// The daemon is waited for rather than assumed. `systemctl start` returns once
/// systemd has accepted the job, not once the unit is up, and `ssh.harden`
/// reloads — which systemd refuses outright on an inactive unit, with
/// `sshd.service is not active, cannot reload`. That fails the task, and a
/// failed task offers nothing to keep or revert, so the verification window
/// these scenarios exist to observe never opens. It surfaced on RHEL, where
/// installing the package leaves the unit enabled but stopped rather than
/// started, but the race was there for any family whose daemon was slow enough.
/// The seed is not a workaround for openSUSE so much as the state every other
/// family is already in. openSUSE ships its `sshd_config` under `/usr/etc` and
/// leaves `/etc/ssh/sshd_config` absent until something writes it — the tool
/// does so in `ensure_config_present`, but these scenarios read the path
/// directly, both here and in ten assertions below. Seeding once at the top
/// keeps those ten reading a file that exists on all six images; without it
/// they receive an empty string, and `starts_with('0')` on nothing is a failure
/// that names the task rather than the missing file.
///
/// The key comes from [`common::TEST_KEY`] rather than being written out here.
/// It was inlined because `concat!` takes literals and nothing else, and the
/// two spellings agreed — but only by hand. The lockout guard these scenarios
/// walk past is tested against the shared constant, so a changed key would have
/// left the interface authorising a different one and the guard refusing to
/// proceed. That surfaces as the verification window never opening: a TUI
/// failure report for a drifted constant, in the file least likely to be
/// suspected.
///
/// The key goes to an **ordinary account** rather than to root, which is the
/// whole point rather than a detail. `ssh.harden` writes `PermitRootLogin no`,
/// so a key held by root authorises nothing once the task finishes and the
/// guard does not count it. Seeding root here — as this did while the guard
/// asked about root alone — leaves the task refusing on a host these scenarios
/// have prepared, and the refusal surfaces as the verification window never
/// opening: a TUI failure report for a seed that names the wrong account.
fn prepare_for_hardening(image: &common::Image) -> String {
    format!(
        "{create} {HARDENING_ACCOUNT} >/dev/null 2>&1; \
         initd authorize-key {HARDENING_ACCOUNT} '{TEST_KEY}' >/dev/null 2>&1; \
         [ -f /etc/ssh/sshd_config ] || cp /usr/etc/ssh/sshd_config /etc/ssh/sshd_config \
           2>/dev/null; \
         systemctl start ssh sshd >/dev/null 2>&1; \
         for _ in $(seq 30); do \
           systemctl is-active --quiet ssh sshd && break; \
           sleep 0.2; \
         done; \
         cp /etc/ssh/sshd_config /tmp/before",
        create = create_account_with_home(image),
    )
}

/// The account the hardening scenarios authorise a key for.
///
/// An ordinary account, since root is the one `ssh.harden` disables.
const HARDENING_ACCOUNT: &str = "initdops";

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
    // Waited for rather than assumed. `Tab` and `Enter` aimed at a dialog that
    // is not drawn yet reach the tree instead, where `Tab` moves the focus and
    // `Enter` runs whatever the cursor is on — so the scenario goes on to assert
    // against a task nobody chose. It used to be reliable by accident, the
    // interface having had more to draw before the dialog appeared.
    assert!(
        tui.wait_for("Enter to confirm", 10),
        "the confirmation must be on screen before it is answered: {}",
        tui.screen()
    );

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
        let tui = tui!(image, "confirm", &prepare_for_hardening(image));

        run_hardening(&tui);

        let screen = tui.screen();
        assert!(
            screen.contains("Yes") && screen.contains("No"),
            "a confirmation dialog must be on screen: {screen}"
        );
        // The risk, in the words this task states it with. It used to be the
        // generic "lock you out" sentence, which the hardening tiers no longer
        // reach: they name the accounts that keep access instead, so the
        // operator can check that theirs is among them. Both halves are
        // asserted, because a dialog that listed accounts without saying what
        // is being taken away would read as reassurance.
        assert!(
            screen.contains("Password authentication is going away"),
            "the dialog must state the risk: {screen}"
        );
        assert!(
            screen.contains("keep SSH access"),
            "the dialog must name the accounts that survive the change: {screen}"
        );
        assert!(
            screen.contains(HARDENING_ACCOUNT),
            "the account holding the key must be listed by name: {screen}"
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
        let tui = tui!(image, "window", &prepare_for_hardening(image));

        run_hardening(&tui);
        confirm_dialog(&tui);

        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open: {}",
            tui.tail()
        );

        let status = tui.tail();
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
        let tui = tui!(image, "revert", &prepare_for_hardening(image));

        run_hardening(&tui);
        confirm_dialog(&tui);
        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open before it can be declined: {}",
            tui.tail()
        );

        tui.type_char('R');

        // The window closing is what says the answer landed. Nothing reports the
        // revert in words any more — that line lived on the status border — so
        // waiting on the banner's disappearance is what keeps this from racing
        // the assertion below, which is the one that proves the file went back.
        assert!(
            tui.wait_for_absence(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must close once R is answered: {}",
            tui.tail()
        );

        assert!(
            tui.files_match("/tmp/before", "/etc/ssh/sshd_config"),
            "the configuration must be byte-for-byte what it was; still set: {}",
            tui.exec("grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config")
        );
    }

    /// Losing the session reverts, which is the case the window exists for.
    ///
    /// `ssh.harden` can sever the very connection that would confirm it, and
    /// the daemon answers a dropped connection with `SIGHUP`. That is the
    /// scenario `signals.rs` was written for and the one nothing exercised: its
    /// unit tests assert that a raised flag is seen, which says nothing about
    /// whether a real process, holding a real verification window, puts a real
    /// file back before it exits.
    ///
    /// The signal is sent from outside tmux to the `initd` process itself, so
    /// what is measured is the handler rather than a keypress. `R` and `K` are
    /// covered above; this is the third path, and the only one an operator
    /// never chooses.
    fn losing_the_session_puts_the_configuration_back(image) {
        let tui = tui!(image, "hangup", &prepare_for_hardening(image));

        run_hardening(&tui);
        confirm_dialog(&tui);
        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open before the session can be lost: {}",
            tui.tail()
        );

        // Confirms the change really landed first: a test that reverts nothing
        // would pass this scenario by comparing two identical files.
        assert!(
            !tui.files_match("/tmp/before", "/etc/ssh/sshd_config"),
            "the hardening must be applied before the session is lost"
        );

        // A signal rather than closing the tmux client: what a dropped
        // connection delivers is `SIGHUP`, and going through tmux would be
        // testing tmux's teardown instead.
        //
        // The pid comes out of /proc and the signal goes through `kill`, not
        // `pkill`: procps is not installed in `debian:13`, so `pkill` is
        // missing there and would exit non-zero without signalling anything —
        // the process would go on running, the file would stay hardened, and
        // this scenario would fail while looking like a defect in the handler.
        // The same shape as the `pgrep` finding already recorded in CLAUDE.md.
        let pid = tui.exec(
            "for p in /proc/[0-9]*; do \
               [ \"$(cat $p/comm 2>/dev/null)\" = initd ] && basename $p && break; \
             done",
        );
        let pid = pid.trim();

        assert!(
            !pid.is_empty(),
            "the interface must be running to be signalled: {}",
            tui.screen()
        );

        tui.exec(&format!("kill -HUP {pid}"));

        // The handler only raises a flag; the event loop notices it on its next
        // hundred-millisecond poll, reverts, and exits. Waiting for the process
        // to go is what says the whole sequence ran.
        let mut waited = 0;

        while tui.is_running() && waited < WINDOW_OPENS_WITHIN {
            std::thread::sleep(std::time::Duration::from_secs(1));
            waited += 1;
        }

        assert!(
            !tui.is_running(),
            "the interface must exit after the hangup: {}",
            tui.screen()
        );

        assert!(
            tui.files_match("/tmp/before", "/etc/ssh/sshd_config"),
            "silence is not confirmation: the configuration must be back to \
             byte-for-byte what it was; still set: {}",
            tui.exec("grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config")
        );
    }

    /// K keeps the change.
    ///
    /// The other half, and the one that proves the window is a real choice
    /// rather than a delayed rollback: after keeping, the change must survive.
    fn keeping_leaves_the_change_in_place(image) {
        let tui = tui!(image, "keep", &prepare_for_hardening(image));

        run_hardening(&tui);
        confirm_dialog(&tui);
        assert!(
            tui.wait_for(VERIFY, WINDOW_OPENS_WITHIN),
            "the verification window must open: {}",
            tui.tail()
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

    /// The scan finds the accounts a real host has, and lists every one.
    ///
    /// The case a mock cannot give. `id -nG` prints a format nothing in this
    /// repository controls, `/etc/shadow` holds hashes only the system writes,
    /// and the whole claim this task now makes — *this host has a way back in*
    /// — is a claim about a machine. A mock asked the same question would
    /// answer with the replies it was handed.
    ///
    /// Two accounts rather than one, deliberately: the scan must not stop at
    /// the first that passes, and a scenario with a single administrator
    /// cannot tell a complete scan from an early return.
    fn the_scan_lists_every_account_that_keeps_access(image) {
        let group = admin_group(image);
        let tui = tui!(
            image,
            "lock-root-scan",
            &format!(
                // Two administrators, each reachable by a different credential,
                // so the dialog has to report both facts rather than one twice.
                // A third account that can log in and cannot escalate is the
                // control: it must be examined and must not be listed.
                "groupadd -f {group} >/dev/null 2>&1; \
                 {create} keeper >/dev/null 2>&1; \
                 {create} second >/dev/null 2>&1; \
                 {create} bystander >/dev/null 2>&1; \
                 usermod -aG {group} keeper >/dev/null 2>&1 || \
                   addgroup keeper {group} >/dev/null 2>&1; \
                 usermod -aG {group} second >/dev/null 2>&1 || \
                   addgroup second {group} >/dev/null 2>&1; \
                 echo 'keeper:correct horse' | chpasswd >/dev/null 2>&1; \
                 echo 'second:battery staple' | chpasswd >/dev/null 2>&1; \
                 echo 'bystander:no escalation' | chpasswd >/dev/null 2>&1",
                create = create_account(image),
                group = group,
            )
        );

        // Identity & Access is the first category, Users the first inside it,
        // and locking root the fourth task there. Positional like every other
        // path in this file, and checked by title for the same reason: a
        // reordered tree would otherwise point this at another task that also
        // opens a dialog, and it would keep passing.
        tui.press("Enter"); // Identity & Access
        tui.press("Enter"); // Users
        tui.press("Down");  // create -> delete
        tui.press("Down");  // delete -> set-shell
        tui.press("Down");  // set-shell -> root access

        let screen = tui.screen();
        assert!(
            screen.contains("Manage root access"),
            "{}: navigation must land on the root-access row; the tree may have been \
             reordered: {screen}",
            image.name
        );

        // Enter opens the confirmation directly, with no form in between. That
        // it does is half the point: this task used to stop at a field asking
        // which account keeps access, and the whole change is that it no longer
        // asks.
        tui.press("Enter");

        // Matched on the dialog's own key hint rather than on a word in the
        // border: nothing is drawn there now, and the hint is unique to this
        // window — a form draws its own, different one.
        assert!(
            tui.wait_for("Enter to confirm", 20),
            "{}: the confirmation must open without asking for an account: {}",
            image.name,
            tui.screen()
        );

        let dialog = tui.screen();

        // openSUSE is the family where membership is not the whole answer:
        // `%wheel` ships commented out, `admin_group_grants_alone` is false for
        // the family, and both administrators are correctly discarded. Which
        // makes it the one image where this scenario asserts the *other* half
        // of the same rule — that the scan does not count a membership the
        // system does not honour.
        if image.name.contains("opensuse") {
            assert!(
                !dialog.contains("keeper — ") && !dialog.contains("second — "),
                "{}: membership alone must not be reported as a way back in \
                 where the group grants nothing: {dialog}",
                image.name
            );
        } else {
            assert!(
                dialog.contains("keeper") && dialog.contains("second"),
                "{}: every account that keeps access must be listed, not just \
                 the first one found: {dialog}",
                image.name
            );
            assert!(
                !dialog.contains("bystander"),
                "{}: an account that cannot escalate is no way back in: {dialog}",
                image.name
            );
        }

        // Cancelled rather than confirmed. What this scenario is about is what
        // the scan *shows*; locking root here would end with a container whose
        // remaining assertions run as an account this test just stranded.
        tui.press("Esc");
    }

    /// A host with no way back in is refused, and says how many it looked at.
    ///
    /// The other half of the claim, and the one that matters: approving a host
    /// that has no way out is the single mistake this task cannot undo. The
    /// image is used as it ships — root and the system accounts, none of which
    /// can both escalate and authenticate.
    fn a_host_with_no_administrator_is_refused(image) {
        let tui = tui!(image, "lock-root-refuses", "true");

        tui.press("Enter"); // Identity & Access
        tui.press("Enter"); // Users
        tui.press("Down");
        tui.press("Down");
        tui.press("Down");

        let screen = tui.screen();
        assert!(
            screen.contains("Manage root access"),
            "{}: navigation must land on the root-access row: {screen}",
            image.name
        );

        tui.press("Enter");  // open the confirmation
        confirm_dialog(&tui); // and answer it Yes

        // `wait_for` rather than one look at the screen: the scan reports a line
        // per account — twenty-one on a stock `debian:13` — so the refusal
        // arrives after a delay that depends on how many accounts the host has.
        //
        // The heading is what is matched, the failure now being reported in the
        // output pane rather than on a border. It is visible because the pane is
        // still following its tail, which is where a report written last lands.
        assert!(
            tui.wait_for("FAILED", 20),
            "{}: a host with no way back in must be refused: {}",
            image.name,
            tui.screen()
        );

        // And refused for the stated reason rather than by some other failure:
        // the per-account diagnosis is what the task prints on the way to it,
        // and it is the thing an operator acts on.
        assert!(
            tui.screen().contains("not in"),
            "{}: and must say why each account was set aside: {}",
            image.name,
            tui.screen()
        );

        // The refusal has to be a refusal rather than a message over a change
        // that happened anyway. Read out of the shadow entry, which is where
        // the expiry the task would have written would show.
        let expiry = tui.exec("grep '^root:' /etc/shadow | cut -d: -f8");
        assert!(
            expiry.trim().is_empty(),
            "{}: root must not have been expired: {expiry:?}",
            image.name
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
