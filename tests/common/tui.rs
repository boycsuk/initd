//! Driving the terminal interface and reading what it drew.
//!
//! ratatui needs a real terminal. Run against a pipe it renders nothing, and
//! `script(1)` — which does allocate a pty — captures nothing readable, because
//! the interface lives in the alternate screen and that is discarded on exit.
//!
//! tmux solves both halves: it allocates the pty *and* can dump a live pane, so
//! the screen can be asserted on while it is being drawn rather than
//! reconstructed from an escape-sequence stream afterwards. It is also a shell
//! tool rather than a crate, so none of this adds a dependency to audit.
//!
//! # Why these run under systemd
//!
//! The verification window — the whole reason `Revert` exists — is only
//! reachable on a host with systemd. Without it, `ssh.harden` writes the file,
//! fails at `systemctl reload`, and the interface reports FAILED; a failed task
//! offers nothing to keep or revert, so the window never opens. Verified in a
//! container before these tests were written, which is why they sit on
//! [`SystemdContainer`] rather than an ephemeral one.

// Only `integration_tui` drives this module, and every test binary that says
// `mod common;` compiles it whole — so in the other nine it is dead by
// construction. That is the cost of sharing a module across binaries, not a
// sign of a helper nobody calls.
#![allow(dead_code)]

use super::Image;
use super::systemd::SystemdContainer;

/// The tmux session the interface runs in.
const SESSION: &str = "initd-tui";

/// Terminal size the interface is driven at.
///
/// The larger of the two the specification draws for. The confirmation dialog
/// is taller than 24 rows once its warning is included, so at 80x24 its
/// buttons fall off the screen and a scenario cannot read which one is
/// selected — found by trying it.
const WIDTH: u16 = 120;
const HEIGHT: u16 = 40;

/// How long to let the interface settle after a keystroke.
///
/// Generous, because the alternative failure is a scenario that reads a screen
/// mid-redraw and reports the interface as broken.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(900);

/// A running interface inside a booted container.
pub struct Tui {
    container: SystemdContainer,
}

impl Tui {
    /// Boots a container, prepares it, and starts the interface.
    ///
    /// `prepare` runs before the interface starts — the place to install
    /// packages, authorise a key, or apply whatever state the scenario needs.
    ///
    /// Returns `None` when the host will not boot the container, so a scenario
    /// can skip rather than fail.
    pub fn start(image: &Image, label: &str, prepare: &str) -> Option<Self> {
        let container = SystemdContainer::boot(image, label)?;

        container.exec(&format!(
            "{install_tmux} >/dev/null 2>&1; \
             {install_ssh} >/dev/null 2>&1; \
             ssh-keygen -A >/dev/null 2>&1; \
             {prepare}",
            install_tmux = image.install_tmux,
            install_ssh = image.install_ssh,
        ));

        // Resized after creation, and then checked, because `-x`/`-y` are a
        // request rather than an instruction: with no client attached, tmux is
        // free to clamp a detached session to the terminal that created it, and
        // Rocky's tmux does. That produced an 80x23 pane where 120x40 was
        // asked for — one row below the height at which the interface draws a
        // key bar at all, so scenarios reading it found the interface had
        // correctly omitted what they were looking for. `-x`/`-y` are kept as
        // well: where they are honoured the window opens at the right size and
        // never redraws.
        let started = container.exec(&format!(
            "tmux new-session -d -s {SESSION} -x {WIDTH} -y {HEIGHT} initd; \
             tmux resize-window -t {SESSION} -x {WIDTH} -y {HEIGHT} 2>/dev/null; \
             tmux display-message -p -t {SESSION} '#{{pane_width}}x#{{pane_height}}'"
        ));
        if !started.status.success() {
            return None;
        }

        // A pane smaller than asked for makes every later assertion a guess
        // about which layout the interface chose, so it is refused here rather
        // than diagnosed from a screen dump further down.
        let pane = String::from_utf8_lossy(&started.stdout);
        let pane = pane.trim();
        assert_eq!(
            pane,
            format!("{WIDTH}x{HEIGHT}"),
            "tmux gave a {pane} pane where {WIDTH}x{HEIGHT} was asked for; \
             the interface sheds its key bar below 24 rows, and scenarios \
             reading it would report the missing bar as missing output"
        );

        let tui = Self { container };
        std::thread::sleep(SETTLE * 2);
        Some(tui)
    }

    /// Sends a named key — `Enter`, `Down`, `Tab`, `Escape`.
    pub fn press(&self, key: &str) {
        self.container
            .exec(&format!("tmux send-keys -t {SESSION} {key}"));
        std::thread::sleep(SETTLE);
    }

    /// Sends a literal character.
    ///
    /// Separate from [`Self::press`] because `send-keys R` is interpreted as a
    /// key name and does not reliably deliver an uppercase `R`; the interface
    /// binds `K` and `R` as distinct from their lowercase forms, so the
    /// literal form is the only one that reaches the right handler.
    pub fn type_char(&self, character: char) {
        self.container
            .exec(&format!("tmux send-keys -t {SESSION} -l '{character}'"));
        std::thread::sleep(SETTLE);
    }

    /// Waits for `needle` to appear on screen, up to `seconds`.
    ///
    /// Polling rather than sleeping a fixed time: a task that installs a
    /// package takes far longer than one that edits a file, and a fixed wait
    /// long enough for the slowest would make every scenario pay for it.
    pub fn wait_for(&self, needle: &str, seconds: u32) -> bool {
        for _ in 0..seconds {
            if self.screen().contains(needle) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        false
    }

    /// The whole visible screen, as text.
    pub fn screen(&self) -> String {
        let output = self
            .container
            .exec(&format!("tmux capture-pane -p -t {SESSION}"));

        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The status row and key bar — the last two non-empty lines.
    ///
    /// The interface states what it is doing there (`VERIFY`, `FAILED`,
    /// `DONE`) and which keys apply, so most assertions belong here rather
    /// than against the body, which is mostly borders.
    pub fn status(&self) -> String {
        self.screen()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .rev()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Runs a shell command in the same container, for checking what the
    /// interface did to the system.
    pub fn exec(&self, script: &str) -> String {
        let output = self.container.exec(script);
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// Whether two files are byte-for-byte identical.
    ///
    /// Compared by hash rather than with `cmp` or `diff`, because Arch's image
    /// ships neither — both live in diffutils, which Debian pulls in and Arch
    /// does not. Reaching for one and then the other produced the same failure
    /// twice: a missing tool reports "differs", which failed the revert
    /// scenario whose revert had worked and *passed* the keep scenario, which
    /// asserts the files differ. `sha256sum` is in coreutils and present in
    /// both, and comparing digests answers the same question.
    pub fn files_match(&self, left: &str, right: &str) -> bool {
        let digests = self.exec(&format!("sha256sum {left} {right} 2>/dev/null"));
        let hashes: Vec<&str> = digests
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect();

        // Two digests or the answer is unknown — one file missing, or
        // sha256sum itself absent, must never read as a match.
        hashes.len() == 2 && hashes[0] == hashes[1]
    }

    /// Whether the interface is still running.
    pub fn is_running(&self) -> bool {
        self.container
            .exec(&format!("tmux has-session -t {SESSION} 2>/dev/null"))
            .status
            .success()
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        // The container is removed by its own Drop; killing the server first
        // keeps a hung interface from delaying that.
        self.container.exec("tmux kill-server 2>/dev/null || true");
    }
}
