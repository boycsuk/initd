//! Terminal setup, teardown and the event loop.
//!
//! Two properties matter here beyond drawing widgets:
//!
//! 1. The terminal is restored even when the application fails, so a crash
//!    never leaves the user with an unusable shell.
//! 2. Running an external process that needs the terminal — `sudo` asking for
//!    a password — hands the terminal over and takes it back afterwards,
//!    following the pattern ratatui documents for spawning an editor.

pub mod app;
pub mod auth;
pub mod clipboard;
pub mod confirm;
pub mod cursor;
pub mod dispatch;
pub mod execution;
pub mod field;
#[cfg(test)]
pub mod fixtures;
pub mod form;
pub mod help;
pub mod layout;
pub mod navigation;
pub mod output;
pub mod probe;
pub mod render;
pub mod search;
pub mod signals;
pub mod status;
pub mod style;
pub mod verify;
pub mod worker;

use std::io::{self, Stdout};

use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::{Error, Result};

/// The concrete terminal type used throughout the TUI.
pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Puts the terminal into raw mode on the alternate screen.
pub fn init() -> Result<Tui> {
    enable_raw_mode().map_err(terminal_error)?;
    execute!(io::stdout(), EnterAlternateScreen).map_err(terminal_error)?;

    Terminal::new(CrosstermBackend::new(io::stdout())).map_err(terminal_error)
}

/// Returns the terminal to its original state.
///
/// Safe to call more than once: leaving an alternate screen that is not active
/// is a no-op, which matters because teardown runs both on the happy path and
/// from the failure path.
pub fn restore() -> Result<()> {
    disable_raw_mode().map_err(terminal_error)?;
    execute!(io::stdout(), LeaveAlternateScreen).map_err(terminal_error)
}

/// Restores the terminal before a panic prints its message.
///
/// `run` restores on both the `Ok` and the `Err` path, but a panic unwinds past
/// that match, so without this the message is drawn into the alternate screen
/// in raw mode — where it scrolls without carriage returns and vanishes with
/// the screen, leaving an unusable shell and no explanation. The hook runs
/// before the default one so the report lands on an ordinary terminal.
///
/// The previous hook is called rather than replaced, so this composes with
/// whatever the runtime installed instead of discarding it.
fn restore_terminal_on_panic() {
    let previous = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        // Nothing useful can be done if restoring fails while already
        // panicking, and the panic itself is the more important message.
        let _ = restore();
        previous(info);
    }));
}

/// Runs a closure with the terminal handed back to the child process.
///
/// `sudo` prompts for a password on the TTY, but raw mode disables echo and
/// line buffering, so a prompt drawn under the TUI is unusable. The sequence
/// is the one ratatui documents: leave the alternate screen, disable raw mode,
/// run the child, then restore and clear.
///
/// The final `clear()` is not cosmetic: without it, programs that query the
/// terminal's colours leave raw ANSI RGB values printed inside the restored
/// interface.
///
/// This is how a helper prompts mid-session. Authenticating once at startup
/// covers `sudo` while its timestamp lasts — five minutes on Arch, which a
/// long task outlives — and covers `doas` and `run0` not at all, since neither
/// has a timestamp to establish. When the executor finds a prompt is coming it
/// asks the interface for the terminal, and this is what lends it.
pub fn with_terminal_released<T>(
    terminal: &mut Tui,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    restore()?;

    // The child's result is captured before restoring, so that the terminal
    // comes back even when the action fails.
    let result = action();

    enable_raw_mode().map_err(terminal_error)?;
    execute!(io::stdout(), EnterAlternateScreen).map_err(terminal_error)?;
    terminal.clear().map_err(terminal_error)?;

    result
}

/// Asks for the password once, before the interface starts.
///
/// The terminal is still ordinary here, so `sudo` prompts and reads the
/// password itself — `initd` never sees it. What this buys is a timestamp the
/// later commands reuse, so a task can run inside the interface instead of the
/// screen being torn down and rebuilt around every privileged command.
///
/// Verified on Debian 13 and Arch containers, with the probes in
/// `tests/fixtures/validate-sudo-*.sh`.
fn preauthenticate(escalator: &dyn crate::exec::privilege::PrivilegeEscalator) {
    let Some((program, args)) = escalator.preauth_command() else {
        return;
    };

    println!("initd needs administrator access.");

    // Every stream is inherited: sudo has to reach the terminal to prompt, and
    // the timestamp it writes is keyed by that terminal.
    let _ = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
}

/// Wraps an I/O failure as a terminal error.
fn terminal_error(source: io::Error) -> Error {
    Error::Terminal { source }
}

/// Starts the TUI, guaranteeing the terminal is restored afterwards.
pub fn run() -> Result<()> {
    let distro = crate::distro::detect::detect()?;
    let backend = crate::backend::for_distro(&distro);

    // The escalator is probed before it is handed to the executor, so the
    // header can state how root will be obtained without the executor having
    // to expose it — a detail the SSH implementation would not share.
    let escalator = crate::exec::privilege::detect();
    let host = crate::distro::host::HostFacts::probe(escalator.as_ref());

    // Authenticating here, before the alternate screen, is the whole reason a
    // task's output can be streamed into the interface later: sudo draws its
    // own prompt on an ordinary terminal, and the timestamp it establishes
    // covers the commands the tasks go on to run.
    //
    // A refusal is not fatal, but not because the prompt simply moves: under
    // the interface it would be drawn inside the alternate screen in raw mode,
    // where it cannot be read or answered. What makes it survivable is that
    // the executor asks for the terminal before any helper prompts, so this is
    // the fast path rather than the only one.
    preauthenticate(escalator.as_ref());

    let executor = crate::exec::local::LocalExecutor::new(escalator);

    // Installed before the screen is taken, so a panic between here and the
    // restore below still lands on a terminal somebody can read.
    restore_terminal_on_panic();

    // Registered before the screen is taken, so a connection dropping during
    // startup is noticed rather than killing the process outright. A failure
    // to register is not fatal: the interface then behaves as it did before,
    // and the verification window says so rather than promising otherwise.
    let hangup = signals::Hangup::listen().unwrap_or_default();

    let mut terminal = init()?;
    let outcome = app::App::new(distro, host, backend, executor)
        .watching_for_hangup(hangup)
        .run(&mut terminal);

    // Restoration must happen whether the app succeeded or failed; a failure
    // to restore is only reported if the app itself did not already fail.
    match (outcome, restore()) {
        (Err(app_error), _) => Err(app_error),
        (Ok(()), restore_result) => restore_result,
    }
}
