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
pub mod confirm;
pub mod field;
pub mod form;
pub mod help;
pub mod layout;
pub mod output;
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
/// Nothing calls this now that the interface authenticates once at startup and
/// runs tasks on a thread. It stays because that arrangement rests on a
/// timestamp `doas` and `run0` do not provide — for those, or if sudo's
/// timestamp expires mid-session, handing the terminal over is still the only
/// way to let a helper prompt.
#[allow(dead_code)]
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
/// Verified on Debian 13 and Arch: see `docs/sudo-timestamp-findings.md`.
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
    let backend = crate::backend::for_family(distro.family);

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
    // A refusal is not fatal. The operator may have cancelled the prompt, or
    // the mechanism may not support this at all, and either way privileged
    // commands still work — they just prompt when they run.
    preauthenticate(escalator.as_ref());

    let executor = crate::exec::local::LocalExecutor::new(escalator);

    let mut terminal = init()?;
    let outcome = app::App::new(distro, host, backend, executor).run(&mut terminal);

    // Restoration must happen whether the app succeeded or failed; a failure
    // to restore is only reported if the app itself did not already fail.
    match (outcome, restore()) {
        (Err(app_error), _) => Err(app_error),
        (Ok(()), restore_result) => restore_result,
    }
}
