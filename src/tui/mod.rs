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
pub mod output;

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

/// Wraps an I/O failure as a terminal error.
fn terminal_error(source: io::Error) -> Error {
    Error::Terminal { source }
}

/// Starts the TUI, guaranteeing the terminal is restored afterwards.
pub fn run() -> Result<()> {
    let distro = crate::distro::detect::detect()?;
    let backend = crate::backend::for_family(distro.family);
    let executor = crate::exec::local::LocalExecutor::new(crate::exec::privilege::detect());

    let mut terminal = init()?;
    let outcome = app::App::new(distro, backend, executor).run(&mut terminal);

    // Restoration must happen whether the app succeeded or failed; a failure
    // to restore is only reported if the app itself did not already fail.
    match (outcome, restore()) {
        (Err(app_error), _) => Err(app_error),
        (Ok(()), restore_result) => restore_result,
    }
}
