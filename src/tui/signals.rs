//! Noticing that the session is going away, in time to put a change back.
//!
//! The verification window applies a change and reverts it unless somebody
//! confirms. Its whole reason for existing is `ssh.harden` and its neighbours:
//! a configuration that is valid, that the daemon accepted, and that may still
//! have locked this administrator out. Only a second login proves otherwise.
//!
//! Which makes the session dying the case the window is *for*, not an edge of
//! it. When an SSH connection drops, the daemon sends `SIGHUP` to the session
//! leader; `systemctl stop` and an ordinary `kill` send `SIGTERM`. Under the
//! default disposition both kill the process outright, so the countdown
//! stops, nothing reverts, and the configuration that severed the session is
//! the one left in place — the exact outcome the window was built to prevent.
//!
//! So the signals are caught, and the event loop reads a flag rather than the
//! handler doing the work: a handler may only touch async-signal-safe things,
//! and reverting means spawning `cp` through an executor that takes locks.
//! Setting a flag an ordinary loop already polls every hundred milliseconds is
//! both safe and quick enough — the alternative is a handler that deadlocks
//! against the code it interrupted.
//!
//! What this does not cover is stated rather than implied: `SIGKILL` cannot be
//! caught by anything, and a machine losing power runs no code at all. The
//! interface says so during the window instead of promising otherwise.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

/// The signals that mean this session is ending.
///
/// `SIGINT` is deliberately absent: `Ctrl-C` is a key the interface already
/// binds to cancelling a task, and the terminal delivers it as a key press
/// rather than as a signal while raw mode is on.
const TERMINAL_SIGNALS: [std::ffi::c_int; 2] =
    [signal_hook::consts::SIGHUP, signal_hook::consts::SIGTERM];

/// A flag raised when the session is going away.
///
/// Cloning shares the flag: one end is registered with the operating system,
/// the other is polled by the event loop.
#[derive(Debug, Clone, Default)]
pub struct Hangup(Arc<AtomicBool>);

impl Hangup {
    /// Arranges for `SIGHUP` and `SIGTERM` to raise the flag instead of
    /// killing the process outright.
    ///
    /// Registration failing is reported rather than ignored: it means the
    /// window cannot keep the promise it makes on screen, and the interface
    /// would go on making it.
    pub fn listen() -> Result<Self> {
        let flag = Arc::new(AtomicBool::new(false));

        for signal in TERMINAL_SIGNALS {
            signal_hook::flag::register(signal, Arc::clone(&flag)).map_err(|source| {
                Error::CommandIo {
                    command: format!("registering signal {signal}"),
                    source,
                }
            })?;
        }

        Ok(Self(flag))
    }

    /// Whether the session has been told to end.
    pub fn received(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Raises the flag as a signal would, for tests.
    #[cfg(test)]
    pub fn raise(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_listener_has_seen_nothing() {
        assert!(!Hangup::default().received());
    }

    #[test]
    fn a_raised_flag_is_seen_by_the_other_end() {
        // The property the event loop depends on: the handler and the loop
        // hold two clones of one flag, not two flags.
        let hangup = Hangup::default();
        let loop_end = hangup.clone();

        hangup.raise();

        assert!(loop_end.received());
    }

    #[test]
    fn registering_twice_is_not_an_error() {
        // `main` builds one, but a test binary may run several scenarios in a
        // process; registration must be idempotent rather than fail the second
        // time and take the interface down with it.
        let first = Hangup::listen();
        let second = Hangup::listen();

        assert!(first.is_ok(), "{first:?}");
        assert!(second.is_ok(), "{second:?}");
    }
}
