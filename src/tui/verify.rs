//! The verification window: applied, but not yet kept.
//!
//! After a change that could sever the administrator's own access, `initd`
//! does not declare success. It has proved the configuration is valid and that
//! the daemon accepted it; what it cannot prove is that *this administrator*
//! can still get in. Only a second session can prove that.
//!
//! So the change is applied and a countdown starts. Keeping it is a deliberate
//! act; losing the session, closing the terminal, or simply not answering all
//! mean the backup goes back. The default outcome of silence is the safe one,
//! because an administrator who has just locked themselves out is by
//! definition unable to press a key.
//!
//! The keys are uppercase `K` and `R` on purpose: lowercase `k` is "move up"
//! everywhere else in this interface, and this is the one place where a
//! mistyped navigation key would do something unrecoverable.

use std::time::{Duration, Instant};

use crate::tasks::revert::Revert;

/// How long the administrator has to confirm they still have access.
///
/// Long enough to open a second session and try a login, short enough that an
/// abandoned terminal does not hold a possibly-broken configuration in place
/// for the rest of the afternoon.
const WINDOW: Duration = Duration::from_secs(60);

/// A change that has been applied but not yet committed.
#[derive(Debug)]
pub struct Verification {
    /// What running out of time, or pressing `R`, would put back.
    revert: Revert,
    /// Which task is being verified, for the interface to name.
    pub task: String,
    /// When the window opened.
    started: Instant,
}

impl Verification {
    /// Opens a window over an applied change.
    pub fn new(task: impl Into<String>, revert: Revert, now: Instant) -> Self {
        Self {
            revert,
            task: task.into(),
            started: now,
        }
    }

    /// How long is left before the change is put back.
    ///
    /// Saturates at zero rather than going negative, so a window that has
    /// expired reads as expired rather than wrapping.
    pub fn remaining(&self, now: Instant) -> Duration {
        WINDOW.saturating_sub(now.duration_since(self.started))
    }

    /// Whether the window has run out.
    pub fn has_expired(&self, now: Instant) -> bool {
        self.remaining(now).is_zero()
    }

    /// The countdown as `m:ss`, for the interface.
    pub fn countdown(&self, now: Instant) -> String {
        let left = self.remaining(now).as_secs();

        format!("{}:{:02}", left / 60, left % 60)
    }

    /// The undo this window is holding open.
    pub const fn revert(&self) -> &Revert {
        &self.revert
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::files::Backup;

    fn verification(now: Instant) -> Verification {
        Verification::new(
            "ssh.harden",
            Revert::ConfigFile {
                backup: Backup {
                    original: "/etc/ssh/sshd_config".to_owned(),
                    copy: "/etc/ssh/sshd_config.initd".to_owned(),
                },
                service: "ssh.service",
            },
            now,
        )
    }

    #[test]
    fn a_fresh_window_has_its_whole_duration_left() {
        let now = Instant::now();

        assert_eq!(verification(now).remaining(now), WINDOW);
        assert!(!verification(now).has_expired(now));
    }

    #[test]
    fn the_countdown_reads_as_minutes_and_seconds() {
        let now = Instant::now();
        let window = verification(now);

        assert_eq!(window.countdown(now), "1:00");
        assert_eq!(window.countdown(now + Duration::from_secs(13)), "0:47");
        assert_eq!(window.countdown(now + Duration::from_secs(59)), "0:01");
    }

    #[test]
    fn the_window_expires_rather_than_going_negative() {
        // A window read after it lapsed must say it lapsed, not wrap around
        // into another minute.
        let now = Instant::now();
        let window = verification(now);
        let later = now + WINDOW + Duration::from_secs(30);

        assert!(window.has_expired(later));
        assert_eq!(window.remaining(later), Duration::ZERO);
        assert_eq!(window.countdown(later), "0:00");
    }

    #[test]
    fn expiry_lands_exactly_at_the_end_of_the_window() {
        let now = Instant::now();
        let window = verification(now);

        assert!(!window.has_expired(now + WINDOW - Duration::from_millis(1)));
        assert!(window.has_expired(now + WINDOW));
    }
}
