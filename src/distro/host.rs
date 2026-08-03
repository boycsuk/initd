//! Facts about the machine being administered.
//!
//! The header states which host `initd` is pointed at, because the whole point
//! of the tool is that it acts on the system it runs on: an administrator with
//! four terminals open needs to see, without asking, which one is about to be
//! changed.
//!
//! Every value here is read once at startup. These are properties of the
//! machine, not of the session, and re-reading them each frame would spend
//! syscalls to observe something that cannot change.

use std::fs;

/// Where the kernel exposes the hostname.
///
/// Read from `/proc` rather than through `gethostname`, which would mean a
/// `libc` dependency for a single string.
const HOSTNAME_PATH: &str = "/proc/sys/kernel/hostname";

/// Shown when the hostname cannot be read.
///
/// An unreadable hostname is not worth failing over — the tool still works —
/// but it must not be silently blank either, or the header would look like it
/// simply forgot to say which machine this is.
const UNKNOWN_HOSTNAME: &str = "unknown host";

/// What the interface states about the machine being administered.
///
/// Probed once at startup and carried thereafter: these are properties of the
/// machine, and re-reading them per frame would spend syscalls observing
/// something that cannot change while the program runs.
#[derive(Debug, Clone)]
pub struct HostFacts {
    /// The machine's name, as the kernel reports it.
    pub hostname: String,
    /// How `initd` obtains root, or why it cannot.
    ///
    /// Stated up front because an administrator needs to know whether
    /// privileged work will succeed *before* starting it, not when it fails.
    pub privilege: String,
}

impl HostFacts {
    /// Probes the machine.
    pub fn probe(escalator: &dyn crate::exec::privilege::PrivilegeEscalator) -> Self {
        Self {
            hostname: hostname(),
            privilege: escalator.name().to_owned(),
        }
    }
}

/// The machine's name, as the kernel reports it.
///
/// Falls back to [`UNKNOWN_HOSTNAME`] rather than failing: `initd` administers
/// the host it runs on, so not knowing its name is a display problem, never a
/// reason to refuse to start.
pub fn hostname() -> String {
    fs::read_to_string(HOSTNAME_PATH)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| UNKNOWN_HOSTNAME.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hostname_is_a_single_trimmed_line() {
        // /proc yields a trailing newline; a header drawn with it would push
        // everything after it onto a row that does not exist.
        let name = hostname();

        assert!(!name.is_empty());
        assert_eq!(name, name.trim());
        assert!(
            !name.contains('\n'),
            "the hostname must be one line: {name:?}"
        );
    }
}
