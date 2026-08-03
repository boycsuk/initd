//! Distribution identity and family resolution.
//!
//! Detection runs once at startup and yields a [`Family`], which selects the
//! backend. Everything above this layer is distro-agnostic: tasks never branch
//! on the distribution, they call domain traits that the backend implements.

pub mod detect;
pub mod host;

use std::fmt;

/// A supported distribution family.
///
/// Adding a distribution means adding a variant here plus one backend module —
/// never editing tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// Debian, Ubuntu and derivatives: `apt`, `ssh.service`.
    Debian,
    /// Arch and derivatives: `pacman`, `sshd.service`.
    Arch,
}

impl Family {
    /// Stable identifier, used in messages and CLI output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Arch => "arch",
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A detected distribution: what the system reports, plus its resolved family.
///
/// `id` and `version_id` are kept for display and diagnostics; only `family`
/// drives behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    /// The `ID` field, e.g. `ubuntu`.
    pub id: String,
    /// The `VERSION_ID` field, absent on rolling releases such as Arch.
    pub version_id: Option<String>,
    /// The `PRETTY_NAME` field, for display.
    pub pretty_name: Option<String>,
    /// The family whose backend handles this distribution.
    pub family: Family,
}

impl Distro {
    /// Human-readable name, falling back to the raw `ID` when the system
    /// declares no `PRETTY_NAME`.
    pub fn display_name(&self) -> &str {
        self.pretty_name.as_deref().unwrap_or(&self.id)
    }
}
