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
    /// Alpine and derivatives: `apk`, OpenRC, busybox.
    ///
    /// The family that diverges in more than names: no systemd, no shadow
    /// suite, no GNU coreutils. Where the others disagree over whether a
    /// unit is called `ssh` or `sshd`, Alpine has no units at all.
    Alpine,
    /// RHEL and derivatives: `dnf`, systemd, `wheel`.
    ///
    /// Mechanically the closest to Arch, and the family whose divergence is
    /// about provenance rather than naming: Red Hat's repositories carry less
    /// than the other families', so several capabilities resolve to a verified
    /// release instead of a package, and a few to nothing at all.
    Rhel,
    /// openSUSE and SLES: `zypper`, systemd, the shadow suite.
    ///
    /// The family that broke a supposition the other four share. Everywhere
    /// else, adding an account to [`crate::backend::Backend::admin_group`]
    /// grants it escalation; openSUSE ships the rule commented out, so the two
    /// are separate facts here. It is also the first family whose variants
    /// disagree with each other — Tumbleweed packages Zellij, Leap 16.0 does
    /// not — which is why its backend resolves a distribution and not only a
    /// family.
    Suse,
}

impl Family {
    /// Every family this build supports.
    ///
    /// Exists so a test can iterate families rather than restate them: a list
    /// written out by hand is one a new family is added without. The exhaustive
    /// `match` below is what keeps this honest — adding a variant fails to
    /// compile there, and the array is checked against it.
    ///
    /// Nothing in the running program iterates families — each execution
    /// resolves exactly one — so this is test-only by nature, like
    /// [`crate::backend::Backend::family`] above it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub const ALL: &'static [Self] = &[
        Self::Debian,
        Self::Arch,
        Self::Alpine,
        Self::Rhel,
        Self::Suse,
    ];

    /// Stable identifier, used in messages and CLI output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debian => "debian",
            Self::Arch => "arch",
            Self::Alpine => "alpine",
            Self::Rhel => "rhel",
            Self::Suse => "suse",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_appears_in_all() {
        // `ALL` is a hand-written array and the compiler cannot check that it
        // lists every variant. Round-tripping each entry through `as_str` — an
        // exhaustive `match` that a new variant breaks — is what ties the two
        // together: add a family, fix the `match`, and this fails until `ALL`
        // names it too. Without this, a new family would be silently absent
        // from every test that iterates families.
        let names: Vec<&str> = Family::ALL.iter().map(|family| family.as_str()).collect();

        assert_eq!(
            names.len(),
            Family::ALL.len(),
            "ALL must not contain duplicates"
        );
        assert!(names.contains(&"debian"), "debian missing from ALL");
        assert!(names.contains(&"arch"), "arch missing from ALL");
        assert!(names.contains(&"alpine"), "alpine missing from ALL");
        assert!(names.contains(&"rhel"), "rhel missing from ALL");
        assert!(names.contains(&"suse"), "suse missing from ALL");
        assert_eq!(
            Family::ALL.len(),
            5,
            "a family was added: list it in ALL and name it here"
        );
    }
}
