//! Message catalogue and locale resolution.
//!
//! Every user-facing string in `initd` goes through this module. Nothing else
//! embeds display text, so adding a language means adding one catalogue module
//! and one `match` arm — never touching call sites.
//!
//! The design is deliberately dependency-free. The catalogue is a closed enum
//! rendered by an exhaustive `match`, so a message that lacks a translation is
//! a compile error rather than a runtime lookup miss.

mod en;

use std::env;

/// A language `initd` can render messages in.
///
/// [`Lang::En`] is both the default and the fallback for unrecognised locales.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
}

impl Lang {
    /// Resolves the language from the environment, honouring the POSIX
    /// precedence `LC_ALL` > `LC_MESSAGES` > `LANG`.
    ///
    /// Unset, empty, or unrecognised values fall back to [`Lang::En`], so this
    /// never fails.
    pub fn from_env() -> Self {
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|var| env::var(var).ok().filter(|value| !value.is_empty()))
            .map_or(Self::default(), |value| Self::from_locale(&value))
    }

    /// Parses a POSIX locale string such as `es_ES.UTF-8` or `en`.
    ///
    /// Only the language part before `_` or `.` is significant; the territory
    /// and encoding are ignored.
    fn from_locale(locale: &str) -> Self {
        let code = locale
            .split(['_', '.', '@'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();

        match code.as_str() {
            // "C" and "POSIX" are not real languages; they mean "no locale".
            "en" | "c" | "posix" => Self::En,
            _ => Self::default(),
        }
    }

    /// Renders a message in this language.
    pub fn render(self, message: &Msg) -> String {
        match self {
            Self::En => en::render(message),
        }
    }
}

/// A user-facing message, as structured data rather than text.
///
/// Variants carry the values to interpolate; the wording lives in the
/// per-language catalogues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    // --- Distro detection ---
    OsReleaseUnreadable {
        path: String,
        source: String,
    },
    OsReleaseMissingId {
        path: String,
    },
    UnsupportedDistro {
        id: String,
        id_like: Option<String>,
    },

    // --- Command execution ---
    ProgramNotFound {
        program: String,
    },
    CommandFailed {
        command: String,
        code: i32,
        stderr: String,
    },
    CommandTerminatedBySignal {
        command: String,
    },
    CommandIo {
        command: String,
        source: String,
    },

    // --- Privileges ---
    NoPrivilegeEscalator,

    // --- SSH ---
    InvalidSshdConfig {
        details: String,
    },
    InvalidPublicKey {
        reason: String,
    },
    InvalidPort {
        port: u32,
    },
    InvalidAllowUsers {
        reason: String,
    },
    LockoutNoKeyForRoot,
    LockoutUnknownUser {
        user: String,
    },
    LockoutNoKeyForAllowedUsers {
        users: String,
    },
    MissingParameter {
        name: String,
    },
    TaskVanished {
        task: String,
    },
    MissingGroup {
        group: String,
    },
    AccountExists {
        user: String,
    },
    NoSuchAccount {
        user: String,
    },
    GroupMembershipFailed {
        user: String,
        group: String,
    },
    NotAnAdministrator {
        user: String,
        group: String,
    },
    NoAuthorizedKey {
        user: String,
    },
    AdminCannotBeRoot,
    ShellNotListed {
        shell: String,
    },

    // --- Tasks ---
    TaskUnsupported {
        task: String,
        family: String,
    },

    // --- Consequences ---
    ConsequencePortChanged {
        task: String,
        from: String,
        to: String,
    },
    ConsequenceRequiresSetting {
        task: String,
        setting: String,
    },
    ConsequenceNeedsRestart {
        task: String,
        service: String,
    },
    ConsequenceAccountNotListed {
        task: String,
        user: String,
    },
    ConsequenceConflictsOverBanRules {
        task: String,
    },
    ConsequenceProviderFirewall {
        port: String,
        protocol: String,
    },
    ConsequenceDnsMustResolve,

    // --- Terminal ---
    Terminal {
        source: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_locale_falls_back_to_english() {
        assert_eq!(Lang::from_locale("de_DE.UTF-8"), Lang::En);
        assert_eq!(Lang::from_locale(""), Lang::En);
    }

    #[test]
    fn parses_language_ignoring_territory_and_encoding() {
        assert_eq!(Lang::from_locale("en_US.UTF-8"), Lang::En);
        assert_eq!(Lang::from_locale("en"), Lang::En);
        assert_eq!(Lang::from_locale("EN_GB"), Lang::En);
    }

    #[test]
    fn c_and_posix_locales_resolve_to_english() {
        assert_eq!(Lang::from_locale("C"), Lang::En);
        assert_eq!(Lang::from_locale("POSIX"), Lang::En);
    }

    #[test]
    fn renders_interpolated_values() {
        let rendered = Lang::En.render(&Msg::InvalidPort { port: 70_000 });
        assert!(rendered.contains("70000"), "port must appear: {rendered}");
    }
}
