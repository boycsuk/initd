//! `/etc/os-release` parsing and family resolution.
//!
//! Format reference: `os-release(5)`. Values may be quoted with single or
//! double quotes, or left bare; comments and blank lines are allowed.

use std::collections::HashMap;
use std::path::Path;

use super::{Distro, Family};
use crate::error::{Error, Result};

/// Canonical location of the release metadata.
///
/// `os-release(5)` defines `/usr/lib/os-release` as the fallback for systems
/// where `/etc` may be absent, and `/etc/os-release` as a symlink to it.
const OS_RELEASE_PATH: &str = "/etc/os-release";
const OS_RELEASE_FALLBACK_PATH: &str = "/usr/lib/os-release";

/// Detects the running distribution from the standard system location.
///
/// Falls back to `/usr/lib/os-release` when `/etc/os-release` is missing, as
/// the specification prescribes.
pub fn detect() -> Result<Distro> {
    let primary = Path::new(OS_RELEASE_PATH);
    let path = if primary.exists() {
        primary
    } else {
        Path::new(OS_RELEASE_FALLBACK_PATH)
    };

    detect_from_path(path)
}

/// Detects the distribution described by a specific `os-release` file.
///
/// Exposed so tests can run against fixtures instead of the host system.
pub fn detect_from_path(path: &Path) -> Result<Distro> {
    let contents = std::fs::read_to_string(path).map_err(|source| Error::OsReleaseUnreadable {
        path: path.to_path_buf(),
        source,
    })?;

    parse(&contents, path)
}

/// Parses `os-release` contents into a [`Distro`].
pub fn parse(contents: &str, path: &Path) -> Result<Distro> {
    let fields = parse_fields(contents);

    let id = fields
        .get("ID")
        .ok_or_else(|| Error::OsReleaseMissingId {
            path: path.to_path_buf(),
        })?
        .clone();

    let id_like = fields.get("ID_LIKE").cloned();
    let family =
        resolve_family(&id, id_like.as_deref()).ok_or_else(|| Error::UnsupportedDistro {
            id: id.clone(),
            id_like: id_like.clone(),
        })?;

    Ok(Distro {
        id,
        version_id: fields.get("VERSION_ID").cloned(),
        pretty_name: fields.get("PRETTY_NAME").cloned(),
        family,
    })
}

/// Splits `KEY=VALUE` lines into a map, unquoting values.
fn parse_fields(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), unquote(value.trim()).to_owned()))
        .collect()
}

/// Strips one layer of matching single or double quotes.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    let is_quoted = bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0];

    if is_quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Resolves a family from `ID`, falling back to `ID_LIKE` for derivatives.
///
/// `ID` wins so that a distribution is never mistaken for its parent. Only if
/// it matches nothing is `ID_LIKE` consulted, in its declared order — the
/// specification lists it most-closely-related first.
fn resolve_family(id: &str, id_like: Option<&str>) -> Option<Family> {
    if let Some(family) = family_from_id(id) {
        return Some(family);
    }

    id_like
        .into_iter()
        .flat_map(str::split_whitespace)
        .find_map(family_from_id)
}

/// Maps a single `os-release` identifier to its family.
fn family_from_id(id: &str) -> Option<Family> {
    match id.to_ascii_lowercase().as_str() {
        "debian" | "ubuntu" => Some(Family::Debian),
        "arch" | "archarm" => Some(Family::Arch),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Path reported as the origin of parsed contents in errors.
    fn default_path() -> PathBuf {
        PathBuf::from(OS_RELEASE_PATH)
    }

    /// Loads a fixture captured from a real system.
    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/os-release")
            .join(name);

        std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("fixture {} unreadable: {err}", path.display()))
    }

    fn parse_fixture(name: &str) -> Result<Distro> {
        parse(&fixture(name), &default_path())
    }

    #[test]
    fn detects_debian_from_id() {
        let distro = parse_fixture("debian13").expect("debian must resolve");

        assert_eq!(distro.family, Family::Debian);
        assert_eq!(distro.id, "debian");
        assert_eq!(distro.version_id.as_deref(), Some("13"));
    }

    #[test]
    fn detects_ubuntu_as_debian_family() {
        // Ubuntu declares ID=ubuntu; only ID_LIKE=debian ties it to the family.
        let distro = parse_fixture("ubuntu2404").expect("ubuntu must resolve");

        assert_eq!(distro.family, Family::Debian);
        assert_eq!(distro.id, "ubuntu");
    }

    #[test]
    fn detects_arch_without_version_id() {
        // Arch is a rolling release and declares no VERSION_ID.
        let distro = parse_fixture("arch").expect("arch must resolve");

        assert_eq!(distro.family, Family::Arch);
        assert_eq!(distro.version_id, None);
    }

    #[test]
    fn resolves_derivative_through_id_like() {
        let distro = parse_fixture("endeavouros").expect("endeavouros must resolve");

        assert_eq!(distro.family, Family::Arch);
        assert_eq!(distro.id, "endeavouros");
    }

    #[test]
    fn unsupported_distro_is_an_error_not_a_panic() {
        let err = parse_fixture("gentoo").expect_err("gentoo is not supported");

        assert!(
            matches!(err, Error::UnsupportedDistro { ref id, .. } if id == "gentoo"),
            "expected UnsupportedDistro, got: {err:?}"
        );
    }

    #[test]
    fn missing_id_is_an_error() {
        let err = parse("NAME=\"Something\"\n", &default_path())
            .expect_err("a file with no ID must fail");

        assert!(matches!(err, Error::OsReleaseMissingId { .. }), "{err:?}");
    }

    #[test]
    fn unreadable_file_is_an_error() {
        let err = detect_from_path(Path::new("/nonexistent/os-release"))
            .expect_err("a missing file must fail");

        assert!(matches!(err, Error::OsReleaseUnreadable { .. }), "{err:?}");
    }

    #[test]
    fn id_takes_precedence_over_id_like() {
        // A Debian-derived distro that also lists arch in ID_LIKE must still
        // resolve through its own ID first.
        assert_eq!(resolve_family("debian", Some("arch")), Some(Family::Debian));
    }

    #[test]
    fn id_like_may_list_several_values() {
        assert_eq!(
            resolve_family("mydistro", Some("mint ubuntu debian")),
            Some(Family::Debian)
        );
    }

    #[test]
    fn unquotes_both_quote_styles_and_bare_values() {
        let fields = parse_fields("A=\"double\"\nB='single'\nC=bare\n");

        assert_eq!(fields.get("A").map(String::as_str), Some("double"));
        assert_eq!(fields.get("B").map(String::as_str), Some("single"));
        assert_eq!(fields.get("C").map(String::as_str), Some("bare"));
    }

    #[test]
    fn ignores_comments_and_blank_lines() {
        let fields = parse_fields("# a comment\n\nID=debian\n\n  # indented\n");

        assert_eq!(fields.len(), 1);
        assert_eq!(fields.get("ID").map(String::as_str), Some("debian"));
    }

    #[test]
    fn keeps_values_containing_equals_signs() {
        // ANSI_COLOR and URLs can contain '=' after the first separator.
        let fields = parse_fields("URL=\"https://x.test/?a=b\"\n");

        assert_eq!(
            fields.get("URL").map(String::as_str),
            Some("https://x.test/?a=b")
        );
    }
}
