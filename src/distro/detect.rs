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
        // Ubuntu derivatives declare their own `VERSION_CODENAME` and carry
        // the Ubuntu one in `UBUNTU_CODENAME`; Docker's repository is keyed by
        // the latter, since a derivative's own name is a suite Docker does not
        // serve. Docker's Debian and Ubuntu instructions differ in exactly this
        // way, which is why the fallback runs in that direction.
        codename: fields
            .get("UBUNTU_CODENAME")
            .or_else(|| fields.get("VERSION_CODENAME"))
            .cloned(),
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
        // `postmarketos` resolves through ID_LIKE rather than here: it reports
        // its own ID and names alpine as what it is like, which is exactly the
        // case ID_LIKE exists for.
        "alpine" => Some(Family::Alpine),
        // `rhel` is what Red Hat Enterprise Linux itself reports. The rebuilds
        // declare their own ID and reach this family through `ID_LIKE`, but are
        // named here as well: Rocky and AlmaLinux list `"rhel centos fedora"`,
        // and resolving them by their own ID keeps that dependency on a field
        // they are free to change out of the common path.
        "rhel" | "centos" | "rocky" | "almalinux" | "fedora" => Some(Family::Rhel),
        // openSUSE reports `opensuse-tumbleweed` or `opensuse-leap`; SLES
        // reports `sles`. The bare `opensuse` and `suse` are what both
        // variants carry in `ID_LIKE` — and they carry them in opposite
        // orders, `"opensuse suse"` on Tumbleweed against `"suse opensuse"` on
        // Leap. That costs nothing only because each token is resolved
        // independently: a reader taking the first entry as the family name
        // would work on one variant and not the other.
        "opensuse-tumbleweed" | "opensuse-leap" | "sles" | "opensuse" | "suse" => {
            Some(Family::Suse)
        }
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
    fn alpine_resolves_by_its_own_id() {
        let distro = parse_fixture("alpine").expect("alpine must resolve");

        assert_eq!(distro.family, Family::Alpine);
        assert_eq!(distro.id, "alpine");
    }

    #[test]
    fn an_alpine_derivative_resolves_through_id_like() {
        // postmarketOS reports its own ID and names alpine as what it is like,
        // which is the case ID_LIKE exists for. Resolving it proves the
        // fallback reaches the third family and not only the first two.
        let distro = parse_fixture("postmarketos").expect("postmarketos must resolve");

        assert_eq!(distro.family, Family::Alpine);
        assert_eq!(distro.id, "postmarketos", "the id it reported must survive");
    }

    #[test]
    fn detects_rhel_by_its_own_id() {
        let distro = parse_fixture("rhel10").expect("rhel must resolve");

        assert_eq!(distro.family, Family::Rhel);
        assert_eq!(distro.id, "rhel");
        assert_eq!(distro.version_id.as_deref(), Some("10.0"));
    }

    #[test]
    fn a_rhel_rebuild_resolves_by_its_own_id_not_its_id_like() {
        // Rocky declares `ID_LIKE="rhel centos fedora"`, so it would resolve
        // through the fallback either way. Naming it in `family_from_id` keeps
        // that off the common path: `ID` is the field a distribution owns, and
        // resolving by it means a rebuild dropping or reordering `ID_LIKE` does
        // not change which backend it gets.
        let distro = parse_fixture("rocky9").expect("rocky must resolve");

        assert_eq!(distro.family, Family::Rhel);
        assert_eq!(distro.id, "rocky", "the id it reported must survive");
    }

    #[test]
    fn detects_both_suse_variants_by_their_own_ids() {
        // Both are named in `family_from_id` rather than left to `ID_LIKE`,
        // for the reason the rebuilds are: `ID` is the field a distribution
        // owns.
        let tumbleweed = parse_fixture("tumbleweed").expect("tumbleweed must resolve");
        let leap = parse_fixture("leap16").expect("leap must resolve");

        assert_eq!(tumbleweed.family, Family::Suse);
        assert_eq!(tumbleweed.id, "opensuse-tumbleweed");
        assert_eq!(leap.family, Family::Suse);
        assert_eq!(leap.version_id.as_deref(), Some("16.0"));
    }

    #[test]
    fn the_suse_variants_order_id_like_differently_and_both_resolve() {
        // Captured from the two images: Tumbleweed reports `"opensuse suse"`
        // and Leap `"suse opensuse"`. Each token is resolved independently, so
        // the order costs nothing — but a reader taking the first entry as the
        // family name would work on one variant and fail on the other, which
        // is the bug this pins against rather than a restatement of the
        // fixtures.
        assert_eq!(
            resolve_family("something-suse-derived", Some("opensuse suse")),
            Some(Family::Suse)
        );
        assert_eq!(
            resolve_family("something-suse-derived", Some("suse opensuse")),
            Some(Family::Suse)
        );
    }

    #[test]
    fn sles_resolves_by_its_own_id() {
        // The enterprise distribution reports `sles` and shares openSUSE's
        // packaging, so it reaches the same backend.
        assert_eq!(resolve_family("sles", None), Some(Family::Suse));
    }

    #[test]
    fn an_unknown_rhel_derivative_still_resolves_through_id_like() {
        // The rebuilds named today are not the only ones there will be, and
        // this is the path that catches the rest.
        assert_eq!(
            resolve_family("oraclelinux", Some("fedora")),
            Some(Family::Rhel)
        );
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
