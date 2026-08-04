//! The install script's checksum check, exercised against a served release.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! The script is piped into a shell and runs as root, so the one thing it must
//! never do is install a binary whose digest does not match what was published
//! beside it. Asserting that by reading the script proves nothing — a `grep`
//! for `sha256sum` passes whether or not the result is acted on. So a release
//! is served from a directory, and the script is pointed at it: once intact,
//! once with the binary replaced after the digest was computed.

mod common;

use std::fs;
use std::process::Command;

/// Runs the install script against a release directory served from a container.
///
/// Everything happens inside one container: the script, the "release" it
/// downloads, and the directory it installs into. A second container would
/// start from a clean image and the installed file would not be there to
/// assert on — the same mistake the account scenarios made once.
fn run_installer(tamper: bool) -> String {
    let script = fs::read_to_string("install.sh").expect("the install script must be readable");

    // Served over plain HTTP from localhost, so the script's `--proto '=https'`
    // is relaxed for the run. That flag is not what is under test here — the
    // checksum check is — and pointing the script at a local file:// or http://
    // release is the only way to exercise it without publishing one.
    let script = script.replace("--proto '=https' --tlsv1.2", "").replace(
        "https://github.com/$REPO/releases/latest/download",
        "http://127.0.0.1:8000",
    );

    let tampering = if tamper {
        // Rewritten *after* the digest was computed, which is exactly the case
        // the check exists for: a binary substituted between publication and
        // download.
        "printf 'tampered' > release/initd-x86_64-unknown-linux-musl;"
    } else {
        ""
    };

    let scenario = format!(
        "set -e\n\
         apk add --no-cache curl >/dev/null 2>&1\n\
         mkdir -p release\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-x86_64-unknown-linux-musl\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-aarch64-unknown-linux-musl\n\
         (cd release && sha256sum initd-* > SHA256SUMS)\n\
         {tampering}\n\
         (cd release && python3 -m http.server 8000 >/dev/null 2>&1 &)\n\
         sleep 2\n\
         cat > /install.sh <<'INSTALLER_EOF'\n\
         {script}\n\
         INSTALLER_EOF\n\
         INITD_INSTALL_DIR=/tmp/bin sh /install.sh 2>&1 || true\n\
         echo \"--- installed? ---\"\n\
         test -f /tmp/bin/initd && echo INSTALLED || echo NOT_INSTALLED\n"
    );

    let output = Command::new("docker")
        .args(["run", "--rm", "python:3-alpine", "sh", "-c", &scenario])
        .output()
        .expect("docker run must execute");

    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
#[ignore = "requires docker"]
fn an_intact_release_installs() {
    require_docker!();

    // The control. Without it a script that refused *everything* would pass
    // the tampering scenario and look like a working check.
    let observed = run_installer(false);

    assert!(
        observed.contains("INSTALLED"),
        "a release matching its checksum must install: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn a_tampered_binary_is_refused() {
    require_docker!();

    // The scenario the whole file exists for: the binary replaced after its
    // digest was published. The script must not install it, and must say why.
    let observed = run_installer(true);

    assert!(
        observed.contains("NOT_INSTALLED"),
        "a binary that does not match its checksum must not be installed: {observed}"
    );
    assert!(
        observed.contains("did not match"),
        "the refusal must name the reason: {observed}"
    );
}
