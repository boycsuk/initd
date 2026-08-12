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

/// Runs the installer as an unprivileged account, naming no directory.
///
/// The scenario the reported failure came from. `INITD_INSTALL_DIR` is
/// deliberately *not* set: needing it is the thing under test.
///
/// `python:3-alpine` like its neighbour, which also makes this the image where
/// `sha256sum` is busybox's applet — the one that knows neither
/// `--ignore-missing` nor `--check`, and refused a genuine release until the
/// verification stopped depending on them.
///
/// `/usr/local/bin` is made root-owned first, so `deploy` genuinely cannot
/// write there and the fallback is genuinely exercised.
///
/// The assertions use `has_line` rather than `contains`, and that is not a
/// stylistic preference: `NOT_INSTALLED` **contains** `INSTALLED`, so the
/// obvious spelling passes when the install failed. Found by deleting the
/// fallback and watching the test pass anyway — the same substring trap this
/// project already recorded for `is-active`, where `inactive` contains
/// `active`. A test that cannot fail proves nothing, so this one was checked
/// against a deliberately broken script rather than assumed to work.
fn run_installer_as_user() -> String {
    let script = fs::read_to_string("install.sh").expect("the install script must be readable");

    let script = script.replace("--proto '=https' --tlsv1.2", "").replace(
        "https://github.com/$REPO/releases/latest/download",
        "http://127.0.0.1:8000",
    );

    let scenario = format!(
        "set -e\n\
         apk add --no-cache curl shadow >/dev/null 2>&1\n\
         adduser -D -s /bin/sh deploy\n\
         mkdir -p release\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-x86_64-unknown-linux-musl\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-aarch64-unknown-linux-musl\n\
         (cd release && sha256sum initd-* > SHA256SUMS)\n\
         (cd release && python3 -m http.server 8000 >/dev/null 2>&1 &)\n\
         sleep 2\n\
         cat > /install.sh <<'INSTALLER_EOF'\n\
         {script}\n\
         INSTALLER_EOF\n\
         chmod 0644 /install.sh\n\
         chmod 0755 /usr/local/bin\n\
         chown root:root /usr/local/bin\n\
         chmod go-w /usr/local/bin\n\
         su deploy -s /bin/sh -c 'sh /install.sh' 2>&1 || true\n\
         echo \"--- installed? ---\"\n\
         test -x /home/deploy/.local/bin/initd && echo INSTALLED || echo NOT_INSTALLED\n"
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

/// Runs the installer as an account with sudo, either passwordless or not.
///
/// `debian:13` rather than the Alpine image its neighbours use, because this
/// is about sudo and Alpine ships none — `doas` is its equivalent, and the
/// script checks for that too, but a scenario asserting on both would be
/// testing two things at once.
///
/// The run is wrapped in `timeout` with stdin closed. That is the assertion as
/// much as the output is: a script piped into a shell cannot answer a password
/// prompt, so one that waits for an answer must fail this rather than stall it.
fn run_installer_with_sudo(passwordless: bool) -> String {
    let script = fs::read_to_string("install.sh").expect("the install script must be readable");

    let script = script.replace("--proto '=https' --tlsv1.2", "").replace(
        "https://github.com/$REPO/releases/latest/download",
        "http://127.0.0.1:8000",
    );

    let sudoers = if passwordless {
        "deploy ALL=(ALL) NOPASSWD: ALL"
    } else {
        "deploy ALL=(ALL) ALL"
    };

    let scenario = format!(
        "set -e\n\
         apt-get update -qq >/dev/null 2>&1\n\
         apt-get install -y -qq python3 curl ca-certificates sudo >/dev/null 2>&1\n\
         useradd -m -s /bin/sh deploy\n\
         echo '{sudoers}' > /etc/sudoers.d/deploy\n\
         chmod 0440 /etc/sudoers.d/deploy\n\
         mkdir -p release\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-x86_64-unknown-linux-musl\n\
         printf '#!/bin/sh\\necho genuine\\n' > release/initd-aarch64-unknown-linux-musl\n\
         (cd release && sha256sum initd-* > SHA256SUMS)\n\
         (cd release && python3 -m http.server 8000 >/dev/null 2>&1 &)\n\
         sleep 2\n\
         cat > /install.sh <<'INSTALLER_EOF'\n\
         {script}\n\
         INSTALLER_EOF\n\
         chmod 0644 /install.sh\n\
         timeout 60 su deploy -s /bin/sh -c 'sh /install.sh </dev/null' 2>&1 || echo TIMED_OUT\n"
    );

    let output = Command::new("docker")
        .args(["run", "--rm", "debian:13", "sh", "-c", &scenario])
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
        common::has_line(&observed, "INSTALLED"),
        "a release matching its checksum must install: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_ordinary_account_installs_without_being_told_where() {
    require_docker!();

    // The case reported from a real host: `curl … | sh` as `deploy`, answered
    // with "run as root, or set INITD_INSTALL_DIR". Neither should be needed —
    // an account that cannot write to `/usr/local/bin` is the ordinary case
    // for a script piped into a shell, not an error.
    let observed = run_installer_as_user();

    assert!(
        common::has_line(&observed, "INSTALLED"),
        "an unprivileged account must get a working install: {observed}"
    );
    assert!(
        observed.contains(".local/bin"),
        "it must land in the account's own bin directory: {observed}"
    );
    assert!(
        !observed.contains("run as root"),
        "and must not ask for root: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_account_that_can_escalate_installs_system_wide() {
    require_docker!();

    // An account with passwordless sudo is an administrator, and the binary
    // belongs where administrators keep binaries: in one account's home a
    // second administrator would not find it, and `sudo initd` would not
    // resolve it either.
    let observed = run_installer_with_sudo(true);

    assert!(
        observed.contains("installed /usr/local/bin/initd"),
        "an account that can escalate must install system-wide: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn sudo_that_would_ask_for_a_password_is_not_used() {
    require_docker!();

    // The case that decides the whole design. `curl … | sh` has already spent
    // stdin on the script, so a password prompt has nowhere to read from: it
    // hangs, or fails in a way that reads as the installer being broken. So
    // "can I escalate" is asked with `sudo -n`, which refuses rather than
    // prompting, and a refusal means the home directory instead.
    //
    // The scenario runs under `timeout` with stdin closed: hanging fails it
    // rather than stalling the suite.
    let observed = run_installer_with_sudo(false);

    assert!(
        observed.contains(".local/bin/initd"),
        "sudo that would prompt must not be used: {observed}"
    );
    assert!(
        !observed.contains("TIMED_OUT"),
        "and asking must never block on a prompt nobody can answer: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_install_the_shell_cannot_reach_says_so() {
    require_docker!();

    // A report of success the operator cannot act on is worse than the refusal
    // it replaced. Measured across the images: Debian adds `~/.local/bin` to
    // PATH only once it exists, Rocky adds it from `.bashrc` — which a `sh`
    // login never reads — and Alpine adds it nowhere. So on most of them the
    // install succeeds and `initd` is still not found.
    let observed = run_installer_as_user();

    assert!(
        observed.contains("not on your PATH"),
        "the note must be printed when the shell will not find it: {observed}"
    );
    assert!(
        observed.contains("export PATH="),
        "and must name the line to add rather than saying 'adjust your PATH': {observed}"
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
        common::has_line(&observed, "NOT_INSTALLED"),
        "a binary that does not match its checksum must not be installed: {observed}"
    );
    assert!(
        observed.contains("did not match"),
        "the refusal must name the reason: {observed}"
    );
}
