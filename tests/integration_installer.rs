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

/// The image most scenarios here run in.
///
/// Not the family matrix: what is under test is the bootstrap shell script,
/// which is the same on every distribution. Chosen for what it *lacks* —
/// neither `sudo` nor `doas` — which is what makes the no-route-to-root
/// scenarios possible, and it carries the `python3` the fake release is served
/// with.
const INSTALLER_IMAGE: &str = "python:3-alpine";

/// The image the sudo scenarios run in.
///
/// Alpine ships no `sudo`, and those scenarios are about `sudo` specifically.
/// Named separately rather than folded into the constant above, because the
/// guard reports the image it was given: one name covering two images would
/// print the wrong one at exactly the moment somebody is trying to work out
/// which container failed to start.
const SUDO_IMAGE: &str = "debian:13";

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
        .args(["run", "--rm", INSTALLER_IMAGE, "sh", "-c", &scenario])
        .output()
        .expect("docker run must execute");

    // Before the output is read as an answer. Without this a daemon that
    // refused to start reports as `a_tampered_binary_is_refused` failing —
    // "the install script does not verify checksums" — which is a security
    // claim about a script that never ran.
    common::panic_if_the_named_container_never_ran(INSTALLER_IMAGE, &output);

    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Runs the installer as an account with no route to root at all.
///
/// `python:3-alpine` ships neither `sudo` nor `doas`, which is what makes this
/// the "cannot escalate by any means" case rather than the "could, but would be
/// asked for a password" one its neighbour covers. The two call for different
/// advice and the script gives different advice, so they are tested apart.
///
/// `INITD_INSTALL_DIR` is deliberately not set: needing it was the original
/// complaint, and it is still not the answer.
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
         if test -x /home/deploy/.local/bin/initd || test -x /usr/local/bin/initd; \\\n\
         then echo INSTALLED; else echo NOT_INSTALLED; fi\n"
    );

    let output = Command::new("docker")
        .args(["run", "--rm", INSTALLER_IMAGE, "sh", "-c", &scenario])
        .output()
        .expect("docker run must execute");

    // Before the output is read as an answer. Without this a daemon that
    // refused to start reports as `a_tampered_binary_is_refused` failing —
    // "the install script does not verify checksums" — which is a security
    // claim about a script that never ran.
    common::panic_if_the_named_container_never_ran(INSTALLER_IMAGE, &output);

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
///
/// `TIMED_OUT` is reported on exit **124** specifically, which is what
/// `timeout` returns when it kills its child. A bare `|| echo TIMED_OUT` was
/// there first and was wrong: the script exits 1 when it refuses, so the label
/// appeared on a run that never hung — a harness saying "it hung" about a
/// deliberate, immediate refusal. The same shape of lie this project has
/// recorded before, where a helper reported a number the assertion then
/// interpreted.
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
         timeout 60 su deploy -s /bin/sh -c 'sh /install.sh </dev/null' 2>&1; \\\n\
         status=$?; \\\n\
         if test $status -eq 124; then echo TIMED_OUT; fi; \\\n\
         echo \"exit status: $status\"\n"
    );

    let output = Command::new("docker")
        .args(["run", "--rm", SUDO_IMAGE, "sh", "-c", &scenario])
        .output()
        .expect("docker run must execute");

    // Before the output is read as an answer. Without this a daemon that
    // refused to start reports as the script having stalled on a password
    // prompt — a claim about code that never ran.
    common::panic_if_the_named_container_never_ran(SUDO_IMAGE, &output);

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
fn an_account_with_no_route_to_root_is_refused() {
    require_docker!();

    // `initd` administers the machine: 138 of the commands it runs are
    // privileged. An account that cannot become root cannot run any of them,
    // so a copy of the binary in that account's home is a program that starts,
    // draws its interface and fails at the first thing anybody asks of it.
    //
    // A `~/.local/bin` fallback was written and removed for that reason. It
    // turned "you cannot install this" into "you have installed this and it
    // does not work", which is the worse of the two.
    let observed = run_installer_as_user();

    assert!(
        common::has_line(&observed, "NOT_INSTALLED"),
        "an account that cannot escalate must not get a binary: {observed}"
    );
    assert!(
        observed.contains("no route to root"),
        "the refusal must say why rather than naming a permission: {observed}"
    );
    assert!(
        observed.contains("Ask an administrator") || observed.contains("run it as root"),
        "and must say what would work instead: {observed}"
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
    // prompting.
    //
    // This account *can* administer the machine — it just cannot do so from a
    // script with no stdin — so the refusal tells it to run one command rather
    // than to find an administrator. Telling somebody with sudo to ask an
    // administrator would be telling them to ask themselves.
    //
    // The scenario runs under `timeout` with stdin closed: hanging fails it
    // rather than stalling the suite.
    let observed = run_installer_with_sudo(false);

    assert!(
        !observed.contains("TIMED_OUT"),
        "asking must never block on a prompt nobody can answer: {observed}"
    );
    assert!(
        observed.contains("| sudo sh"),
        "the refusal must name the command that would work: {observed}"
    );
    assert!(
        !observed.contains("Ask an administrator"),
        "and must not send an administrator looking for one: {observed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_install_the_shell_cannot_reach_says_so() {
    require_docker!();

    // `/usr/local/bin` is on every PATH this project has measured, so the note
    // is for `INITD_INSTALL_DIR` — which can name anywhere at all. A report of
    // success that leaves the operator unable to run the thing is worse than a
    // refusal, so the one case that can still produce it is pinned.
    let observed = run_installer(false);

    assert!(
        common::has_line(&observed, "INSTALLED"),
        "the control must still install: {observed}"
    );
    assert!(
        observed.contains("not on your PATH"),
        "/tmp/bin is not on PATH, so the note must be printed: {observed}"
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
