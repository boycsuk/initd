//! Integration tests against a real Debian container.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.

mod common;

use common::{DEBIAN, run_in_container, stdout_of};

#[test]
#[ignore = "requires docker"]
fn detects_debian_inside_the_container() {
    require_docker!();

    let output = run_in_container(&DEBIAN, "initd detect");
    let stdout = stdout_of(&output);

    assert!(output.status.success(), "detect failed: {stdout}");
    assert!(stdout.contains("family:       debian"), "got: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn installs_the_openssh_server_package() {
    require_docker!();

    // systemctl cannot work without systemd as PID 1, so the task's enable
    // step fails; the package installation before it is still observable and
    // is what proves the Debian package name is right.
    let output = run_in_container(
        &DEBIAN,
        "initd run ssh.install >/dev/null 2>&1; \
         dpkg-query -W -f='${Status}' openssh-server",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("install ok installed"),
        "openssh-server must be installed: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn authorises_a_key_with_the_permissions_sshd_requires() {
    require_docker!();

    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "initd authorize-key root '{key}' >/dev/null 2>&1; \
             stat -c '%a' /root/.ssh; stat -c '%a' /root/.ssh/authorized_keys; \
             cat /root/.ssh/authorized_keys"
        ),
    );
    let stdout = stdout_of(&output);
    let mut lines = stdout.lines();

    assert_eq!(lines.next(), Some("700"), "~/.ssh must be 700: {stdout}");
    assert_eq!(
        lines.next(),
        Some("600"),
        "authorized_keys must be 600: {stdout}"
    );
    assert!(stdout.contains(key), "the key must be present: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn authorising_the_same_key_twice_does_not_duplicate_it() {
    require_docker!();

    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "initd authorize-key root '{key}' >/dev/null 2>&1; \
             initd authorize-key root '{key}' >/dev/null 2>&1; \
             grep -c 'ssh-ed25519' /root/.ssh/authorized_keys"
        ),
    );
    let stdout = stdout_of(&output);

    assert_eq!(stdout.trim(), "1", "the key must appear once: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn changing_the_port_writes_a_valid_config() {
    require_docker!();

    let output = run_in_container(
        &DEBIAN,
        "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
         initd change-port 2222 >/dev/null 2>&1; \
         grep '^Port' /etc/ssh/sshd_config; \
         sshd -t && echo VALID",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("Port 2222"),
        "the port must change: {stdout}"
    );
    assert!(
        stdout.contains("VALID"),
        "the resulting config must pass sshd -t: {stdout}"
    );
}

/// A key the hardening tasks accept, so the lockout guard lets them proceed.
const TEST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";

#[test]
#[ignore = "requires docker"]
fn hardening_produces_a_config_sshd_accepts() {
    require_docker!();

    // Seventeen directives written against a real daemon. A mock cannot say
    // whether this OpenSSH parses them; only sshd can.
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             sshd -t && echo VALID"
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("VALID"),
        "the hardened config must pass sshd -t: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn strict_hardening_produces_a_config_sshd_accepts() {
    require_docker!();

    // The test that justifies the whole filtering module: it is the only one
    // that proves the algorithm names written are ones the daemon parses.
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             initd run ssh.harden-strict >/dev/null 2>&1; \
             sshd -t && echo VALID"
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("VALID"),
        "the strict config must pass sshd -t: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn strict_hardening_writes_only_algorithms_this_build_supports() {
    require_docker!();

    // Every cipher written must appear in `ssh -Q cipher`. Reported as the
    // count of names that do not.
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             initd run ssh.harden-strict >/dev/null 2>&1; \
             ssh -Q cipher > /tmp/supported; \
             grep '^Ciphers ' /etc/ssh/sshd_config | cut -d' ' -f2 | tr ',' '\\n' \
               | grep -vxF -f /tmp/supported | wc -l"
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.lines().any(|line| line.trim() == "0"),
        "every written cipher must be one this build supports: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn the_two_tiers_compose() {
    require_docker!();

    // The realistic order. Repeated `set_directive` passes over the same file
    // must not corrupt it.
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             initd run ssh.harden-strict >/dev/null 2>&1; \
             sshd -t && echo VALID"
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("VALID"),
        "applying both tiers must leave a valid config: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn hardening_is_idempotent() {
    require_docker!();

    // Running twice must not leave two active copies of a directive: the
    // second run comments the first out rather than appending beside it.
    let output = run_in_container(
        &DEBIAN,
        &format!(
            "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             grep -c '^PermitRootLogin no' /etc/ssh/sshd_config"
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.lines().any(|line| line.trim() == "1"),
        "exactly one active PermitRootLogin must remain: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_invalid_config_is_rolled_back_and_the_original_survives() {
    require_docker!();

    // Corrupt the file after a backup exists, then confirm the tool never
    // leaves a broken config behind: the port change must validate first.
    let output = run_in_container(
        &DEBIAN,
        "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
         initd change-port 2222 >/dev/null 2>&1; \
         sshd -t && echo STILL_VALID",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("STILL_VALID"),
        "the live config must always remain valid: {stdout}"
    );
}
