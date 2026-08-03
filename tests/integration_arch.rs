//! Integration tests against a real Arch container.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.

mod common;

use common::{ARCH, run_in_container, stdout_of};

#[test]
#[ignore = "requires docker"]
fn detects_arch_inside_the_container() {
    require_docker!();

    let output = run_in_container(&ARCH, "initd detect");
    let stdout = stdout_of(&output);

    assert!(output.status.success(), "detect failed: {stdout}");
    assert!(stdout.contains("family:       arch"), "got: {stdout}");
    assert!(stdout.contains("id:           arch"), "got: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn installs_the_openssh_package_under_its_arch_name() {
    require_docker!();

    // The package is `openssh` here, not `openssh-server` as on Debian: this
    // is the divergence the backend abstraction exists to absorb.
    let output = run_in_container(
        &ARCH,
        "initd run ssh.install >/dev/null 2>&1; pacman -Q openssh",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("openssh"),
        "openssh must be installed: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn authorises_a_key_with_the_permissions_sshd_requires() {
    require_docker!();

    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";
    let output = run_in_container(
        &ARCH,
        &format!(
            "initd authorize-key root '{key}' >/dev/null 2>&1; \
             stat -c '%a' /root/.ssh; stat -c '%a' /root/.ssh/authorized_keys"
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
}

#[test]
#[ignore = "requires docker"]
fn missing_host_keys_do_not_block_a_port_change() {
    require_docker!();

    // The empirically verified Arch case: on a fresh install `sshd -t` fails
    // with "no hostkeys available" even though the config is fine. Treating
    // that as a syntax error would make the task refuse a valid file, so the
    // change must still be applied.
    let output = run_in_container(
        &ARCH,
        "pacman -S --needed --noconfirm openssh >/dev/null 2>&1; \
         rm -f /etc/ssh/ssh_host_*; \
         initd change-port 2222 >/dev/null 2>&1; \
         grep '^Port' /etc/ssh/sshd_config",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("Port 2222"),
        "a missing host key must not block a valid config: {stdout}"
    );
}

#[test]
#[ignore = "requires docker"]
fn hardening_refuses_without_an_authorised_key() {
    require_docker!();

    // The lockout guard must hold on a real system, not just against mocks.
    let output = run_in_container(
        &ARCH,
        "pacman -S --needed --noconfirm openssh >/dev/null 2>&1; \
         initd run ssh.harden 2>&1; \
         grep -c '^PasswordAuthentication no' /etc/ssh/sshd_config || true",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.trim().ends_with('0'),
        "password auth must not be disabled without a key: {stdout}"
    );
}
