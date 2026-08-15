//! Behaviour that is particular to Arch, not shared with every family.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! Invariants that must hold everywhere live in `integration_shared.rs`. What
//! remains here is behaviour whose *reason* is specific to this distribution —
//! each one states that reason, because a scenario that cannot say why it is
//! not shared is usually a shared scenario in the wrong file.

mod common;

use common::{ARCH, run_in_container, stdout_of};

#[test]
#[ignore = "requires docker"]
fn detection_resolves_the_id_as_well_as_the_family() {
    require_docker!();

    // Arch is where `id` and `family` coincide, which is the case a shared
    // scenario cannot assert: on Ubuntu the id is `ubuntu` and the family is
    // `debian`, resolved through ID_LIKE. Only checking the family would let a
    // backend claim the right family while reporting the wrong distribution.
    let output = run_in_container(&ARCH, "initd detect");
    let stdout = stdout_of(&output);

    assert!(output.status.success(), "detect failed: {stdout}");
    assert!(stdout.contains("id:           arch"), "got: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn missing_host_keys_do_not_block_a_port_change() {
    require_docker!();

    // The empirically verified Arch case, and the reason `NON_SYNTAX_FAILURES`
    // exists: on a fresh install `sshd -t` fails with "no hostkeys available"
    // even though the config is fine. Treating that as a syntax error would
    // make the task refuse a valid file, so the change must still be applied.
    //
    // Not shared, because it needs the host keys removed first — a state the
    // other families' images do not naturally arrive at, and one that would be
    // destroyed outright if these images were ever pre-baked with keys.
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
fn hardening_applies_even_when_every_validation_is_inconclusive() {
    require_docker!();

    // A fresh Arch container has no host keys, so *every* `sshd -t` here
    // returns the inconclusive failure. If the directive probe read that as
    // "unknown keyword" the whole tier would be skipped — and this test would
    // find the directives missing.
    //
    // The shared tier scenarios cannot catch this: they install openssh, which
    // on Debian generates host keys, so validation there is conclusive.
    let output = run_in_container(
        &ARCH,
        &format!(
            // The key goes to an ordinary account rather than to root:
            // `ssh.harden` writes `PermitRootLogin no`, so a root key
            // authorises nothing afterwards and its guard does not count it.
            "pacman -S --needed --noconfirm openssh >/dev/null 2>&1; \
             rm -f /etc/ssh/ssh_host_*; \
             useradd -m initdops >/dev/null 2>&1; \
             initd authorize-key initdops '{}' >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             grep -c '^MaxAuthTries 3' /etc/ssh/sshd_config",
            common::TEST_KEY
        ),
    );
    let stdout = stdout_of(&output);

    assert!(
        common::has_line(&stdout, "1"),
        "the safe tier must apply even with no host keys present: {stdout}"
    );
}
