//! Behaviour that is particular to Debian, not shared with every family.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! Invariants that must hold everywhere live in `integration_shared.rs`. Most
//! of what this file used to assert turned out to be exactly that, and moved
//! there — what remains is behaviour whose reason is specific to Debian.

mod common;

use common::{DEBIAN, run_in_container, stdout_of};

#[test]
#[ignore = "requires docker"]
fn detection_resolves_the_id_as_well_as_the_family() {
    require_docker!();

    // The counterpart to the Arch check: here `id` and `family` also coincide,
    // which pins the base case that ID_LIKE resolution is measured against. A
    // derivative reporting `debian` as its id would mean detection fell back
    // to the family and lost the distribution it actually found.
    let output = run_in_container(&DEBIAN, "initd detect");
    let stdout = stdout_of(&output);

    assert!(output.status.success(), "detect failed: {stdout}");
    assert!(stdout.contains("id:           debian"), "got: {stdout}");
}

#[test]
#[ignore = "requires docker"]
fn the_package_alone_leaves_a_daemon_that_validates() {
    require_docker!();

    // The mirror of Arch's inconclusive case, and the reason the two families
    // are worth running: installing openssh-server here generates host keys as
    // part of packaging, so `sshd -t` returns a verdict on the file. On Arch
    // that job belongs to a systemd unit which never runs in a container, so
    // the same command reports "no hostkeys available" and decides nothing.
    //
    // No `ssh-keygen -A` here, deliberately — that is what the shared helper
    // does to make validation conclusive everywhere. This asserts the
    // untouched packaging behaviour, which is what makes the divergence real
    // rather than an artefact of how the tests set themselves up.
    let output = run_in_container(
        &DEBIAN,
        "apt-get install -y -qq openssh-server >/dev/null 2>&1; \
         sshd -t && echo CONCLUSIVE",
    );
    let stdout = stdout_of(&output);

    assert!(
        stdout.contains("CONCLUSIVE"),
        "the package alone must leave a daemon that validates cleanly: {stdout}"
    );
}
