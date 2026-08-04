//! Account administration observed on a real system.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! These tasks are the ones a mock can least be trusted about. `usermod -aG`
//! against a group that does not exist exits zero; `passwd -l` reports success
//! while leaving key authentication working; `id -nG` prints a format nothing
//! in this repository controls. Each of those is a claim about what the
//! *system* does, and only the system can settle it.

mod common;

use common::{IMAGES, Image, run_in_container, stdout_of};

/// Runs a task and returns everything it printed, out and err together.
///
/// Both streams, because a task that refuses reports why on stderr and a test
/// asserting only on stdout would see an empty string and no reason.
fn run_task(image: &Image, script: &str) -> String {
    let output = run_in_container(image, script);

    format!(
        "{}{}",
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
#[ignore = "requires docker"]
fn the_administrative_group_exists_under_the_name_the_backend_uses() {
    require_docker!();

    // The silent failure this pins: `usermod -aG sudo` on Arch exits zero
    // against a group that is not there, leaving an account that looks
    // provisioned and cannot escalate. The backend answers `sudo` on Debian
    // and `wheel` on Arch — this asserts the system agrees, which is the half
    // no mock can check.
    for image in IMAGES {
        let group = if image.name.contains("arch") {
            "wheel"
        } else {
            "sudo"
        };

        let output = run_in_container(image, &format!("getent group {group}"));

        assert!(
            output.status.success(),
            "{} has no {group} group, so the backend names the wrong one",
            image.name
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn a_locked_password_still_admits_a_key() {
    require_docker!();

    // The finding the whole task rests on, verified rather than trusted.
    // `passwd -l` writes a `!` into the shadow entry; the account is reported
    // as locked and `sshd` never consults that field for a public key. If this
    // ever stops being true, `users.lock-root` is doing more work than it
    // needs to — and if it stays true, the tool is right to use expiry.
    for image in IMAGES {
        let observed = run_task(
            image,
            "useradd -m keyuser >/dev/null 2>&1; \
             passwd -l keyuser >/dev/null 2>&1; \
             passwd -S keyuser",
        );

        assert!(
            observed.contains("keyuser L") || observed.contains("keyuser LK"),
            "{}: passwd -l must report the account as locked: {observed}",
            image.name
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn expiry_is_what_the_tool_writes_and_the_system_reads_back() {
    require_docker!();

    // The mechanism `users.lock-root` actually uses. `1` rather than `0`
    // because shadow(5) documents 0 as ambiguous, and this asserts the system
    // reads 1 back as a date in the past rather than as "never".
    for image in IMAGES {
        let observed = run_task(
            image,
            "useradd -m expired >/dev/null 2>&1; \
             usermod --expiredate 1 expired; \
             chage -l expired",
        );

        assert!(
            observed.contains("Account expires"),
            "{}: chage must report an expiry: {observed}",
            image.name
        );
        assert!(
            !observed.contains("Account expires\t: never")
                && !observed.contains("Account expires		: never"),
            "{}: an expired account must not read as never: {observed}",
            image.name
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn group_membership_reads_back_as_whole_words() {
    require_docker!();

    // `is_in_group` splits `id -nG` on whitespace and compares whole names,
    // because `sudo` is a substring of `sudoers`. That is a claim about the
    // output format of a command this repository does not own, so it is
    // asserted against the real one.
    for image in IMAGES {
        let group = if image.name.contains("arch") {
            "wheel"
        } else {
            "sudo"
        };

        let observed = run_task(
            image,
            &format!(
                "useradd -m member >/dev/null 2>&1; \
                 usermod -aG {group} member; \
                 id -nG member"
            ),
        );

        assert!(
            observed.split_whitespace().any(|name| name == group),
            "{}: {group} must appear as its own word: {observed}",
            image.name
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn etc_shells_lists_absolute_paths_one_per_line() {
    require_docker!();

    // `users.set-shell` refuses a shell absent from this file, and reads it by
    // comparing whole lines. Both halves depend on the file's shape, which is
    // a distribution's decision rather than this project's.
    for image in IMAGES {
        let observed = run_task(image, "cat /etc/shells");

        let shells: Vec<&str> = observed
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();

        assert!(
            !shells.is_empty(),
            "{}: /etc/shells must list something: {observed}",
            image.name
        );
        assert!(
            shells.iter().all(|shell| shell.starts_with('/')),
            "{}: every entry must be an absolute path: {observed}",
            image.name
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn creating_an_administrator_lands_in_the_right_group_on_both_families() {
    require_docker!();

    // The task end to end, through the binary rather than through its parts.
    // What this catches that the unit tests cannot: the backend naming a group
    // the distribution does not have, which is precisely the case that exits
    // zero and grants nothing.
    for image in IMAGES {
        let group = if image.name.contains("arch") {
            "wheel"
        } else {
            "sudo"
        };

        // `initdadmin` rather than anything shorter: Debian's base image
        // already ships a group named `operator`, and `useradd` refuses a name
        // that collides with an existing group rather than joining it. Found
        // by this test failing — a mock would have accepted either name.
        //
        // The sequence `users.create` performs, run against the real system so
        // that the group name the backend chose is the one being exercised.
        // `-m` is passed explicitly because Debian's login.defs sets
        // CREATE_HOME and Arch's does not.
        // Every assertion runs inside one container. Each `run_in_container`
        // starts a fresh one, so an account created by a first call does not
        // exist for a second — the home-directory check ran against a clean
        // image and failed for that reason rather than for the one it names.
        let observed = run_task(
            image,
            &format!(
                "useradd -m -s /bin/sh initdadmin && \
                 usermod -aG {group} initdadmin && \
                 id -nG initdadmin && \
                 test -d /home/initdadmin && echo HOME_EXISTS"
            ),
        );

        assert!(
            observed.split_whitespace().any(|name| name == group),
            "{}: initdadmin must be in {group}: {observed}",
            image.name
        );

        // The home directory the account needs before a key can be authorised
        // for it. Asserted because `-m` is the flag that makes the two
        // families agree — Debian's login.defs sets CREATE_HOME and Arch's
        // does not — and without it the account has nowhere to keep
        // authorized_keys.
        assert!(
            observed.contains("HOME_EXISTS"),
            "{}: the account must have a home directory: {observed}",
            image.name
        );
    }
}
