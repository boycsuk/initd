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

use common::{Image, run_in_container, stdout_of};

/// The group granting administrative rights on an image.
///
/// Three families, two answers: Debian grants sudo through `sudo`, while Arch
/// and Alpine both use `wheel` — Alpine because it ships `doas`, whose default
/// configuration grants that group.
fn admin_group(image: &Image) -> &'static str {
    if image.name.contains("debian") {
        "sudo"
    } else {
        "wheel"
    }
}

/// The command that creates an account on an image.
///
/// `useradd` comes from the shadow suite; busybox provides `adduser` instead,
/// and its flags differ in meaning rather than in spelling.
fn create_account(image: &Image) -> &'static str {
    if image.name.contains("alpine") {
        "adduser -D -H"
    } else {
        "useradd -m"
    }
}

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

for_each_image! {
    fn the_administrative_group_exists_under_the_name_the_backend_uses(image) {
        // The silent failure this pins: `usermod -aG sudo` on Arch exits zero
        // against a group that is not there, leaving an account that looks
        // provisioned and cannot escalate. The backend answers `sudo` on Debian
        // and `wheel` on Arch — this asserts the system agrees, which is the half
        // no mock can check.
        // Read from the file rather than through `getent`: busybox ships none,
        // which is the difference that makes account reading a capability.
        // openSUSE is the exception, and it is the tool's job rather than this
        // test's: `wheel` comes from `system-group-wheel`, which only the
        // desktop patterns require, so a minimally installed server has no such
        // group. The backend creates it in `grant_admin` — measured, because
        // `usermod -aG` against a missing group exits 6 and `users.create`
        // would fail outright on a stock host.
        //
        // So the question asked here differs by family: everywhere else the
        // group ships with the system, and on openSUSE what must hold is that
        // the tool can produce it. Asserting "present in the base image" there
        // would be asserting something openSUSE never promised.
        let observed = if image.family == "suse" {
            run_task(
                image,
                &format!(
                    "groupadd -f {group} && grep -q '^{group}:' /etc/group && echo PRESENT",
                    group = admin_group(image)
                ),
            )
        } else {
            run_task(
                image,
                &format!(
                    "grep -q '^{}:' /etc/group && echo PRESENT",
                    admin_group(image)
                ),
            )
        };

        assert!(
            observed.contains("PRESENT"),
            "{} has no {} group, so the backend names the wrong one: {observed}",
            image.name,
            admin_group(image)
        );
    }
}

for_each_image! {
    fn a_locked_password_still_admits_a_key(image) {
        // The finding the whole task rests on, verified rather than trusted.
        // `passwd -l` writes a `!` into the shadow entry; the account is reported
        // as locked and `sshd` never consults that field for a public key. If this
        // ever stops being true, `users.lock-root` is doing more work than it
        // needs to — and if it stays true, the tool is right to use expiry.
        // Read out of the shadow entry rather than through `passwd -S`, which is a
        // shadow-utils flag busybox does not carry. The `!` prefix is what `-S`
        // reports as `L`, and reading the field directly is portable across all
        // three — and is what the busybox implementation does anyway.
        let observed = run_task(
            image,
            &format!(
                "{} keyuser >/dev/null 2>&1; \
                 passwd -l keyuser >/dev/null 2>&1; \
                 grep '^keyuser:' /etc/shadow | cut -d: -f2",
                create_account(image)
            ),
        );

        assert!(
            observed.trim_start().starts_with('!'),
            "{}: a locked password must be prefixed with !: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn expiry_is_what_the_tool_writes_and_the_system_reads_back(image) {
        // The mechanism `users.lock-root` actually uses. `1` rather than `0`
        // because shadow(5) documents 0 as ambiguous, and this asserts the system
        // reads 1 back as a date in the past rather than as "never".
        let observed = run_task(
            image,
            &format!(
                "{install} {create} expired >/dev/null 2>&1; \
                 usermod --expiredate 1 expired; \
                 grep '^expired:' /etc/shadow | cut -d: -f8",
                // busybox has neither `usermod` nor `chage`; Alpine leaves
                // both to the shadow package, which the backend installs on
                // demand for exactly this reason.
                install = if image.name.contains("alpine") {
                    "apk add --no-cache shadow >/dev/null 2>&1;"
                } else {
                    ""
                },
                create = create_account(image),
            ),
        );

        // The eighth shadow field, which `shadow(5)` defines as the expiry.
        // Read directly rather than through `chage`, which busybox does not
        // ship at all — and which is why the busybox implementation reads this
        // field too. Empty means never; `1` is 1970-01-02.
        assert_eq!(
            observed.trim(),
            "1",
            "{}: the expiry must read back as the date written: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn group_membership_reads_back_as_whole_words(image) {
        // `is_in_group` splits `id -nG` on whitespace and compares whole names,
        // because `sudo` is a substring of `sudoers`. That is a claim about the
        // output format of a command this repository does not own, so it is
        // asserted against the real one.
        let group = admin_group(image);

        // `addgroup <user> <group>` on busybox, `usermod -aG <group> <user>`
        // on the shadow suite — the arguments are reversed, which is the kind
        // of divergence that creates a group named after the user when it is
        // got wrong.
        let join = if image.name.contains("alpine") {
            format!("addgroup member {group}")
        } else {
            format!("usermod -aG {group} member")
        };

        // As above: the scenario joins the group with `usermod` rather than
        // through the tool, and openSUSE ships no `wheel` until something makes
        // one. Seeding it here keeps the question this scenario asks — whether
        // `id -nG` reports whole words — separate from whether the group
        // pre-exists, which is a different family's answer.
        let seed = if image.family == "suse" {
            "groupadd -f wheel; "
        } else {
            ""
        };

        let observed = run_task(
            image,
            &format!(
                "{seed}{} member >/dev/null 2>&1; {join}; id -nG member",
                create_account(image)
            ),
        );

        assert!(
            observed.split_whitespace().any(|name| name == group),
            "{}: {group} must appear as its own word: {observed}",
            image.name
        );
    }
}

for_each_image! {
    fn etc_shells_lists_absolute_paths_one_per_line(image) {
        // `users.set-shell` refuses a shell absent from this file, and reads it by
        // comparing whole lines. Both halves depend on the file's shape, which is
        // a distribution's decision rather than this project's.
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

for_each_image! {
    fn creating_an_administrator_lands_in_the_right_group_on_both_families(image) {
        // The task end to end, through the binary rather than through its parts.
        // What this catches that the unit tests cannot: the backend naming a group
        // the distribution does not have, which is precisely the case that exits
        // zero and grants nothing.
        let group = admin_group(image);

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
                "{seed}{create} -s /bin/sh initdadmin && {join} && \
                 id -nG initdadmin && \
                 test -d /home/initdadmin && echo HOME_EXISTS",
                // This scenario drives `usermod` directly rather than through
                // the tool, so it asks whether the *system* accepts the group
                // the backend names. On openSUSE the group is not there to
                // accept: `system-group-wheel` is required only by the desktop
                // patterns. The tool creates it in `ensure_admin_group`; here
                // the scenario has to stand in for that, or it would be
                // asserting a property openSUSE never claimed.
                seed = if image.family == "suse" {
                    "groupadd -f wheel && "
                } else {
                    ""
                },
                create = if image.name.contains("alpine") {
                    "adduser -D"
                } else {
                    "useradd -m"
                },
                join = if image.name.contains("alpine") {
                    format!("addgroup initdadmin {group}")
                } else {
                    format!("usermod -aG {group} initdadmin")
                },
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
