//! Scenarios that must hold on every supported distribution.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! Each scenario here is written once and expanded across [`common::IMAGES`] by
//! `for_each_image!`, producing one test per family. Behaviour that is
//! genuinely particular to one distribution does not belong here — it lives in
//! `integration_debian.rs` or `integration_arch.rs`, where the reason it is
//! particular can be stated.
//!
//! The dividing question is: *would this assertion still be meaningful on a
//! family that does not exist yet?* If yes, it is an invariant and belongs
//! here.
//!
//! # One documented case with no scenario
//!
//! `docs/cli.md` states that a task unsupported on the running distribution
//! exits `1`. Every task supports both families `Family` resolves, so that
//! branch cannot be reached from any container: it is waiting on a
//! distribution that does not exist yet, not on a test. It becomes reachable —
//! and worth covering — with the first family a task declines, which is the
//! same reason Alpine has no matrix entry.

mod common;

use common::{
    DEBIAN, has_line, run_in_container, run_with_os_release, run_with_ssh_ready, stdout_of,
};

for_each_image! {
    /// Detection must resolve the family the image actually is.
    ///
    /// The one scenario that would catch a backend resolved for the wrong
    /// family, which is the single mistake the whole indirection could make
    /// silently.
    fn detection_reports_the_right_family(image) {
        let output = run_in_container(image, "initd detect");
        let stdout = stdout_of(&output);

        assert!(output.status.success(), "detect failed: {stdout}");
        assert!(
            stdout.contains(&format!("family:       {}", image.family)),
            "expected family {}: {stdout}",
            image.family
        );
    }

    /// The three documented exit codes must mean what `docs/cli.md` says.
    ///
    /// The contract exists for automation — a script that retries on `1` and
    /// gives up on `2` depends on the difference — and nothing verified it.
    /// Every case here is one the documentation states, so a change to either
    /// side that is not matched on the other fails this.
    ///
    /// Grouped into one scenario rather than a dozen because each starts a
    /// container: as separate tests the cost would be a minute of pulls to
    /// answer twelve questions worth one assertion each.
    fn the_documented_exit_codes_hold(image) {
        // Succeeding commands. Read-only ones, since a scenario asserting on
        // the code should not depend on a task's side effects.
        for command in ["detect", "privileges", "list"] {
            assert_eq!(
                common::exit_code_of(image, command),
                0,
                "`initd {command}` must succeed"
            );
        }

        // Wrong invocation: an unknown subcommand, an unknown task, and every
        // subcommand that needs arguments it was not given.
        for command in [
            "definitely-not-a-subcommand",
            "run",
            "run no.such.task",
            "authorize-key",
            "authorize-key onlyauser",
            "change-port",
            "change-port not-a-number",
            // `run` with values: the same three ways an invocation can be
            // wrong, now that any task is reachable through it. A task whose
            // values are missing, one given a name it does not declare, and
            // one given a value that fails the check the interactive form
            // applies — the CLI never passes through the keystroke filter, so
            // this is the only barrier between an argument and a system file.
            "run firewall.allow-port",
            "run firewall.allow-port porta=443",
            "run firewall.allow-port port=99999",
            "run firewall.allow-port port=443 protocol=sctp",
            "run users.create user=has\\ a\\ space",
            // Refused whatever the arguments: both apply a change that can end
            // the session applying it, and only the interactive interface can
            // hold one open to be confirmed.
            "run ssh.allow-users users=root",
            // With no arguments at all, now that this task takes none: the
            // refusal is structural and precedes argument parsing, so it must
            // hold for the invocation a script would actually write.
            "run users.lock-root",
        ] {
            assert_eq!(
                common::exit_code_of(image, command),
                2,
                "`initd {command}` must exit 2 as a wrong invocation"
            );
        }

        // Failure: the invocation is well-formed and the work cannot be done.
        // The distinction from 2 is the whole point of having both.
        for command in ["change-port 99999", "authorize-key root not-a-valid-key"] {
            assert_eq!(
                common::exit_code_of(image, command),
                1,
                "`initd {command}` must exit 1 as a failure"
            );
        }
    }

    /// The port range must be enforced at both ends.
    ///
    /// `docs/cli.md` puts the valid range at 1–65535, and the codes either
    /// side of it differ: a non-numeric port is a wrong invocation (`2`), an
    /// out-of-range one is a failure (`1`). Both boundaries are checked
    /// together with the values just inside them, since an off-by-one in the
    /// comparison would show at exactly one of the four.
    ///
    /// The valid ports are asserted by their message rather than their exit
    /// code: with no openssh installed there is no `sshd_config` to edit, so
    /// they fail afterwards for a reason that has nothing to do with the
    /// range. Reading the code alone here would report the tool as rejecting
    /// port 1.
    fn the_port_range_is_enforced_at_both_ends(image) {
        for out_of_range in ["0", "65536"] {
            assert_eq!(
                common::exit_code_of(image, &format!("change-port {out_of_range}")),
                1,
                "port {out_of_range} is outside 1-65535 and must be refused"
            );
        }

        let output = run_with_ssh_ready(
            image,
            "initd change-port 1 2>&1 | head -1; initd change-port 65535 2>&1 | head -1",
        );
        let stdout = stdout_of(&output);

        assert!(
            !stdout.contains("invalid port"),
            "1 and 65535 are inside the range and must not be refused: {stdout}"
        );
    }

    /// An unknown task id must be refused before anything runs.
    ///
    /// `run` is the subcommand a script drives, and a typo in a task id must
    /// not be indistinguishable from a task that ran and did nothing. The code
    /// is checked above; this pins that it also says which id it did not know.
    fn running_an_unknown_task_names_the_identifier(image) {
        let output = run_in_container(image, "initd run ssh.hardne 2>&1");
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("ssh.hardne"),
            "the error must name the unknown identifier: {stdout}"
        );
    }

    /// `initd list` must print the task tree.
    ///
    /// The subcommand a script would use to discover what can be run, so its
    /// output is a contract: identifiers that change silently break callers.
    fn listing_prints_the_task_tree(image) {
        let output = run_in_container(image, "initd list");
        let stdout = stdout_of(&output);

        assert!(output.status.success(), "list must succeed: {stdout}");
        assert!(
            stdout.contains("ssh.harden") && stdout.contains("ssh.install"),
            "the tree must name its task identifiers: {stdout}"
        );
    }

    /// `initd privileges` must report that root needs no escalation.
    ///
    /// A container runs as uid 0, which is the case where the answer must be
    /// `none`: naming a mechanism there would mean the resolution ignored the
    /// effective user and would make every privileged command run under a
    /// `sudo` that is not needed and may not exist.
    fn privileges_reports_that_root_needs_no_escalation(image) {
        let output = run_in_container(image, "initd privileges");
        let stdout = stdout_of(&output);

        assert!(output.status.success(), "privileges must succeed: {stdout}");
        assert!(
            stdout.contains("effective uid: 0"),
            "a container runs as root: {stdout}"
        );
        assert!(
            stdout.contains("escalation: none"),
            "root must need no escalation mechanism: {stdout}"
        );
    }

    /// Installing the SSH capability must install whatever this family calls
    /// the package.
    ///
    /// systemctl cannot work without systemd as PID 1, so the task's enable
    /// step fails; the installation before it is still observable and is what
    /// proves the package name is right.
    fn installing_ssh_installs_the_family_s_package(image) {
        let output = run_in_container(
            image,
            &format!("initd run ssh.install >/dev/null 2>&1; {}", image.query_ssh),
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains(image.installed_needle),
            "openssh must be installed on {}: {stdout}",
            image.family
        );
    }

    /// sshd refuses a key file other users can read, so the permissions are
    /// part of the task's contract rather than a detail.
    fn authorising_a_key_applies_the_permissions_sshd_requires(image) {
        let output = run_in_container(
            image,
            &format!(
                "initd authorize-key root '{}' >/dev/null 2>&1; \
                 stat -c '%a' /root/.ssh; stat -c '%a' /root/.ssh/authorized_keys; \
                 cat /root/.ssh/authorized_keys",
                common::TEST_KEY
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
        assert!(
            stdout.contains(common::TEST_KEY),
            "the key must be present: {stdout}"
        );
    }

    /// Authorising the same key twice must not append it twice.
    fn authorising_the_same_key_twice_does_not_duplicate_it(image) {
        let output = run_in_container(
            image,
            &format!(
                "initd authorize-key root '{key}' >/dev/null 2>&1; \
                 initd authorize-key root '{key}' >/dev/null 2>&1; \
                 grep -c 'ssh-ed25519' /root/.ssh/authorized_keys",
                key = common::TEST_KEY
            ),
        );
        let stdout = stdout_of(&output);

        assert!(
            has_line(&stdout, "1"),
            "the key must appear once: {stdout}"
        );
    }

    /// A port change must both take effect and leave a config sshd accepts.
    fn changing_the_port_writes_a_config_sshd_accepts(image) {
        let output = run_with_ssh_ready(
            image,
            "initd change-port 2222 >/dev/null 2>&1; \
             grep '^Port' /etc/ssh/sshd_config; \
             sshd -t && echo VALID",
        );
        let stdout = stdout_of(&output);

        assert!(stdout.contains("Port 2222"), "the port must change: {stdout}");
        assert!(
            stdout.contains("VALID"),
            "the resulting config must pass sshd -t: {stdout}"
        );
    }

    /// The safe tier writes seventeen directives against a real daemon.
    ///
    /// A mock cannot say whether this OpenSSH parses them; only sshd can, and
    /// the answer differs by family because each ships a different release.
    fn hardening_produces_a_config_sshd_accepts(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden >/dev/null 2>&1; sshd -t && echo VALID",
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("VALID"),
            "the hardened config must pass sshd -t: {stdout}"
        );
    }

    /// The strict tier must also survive validation.
    fn strict_hardening_produces_a_config_sshd_accepts(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden-strict >/dev/null 2>&1; sshd -t && echo VALID",
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("VALID"),
            "the strict config must pass sshd -t: {stdout}"
        );
    }

    /// Every cipher written must be one this build supports.
    ///
    /// The scenario that justifies the filtering module. Each family ships a
    /// different OpenSSH, so the surviving set differs; what must hold on all
    /// of them is that nothing unsupported is written. Reported as the count
    /// of names absent from `ssh -Q`.
    fn strict_hardening_writes_only_ciphers_this_build_supports(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden-strict >/dev/null 2>&1; \
             ssh -Q cipher > /tmp/supported; \
             grep '^Ciphers ' /etc/ssh/sshd_config | cut -d' ' -f2 | tr ',' '\\n' \
               | grep -vxF -f /tmp/supported | wc -l",
        );
        let stdout = stdout_of(&output);

        assert!(
            has_line(&stdout, "0"),
            "every written cipher must be supported on {}: {stdout}",
            image.family
        );
    }

    /// The same, for key exchange algorithms.
    ///
    /// Kept separate from ciphers because post-quantum kex arrived in OpenSSH 9
    /// while the cipher list has been stable far longer — the two directives
    /// fail on different releases, so one passing says nothing about the other.
    fn strict_hardening_writes_only_kex_algorithms_this_build_supports(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden-strict >/dev/null 2>&1; \
             ssh -Q kex > /tmp/supported; \
             grep '^KexAlgorithms ' /etc/ssh/sshd_config | cut -d' ' -f2 | tr ',' '\\n' \
               | grep -vxF -f /tmp/supported | wc -l",
        );
        let stdout = stdout_of(&output);

        assert!(
            has_line(&stdout, "0"),
            "every written kex algorithm must be supported on {}: {stdout}",
            image.family
        );
    }

    /// Applying both tiers in the realistic order must leave a valid config.
    ///
    /// Repeated `set_directive` passes over the same file must not corrupt it.
    fn the_two_tiers_compose(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden >/dev/null 2>&1; \
             initd run ssh.harden-strict >/dev/null 2>&1; \
             sshd -t && echo VALID",
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("VALID"),
            "applying both tiers must leave a valid config: {stdout}"
        );
    }

    /// Hardening twice must not leave two active copies of a directive: the
    /// second run comments the first out rather than appending beside it.
    fn hardening_is_idempotent(image) {
        let output = run_with_ssh_ready(
            image,
            "initd run ssh.harden >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             grep -c '^PermitRootLogin no' /etc/ssh/sshd_config",
        );
        let stdout = stdout_of(&output);

        assert!(
            has_line(&stdout, "1"),
            "exactly one active PermitRootLogin must remain: {stdout}"
        );
    }

    /// The lockout guard must hold on a real system, not just against mocks:
    /// with no authorised key, password authentication must survive.
    fn hardening_refuses_without_an_authorised_key(image) {
        let output = run_in_container(
            image,
            &format!(
                "{} >/dev/null 2>&1; \
                 initd run ssh.harden >/dev/null 2>&1; \
                 grep -c '^PasswordAuthentication no' /etc/ssh/sshd_config || true",
                image.install_ssh
            ),
        );
        let stdout = stdout_of(&output);

        assert!(
            has_line(&stdout, "0"),
            "password auth must not be disabled without a key: {stdout}"
        );
    }

    /// The live config must never be left in a state sshd rejects, whatever
    /// the task did — the backup is restored over a file that fails to parse.
    fn the_live_config_always_survives_validation(image) {
        let output = run_with_ssh_ready(
            image,
            "initd change-port 2222 >/dev/null 2>&1; sshd -t && echo STILL_VALID",
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("STILL_VALID"),
            "the live config must always remain valid: {stdout}"
        );
    }
}

/// The matrix and the macro must name the same images.
///
/// `macro_rules!` cannot iterate a constant, so `for_each_image!` lists the
/// families it expands to by hand. That is the one place adding a distribution
/// touches beyond its `Image` entry, and nothing else would notice if the two
/// drifted — a family present in `IMAGES` but missing from the macro would
/// simply never run, and the suite would stay green while covering less.
#[test]
fn every_image_in_the_matrix_is_expanded_by_the_macro() {
    // Kept in step by hand with the `@image` lines in `for_each_image!`.
    //
    // `suse` appears twice, and that is the assertion rather than a slip:
    // Tumbleweed and Leap are two images of one family because they resolve
    // Zellij differently. Comparing families as a *sequence* is what keeps that
    // honest — deduplicating here would let one of the two silently vanish from
    // the matrix while this still passed.
    const EXPANDED: &[&str] = &["debian", "arch", "alpine", "rhel", "suse", "suse"];

    let matrix: Vec<&str> = common::IMAGES.iter().map(|image| image.family).collect();

    assert_eq!(
        matrix, EXPANDED,
        "IMAGES and for_each_image! have drifted: add the missing family to \
         the macro's @image lines, or the scenarios will silently skip it"
    );
}

/// A derivative must resolve to its parent family while keeping its own name.
///
/// Outside `for_each_image!`: the fixture *is* the distribution under test, so
/// running it against both images would ask the same question twice while the
/// image underneath is irrelevant.
///
/// This is the step the unit tests cannot reach. They parse the same file and
/// prove the parser; what they cannot prove is that the binary reads
/// `/etc/os-release` at the real path and resolves a backend from what it
/// finds there. Ubuntu is the case that matters, since its `ID` is not a
/// family and only `ID_LIKE` says which backend to use — get that wrong and
/// every Ubuntu server is unsupported.
#[test]
#[ignore = "requires docker"]
fn a_derivative_resolves_through_id_like_to_its_parent_family() {
    require_docker!();

    let output = run_with_os_release(&DEBIAN, "ubuntu2404", "initd detect");
    let stdout = stdout_of(&output);

    assert!(output.status.success(), "detect must succeed: {stdout}");
    assert!(
        stdout.contains("family:       debian"),
        "Ubuntu must resolve to the debian family: {stdout}"
    );
    assert!(
        stdout.contains("id:           ubuntu"),
        "and must still report its own id, not its family's: {stdout}"
    );
}

/// An unsupported distribution must be refused, not guessed at.
///
/// The alternative is worse than failing: picking a backend for a system whose
/// package manager it does not have would run `apt` on Gentoo. The error names
/// what it saw and what it supports, so the person reading it knows whether
/// they hit a gap or a bug.
#[test]
#[ignore = "requires docker"]
fn an_unsupported_distribution_is_refused_naming_what_it_found() {
    require_docker!();

    let output = run_with_os_release(&DEBIAN, "gentoo", "initd detect 2>&1; echo exit=$?");
    let stdout = stdout_of(&output);

    // A whole line, not a substring: `exit=1` is a prefix of `exit=127`, which
    // is what the shell reports when the binary was never mounted. That would
    // pass this as proof the distribution was refused, having run nothing.
    assert!(
        common::has_line(&stdout, "exit=1"),
        "an unsupported distribution must exit 1: {stdout}"
    );
    assert!(
        stdout.contains("gentoo"),
        "the error must name the distribution it found: {stdout}"
    );
    assert!(
        stdout.contains("debian") && stdout.contains("arch"),
        "and the families it does support: {stdout}"
    );
}
