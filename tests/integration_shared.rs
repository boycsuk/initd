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

mod common;

use common::{has_line, run_in_container, run_with_ssh_ready, stdout_of};

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
    const EXPANDED: &[&str] = &["debian", "arch"];

    let matrix: Vec<&str> = common::IMAGES.iter().map(|image| image.family).collect();

    assert_eq!(
        matrix, EXPANDED,
        "IMAGES and for_each_image! have drifted: add the missing family to \
         the macro's @image lines, or the scenarios will silently skip it"
    );
}
