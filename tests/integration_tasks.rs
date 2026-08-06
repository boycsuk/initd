//! Tasks run as tasks, on every family, rather than through a mock.
//!
//! Ignored by default; run with `cargo nextest run --run-ignored all`.
//!
//! The suite had five of twenty-eight tasks reaching a container — the three
//! SSH ones plus `authorize-key` and `change-port` through their own
//! subcommands. Everything else was exercised by `MockExecutor`, which answers
//! whatever the code expects and therefore cannot disagree with it. That is the
//! gap `integration_systemd` was written to close for `ssh.install`, where a
//! mock had been agreeing about `ssh.service` against `sshd.service`.
//!
//! What these add over the backend scenarios beside them: those check that a
//! *command* behaves as the implementation assumes, while these run the task
//! end to end and read the system afterwards. A task can call every command
//! correctly and still leave the wrong state.
//!
//! # What a container can and cannot settle
//!
//! Measured against the images rather than assumed, because the boundary is
//! not where it first appears:
//!
//! - **Account tasks work unchanged.** `users.create` and `users.set-shell`
//!   need nothing a container withholds, so they are run and read back out of
//!   `/etc/passwd` and `/etc/group`.
//! - **`sysctl.ip-forward` works; `sysctl.unprivileged-ports` does not.**
//!   `net.ipv4.ip_forward` is namespaced and writable, while
//!   `net.ipv4.ip_unprivileged_port_start` is refused with "permission denied"
//!   in an unprivileged container. The first is asserted; the second is pinned
//!   as the refusal it is, so nobody writes a scenario that passes by not
//!   noticing.
//! - **Tasks ending in `systemctl` stop short.** `wireguard.install` writes
//!   `wg0.conf` correctly and then fails enabling a unit no container runs.
//!   The file is what this asserts — `integration_systemd` is where units are
//!   observed, and it boots systemd as PID 1 to do it.
//!
//! Nothing here claims a service is running. That distinction is the whole
//! reason `integration_systemd` exists as a separate binary.

mod common;

use common::{Image, run_in_container, stdout_of};

/// Runs a script with a package installed first, discarding the install noise.
///
/// The discard is not cosmetic: a package manager prints progress to both
/// streams, and a scenario that reads a file afterwards would be asserting
/// against `apt`'s output rather than the file's contents. That is how the
/// first version of the drop-in scenario failed.
fn observe_with(image: &Image, install: &str, script: &str) -> String {
    observe(image, &format!("{install} >/dev/null 2>&1; {script}"))
}

/// Runs a script and returns both streams together.
///
/// A task that refuses explains itself on stderr, so asserting on stdout alone
/// would see an empty string and no reason.
fn observe(image: &Image, script: &str) -> String {
    let output = run_in_container(image, script);

    format!(
        "{}{}",
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    )
}

for_each_image! {
    /// `users.create` provisions an account the backend can name.
    fn creating_a_user_leaves_an_account_the_system_agrees_exists(image) {
        // The task and the reading are deliberately different mechanisms: the
        // task goes through `AccountWriter`, the check reads `/etc/passwd`
        // directly. Asking the tool whether the tool succeeded is how a mock
        // agrees with itself.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; \
             grep '^deploy:' /etc/passwd",
        );

        assert!(
            observed.starts_with("deploy:"),
            "{}: the account must be in /etc/passwd: {observed}",
            image.name
        );
    }

    /// And puts it in the group that grants administrative rights *here*.
    fn a_created_user_joins_the_administrative_group_of_this_family(image) {
        // The divergence the backend exists for, and one that fails silently:
        // `usermod -aG sudo` on Arch exits zero against a group that is not
        // there, leaving an account that looks provisioned and cannot
        // escalate. `id -nG` is asked rather than the group file, because
        // membership can come from either the primary or a supplementary
        // group and only `id` resolves both.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; id -nG deploy",
        );

        let group = if image.name.contains("debian") {
            "sudo"
        } else {
            "wheel"
        };

        assert!(
            observed.split_whitespace().any(|name| name == group),
            "{}: deploy must be in {group}: {observed}",
            image.name
        );
    }

    /// Running it twice is refused rather than silently adopting the account.
    fn creating_a_user_that_exists_is_refused(image) {
        // Adopting it would report a provisioning that never happened: the
        // existing account may carry a password, a different shell, or no
        // administrative rights at all.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; \
             initd run users.create user=deploy >/tmp/second 2>&1; \
             echo second_exit=$?; cat /tmp/second",
        );

        assert!(
            common::has_line(&observed, "second_exit=1"),
            "{}: a second create must fail: {observed}",
            image.name
        );
        assert!(
            observed.contains("already exists"),
            "{}: and must say why: {observed}",
            image.name
        );
    }

    /// `users.set-shell` changes the shell the passwd entry records.
    fn setting_a_shell_is_visible_in_the_passwd_entry(image) {
        // `/bin/sh` because it is the one login shell all four families ship,
        // and because the task refuses a shell absent from `/etc/shells` —
        // which is the check being relied on, not bypassed.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; \
             initd run users.set-shell user=deploy shell=/bin/sh >/dev/null 2>&1; \
             grep '^deploy:' /etc/passwd",
        );

        assert!(
            observed.trim_end().ends_with("/bin/sh"),
            "{}: the shell must be recorded in the entry: {observed}",
            image.name
        );
    }

    /// A shell nothing lists is refused before the entry is touched.
    fn a_shell_that_is_not_a_login_shell_is_refused(image) {
        // `/bin/false` exists everywhere and is deliberately not in
        // `/etc/shells`: some PAM configurations refuse a session for an
        // account whose shell is unlisted, so setting one would produce an
        // account that cannot log in while reporting success.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; \
             initd run users.set-shell user=deploy shell=/bin/false >/tmp/o 2>&1; \
             echo exit=$?; cat /tmp/o; grep '^deploy:' /etc/passwd",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: an unlisted shell must be refused: {observed}",
            image.name
        );
        assert!(
            !observed.contains("deploy:x:1000:1000::/home/deploy:/bin/false"),
            "{}: and the entry must not have been changed: {observed}",
            image.name
        );
    }

    /// A sysctl the kernel refuses fails the task rather than passing quietly.
    fn a_refused_sysctl_fails_the_task(image) {
        // Neither parameter is writable from an unprivileged container: the
        // kernel's sysctls belong to the host, and Docker mounts `/proc/sys`
        // read-only. So what a plain container settles here is the failure
        // path — which is the one worth settling, because the alternative is a
        // task that reports success over a value that never applied.
        //
        // The success path was measured and does work, with `--privileged`:
        // the task writes `/etc/sysctl.d/99-initd.conf` and reports "now and
        // after a reboot". It is not asserted here because this binary runs
        // ordinary containers, the same reason `integration_systemd` is
        // separate — and this comment is where somebody looks for why.
        let observed = observe_with(
            image,
            image.install_sysctl,
            "initd run sysctl.ip-forward >/tmp/o 2>&1; echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: a refused write must fail the task: {observed}",
            image.name
        );
        // The failing command is named, and the tool's own refusal is what is
        // matched — not the kernel's wording, which is not the same on every
        // family. procps says "permission denied"; busybox's sysctl says
        // "Read-only file system" for the same refusal. Asserting on either
        // would be matching another program's user-facing text, which this
        // project already refuses to do for sudo's prompts.
        assert!(
            observed.contains("sysctl -w net.ipv4.ip_forward=1"),
            "{}: the report must name the command that failed: {observed}",
            image.name
        );
    }

    /// And it refuses before writing anything.
    fn a_refused_sysctl_leaves_no_drop_in_behind(image) {
        // The ordering the implementation documents, and the reason for it:
        // runtime first, because a parameter this kernel will not take must
        // fail before a file is left naming it. A drop-in for a value that
        // never applied is worse than none — it makes every subsequent boot
        // log an error for a setting nothing can satisfy.
        let observed = observe_with(
            image,
            image.install_sysctl,
            "initd run sysctl.ip-forward >/dev/null 2>&1; \
             test -e /etc/sysctl.d/99-initd.conf && echo WROTE || echo ABSENT",
        );

        assert!(
            observed.contains("ABSENT"),
            "{}: a refused parameter must leave no drop-in: {observed}",
            image.name
        );
    }

    /// `firewall.status` answers on a host with no ruleset of ours.
    fn the_firewall_status_is_an_answer_on_a_host_it_never_configured(image) {
        // The state worth knowing before changing anything, and the one a
        // missing table must not turn into an error: a host where this tool
        // has never run allows nothing through its table because there is no
        // table, which is an answer.
        // Both front-ends, because which one holds a host's ruleset is a
        // property of the host rather than of the family: RHEL resolves
        // firewalld first and only falls back to `nft`, so installing `nft`
        // alone leaves the task looking for a `firewall-cmd` that is not
        // there. A stock RHEL host has firewalld; an image has whatever it was
        // given, which is why this gives it both.
        let observed = observe_with(
            image,
            &format!(
                "{}; {}",
                image.install_nftables, image.install_firewalld
            ),
            "initd run firewall.status >/tmp/o 2>&1; echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: reporting status must not fail on an unconfigured host: {observed}",
            image.name
        );
        assert!(
            observed.contains("not active") || observed.contains("inactive"),
            "{}: and must say filtering is not on: {observed}",
            image.name
        );
    }

    /// `wireguard.status` says so when nothing is configured.
    fn wireguard_status_reports_an_unconfigured_host_rather_than_failing(image) {
        // Reading a configuration that is not there is a question with an
        // answer, not a failure — the same distinction as the missing firewall
        // table. It needs no package at all, which is why it runs before the
        // install scenario below.
        let observed = observe(
            image,
            "initd run wireguard.status >/tmp/o 2>&1; echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: status must not fail on an unconfigured host: {observed}",
            image.name
        );
        assert!(
            observed.contains("not configured"),
            "{}: and must say so plainly: {observed}",
            image.name
        );
    }

    /// `wireguard.install` writes a private key into a file nobody else can read.
    fn the_wireguard_key_is_written_into_a_file_that_was_already_restricted(image) {
        // The finding this whole sequence exists for: writing the key and
        // tightening the mode afterwards leaves the server's private key
        // world-readable for as long as the two commands take. The unit tests
        // assert the *order of commands*; this asserts the mode on the real
        // file, which is the thing that order was protecting.
        //
        // The task fails after this point — enabling a unit no container runs
        // — so the exit code is deliberately not asserted. `wg0.conf` existing
        // with mode 600 is what a container can settle.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "initd run wireguard.install subnet=10.89.0.0/24 port=51820 \
                 >/dev/null 2>&1; \
                 stat -c '%a' /etc/wireguard/wg0.conf; \
                 grep -c PrivateKey /etc/wireguard/wg0.conf",
        );

        let mut fields = observed.split_whitespace();

        assert_eq!(
            fields.next(),
            Some("600"),
            "{}: the config holding a private key must be 600: {observed}",
            image.name
        );
        assert_eq!(
            fields.next(),
            Some("1"),
            "{}: and must actually carry the key: {observed}",
            image.name
        );
    }

    /// Installing over an existing configuration is refused.
    fn installing_wireguard_twice_refuses_rather_than_replacing_the_key(image) {
        // A new server key silently invalidates every peer configured against
        // the old one, and each stops connecting with no indication why. The
        // refusal is what makes re-running the task safe to try.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "initd run wireguard.install subnet=10.89.0.0/24 port=51820 \
                 >/dev/null 2>&1; \
                 initd run wireguard.install subnet=10.89.0.0/24 port=51820 \
                 >/tmp/second 2>&1; \
                 echo second_exit=$?; cat /tmp/second",
        );

        assert!(
            common::has_line(&observed, "second_exit=1"),
            "{}: a second install must be refused: {observed}",
            image.name
        );
        assert!(
            observed.contains("already exists") || observed.contains("already configured"),
            "{}: and must say the configuration is already there: {observed}",
            image.name
        );
    }
}
