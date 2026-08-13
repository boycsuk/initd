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
        // `/bin/sh` because it is the one login shell all five families ship,
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
        // The guard: some PAM configurations refuse a session for an account
        // whose shell is unlisted, so setting one would produce an account that
        // cannot log in while reporting success.
        //
        // This used to name `/bin/false`, on the grounds that it exists
        // everywhere and is listed nowhere. The first half is true; the second
        // was true of four families and false of the fifth — openSUSE lists
        // `/bin/false` in `/etc/shells`, so the task accepted it and this
        // scenario read a correct refusal-to-refuse as a defect.
        //
        // `/bin/sync` is named instead: a real binary on every image and absent
        // from every `/etc/shells` here, checked on all six. The property being
        // asserted was always "a shell this system does not list", and naming a
        // path that happens to satisfy it on the images at hand is how that
        // turned into a claim about `/bin/false` specifically.
        let observed = observe(
            image,
            "initd run users.create user=deploy >/dev/null 2>&1; \
             initd run users.set-shell user=deploy shell=/bin/sync >/tmp/o 2>&1; \
             echo exit=$?; cat /tmp/o; grep '^deploy:' /etc/passwd",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: an unlisted shell must be refused: {observed}",
            image.name
        );
        assert!(
            !observed.contains("deploy:x:1000:1000::/home/deploy:/bin/sync"),
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

    /// Adding a peer leaves no copy of the key file on the filesystem.
    fn adding_a_peer_leaves_no_copy_of_the_key_file_on_disk(image) {
        // The unit test asserts which commands the task emits; this asserts
        // what is on the disk afterwards, which is the thing those commands
        // were about. `wg0.conf` holds the server's private key and every
        // peer's preshared key, and the ordinary `write` path copies a file
        // to `<path>.initd.bak` before changing it — so the task that
        // deliberately records nothing in the index was still leaving a
        // second copy of all of it beside the original, for the life of the
        // host, because retention only reaches copies the index names.
        //
        // Asserted by listing the directory rather than by testing one name:
        // a copy taken under some third suffix is the failure this is for,
        // and `test -e` on a name nobody chose yet would not find it.
        //
        // Both tasks fail at the point they reload a unit no container runs,
        // so no exit code is asserted — the files are what a container can
        // settle.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "initd run wireguard.install subnet=10.89.0.0/24 port=51820 \
                 >/dev/null 2>&1; \
                 initd run wireguard.add-peer name=laptop address=10.89.0.2 \
                 endpoint=198.51.100.7:51820 >/dev/null 2>&1; \
                 ls /etc/wireguard/; \
                 echo peers=$(grep -c '\\[Peer\\]' /etc/wireguard/wg0.conf)",
        );

        assert!(
            !observed.contains(".initd.bak"),
            "{}: no copy of the key file may be left beside it: {observed}",
            image.name
        );

        // The other direction, so a task that failed before writing anything
        // cannot pass this by having done nothing. A peer block in the file
        // is what proves the write the copy would have preceded took place.
        assert!(
            common::has_line(&observed, "peers=1"),
            "{}: and the peer must actually have been added: {observed}",
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

    /// `wireguard.add-peer` refuses before there is a server to add one to.
    fn adding_a_peer_before_the_interface_exists_is_refused(image) {
        // The ordering that reads as arbitrary and is not: a peer written into
        // a `wg0.conf` that does not exist would be a file naming a server key
        // nothing generated, and `wg-quick up` would then fail on a
        // configuration this tool reported as complete.
        let observed = observe_with(
            image,
            image.install_wireguard,
            "initd run wireguard.add-peer name=laptop address=10.89.0.2 \
                 endpoint=vpn.example.com:51820 >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o; \
                 test -e /etc/wireguard/wg0.conf && echo WROTE || echo ABSENT",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: a peer needs an interface first: {observed}",
            image.name
        );
        // And left nothing behind. A half-written `wg0.conf` carrying a peer
        // and no server key is worse than none: `wireguard.install` would then
        // refuse it as already configured, and the host is stuck needing a file
        // deleted by hand.
        assert!(
            observed.contains("ABSENT"),
            "{}: and must not have created a configuration: {observed}",
            image.name
        );
    }

    /// `firewall.enable` fails rather than half-applying where it cannot filter.
    fn enabling_the_firewall_without_the_capability_fails_rather_than_pretending(image) {
        // Loading a ruleset needs `CAP_NET_ADMIN`, which an ordinary container
        // does not have: `nft -f -` fails with "cache initialization failed:
        // Operation not permitted". Measured, not assumed — and it is the same
        // boundary `sysctl` runs into, so it is pinned the same way. The
        // success path lives in `integration_privileged`, where the capability
        // is granted.
        //
        // What matters here is that a firewall that could not be enabled is
        // reported as failed. A task that exited zero over an unloaded ruleset
        // would tell an administrator their host is filtering when it is not,
        // which is worse than not offering the task at all.
        let observed = observe_with(
            image,
            &format!("{}; {}", image.install_nftables, image.install_firewalld),
            "initd run firewall.enable ssh_port=22 >/tmp/o 2>&1; echo exit=$?; \
                 cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: a ruleset that could not be loaded must fail the task: {observed}",
            image.name
        );
        assert!(
            observed.contains("nft") || observed.contains("firewall-cmd"),
            "{}: and must name the command that failed: {observed}",
            image.name
        );
    }

    /// `firewall.manage-ports` refuses where nothing is filtering yet.
    fn managing_ports_before_anything_filters_is_refused(image) {
        // Against no default-deny policy every port is already reachable, so a
        // rule admitting one enforces nothing — and on a host where
        // `firewall.enable` has never run there is no table to add it to
        // either. Reported from a Debian 13 host as `nft` failing with
        // `Could not process rule: No such file or directory`, which names a
        // file for a table nobody created and reads as a defect in the rule.
        let observed = observe(
            image,
            "initd run firewall.manage-ports ports=8080/tcp >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: opening a port needs a front-end: {observed}",
            image.name
        );
        // The refusal names the *step* that is missing rather than a program,
        // and that is a change from what this test used to assert. It expected
        // `nft` to be named, because resolving the front-end was what failed
        // first on a host carrying neither — a true message about the second
        // problem. The first is that a port opened against no default-deny
        // policy admits nothing it did not already, so the task now refuses
        // before it goes looking for a front-end at all.
        //
        // Naming `firewall.enable` is what makes the refusal actionable: an
        // operator told `nft` is missing installs `nft` and is refused again,
        // this time for the reason that was true all along.
        assert!(
            observed.contains("firewall.enable"),
            "{}: and must name the step that is missing: {observed}",
            image.name
        );
    }

    /// A release this build carries no digest for is refused before any download.
    fn an_unverifiable_version_is_refused_before_anything_is_fetched(image) {
        // The refusal path rather than the download, deliberately: what is
        // worth pinning is that an unknown version stops *before* the network
        // is touched, which is also what keeps this scenario offline.
        // `integration_installer` covers a digest that fails after a fetch.
        //
        // The version is well-formed and simply unknown — `9.9.9` rather than
        // something like `0.0.0-nonexistent`, which never reaches the digest
        // table at all: `ParamKind::Version` rejects the shape first and exits
        // 2 as a malformed request. Measured rather than assumed, and the two
        // refusals are genuinely different: one says the argument is not a
        // version, this one says the version cannot be verified.
        //
        // Arch packages zellij, so there the task installs from the repository
        // and never resolves a version at all — the branch the backend exists
        // to choose, which is why both answers are admitted.
        let observed = observe(
            image,
            "initd run zellij.install version=9.9.9 >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o",
        );

        if observed.contains("from the distribution") || observed.contains("already installed") {
            return;
        }

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: an unverifiable version must fail the task: {observed}",
            image.name
        );
        assert!(
            observed.contains("9.9.9"),
            "{}: and the refusal must name the version asked for: {observed}",
            image.name
        );
    }

    /// And the refusal names the versions it could have verified.
    fn an_unverifiable_version_is_told_which_ones_are_known(image) {
        // A refusal that only says "no" leaves the operator guessing at a
        // version string. The known list is compiled into this build, so naming
        // it costs nothing and is the difference between a dead end and a next
        // step. Asserted separately from the refusal above because a message
        // can be correct about the failure and still useless.
        let observed = observe(
            image,
            "initd run zellij.install version=9.9.9 >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o",
        );

        if observed.contains("from the distribution") || observed.contains("already installed") {
            return;
        }

        // The wording is the tool's own — "it knows: 0.44.3, 0.43.1" — and what
        // is asserted is that a real version from the compiled-in table appears,
        // rather than the sentence around it. A refusal listing nothing would
        // still contain the preamble.
        assert!(
            observed.contains("0.44."),
            "{}: the refusal must name a version it can verify: {observed}",
            image.name
        );
    }

    /// A version that is not one at all is refused as a bad request instead.
    fn a_malformed_version_is_refused_before_the_task_runs(image) {
        // Exit 2, not 1, and the distinction is the contract `docs/cli.md`
        // sells to scripts: 1 is a task that ran and failed, 2 is a request
        // that was never going to run. Validation happens against the task's
        // own parameter declaration, so this never reaches the digest table.
        let observed = observe(
            image,
            "initd run zellij.install version=not-a-version >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=2"),
            "{}: a malformed value is a bad request, not a failed task: {observed}",
            image.name
        );
        assert!(
            observed.contains("version"),
            "{}: and must name the parameter that was wrong: {observed}",
            image.name
        );
    }

    /// `updates.unattended-security` writes the drop-in that carries the policy.
    fn unattended_updates_leave_the_policy_drop_in_behind(image) {
        // Debian only, and the task says so itself on the other four — which
        // is the half asserted there. The drop-in is what a container can
        // settle: the task goes on to ask whether the timer is scheduled, and
        // no container runs one, so the exit code is deliberately not asserted
        // here for the same reason `wireguard.install` does not assert its own.
        let observed = observe_with(
            image,
            image.refresh,
            "initd run updates.unattended-security >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o; \
                 cat /etc/apt/apt.conf.d/51initd-unattended 2>/dev/null",
        );

        if image.name.contains("debian") {
            assert!(
                observed.contains("51initd-unattended") || observed.contains("Unattended-Upgrade"),
                "{}: the policy drop-in must be written: {observed}",
                image.name
            );
        } else {
            assert!(
                common::has_line(&observed, "exit=1"),
                "{}: a family with no mechanism must refuse: {observed}",
                image.name
            );
        }
    }

    /// `users.lock-root` refuses through the CLI whatever it is given.
    fn locking_root_is_refused_without_a_verification_window(image) {
        // Not a validation failure but a structural one: locking root is the
        // change no keyboard undoes, so it is offered only where a second
        // session can prove the way back in before it is kept. The CLI exits
        // immediately and has no window to offer, so it declines rather than
        // applying something it cannot roll back.
        // The account is compared before and after rather than matched against
        // a pattern. Every image ships root already password-less — Debian
        // writes `root:*` — so a scenario asserting the absence of `*` asserts
        // something that was never true, and would fail whether or not the task
        // ran. What matters is that the entry is the one that was there.
        let observed = observe(
            image,
            "cp /etc/shadow /tmp/before; \
                 initd run users.lock-root >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o; \
                 before=$(sha256sum </tmp/before); \
                 after=$(sha256sum </etc/shadow); \
                 [ \"$before\" = \"$after\" ] && echo UNTOUCHED || echo CHANGED",
        );

        // Exit 2 rather than 1, and the difference is the contract `docs/cli.md`
        // sells to scripts: 1 is a task that ran and failed, 2 is a request
        // that was never going to run. A caller that retries on 1 must not
        // retry this.
        assert!(
            common::has_line(&observed, "exit=2"),
            "{}: the CLI must refuse this task as a bad request: {observed}",
            image.name
        );
        assert!(
            observed.contains("interactive interface"),
            "{}: and must say why rather than looking like a bad argument: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "UNTOUCHED"),
            "{}: and must not have touched the account database: {observed}",
            image.name
        );
    }

    /// `ssh.allow-users` is refused for the same reason, and says so.
    fn restricting_ssh_logins_is_refused_without_a_verification_window(image) {
        // The other half of the same rule. Asserted separately because a single
        // shared refusal would pass if one of the two ids were dropped from the
        // list — and `AllowUsers` naming an account that cannot log in is
        // exactly the lockout the window exists to catch.
        // `grep -c` over a file that may not be there yet: openSUSE ships its
        // sshd_config under /usr/etc and /etc/ssh/sshd_config appears only once
        // a task seeds it — and this task refuses before seeding anything, which
        // is the behaviour under test. `cat` of both paths, discarding the
        // error, counts the directive wherever the file lives and answers 0
        // where neither exists, which is the same answer for the same reason.
        let observed = observe_with(
            image,
            image.install_ssh,
            "initd run ssh.allow-users users=deploy >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o; \
                 echo directives=$(cat /etc/ssh/sshd_config /usr/etc/ssh/sshd_config \
                     2>/dev/null | grep -c '^AllowUsers')",
        );

        assert!(
            common::has_line(&observed, "exit=2"),
            "{}: the CLI must refuse this task as a bad request: {observed}",
            image.name
        );
        assert!(
            observed.contains("interactive interface"),
            "{}: and must say why: {observed}",
            image.name
        );
        // Labelled rather than a bare `0`, which is a line the refusal's own
        // output could produce for an unrelated reason.
        assert!(
            common::has_line(&observed, "directives=0"),
            "{}: and must not have written the directive: {observed}",
            image.name
        );
    }

    /// `caddy.validate` answers rather than failing where Caddy is absent.
    fn validating_caddy_where_it_is_not_installed_says_so(image) {
        // The distinction this pins: "the configuration is wrong" and "there is
        // no Caddy to ask" are different answers, and collapsing them would
        // report a broken configuration on a host that simply has none.
        let observed = observe(
            image,
            "initd run caddy.validate >/tmp/o 2>&1; echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: with no Caddy there is nothing to validate: {observed}",
            image.name
        );
        assert!(
            !observed.contains("panicked"),
            "{}: and it must be reported rather than panicking: {observed}",
            image.name
        );
    }

    /// `docker-rootless.install` refuses an account with no subordinate ids.
    fn rootless_docker_refuses_an_account_that_cannot_own_a_user_namespace(image) {
        // Rootless Docker maps container uids into a range the host delegates
        // to the account. Without one there is no namespace to enter, and the
        // daemon fails at first use rather than at install — so the check
        // happens here, where the failure can still name its cause.
        let observed = observe(
            image,
            "initd run docker-rootless.install user=nobody >/tmp/o 2>&1; \
                 echo exit=$?; cat /tmp/o",
        );

        assert!(
            common::has_line(&observed, "exit=1"),
            "{}: an account with no subordinate range must be refused: {observed}",
            image.name
        );
        assert!(
            !observed.contains("panicked"),
            "{}: and reported rather than panicking: {observed}",
            image.name
        );
    }

    /// A recorded change leaves a copy the next change to the same file cannot
    /// reach, and an index nobody else can read.
    fn a_recorded_change_survives_the_next_one_and_stays_private(image) {
        // `ssh.harden` twice, because one write proves nothing about the
        // problem the index exists for: the copy `write` takes lands at one
        // fixed `.initd.bak` per file, so the second change overwrites the
        // first one's copy. What has to survive is the *older* state.
        //
        // The modes are asserted here rather than in a unit test because a
        // mock has no umask. Both were wrong when this was first written —
        // /var/lib/initd came out 0755 and the index 0644 — and neither could
        // have been noticed anywhere but on a filesystem.
        // `ssh.change-port` twice rather than two different tasks, and the
        // exit codes are deliberately ignored: reloading sshd fails in a
        // container with no service manager, and what is being measured here
        // happens before the reload. A scenario that demanded success would be
        // testing the container's init rather than the index.
        let observed = observe_with(
            image,
            &format!("{} && ssh-keygen -A", image.install_ssh),
            "initd run ssh.change-port port=2222 >/dev/null 2>&1; \
             initd run ssh.change-port port=2223 >/dev/null 2>&1; \
             echo copies=$(ls /var/lib/initd/backups 2>/dev/null | wc -l); \
             echo records=$(wc -l < /var/lib/initd/backups.jsonl 2>/dev/null); \
             echo dirmode=$(stat -c %a /var/lib/initd); \
             echo filemode=$(stat -c %a /var/lib/initd/backups.jsonl)",
        );

        // Two changes, two copies. One would mean the second overwrote the
        // first, which is exactly the failure the timestamped names prevent.
        assert!(
            common::has_line(&observed, "copies=2"),
            "{}: each change must leave its own copy: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "records=2"),
            "{}: and its own record: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "dirmode=700"),
            "{}: the directory must not be listable by other accounts: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "filemode=600"),
            "{}: the index must not be readable by other accounts: {observed}",
            image.name
        );
    }

    /// A record names a copy that really holds the previous contents.
    fn the_recorded_copy_is_the_state_that_preceded_the_change(image) {
        // The record's whole promise. A copy that did not hold the previous
        // version would still satisfy every count above, and would restore
        // something nobody asked for.
        let observed = observe_with(
            image,
            &format!("{} && ssh-keygen -A", image.install_ssh),
            "initd run ssh.change-port port=2222 >/dev/null 2>&1; \
             echo after=$(grep -c '^Port 2222' /etc/ssh/sshd_config); \
             COPY=$(sed -n 's/.*\"copy\":\"\\([^\"]*\\)\".*/\\1/p' \
                 /var/lib/initd/backups.jsonl | head -1); \
             echo incopy=$(grep -c '^Port 2222' \"$COPY\")",
        );

        // The live file carries the new port; the copy must not, since the
        // copy is what preceded the change.
        assert!(
            common::has_line(&observed, "after=1"),
            "{}: the task must have written the new port: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "incopy=0"),
            "{}: the copy must hold the state from before the change: {observed}",
            image.name
        );
    }
}
