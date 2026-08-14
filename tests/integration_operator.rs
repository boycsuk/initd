//! What the tool sees when it runs as the operator rather than as root.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! The environment every other scenario in this suite was missing, and the
//! reason five defects reached a production host at once. `docker run` is root,
//! and root's `PATH` carries `/usr/sbin`. But `initd` is documented — in
//! `docs/cli.md`, in the README, and in `exec::privilege`'s own module comment —
//! to run *unprivileged* and escalate command by command, so the environment it
//! inherits is a login shell's. On `debian:13` that is
//! `/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games`, with `/usr/sbin`
//! absent while `/usr/sbin/sshd` and `/usr/sbin/nft` sit on disk.
//!
//! So the suite exercised the one environment in which a lookup for a system
//! daemon could not fail, and four defects passed it for as long as they
//! shipped:
//!
//! - `docker.rootless` refused every host that had an engine.
//! - Four `sshd_config` tasks refused a preinstalled SSH server.
//! - `firewall.manage-ports` reported no front-end where one was installed.
//! - `firewall.enable`'s row offered to enable a firewall already running.
//!
//! Each is asserted here against the account that found it. What these
//! scenarios must never do is grant that account root's `PATH` — the helper
//! uses `su -` for exactly that reason, and a future one reaching for
//! `docker run --user` would inherit the daemon's environment and quietly
//! restore the blindness this file exists to remove.

mod common;

use common::{DEBIAN, run_in_container_as_operator, stdout_of};

#[test]
#[ignore = "requires docker"]
fn an_operator_still_finds_a_preinstalled_ssh_server() {
    require_docker!();

    // Debian alone, and the restriction is measured rather than convenient.
    // Two things have to coincide for this defect to be *reproducible*, and the
    // matrix splits on both:
    //
    // - `/usr/sbin` absent from a non-root login: true on Debian, Arch,
    //   Tumbleweed and Leap; false on Alpine and RHEL, whose `/etc/profile`
    //   hands an ordinary account the sbin directories too.
    // - `sshd` present *only* in `/usr/sbin`: true on Debian and SUSE; Arch
    //   also ships `/usr/bin/sshd`, which the operator can see, so the lookup
    //   there succeeds either way.
    //
    // That leaves Debian and SUSE, and SUSE cannot reach the assertion in a
    // container at all: it resolves `run0`, which needs systemd as PID 1, so
    // the task dies at "System has not been booted with systemd" before the
    // daemon is ever looked for.
    //
    // Verified by reintroducing the defect: only `debian` failed, and it failed
    // with the exact refusal reported from a live host. The others passed while
    // the bug was present, which is why writing this across the matrix would
    // have produced five tests that cannot fail.
    let script = "sudo apt-get install -y -qq openssh-server >/dev/null 2>&1; \
                  ls /usr/sbin/sshd >/dev/null 2>&1 && echo ON_DISK; \
                  command -v sshd >/dev/null 2>&1 || echo INVISIBLE_TO_THE_SHELL; \
                  initd run ssh.change-port port=2222 2>&1 | tail -5";

    let output = run_in_container_as_operator(&DEBIAN, script);
    let seen = stdout_of(&output);

    assert!(
        seen.contains("ON_DISK"),
        "the daemon must be installed for this to mean anything: {seen}"
    );
    assert!(
        seen.contains("INVISIBLE_TO_THE_SHELL"),
        "and must be invisible to the operator's own shell, or this proves \
         nothing about the lookup: {seen}"
    );

    // `ssh.change-port` rather than `ssh.harden`: the latter refuses first with
    // "no authorised key found for root", a lockout guard that runs *before*
    // the daemon is looked for, so it never reaches the lookup under test.
    // Measured — with the defect reintroduced, `harden` passed on all six
    // images while `change-port` reproduced the operator's refusal.
    //
    // Not asserted on success: the task reloads a unit no container runs, so it
    // legitimately fails at that step. What must never appear is the refusal
    // that says the daemon is absent.
    assert!(
        !seen.contains("SSH server is not installed"),
        "a preinstalled sshd must be found by an unprivileged operator: {seen}"
    );
}

for_each_image! {
    /// The firewall front-end is found by the same account.
    ///
    /// `nft` lives in `/usr/sbin` too, and its availability probe was the one
    /// unprivileged command in a module whose every other call is
    /// `.privileged()` — so it alone was spawned under the operator's `PATH`.
    /// Detection gates every other firewall call, which is how one invisible
    /// binary disabled all of them.
    fn an_operator_still_finds_the_firewall_front_end(image) {
        let script = format!(
            "{refresh} >/dev/null 2>&1; {install_nftables} >/dev/null 2>&1; \
             {install_firewalld} >/dev/null 2>&1; \
             initd run firewall.status 2>&1 | tail -5",
            refresh = image.refresh,
            install_nftables = image.install_nftables,
            install_firewalld = image.install_firewalld,
        );

        let output = run_in_container_as_operator(image, &script);
        let seen = stdout_of(&output);

        assert!(
            !seen.contains("no inbound filtering front-end"),
            "an installed front-end must be found by an unprivileged operator: {seen}"
        );
    }
}

#[test]
#[ignore = "requires docker"]
fn an_operator_is_not_told_a_docker_engine_is_missing() {
    require_docker!();

    // The defect verbatim: the engine is installed and `docker.rootless`
    // refuses, having asked `test -f /usr/local/bin/docker` — this tool's own
    // directory for release binaries, where no route to Docker ever writes.
    //
    // Debian alone, because what is under test is the *lookup* rather than the
    // packaging: one host with a real `/usr/bin/docker` settles it, and pulling
    // an engine into six images to re-ask the same question is minutes of CI
    // for no extra answer.
    // Installed by the operator through `sudo` rather than by the setup, which
    // keeps the whole scenario inside the account under test — and is what a
    // real operator does anyway.
    let script = "sudo apt-get update -qq >/dev/null 2>&1; \
                  sudo apt-get install -y -qq docker.io >/dev/null 2>&1; \
                  ls /usr/bin/docker >/dev/null 2>&1 && echo ENGINE_ON_DISK; \
                  initd run docker.rootless user=initdtest 2>&1 | tail -5";

    let output = run_in_container_as_operator(&DEBIAN, script);
    let seen = stdout_of(&output);

    assert!(
        seen.contains("ENGINE_ON_DISK"),
        "the engine must be installed for this to mean anything: {seen}"
    );

    // Again not asserted on success: the rootless setup needs a per-user
    // systemd, which no ephemeral container has. The refusal under test is the
    // one that denies the engine exists at all.
    assert!(
        !seen.contains("docker engine is not installed"),
        "an installed engine must be found by an unprivileged operator: {seen}"
    );
}

#[test]
#[ignore = "requires docker"]
fn an_operator_is_never_told_a_running_firewall_is_off() {
    require_docker!();

    // The report this batch started from: the firewall was enabled as root, the
    // operator came back as an unprivileged admin, and the tool said nothing
    // was being filtered — because `nft list` needs root, and every non-answer
    // was read as "no table".
    //
    // The container cannot hold a real ruleset (no `NET_ADMIN`), so what is
    // asserted is the half that is about this tool rather than the kernel: a
    // state that could not be read must never be reported as a state that was.
    let script = "sudo apt-get install -y -qq nftables >/dev/null 2>&1; \
                  initd run firewall.status 2>&1 | tail -10";

    let output = run_in_container_as_operator(&DEBIAN, script);
    let seen = stdout_of(&output);

    // Whatever it says, it must not claim the host admits nothing on the
    // strength of a listing it was refused. Either it read the ruleset, or it
    // says it could not.
    let claimed_off = seen.contains("nothing is being filtered");
    let admitted_it_could_not_look = seen.contains("could not be read");

    assert!(
        !claimed_off || admitted_it_could_not_look,
        "a ruleset that could not be read must not be reported as no firewall: {seen}"
    );
}
