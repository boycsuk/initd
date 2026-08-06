//! The three backends that had only ever answered to a mock.
//!
//! Ignored by default; run with `cargo nextest run --run-ignored all`.
//!
//! `firewalld`, `semanage` and `openrc` are each the implementation a whole
//! family depends on, and each was written against `MockExecutor` alone — the
//! arrangement `integration_systemd` exists because of, where `ssh.service`
//! against `sshd.service` had been checked by a mock that agreed with whatever
//! the code said.
//!
//! What each scenario can honestly claim differs, and the difference was
//! measured in the images rather than assumed:
//!
//! - **firewalld** works fully offline. `firewall-offline-cmd` writes a zone's
//!   configuration with no daemon running and reads it back, which is the path
//!   `FirewalldFirewall::enable` uses precisely so that turning filtering on
//!   cannot lock anybody out. So these are real assertions about real state.
//!
//! - **OpenRC** enables and lists services with no init running, so
//!   `rc-update` is assertable. `rc-service <name> status` is not: it refuses
//!   with "openrc did not boot", because the container was booted by something
//!   else. The scenario asserts the enable half and pins the refusal.
//!
//! - **semanage cannot be tested in an ordinary container at all**, and the
//!   scenario here proves that rather than pretending otherwise. There is no
//!   SELinux policy store, so every invocation fails with `SELinux policy is
//!   not managed`. What is asserted is the shape of that failure, so the day an
//!   image does carry a policy store, this fails and the real labelling
//!   scenario can be written.
//!
//! Both refusals were measured twice. The first probe piped them through
//! `head`, which reports the *pipeline's* status rather than the command's, and
//! made both look like they exited 0 — the same shape of mistake as a
//! comparison tool that is missing and reports "differs". Redirecting to a file
//! and reading `$?` gives 1 for both. The tests failed on the wrong claim,
//! which is how it was caught.

mod common;

use common::{ALPINE, RHEL, run_in_container, stdout_of};

#[test]
#[ignore = "requires docker"]
fn firewalld_writes_a_port_into_the_zone_it_claims_to() {
    require_docker!();
    require_runnable!(&RHEL);

    // The offline path, which is what `enable` uses: firewalld filters
    // whenever it runs and its default zone already rejects what it was not
    // told to admit, so the ports are written before the daemon starts rather
    // than after — which is why enabling cannot lock anybody out.
    let output = run_in_container(
        &RHEL,
        "dnf install -y -q firewalld >/dev/null 2>&1; \
         firewall-offline-cmd --zone=public --add-port=2222/tcp >/dev/null; \
         firewall-offline-cmd --zone=public --list-ports",
    );

    let listed = stdout_of(&output);

    assert!(
        listed.split_whitespace().any(|spec| spec == "2222/tcp"),
        "the port must be readable back out of the zone: {listed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn firewalld_admits_ssh_as_a_service_rather_than_as_a_port() {
    require_docker!();
    require_runnable!(&RHEL);

    // The reason `is_allowed` asks about services as well as ports. RHEL
    // admits SSH as the *service* `ssh` on a stock host, so an implementation
    // that only asked `--list-ports` would answer "closed" for a port that is
    // plainly reachable — the default case, not an edge one.
    let output = run_in_container(
        &RHEL,
        "dnf install -y -q firewalld >/dev/null 2>&1; \
         firewall-offline-cmd --zone=public --list-services",
    );

    let listed = stdout_of(&output);

    assert!(
        listed.split_whitespace().any(|name| name == "ssh"),
        "a stock zone admits ssh by service name: {listed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn openrc_enables_a_service_and_says_so_when_asked() {
    require_docker!();
    require_runnable!(&ALPINE);

    // `rc-update add` and `rc-update show` both work without an init, so the
    // enable half of `OpenRcServices` is genuinely observable. This is the
    // Alpine equivalent of what `integration_systemd` proves for systemd, and
    // the same class of divergence: the unit is `sshd` here where Debian's is
    // `ssh`, and until now only a mock had an opinion about which.
    let output = run_in_container(
        &ALPINE,
        "apk add --no-cache openrc openssh >/dev/null 2>&1; \
         rc-update add sshd default >/dev/null 2>&1; \
         rc-update show default",
    );

    let listed = stdout_of(&output);

    assert!(
        listed.lines().any(|line| line
            .split('|')
            .next()
            .is_some_and(|name| name.trim() == "sshd")),
        "sshd must be in the default runlevel: {listed}"
    );
}

#[test]
#[ignore = "requires docker"]
fn openrc_refuses_to_report_status_without_having_booted() {
    require_docker!();
    require_runnable!(&ALPINE);

    // Pinned because it bounds what the enable scenario above can claim. A
    // container is booted by something other than OpenRC, so `status` refuses
    // rather than answering — which is why no scenario here asserts that a
    // service is *running*, only that it was added to a runlevel. Proving the
    // service actually starts needs OpenRC as the init, the way
    // `integration_systemd` boots systemd as PID 1.
    //
    // The exit code is captured through a file rather than a pipe: `cmd | head`
    // reports the pipeline's status, not the command's, and that difference
    // made an earlier reading of this call look like it exited 0.
    let output = run_in_container(
        &ALPINE,
        "apk add --no-cache openrc openssh >/dev/null 2>&1; \
         rc-service sshd status >/tmp/status 2>&1; echo status_exit=$?; \
         cat /tmp/status",
    );

    let text = stdout_of(&output);

    assert!(
        text.contains("openrc did not boot"),
        "the refusal must say why: {text}"
    );
    assert!(
        common::has_line(&text, "status_exit=1"),
        "and must report it in the exit code: {text}"
    );
}

#[test]
#[ignore = "requires docker"]
fn semanage_cannot_label_anything_in_a_container() {
    require_docker!();
    require_runnable!(&RHEL);

    // This scenario exists to stop a *different* one being written. `semanage`
    // is the highest-risk thing the RHEL backend does — a port sshd is told to
    // listen on that SELinux has not labelled makes the daemon fail to start,
    // from a file that is valid and that `sshd -t` approved — so a container
    // test for it is the obvious thing to reach for.
    //
    // It cannot work. A container has no SELinux policy store, so every
    // invocation fails with `SELinux policy is not managed` and changes
    // nothing. A scenario that labelled a port and asserted on the result
    // would be asserting against a tool that never ran — passing for a reason
    // unrelated to the code, and going on passing if the labelling broke.
    //
    // So what is asserted is the reason the honest test is absent. If an image
    // ever does carry a policy store this fails, and whoever sees it can write
    // the real scenario: label a port, move sshd onto it, and watch the daemon
    // either bind or refuse.
    let output = run_in_container(
        &RHEL,
        "dnf install -y -q policycoreutils-python-utils >/dev/null 2>&1; \
         semanage port -a -t ssh_port_t -p tcp 2222 >/tmp/sem 2>&1; \
         echo semanage_exit=$?; cat /tmp/sem",
    );

    let text = stdout_of(&output);

    assert!(
        text.contains("SELinux policy is not managed"),
        "a container has no policy store; if this changed, the real labelling \
         scenario can now be written: {text}"
    );
    assert!(
        common::has_line(&text, "semanage_exit=1"),
        "and the failure is visible in the exit code: {text}"
    );
}
