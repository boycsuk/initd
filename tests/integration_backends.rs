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
//!   `Firewalld::enable` uses precisely so that turning filtering on
//!   cannot lock anybody out. So these are real assertions about real state.
//!
//! - **OpenRC** enables and lists services with no init running, so
//!   `rc-update` is assertable. `rc-service <name> status` is not: it refuses
//!   with "openrc did not boot", because the container was booted by something
//!   else. The scenario asserts the enable half and pins the refusal.
//!
//! - **semanage** manages the policy store, which is a matter of writing files
//!   under `/etc/selinux` rather than of enforcing anything — so labelling and
//!   listing are observable, without `--privileged`. What is *not* observable
//!   is whether a label takes effect: that needs a kernel enforcing SELinux,
//!   which a container shares with its host and cannot be given. So these
//!   scenarios assert the type name and the labelling, and claim nothing about
//!   enforcement.
//!
//! Two measurements here were wrong before they were right, both in the
//! direction of concluding less than was true.
//!
//! The first piped the OpenRC and semanage refusals through `head`, which
//! reports the *pipeline's* status rather than the command's, making both look
//! like they exited 0. Redirecting to a file and reading `$?` gives 1. The
//! tests failed on the false claim, which is how it surfaced.
//!
//! The second installed `policycoreutils-python-utils` alone and concluded from
//! `SELinux policy is not managed` that semanage could not be observed in a
//! container at all — and this file said so. It needs
//! `selinux-policy-targeted` beside it: the command without a policy to manage
//! is not the same as a container that cannot manage one. The rule the suite
//! already had — check a tool against the image before relying on it — applies
//! to what the tool *needs* as much as to whether it is installed.

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

/// Installs `semanage` *and* a policy for it to manage.
///
/// Both halves, which is the thing an earlier reading of this got wrong.
/// `policycoreutils-python-utils` provides the command; without
/// `selinux-policy-targeted` there is no store behind it, and every invocation
/// fails with `SELinux policy is not managed`. Installing only the first led to
/// the conclusion that semanage could not be observed in a container at all.
///
/// No `--privileged` is needed: managing the policy store is a matter of
/// writing files under `/etc/selinux`, not of enforcing anything. Nothing here
/// claims the labels take effect — that needs a kernel enforcing SELinux, which
/// a container shares with its host and cannot be given.
const WITH_SELINUX: &str =
    "dnf install -y -q policycoreutils-python-utils selinux-policy-targeted >/dev/null 2>&1";

#[test]
#[ignore = "requires docker"]
fn semanage_labels_a_port_and_reports_it_back() {
    require_docker!();
    require_runnable!(&RHEL);

    // The highest-risk thing the RHEL backend does, and until now checked by a
    // mock alone. A port sshd is told to listen on that SELinux has not
    // labelled does not produce a permission error: the daemon fails to start,
    // from a configuration file that is valid and that `sshd -t` approved.
    //
    // What this settles is that `ssh_port_t` is the right type name and that
    // the label lands where `semanage port -l` reports it — both claims about
    // Red Hat's policy rather than about this repository, and both invisible to
    // a mock that agrees with whatever the code says.
    let output = run_in_container(
        &RHEL,
        &format!(
            "{WITH_SELINUX}; \
             semanage port -a -t ssh_port_t -p tcp 2222 >/tmp/add 2>&1; \
             echo add_exit=$?; \
             semanage port -l | grep '^ssh_port_t'"
        ),
    );

    let text = stdout_of(&output);

    assert!(
        common::has_line(&text, "add_exit=0"),
        "labelling must succeed: {text}"
    );
    assert!(
        text.lines().any(|line| {
            line.starts_with("ssh_port_t")
                && line.contains("tcp")
                && line
                    .split_whitespace()
                    .any(|field| field.trim_end_matches(',') == "2222")
        }),
        "the port must appear under ssh_port_t: {text}"
    );
}

#[test]
#[ignore = "requires docker"]
fn labelling_a_port_twice_is_not_an_error() {
    require_docker!();
    require_runnable!(&RHEL);

    // Re-running `ssh.change-port` on a host already labelled must not report a
    // problem that is not one. The backend covers this by trying `-a` and
    // falling through to `-m` on failure, with a comment stating that "`-a`
    // adds and fails if the port is already labelled".
    //
    // That premise is wrong, at least on this policycoreutils. A second `-a`
    // prints "already defined, modifying instead" and exits **0** — semanage
    // does the fallback itself. The code is still correct, because the second
    // command simply never runs; the reasoning written beside it was not.
    //
    // Pinned in both directions: the re-add succeeds, and `-m` on an existing
    // port succeeds too, so whichever path the implementation takes is one this
    // has observed rather than assumed.
    let output = run_in_container(
        &RHEL,
        &format!(
            "{WITH_SELINUX}; \
             semanage port -a -t ssh_port_t -p tcp 2222 >/dev/null 2>&1; \
             semanage port -a -t ssh_port_t -p tcp 2222 >/tmp/readd 2>&1; \
             echo readd_exit=$?; cat /tmp/readd; \
             semanage port -m -t ssh_port_t -p tcp 2222 >/dev/null 2>&1; \
             echo modify_exit=$?"
        ),
    );

    let text = stdout_of(&output);

    assert!(
        common::has_line(&text, "readd_exit=0"),
        "a second add must not fail, which is why the fallback never runs: {text}"
    );
    assert!(
        text.contains("already defined, modifying instead"),
        "and semanage must say it did the modify itself: {text}"
    );
    assert!(
        common::has_line(&text, "modify_exit=0"),
        "the fallback path must also work, since the code may still take it: {text}"
    );
}
