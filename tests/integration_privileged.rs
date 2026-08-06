//! Scenarios that need a writable `/proc/sys`.
//!
//! Ignored by default; run with `cargo nextest run --run-ignored all`. They
//! also need a host that will run a privileged container, and skip rather than
//! fail where it will not — a rootless Docker has not found a bug.
//!
//! # Why this is a separate binary
//!
//! `integration_tasks` runs ordinary containers, where Docker mounts
//! `/proc/sys` read-only. That is not an obstacle worked around there but a
//! measurement: `sysctl.ip-forward` is pinned as the refusal it is, so nobody
//! writes a scenario that passes by not noticing the write never happened.
//! What that leaves unobserved is the half the task exists for — the value
//! applied, the drop-in written, and the two agreeing.
//!
//! This is the same arrangement `integration_systemd` uses, and for the same
//! reason: a capability an ordinary run does not have belongs in a binary that
//! can skip as a whole, rather than in scenarios that quietly assert less.
//! It needs only `--privileged`, not the `--cgroupns=host` systemd also
//! requires — nothing here boots an init.
//!
//! # What a privileged container still cannot settle
//!
//! The sysctls are the *host's*. A value written here is written on the
//! machine running the tests, not into a namespace of its own —
//! `net.ipv4.ip_forward` is namespaced per network namespace, which is what
//! makes it safe to set; a scenario that wrote a non-namespaced parameter
//! would be reconfiguring the developer's laptop. Nothing below writes one.

mod common;

use common::{Image, run_in_privileged_container, stdout_of};

/// Runs a script with a package installed first, or skips.
///
/// Two reasons to skip, and they are deliberately not distinguished in the
/// result: a host that refuses `--privileged`, and an image whose binary was
/// never built. Neither is a failure of the code under test.
///
/// The install noise is discarded for the reason `integration_tasks` documents:
/// a package manager prints progress to both streams, and a scenario reading a
/// file afterwards would assert against `apt`'s output rather than the file.
fn observe_privileged(image: &Image, install: &str, script: &str) -> Option<String> {
    let output =
        run_in_privileged_container(image, &format!("{install} >/dev/null 2>&1; {script}"))?;

    Some(format!(
        "{}{}",
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Skips a scenario the host will not let run, saying which capability it wanted.
macro_rules! privileged {
    ($observed:expr) => {
        match $observed {
            Some(observed) => observed,
            None => {
                eprintln!("skipping: this host will not run a privileged container");
                return;
            }
        }
    };
}

for_each_image! {
    /// `sysctl.ip-forward` applies the value the kernel is actually running.
    fn forwarding_is_on_in_the_kernel_after_the_task_runs(image) {
        // Read out of `/proc/sys` rather than through `sysctl`, and neither
        // through this tool: the question is what the kernel is running, and
        // the file is the kernel's own answer. Asking the tool whether the tool
        // succeeded is how a mock agrees with itself.
        let observed = privileged!(observe_privileged(
            image,
            image.install_sysctl,
            "initd run sysctl.ip-forward >/tmp/o 2>&1; echo exit=$?; \
             echo running=$(cat /proc/sys/net/ipv4/ip_forward)",
        ));

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: the task must succeed where the write is permitted: {observed}",
            image.name
        );
        // Labelled rather than left as a bare `1`. The task reports what it did
        // on the same stream, so an unlabelled digit is a line this assertion
        // could match for a reason that has nothing to do with the kernel.
        assert!(
            common::has_line(&observed, "running=1"),
            "{}: and the running kernel must have the value: {observed}",
            image.name
        );
    }

    /// And writes the drop-in that survives the reboot.
    fn forwarding_is_written_where_a_reboot_will_find_it(image) {
        // The half a runtime read cannot see. `sysctl -w` alone is forgotten on
        // reboot, so a task that only did that would report "now and after a
        // reboot" over a setting that lasts until the next one — which is the
        // bug the audit found and this pins.
        let observed = privileged!(observe_privileged(
            image,
            image.install_sysctl,
            "initd run sysctl.ip-forward >/dev/null 2>&1; \
             cat /etc/sysctl.d/99-initd.conf",
        ));

        assert!(
            observed.contains("net.ipv4.ip_forward"),
            "{}: the drop-in must name the parameter: {observed}",
            image.name
        );
        assert!(
            observed.contains("net.ipv4.ip_forward = 1")
                || observed.contains("net.ipv4.ip_forward=1"),
            "{}: and carry the value that was applied: {observed}",
            image.name
        );
    }

    /// A parameter already live is still persisted rather than skipped.
    fn a_value_already_live_is_still_written_to_the_drop_in(image) {
        // The exact shape of the bug the audit fixed: the task read the running
        // value first and returned early when it already matched, so a host
        // where forwarding happened to be on got no drop-in — and lost the
        // setting at the next boot, having been told it would survive one.
        //
        // Running the task twice is what reproduces it: the second run is by
        // definition one where the value is already live.
        let observed = privileged!(observe_privileged(
            image,
            image.install_sysctl,
            "initd run sysctl.ip-forward >/dev/null 2>&1; \
             rm -f /etc/sysctl.d/99-initd.conf; \
             initd run sysctl.ip-forward >/tmp/o 2>&1; echo exit=$?; \
             cat /etc/sysctl.d/99-initd.conf 2>/dev/null || echo ABSENT",
        ));

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: a second run must succeed: {observed}",
            image.name
        );
        assert!(
            !observed.contains("ABSENT"),
            "{}: and must write the drop-in even though the value was live: {observed}",
            image.name
        );
    }

    /// `firewall.enable` loads a ruleset that admits the port it was given.
    fn enabling_the_firewall_admits_the_port_it_was_told_to_keep(image) {
        // The other capability an ordinary container withholds: loading a
        // ruleset needs `CAP_NET_ADMIN`, so `integration_tasks` can only pin
        // the failure. Here the rules are actually installed.
        //
        // Both front-ends are installed, for the reason `firewall.status`
        // states: RHEL resolves firewalld first, so an image given only `nft`
        // sends the task looking for a `firewall-cmd` that is not there.
        //
        // The ruleset is read back through the front-end's own query rather
        // than through this tool, so the assertion cannot be satisfied by the
        // task agreeing with itself. Which of the two answers depends on which
        // front-end holds the ruleset, so both are asked.
        let observed = privileged!(observe_privileged(
            image,
            &format!("{}; {}", image.install_nftables, image.install_firewalld),
            "initd run firewall.enable ssh_port=22 >/tmp/o 2>&1; echo exit=$?; \
             cat /tmp/o; \
             echo '--- ruleset ---'; \
             nft list ruleset 2>/dev/null; \
             firewall-cmd --list-all 2>/dev/null",
        ));

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: enabling the firewall must succeed where it is permitted: {observed}",
            image.name
        );

        // Read from the ruleset dump alone. The task's own report names the
        // port too, so matching the whole output would pass on a host where
        // nothing was loaded.
        let ruleset = observed
            .split_once("--- ruleset ---")
            .map(|(_, after)| after)
            .unwrap_or_default();

        assert!(
            ruleset.contains("22"),
            "{}: the loaded ruleset must admit the port it was given: {observed}",
            image.name
        );
    }

    /// And a port opened afterwards reaches the ruleset that is filtering.
    fn a_port_opened_after_the_firewall_is_on_reaches_the_live_ruleset(image) {
        // `firewall.allow-port` resolves the front-end rather than assuming
        // one, because a rule added to the front-end that is *not* filtering is
        // a rule nothing enforces — a port reported open that stays closed.
        // Enabling first is what makes the resolution meaningful.
        let observed = privileged!(observe_privileged(
            image,
            &format!("{}; {}", image.install_nftables, image.install_firewalld),
            "initd run firewall.enable ssh_port=22 >/dev/null 2>&1; \
             initd run firewall.allow-port port=8080 protocol=tcp >/tmp/o 2>&1; \
             echo exit=$?; cat /tmp/o; \
             echo '--- ruleset ---'; \
             nft list ruleset 2>/dev/null; \
             firewall-cmd --list-all 2>/dev/null",
        ));

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: opening a port must succeed once something is filtering: {observed}",
            image.name
        );

        let ruleset = observed
            .split_once("--- ruleset ---")
            .map(|(_, after)| after)
            .unwrap_or_default();

        assert!(
            ruleset.contains("8080"),
            "{}: and the port must be in the live ruleset: {observed}",
            image.name
        );
    }

    /// `sysctl.unprivileged-ports` applies where the kernel permits the write.
    fn the_unprivileged_port_floor_is_lowered_where_the_write_is_permitted(image) {
        // The task `integration_tasks` can only pin as a refusal, since
        // `net.ipv4.ip_unprivileged_port_start` is refused outright in an
        // unprivileged container. Here it is the success path, read back out of
        // `/proc/sys` — the floor is what lets a rootless container bind 80
        // without the capability that would let it bind anything.
        let observed = privileged!(observe_privileged(
            image,
            image.install_sysctl,
            "initd run sysctl.unprivileged-ports >/tmp/o 2>&1; echo exit=$?; \
             echo floor=$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start)",
        ));

        assert!(
            common::has_line(&observed, "exit=0"),
            "{}: the task must succeed where the write is permitted: {observed}",
            image.name
        );
        assert!(
            common::has_line(&observed, "floor=80"),
            "{}: and the floor must be where a web server can reach: {observed}",
            image.name
        );
    }
}
