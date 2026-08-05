//! The privilege handoff observed where it actually bites.
//!
//! Ignored by default; run with `cargo nextest run --run-ignored all`.
//!
//! Alpine ships `doas` and no `sudo`, and `doas` has no validate flag, so
//! nothing authenticates when the interface starts and the *first* privileged
//! command is already the one that prompts. Under the interface that prompt is
//! written into the alternate screen in raw mode, where it can be neither read
//! nor answered — the interface simply appears to hang.
//!
//! What makes that avoidable is the probe: `doas -n` answers whether a prompt
//! is coming without raising one. Everything here is a claim about what `doas`
//! does rather than about what this repository does, so a mock cannot settle
//! any of it — the probe is only worth having if its exit codes mean what the
//! backend believes they mean, and that belief was wrong once already.

mod common;

use common::{ALPINE, run_in_container, stdout_of};

/// Installs `doas` and creates an unprivileged account to run as.
///
/// `sudo` is deliberately never installed: the whole point of the scenario is
/// a machine where the startup pre-authentication has nothing to work with.
const PREPARE: &str = "apk add --no-cache doas >/dev/null 2>&1; adduser -D alice";

/// Writes a `doas.conf` granting `alice` the given rule.
///
/// The mode matters to `doas` itself: it refuses to read a configuration that
/// is group- or world-readable, and reports it as a parse failure rather than
/// as a permission problem.
fn doas_conf(rule: &str) -> String {
    format!("echo '{rule}' > /etc/doas.conf; chmod 0400 /etc/doas.conf")
}

#[test]
#[ignore = "requires docker"]
fn the_probe_passes_where_doas_would_not_have_asked() {
    require_docker!();
    require_runnable!(&ALPINE);

    // `nopass` is the case where handing the terminal over would be a pointless
    // teardown of the interface: nothing was going to prompt.
    let out = run_in_container(
        &ALPINE,
        &format!(
            "{PREPARE}; {}; su alice -c 'doas -n true' </dev/null; echo probe=$?",
            doas_conf("permit nopass alice")
        ),
    );

    assert!(
        common::has_line(&stdout_of(&out), "probe=0"),
        "a nopass rule must probe clean, or every command pays for a handoff: {}",
        stdout_of(&out)
    );
}

#[test]
#[ignore = "requires docker"]
fn the_probe_fails_where_doas_is_about_to_ask() {
    require_docker!();
    require_runnable!(&ALPINE);

    // The case the handoff exists for. Without the probe this is the command
    // that blocks on an invisible prompt: `doas` does not fail here, it waits.
    let out = run_in_container(
        &ALPINE,
        &format!(
            "{PREPARE}; {}; su alice -c 'doas -n true' </dev/null; echo probe=$?",
            doas_conf("permit alice")
        ),
    );

    // A whole-line comparison, not a substring: `probe=1` is a prefix of
    // `probe=127`, which is what `su` reports when `doas` is not installed at
    // all. A container whose `apk add doas` failed would otherwise pass this
    // as proof the probe works, having probed nothing — the same shape as the
    // `inactive` containing `active` bug this suite already learned once.
    assert!(
        common::has_line(&stdout_of(&out), "probe=1"),
        "a rule wanting a password must probe non-zero, or the handoff never \
         happens and the prompt lands under the interface: {}",
        stdout_of(&out)
    );
}

#[test]
#[ignore = "requires docker"]
fn doas_is_what_gets_resolved_where_there_is_no_sudo() {
    require_docker!();
    require_runnable!(&ALPINE);

    // The premise underneath both probes: if detection picked something else,
    // the arguments above would be the wrong ones to send.
    let out = run_in_container(
        &ALPINE,
        &format!(
            "{PREPARE}; {}; su alice -c 'initd privileges' </dev/null",
            doas_conf("permit alice")
        ),
    );

    let text = stdout_of(&out);

    assert!(
        text.lines().any(|line| line.trim() == "escalation: doas"),
        "an Alpine host with no sudo must resolve doas: {text}"
    );
}
