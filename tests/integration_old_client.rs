//! Whether a client older than the server can still log in after hardening.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! `integration_connection.rs` proves a session negotiates, but its client and
//! server come from one image and so from one OpenSSH release. That leaves the
//! question `ssh.harden-strict` actually raises unanswered: it narrows the
//! algorithm lists, and an algorithm the server now insists on is one an older
//! client may never have learned. A filtered list can look perfectly healthy
//! against a modern client and still exclude every algorithm an old one
//! offers.
//!
//! The gap here is real: the client is Debian 11's OpenSSH 8.4 and the servers
//! are 10.0 and 10.4, so the pair straddles OpenSSH 9 — where the key exchange
//! defaults moved.
//!
//! These are the slowest scenarios in the suite: two containers, a network,
//! and a package install in each.

mod common;

use common::two_hosts::TwoHosts;

/// Brings up the pair or skips the test.
macro_rules! two_hosts {
    ($image:expr, $label:expr, $configure:expr) => {
        match TwoHosts::start($image, $label, $configure) {
            Some(hosts) => hosts,
            None => {
                eprintln!("skipping: this host will not run the two-container pair");
                return;
            }
        }
    };
}

for_each_image! {
    /// The old client must reach an untouched server.
    ///
    /// The control, and it earns its place twice over: it fixes the version
    /// gap the other scenarios rely on, and without it a refusal below could
    /// as easily be a client too old to talk to this server at all as one
    /// locked out by hardening.
    fn an_old_client_reaches_an_untouched_server(image) {
        let hosts = two_hosts!(image, "control", "true");
        let output = hosts.attempt_login();
        let stdout = common::stdout_of(&output);

        assert!(
            stdout.contains(common::CONNECTED),
            "an old client must reach an untouched {} server \
             (client {}, server {}): {stdout}",
            image.family,
            hosts.client_version(),
            hosts.server_version()
        );
    }

    /// The safe tier must not lock out an old client.
    ///
    /// Its justification is that every directive either matches an OpenSSH
    /// default or tightens something no ordinary client depends on. "Ordinary"
    /// has to include one several releases behind, or the claim means much
    /// less than it sounds like.
    fn an_old_client_survives_the_safe_tier(image) {
        let hosts = two_hosts!(image, "safe", "initd run ssh.harden");
        let output = hosts.attempt_login();
        let stdout = common::stdout_of(&output);

        assert!(
            stdout.contains(common::CONNECTED),
            "ssh.harden must not lock out an old client \
             (client {}, server {}): {stdout}",
            hosts.client_version(),
            hosts.server_version()
        );
    }

    /// The strict tier is the one that may legitimately refuse an old client.
    ///
    /// This scenario does not demand it connect. `ssh.harden-strict` is
    /// documented as the only tier that can cost a client its connection, so
    /// an old client being refused is the tier working, not failing.
    ///
    /// What it asserts is that the outcome is *decided*, not accidental: the
    /// session either succeeds or is refused for a reason the daemon states.
    /// A hang, a crash, or a daemon that died mid-handshake would all be
    /// bugs, and all three are invisible to `sshd -t`.
    fn the_strict_tier_either_admits_an_old_client_or_refuses_it_cleanly(image) {
        let hosts = two_hosts!(image, "strict", "initd run ssh.harden-strict");
        let output = hosts.attempt_login();
        let stdout = common::stdout_of(&output);

        let connected = stdout.contains(common::CONNECTED);
        // The refusals OpenSSH states plainly. Anything else — an empty
        // output, a timeout, a broken pipe — means the daemon did not answer.
        let refused_cleanly = stdout.contains("no matching")
            || stdout.contains("Permission denied")
            || stdout.contains("Unable to negotiate");

        assert!(
            connected || refused_cleanly,
            "the strict tier must leave a daemon that answers, whether it \
             admits this client or not (client {}, server {}): {stdout}",
            hosts.client_version(),
            hosts.server_version()
        );

        // Recorded rather than asserted: which way it went is a fact about
        // this pair of OpenSSH releases, and it will change as they move.
        eprintln!(
            "strict tier on {}: old client {}",
            image.family,
            if connected { "admitted" } else { "refused" }
        );
    }
}
