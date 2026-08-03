//! Scenarios that prove a client can still log in after a task ran.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`.
//!
//! Every other container scenario stops at `sshd -t`, which parses the file
//! and reports whether it is well-formed. That is a real question, but it is
//! not the one an administrator cares about: a configuration narrowed to an
//! empty or mutually unusable set of algorithms is *valid*, validation
//! succeeds, and nobody can log in. `ssh.harden-strict` is documented as the
//! only tier that can cost a client its connection, so it is the one tier
//! whose success cannot be read off `sshd -t`.
//!
//! These scenarios start a real daemon and authenticate against it. They are
//! slower than the rest — a daemon start and a full handshake per test — which
//! is why they cover the tiers and the reversal rather than every task.
//!
//! Client and server here are the same OpenSSH release, since both come from
//! one container. That answers "does a session negotiate?" but not "can an
//! *older* client still connect?", which is the sharper version of the same
//! question and needs a second image to ask.

mod common;

use common::{CONNECTED, run_and_ask_offered_methods, run_and_connect, stdout_of};

for_each_image! {
    /// A session must work before any hardening, or nothing below means
    /// anything.
    ///
    /// The control. Without it, a failure in the hardened scenarios could just
    /// as easily be the harness — a daemon that never started, a key never
    /// authorised — and every conclusion drawn from them would be wrong.
    fn a_session_is_established_before_any_hardening(image) {
        let output = run_and_connect(image, "true");
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains(CONNECTED),
            "the harness must establish a session on an untouched config: {stdout}"
        );
    }

    /// The safe tier must not cost a client its connection.
    ///
    /// Its whole justification is that every directive either matches an
    /// OpenSSH default or tightens something no ordinary client depends on.
    /// That claim is about *connectivity*, so validation cannot check it.
    fn a_session_survives_the_safe_tier(image) {
        let output = run_and_connect(image, "initd run ssh.harden");
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains(CONNECTED),
            "key authentication must survive ssh.harden: {stdout}"
        );
    }

    /// The strict tier must still leave a usable daemon.
    ///
    /// This is the scenario the algorithm filtering exists for. If the
    /// intersection with `ssh -Q` were computed wrongly — empty, or naming
    /// only algorithms the client will not offer — `sshd -t` would still pass
    /// and this is the only place it would show.
    fn a_session_survives_the_strict_tier(image) {
        let output = run_and_connect(image, "initd run ssh.harden-strict");
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains(CONNECTED),
            "key authentication must survive ssh.harden-strict: {stdout}"
        );
    }

    /// Both tiers applied in the realistic order must still leave a client
    /// able to log in.
    ///
    /// The composition is where a contradiction would appear: each tier can be
    /// individually sound while together narrowing the algorithms past what a
    /// handshake needs.
    fn a_session_survives_both_tiers(image) {
        let output = run_and_connect(
            image,
            "initd run ssh.harden && initd run ssh.harden-strict",
        );
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains(CONNECTED),
            "key authentication must survive both tiers applied in order: {stdout}"
        );
    }

    /// An untouched daemon must still offer password authentication.
    ///
    /// The baseline the next scenario is measured against. Without it, a
    /// daemon that never offered passwords for some unrelated reason would
    /// make the hardening below look effective while proving nothing.
    fn an_untouched_daemon_offers_password_authentication(image) {
        let output = run_and_ask_offered_methods(image, "true");
        let stdout = stdout_of(&output);

        assert!(
            stdout.contains("password"),
            "the default daemon must offer password authentication: {stdout}"
        );
    }

    /// Hardening must actually stop the running daemon offering passwords.
    ///
    /// The complement of the scenarios above: those prove hardening did not
    /// take too much away, this proves it took anything away at all. A tier
    /// that silently failed to write its directives would satisfy every
    /// "a session survives" assertion perfectly.
    ///
    /// Read from the daemon's own refusal rather than from `sshd_config`,
    /// because a directive written into a file the daemon never loaded would
    /// pass a grep and change nothing.
    fn hardening_stops_the_daemon_offering_passwords(image) {
        let output = run_and_ask_offered_methods(image, "initd run ssh.harden");
        let stdout = stdout_of(&output);

        // The refusal must have happened at all — an empty output would mean
        // the client never reached a daemon, which is not the same thing.
        assert!(
            stdout.contains("Permission denied"),
            "the attempt must have been refused by a running daemon: {stdout}"
        );
        assert!(
            !stdout.contains("password"),
            "the hardened daemon must no longer offer passwords: {stdout}"
        );
    }
}
