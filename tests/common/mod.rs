//! Shared helpers for container integration tests.
//!
//! These tests are `#[ignore]` by default: they need Docker and pull real
//! packages, so `cargo nextest run` stays fast and offline. Run them with
//! `cargo nextest run -- --ignored`.
//!
//! # The matrix
//!
//! Everything a scenario needs to know about a distribution lives in [`Image`],
//! and [`IMAGES`] lists the ones covered. Scenarios that must hold on every
//! family are written once and expanded across the matrix by
//! [`for_each_image!`]; only genuinely family-specific behaviour is written
//! against a single image.
//!
//! This mirrors the rule the production code follows — adding a distribution
//! means adding one module, never editing every task. Here it means adding one
//! [`Image`] entry, never writing a fresh copy of every scenario. With five
//! families the alternative is five near-identical files.
//!
//! Package names deliberately are *not* restated here: a scenario that needs
//! openssh installed calls [`Image::install_ssh`], and the name inside it is
//! the same one the backend claims. Naming it twice would let the test agree
//! with itself while disagreeing with the tool.
//!
//! # Known limitations
//!
//! systemd is not PID 1 in an ordinary container, so `systemctl enable` cannot
//! be verified for real. These tests therefore assert on what *is* observable —
//! the package being installed, files written, permissions applied — and the
//! unit-level tests assert on the exact command built. Verifying the effect of
//! `systemctl` would need systemd-enabled images and privileged containers,
//! which is out of scope for this slice.
//!
//! `ssh.allow-users` has no coverage here either, for a different reason: it
//! is deliberately interactive-only, so there is no subcommand to drive it
//! from a container script. Widening the CLI surface to make it testable would
//! reintroduce the very risk that keeping it out of the CLI avoids, so the gap
//! is accepted and its guards are covered against mocks instead.

// Each integration binary compiles this module in full, so whatever the other
// binary uses looks unused from here. That is inherent to sharing a module
// across test binaries, not a sign of dead code.
#![allow(dead_code)]

use std::process::Command;

/// A container image these tests run against.
///
/// One entry per distribution covered. The fields are the operations every
/// scenario needs expressed per-family, so a scenario can stay distro-agnostic
/// in exactly the way the tasks themselves are.
pub struct Image {
    /// The image tag passed to `docker run`.
    pub name: &'static str,
    /// The family `initd detect` must report inside this image.
    pub family: &'static str,
    /// Refreshes the package index. Run before anything else.
    pub refresh: &'static str,
    /// Installs the OpenSSH server under whatever this family calls it.
    pub install_ssh: &'static str,
    /// Prints something containing `needle` when OpenSSH is installed, so a
    /// scenario can confirm installation without knowing the query tool.
    pub query_ssh: &'static str,
    /// A substring of `query_ssh`'s output that proves the package is present.
    pub installed_needle: &'static str,
}

/// Debian and derivatives: `apt`, `openssh-server`.
pub const DEBIAN: Image = Image {
    name: "debian:13",
    family: "debian",
    refresh: "apt-get update -qq",
    install_ssh: "apt-get install -y -qq openssh-server",
    query_ssh: "dpkg-query -W -f='${Status}' openssh-server",
    installed_needle: "install ok installed",
};

/// Arch and derivatives: `pacman`, `openssh`.
pub const ARCH: Image = Image {
    name: "archlinux:latest",
    family: "arch",
    refresh: "pacman -Sy --noconfirm",
    install_ssh: "pacman -S --needed --noconfirm openssh",
    query_ssh: "pacman -Q openssh",
    installed_needle: "openssh",
};

/// Every image the shared scenarios run against.
///
/// Only families [`crate::distro::Family`] actually resolves belong here. RHEL,
/// SUSE and Alpine are absent because their backends are, and a matrix entry
/// without a backend would fail for code deliberately not written yet.
pub const IMAGES: &[&Image] = &[&DEBIAN, &ARCH];

/// A public key the hardening tasks accept, so the lockout guard lets them
/// proceed. Every scenario that hardens needs one first.
pub const TEST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";

/// Whether Docker is usable, so tests can skip rather than fail without it.
pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Builds the binary for the container's architecture and returns its path.
///
/// The debug binary is reused: these tests exercise behaviour, not
/// performance, and a release build would dominate the runtime.
pub fn binary_path() -> String {
    let mut path = std::env::current_exe().expect("the test binary must have a path");
    // target/debug/deps/<test> -> target/debug/initd
    path.pop();
    path.pop();
    path.push("initd");

    path.to_string_lossy().into_owned()
}

/// Runs a shell command inside a fresh container, with the binary mounted.
///
/// The binary is bind-mounted rather than copied so the container starts from
/// the pristine image every time.
pub fn run_in_container(image: &Image, script: &str) -> std::process::Output {
    let binary = binary_path();
    let mount = format!("{binary}:/usr/local/bin/initd:ro");

    // The refresh step runs first so package installation works, offline-ish
    // caches aside; joining it here keeps each test to a single container.
    let full_script = format!("{} >/dev/null 2>&1; {script}", image.refresh);

    Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            image.name,
            "sh",
            "-c",
            &full_script,
        ])
        .output()
        .expect("docker run must execute")
}

/// Runs a script in a container that has OpenSSH installed, host keys present
/// and a key authorised for root.
///
/// All three are needed before a scenario can assert anything about a written
/// configuration, and each is easy to forget in a way that makes the scenario
/// pass for the wrong reason.
///
/// The host keys are the subtle one. Debian's packaging generates them, Arch's
/// leaves it to `sshdgenkeys.service` — which never runs without systemd as
/// PID 1 — so on Arch every `sshd -t` returns `no hostkeys available` and is
/// *inconclusive* rather than a verdict on the file. A scenario asserting
/// "sshd accepts this config" would then be asserting nothing there, while
/// passing on Debian and looking covered. `ssh-keygen -A` is portable across
/// OpenSSH and generates only what is missing.
///
/// This is precisely the inconclusive case `NON_SYNTAX_FAILURES` exists to
/// classify, so it is deliberately covered on its own terms in
/// `integration_arch.rs` rather than smuggled into every shared scenario.
pub fn run_with_ssh_ready(image: &Image, script: &str) -> std::process::Output {
    run_in_container(
        image,
        &format!(
            "{} >/dev/null 2>&1; \
             ssh-keygen -A >/dev/null 2>&1; \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             {script}",
            image.install_ssh
        ),
    )
}

/// Convenience wrapper returning stdout as a string.
pub fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Whether any line of `stdout`, trimmed, is exactly `expected`.
///
/// Container scripts interleave package-manager chatter with the line under
/// test, so a whole-output comparison would be answering a different question.
pub fn has_line(stdout: &str, expected: &str) -> bool {
    stdout.lines().any(|line| line.trim() == expected)
}

/// Skips the test body when Docker is unavailable.
///
/// Returning rather than failing keeps the suite usable on a machine without
/// Docker, where these tests simply cannot run.
#[macro_export]
macro_rules! require_docker {
    () => {
        if !common::docker_available() {
            eprintln!("skipping: docker is not available");
            return;
        }
    };
}

/// Expands one scenario body into a `#[test]` per image in the matrix.
///
/// A declarative macro rather than a loop over [`IMAGES`], because a loop is a
/// single test: the first family to fail hides every family after it, and the
/// failure names a line rather than a distribution. Here each pair is its own
/// test, so `nextest` runs them in parallel and reports
/// `hardening_passes_validation::arch` by name.
///
/// A crate such as `rstest` would do the same, but this needs no dependency to
/// audit, and the matrix is the thing that has to stay cheap to extend.
///
/// ```ignore
/// for_each_image! {
///     /// Doc comments and attributes pass through.
///     fn hardening_passes_validation(image) {
///         let output = run_with_ssh_ready(image, "initd run ssh.harden; sshd -t && echo VALID");
///         assert!(stdout_of(&output).contains("VALID"));
///     }
/// }
/// ```
#[macro_export]
macro_rules! for_each_image {
    ($(
        $(#[$meta:meta])*
        fn $name:ident($image:ident) $body:block
    )*) => {
        $(
            $(#[$meta])*
            mod $name {
                use super::*;

                $crate::for_each_image!(@image debian, common::DEBIAN, $image, $body);
                $crate::for_each_image!(@image arch, common::ARCH, $image, $body);
            }
        )*
    };

    // One test per image. Adding a family means adding a line above and an
    // `Image` entry beside it — never touching a scenario.
    (@image $fname:ident, $konst:path, $image:ident, $body:block) => {
        #[test]
        #[ignore = "requires docker"]
        fn $fname() {
            require_docker!();

            let $image: &common::Image = &$konst;
            $body
        }
    };
}
