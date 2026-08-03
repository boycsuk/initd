//! Shared helpers for container integration tests.
//!
//! Each integration binary compiles this module in full, so whichever image
//! the other binary uses looks unused from here — hence the crate-level
//! `allow`. That is inherent to sharing a module across test binaries, not a
//! sign of dead code.

#![allow(dead_code)]
//!
//! These tests are `#[ignore]` by default: they need Docker and pull real
//! packages, so `cargo nextest run` stays fast and offline. Run them with
//! `cargo nextest run -- --ignored`.
//!
//! # Known limitation
//!
//! systemd is not PID 1 in an ordinary container, so `systemctl enable` cannot
//! be verified for real. These tests therefore assert on what *is* observable —
//! the package being installed, files written, permissions applied — and the
//! unit-level tests assert on the exact command built. Verifying the effect of
//! `systemctl` would need systemd-enabled images and privileged containers,
//! which is out of scope for this slice.

use std::process::Command;

/// A container image these tests run against.
pub struct Image {
    pub name: &'static str,
    /// Command that refreshes the package index, run before anything else.
    pub refresh: &'static [&'static str],
}

pub const DEBIAN: Image = Image {
    name: "debian:13",
    refresh: &["apt-get", "update", "-qq"],
};

pub const ARCH: Image = Image {
    name: "archlinux:latest",
    refresh: &["pacman", "-Sy", "--noconfirm"],
};

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

    // The refresh step runs first so package installation works offline-ish
    // caches aside; joining it here keeps each test to a single container.
    let full_script = format!("{} >/dev/null 2>&1; {script}", image.refresh.join(" "));

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

/// Convenience wrapper returning stdout as a string.
pub fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
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
