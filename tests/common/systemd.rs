//! A container running systemd as PID 1, so `systemctl` means what it means
//! on a real host.
//!
//! Every other container test starts a fresh image, runs a script and throws
//! it away. That cannot work here: systemd has to boot and stay booted, and
//! the commands run against it afterwards. So a [`SystemdContainer`] is
//! started, kept, and removed on drop.
//!
//! # What this needs from the host
//!
//! `--privileged` and `--cgroupns=host`. The second was found empirically:
//! without it systemd exits 255 immediately and logs nothing at all, which
//! reads like a broken image rather than a missing flag.
//!
//! Both are more than an ordinary test should demand, which is why these
//! scenarios live in their own binary and skip when the host will not have
//! them, rather than failing the suite for everyone whose Docker is rootless
//! or whose runner forbids privileged containers.
//!
//! # Why it is worth the trouble
//!
//! `ssh.install` enables a unit, `ssh.harden` reloads one, and `revert`
//! restores one. None of that could be observed before: without systemd the
//! enable step simply fails and the tests assert on the package instead. The
//! unit names also diverge — `ssh.service` on Debian, `sshd.service` on Arch —
//! and that divergence has only ever been checked against a mock.

#![allow(dead_code)]

use std::process::{Command, Output};

use super::{Image, binary_path};

/// How long to wait for systemd to finish booting.
///
/// It reaches `degraded` in a second or two on both families — a container
/// cannot mount the kernel filesystems or start a getty, so `degraded` is the
/// healthy outcome here, not a warning. The allowance is generous because a
/// cold image pull on a loaded CI runner is slower than a warm local one, and
/// the cost of being wrong is a spurious failure.
const BOOT_TIMEOUT_SECS: u32 = 60;

/// A booted systemd container, removed when it goes out of scope.
pub struct SystemdContainer {
    name: String,
}

impl SystemdContainer {
    /// Boots `image` with systemd as PID 1 and the binary mounted.
    ///
    /// Returns `None` when the host will not run it, so a caller can skip
    /// rather than fail. That distinction matters: a machine without
    /// privileged containers has not found a bug.
    pub fn boot(image: &Image, label: &str) -> Option<Self> {
        let tag = build_systemd_image(image)?;
        let name = format!("initd-systemd-{}-{}", image.family, label);

        // A leftover from an interrupted run would make `docker run` fail on
        // the name alone.
        remove_container(&name);

        let binary = binary_path();
        let mount = format!("{binary}:/usr/local/bin/initd:ro");

        let started = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &name,
                "--privileged",
                // Without this systemd exits 255 and logs nothing.
                "--cgroupns=host",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
                "-v",
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "-v",
                &mount,
                &tag,
                image.init_path,
            ])
            .output()
            .ok()?;

        if !started.status.success() {
            return None;
        }

        let container = Self { name };
        if !container.wait_until_booted() {
            return None;
        }

        // The ephemeral containers refresh the package index as part of every
        // script; this one boots an init instead, so it has to be done here.
        // Arch's image ships no package database at all, and without this the
        // first install fails with "database file for 'core' does not exist"
        // — which surfaces as a task that did nothing rather than as an
        // obviously broken harness.
        container.exec(image.refresh);

        Some(container)
    }

    /// Runs a shell command inside the booted container.
    pub fn exec(&self, script: &str) -> Output {
        Command::new("docker")
            .args(["exec", &self.name, "sh", "-c", script])
            .output()
            .expect("docker exec must execute")
    }

    /// Waits for systemd to finish booting.
    ///
    /// `degraded` counts as booted: a container cannot mount the kernel
    /// filesystems or start a getty, so those units fail on every healthy run.
    /// Waiting for `running` would wait forever.
    fn wait_until_booted(&self) -> bool {
        for _ in 0..BOOT_TIMEOUT_SECS {
            let state = self.exec("systemctl is-system-running");
            let reported = String::from_utf8_lossy(&state.stdout);
            let reported = reported.trim();

            if reported == "running" || reported == "degraded" {
                return true;
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        false
    }
}

impl Drop for SystemdContainer {
    fn drop(&mut self) {
        remove_container(&self.name);
    }
}

fn remove_container(name: &str) {
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}

/// Builds an image of `image` that can boot systemd, and returns its tag.
///
/// Debian's base image ships no init; Arch's does. Rather than branch on that,
/// each entry names its own install step and this runs whatever it is — `true`
/// where there is nothing to do.
///
/// The image is committed rather than built from a Dockerfile so the tests
/// stay self-contained: no build context, no second source of truth about what
/// each family installs.
///
/// It is deliberately *not* removed afterwards, unlike the containers. Every
/// scenario boots one, and rebuilding per test would add a package install to
/// each; reusing it costs a few hundred megabytes per family that survive the
/// run. Remove them with `docker rmi initd-systemd-debian:test
/// initd-systemd-arch:test` when the disk matters more than the next run's
/// speed.
fn build_systemd_image(image: &Image) -> Option<String> {
    let tag = format!("initd-systemd-{}:test", image.family);

    // Already built by an earlier scenario in this run.
    let existing = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .ok()?;
    if existing.status.success() {
        return Some(tag);
    }

    let builder = format!("initd-systemd-build-{}", image.family);
    remove_container(&builder);

    let installed = Command::new("docker")
        .args([
            "run",
            "--name",
            &builder,
            image.name,
            "sh",
            "-c",
            image.install_systemd,
        ])
        .output()
        .ok()?;

    if !installed.status.success() {
        remove_container(&builder);
        return None;
    }

    let committed = Command::new("docker")
        .args(["commit", &builder, &tag])
        .output()
        .ok()?;

    remove_container(&builder);
    committed.status.success().then_some(tag)
}
