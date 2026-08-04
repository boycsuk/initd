//! Scenarios that need systemd running as PID 1.
//!
//! Ignored by default; run with `cargo nextest run -- --ignored`. They also
//! need a host that will run a privileged container, and skip rather than fail
//! where it will not — a rootless Docker has not found a bug.
//!
//! Every other container test works around systemd's absence. `ssh.install`
//! enables a unit and the enable step simply fails, so those tests assert the
//! package was installed instead and the enable goes unchecked. `ssh.harden`
//! reloads a unit; that reload has never been observed to succeed. The unit
//! names differ between families — `ssh.service` against `sshd.service` — and
//! that divergence has only ever been checked against a mock.
//!
//! These are the scenarios that close that gap. They are slower than the rest
//! by a wide margin: each boots an init system.

mod common;

use common::systemd::SystemdContainer;

/// Boots a container or skips the test.
///
/// A host that will not run privileged containers cannot answer these
/// questions, and failing there would make the suite unusable on exactly the
/// machines that are most locked down.
macro_rules! systemd_container {
    ($image:expr, $label:expr) => {
        match SystemdContainer::boot($image, $label) {
            Some(container) => container,
            None => {
                eprintln!("skipping: this host will not boot a privileged systemd container");
                return;
            }
        }
    };
}

for_each_image! {
    /// systemd must actually be PID 1, or every scenario below is measuring
    /// something else.
    ///
    /// The control. `degraded` is the healthy state in a container — the
    /// kernel filesystem mounts and the getty cannot work there — so this
    /// asserts on PID 1 rather than on a clean boot.
    fn systemd_boots_as_pid_one(image) {
        let container = systemd_container!(image, "boots");

        let output = container.exec("cat /proc/1/comm");
        let stdout = common::stdout_of(&output);

        assert_eq!(
            stdout.trim(),
            "systemd",
            "systemd must be PID 1 for these scenarios to mean anything: {stdout}"
        );
    }

    /// Installing the SSH capability must leave its unit enabled.
    ///
    /// The assertion the ordinary container tests cannot make. There they
    /// check the package landed and let the enable step fail silently, so a
    /// task that installed correctly and enabled the wrong unit — or no unit —
    /// would pass every one of them.
    fn installing_ssh_enables_the_units_this_family_names(image) {
        let container = systemd_container!(image, "install");

        let output = container.exec(&format!(
            "initd run ssh.install >/dev/null 2>&1; \
             systemctl is-enabled {unit}",
            unit = image.ssh_unit
        ));
        let stdout = common::stdout_of(&output);

        // Exact line, for the same reason `is-active` needs one: the states
        // `systemctl` reports are words that contain each other, and
        // `enabled-runtime` means enabled only until the next reboot.
        assert!(
            common::has_line(&stdout, "enabled"),
            "{} must be enabled after ssh.install: {stdout}",
            image.ssh_unit
        );
    }

    /// The unit must also be running, not merely enabled.
    ///
    /// Enabled means "starts at boot"; active means "is up now". A task that
    /// enabled without starting would leave the administrator with a server
    /// that is only reachable after a reboot.
    fn installing_ssh_leaves_the_service_running(image) {
        let container = systemd_container!(image, "active");

        let output = container.exec(&format!(
            "initd run ssh.install >/dev/null 2>&1; \
             systemctl is-active {unit}",
            unit = image.ssh_unit
        ));
        let stdout = common::stdout_of(&output);

        // An exact line, not a substring: `systemctl is-active` answers
        // `inactive` for a unit that does not exist, and `inactive` *contains*
        // `active`. Written as a substring check this passed against a
        // container where the package had failed to install — the precise
        // case it exists to catch.
        assert!(
            common::has_line(&stdout, "active"),
            "{} must be running after ssh.install: {stdout}",
            image.ssh_unit
        );
    }

    /// Hardening must reload the unit and leave it running.
    ///
    /// The reload is where hardening either takes effect or silently does not,
    /// and without systemd it has never once succeeded in a test. A reload
    /// that killed the service would strand every existing session — which is
    /// the failure this scenario exists to notice.
    fn hardening_reloads_the_unit_without_stopping_it(image) {
        let container = systemd_container!(image, "reload");

        let output = container.exec(&format!(
            "initd run ssh.install >/dev/null 2>&1; \
             initd authorize-key root '{key}' >/dev/null 2>&1; \
             initd run ssh.harden >/dev/null 2>&1; \
             systemctl is-active {unit}",
            key = common::TEST_KEY,
            unit = image.ssh_unit
        ));
        let stdout = common::stdout_of(&output);

        // Exact line: `inactive` contains `active`.
        assert!(
            common::has_line(&stdout, "active"),
            "{} must still be running after ssh.harden: {stdout}",
            image.ssh_unit
        );
    }

    /// A port change must leave a service systemd still considers healthy.
    ///
    /// `sshd -t` accepting the file says nothing about whether the unit came
    /// back up with it. A daemon that fails to restart on the new port is
    /// exactly how an administrator loses a server.
    fn changing_the_port_leaves_the_service_healthy(image) {
        let container = systemd_container!(image, "port");

        let output = container.exec(&format!(
            "initd run ssh.install >/dev/null 2>&1; \
             initd change-port 2222 >/dev/null 2>&1; \
             systemctl is-active {unit}; \
             grep '^Port' /etc/ssh/sshd_config",
            unit = image.ssh_unit
        ));
        let stdout = common::stdout_of(&output);

        assert!(
            stdout.contains("Port 2222"),
            "the port must change: {stdout}"
        );
        // Exact line: `inactive` contains `active`.
        assert!(
            common::has_line(&stdout, "active"),
            "{} must still be running on the new port: {stdout}",
            image.ssh_unit
        );
    }
}

/// Changing the port must warn when Debian's socket unit owns it.
///
/// Outside `for_each_image!` on purpose: socket activation is a Debian
/// arrangement. `ssh.socket` ships with that package and defines the listening
/// port itself, so the `Port` the task writes has nothing to do until the unit
/// is reconfigured — and silence there would be the worst outcome available:
/// success reported, the file reading 2222, the daemon still answering on 22.
///
/// Arch's openssh ships `sshd.service`, `sshd@.service` and
/// `sshdgenkeys.service`, and no socket unit at all, so the situation cannot
/// arise there. Written first as a matrix scenario and moved once it failed on
/// Arch for exactly that reason.
///
/// It lives in this binary rather than `integration_debian.rs` because it
/// needs a privileged container, and that file runs in the CI job that cannot
/// provide one — where it would have skipped silently every time.
#[test]
#[ignore = "requires docker"]
fn changing_the_port_warns_when_debians_socket_unit_owns_it() {
    require_docker!();

    let container = systemd_container!(&common::DEBIAN, "socket");

    // `/run/sshd` is recreated *after* the stop, with explicit ownership and
    // mode. The unit declares `RuntimeDirectory=sshd` and
    // `RuntimeDirectoryPreserve=no`, so systemd deletes that directory on stop
    // and a `mkdir` beforehand is undone by the stop itself; recreated
    // afterwards it needs 0755 root-owned or `sshd -t` rejects it as
    // group-writable. Both abort the port change before it can warn about
    // anything, which is how this failed twice while looking like a missing
    // warning.
    let output = container.exec(
        "initd run ssh.install >/dev/null 2>&1; \
         systemctl stop ssh.service >/dev/null 2>&1; \
         systemctl enable --now ssh.socket >/dev/null 2>&1; \
         mkdir -p /run/sshd && chmod 0755 /run/sshd && chown root:root /run/sshd; \
         initd change-port 2222 2>&1",
    );
    let stdout = common::stdout_of(&output);

    assert!(
        stdout.contains("ssh.socket") && stdout.contains("will not take effect"),
        "the port change must warn that ssh.socket owns the port: {stdout}"
    );
}
