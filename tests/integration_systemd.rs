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
