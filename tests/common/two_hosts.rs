//! A hardened server in one container, an older client in another.
//!
//! The single-container connection scenarios prove a session negotiates, but
//! client and server there come from the same image and so from the same
//! OpenSSH release. That answers "can anyone connect?" and not "can an *old*
//! client connect?" — which is the sharper question, because
//! `ssh.harden-strict` narrows the algorithm lists and an algorithm the server
//! now requires is one an older client may never have learned.
//!
//! The version gap is the point: Debian 11 ships OpenSSH 8.4 and Arch ships
//! 10.4, and post-quantum key exchange arrived in 9. A filtered list that
//! looked fine against a modern client can still exclude everything an 8.4
//! client offers.
//!
//! # Shape
//!
//! Two long-lived containers on a private network rather than one ephemeral
//! script, because the client has to reach the server by name while both are
//! up. Both are removed on drop, as is the network.

#![allow(dead_code)]

use std::process::{Command, Output};

use super::{Image, LOGIN_USER, PREPARE_LOGIN_ACCOUNT, TEST_KEY, binary_path};

/// The oldest client worth testing against.
///
/// Debian 11 rather than something older because it is the earliest still
/// carrying security support at the time of writing, so it is the oldest
/// client an administrator can reasonably still be running — and it predates
/// the OpenSSH 9 algorithm changes the strict tier depends on.
const OLD_CLIENT_IMAGE: &str = "debian:11";

/// How the client installs OpenSSH, matching [`OLD_CLIENT_IMAGE`].
const OLD_CLIENT_INSTALL: &str = "apt-get update -qq >/dev/null 2>&1 && \
     apt-get install -y -qq openssh-client >/dev/null 2>&1";

/// The hostname the client reaches the server by.
const SERVER_HOST: &str = "initd-server";

/// A server container, a client container and the network between them.
pub struct TwoHosts {
    server: String,
    client: String,
    network: String,
}

impl TwoHosts {
    /// Brings up a server running `configure`, plus an older client.
    ///
    /// Returns `None` when Docker will not provide what this needs, so a
    /// caller can skip rather than fail.
    pub fn start(image: &Image, label: &str, configure: &str) -> Option<Self> {
        let suffix = format!("{}-{}", image.family, label);
        let hosts = Self {
            server: format!("initd-server-{suffix}"),
            client: format!("initd-client-{suffix}"),
            network: format!("initd-net-{suffix}"),
        };

        // Leftovers from an interrupted run would collide on the names.
        hosts.tear_down();

        Command::new("docker")
            .args(["network", "create", &hosts.network])
            .output()
            .ok()?
            .status
            .success()
            .then_some(())?;

        hosts.start_server(image, configure)?;
        hosts.start_client()?;

        Some(hosts)
    }

    /// Attempts a login from the old client and returns what it printed.
    ///
    /// `BatchMode=yes` so a refusal is reported rather than turning into a
    /// password prompt that hangs, and the host key checks are disabled
    /// because the server is new every run.
    pub fn attempt_login(&self) -> Output {
        Command::new("docker")
            .args([
                "exec",
                &self.client,
                "sh",
                "-c",
                // As the unprivileged account, not root: `ssh.harden` writes
                // `PermitRootLogin no`, so a root login afterwards is refused
                // by design. Asserting on it would report the safe tier as
                // locking out old clients when the server log plainly says
                // ROOT LOGIN REFUSED — measuring the harness, not the tier.
                &format!(
                    "ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
                     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
                     -i /root/.ssh/id_ed25519 \
                     {LOGIN_USER}@{SERVER_HOST} 'echo INITD_SESSION_ESTABLISHED' 2>&1"
                ),
            ])
            .output()
            .expect("docker exec must execute")
    }

    /// The client's OpenSSH version, so a scenario can report what it proved.
    pub fn client_version(&self) -> String {
        let output = Command::new("docker")
            .args(["exec", &self.client, "sh", "-c", "ssh -V 2>&1"])
            .output()
            .expect("docker exec must execute");

        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// The server's OpenSSH version.
    pub fn server_version(&self) -> String {
        let output = Command::new("docker")
            .args([
                "exec",
                &self.server,
                "sh",
                "-c",
                "sshd -V 2>&1 || ssh -V 2>&1",
            ])
            .output()
            .expect("docker exec must execute");

        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// Boots the server, applies `configure`, and starts sshd.
    ///
    /// Configured before the daemon starts, for the reason the single-host
    /// helper documents: the tasks reload a unit that does not exist here, and
    /// a daemon started first stops listening the moment hardening runs.
    fn start_server(&self, image: &Image, configure: &str) -> Option<()> {
        let binary = binary_path();
        let mount = format!("{binary}:/usr/local/bin/initd:ro");

        let started = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &self.server,
                "--network",
                &self.network,
                "--network-alias",
                SERVER_HOST,
                "-v",
                &mount,
                image.name,
                "sleep",
                "600",
            ])
            .output()
            .ok()?;
        started.status.success().then_some(())?;

        // The daemon is started separately, once the client's key is in place;
        // configuring before it starts is what the single-host helper
        // documents, and the account has to exist before the key can be
        // appended to it.
        let setup = format!(
            "{refresh} >/dev/null 2>&1; \
             {install} >/dev/null 2>&1; \
             {install_useradd} >/dev/null 2>&1; \
             ssh-keygen -A >/dev/null 2>&1; \
             mkdir -p /root/.ssh /run/sshd; \
             {PREPARE_LOGIN_ACCOUNT} \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             {configure} >/dev/null 2>&1; \
             touch /tmp/initd-server-ready",
            refresh = image.refresh,
            install = image.install_ssh,
            install_useradd = image.install_useradd,
        );

        Command::new("docker")
            .args(["exec", "-d", &self.server, "sh", "-c", &setup])
            .output()
            .ok()?;

        Some(())
    }

    /// Boots the old client and gives it a key the server will accept.
    ///
    /// The key pair is generated on the client and its public half appended to
    /// the server's `authorized_keys`, so the login being tested is a real
    /// public-key authentication rather than something the harness waved
    /// through.
    fn start_client(&self) -> Option<()> {
        let started = Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &self.client,
                "--network",
                &self.network,
                OLD_CLIENT_IMAGE,
                "sleep",
                "600",
            ])
            .output()
            .ok()?;
        started.status.success().then_some(())?;

        let setup = format!(
            "{OLD_CLIENT_INSTALL}; \
             mkdir -p /root/.ssh && chmod 700 /root/.ssh; \
             ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 -q; \
             cat /root/.ssh/id_ed25519.pub"
        );

        let keygen = Command::new("docker")
            .args(["exec", &self.client, "sh", "-c", &setup])
            .output()
            .ok()?;

        let public_key = String::from_utf8_lossy(&keygen.stdout);
        let public_key = public_key.lines().last()?.trim().to_owned();
        if !public_key.starts_with("ssh-") {
            return None;
        }

        // The account has to exist before its authorized_keys can be written,
        // and the configuration has to be in place before the daemon reads it.
        self.wait_for_server_setup()?;

        Command::new("docker")
            .args([
                "exec",
                &self.server,
                "sh",
                "-c",
                &format!(
                    "echo '{public_key}' >> /home/{LOGIN_USER}/.ssh/authorized_keys; \
                     chown {LOGIN_USER}:{LOGIN_USER} /home/{LOGIN_USER}/.ssh/authorized_keys; \
                     chmod 600 /home/{LOGIN_USER}/.ssh/authorized_keys"
                ),
            ])
            .output()
            .ok()?;

        self.start_server_daemon();
        Some(())
    }

    /// Waits for the server's package installs and configuration to finish.
    ///
    /// Polls for a marker the setup script writes last, rather than for the
    /// daemon: the daemon is started afterwards, and waiting on a process that
    /// nothing has launched yet would always time out.
    fn wait_for_server_setup(&self) -> Option<()> {
        for _ in 0..120 {
            let ready = Command::new("docker")
                .args([
                    "exec",
                    &self.server,
                    "sh",
                    "-c",
                    "test -f /tmp/initd-server-ready && echo ready",
                ])
                .output();

            if ready.is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("ready")) {
                return Some(());
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        None
    }

    /// Starts the daemon and waits for it to listen.
    fn start_server_daemon(&self) {
        let _ = Command::new("docker")
            .args([
                "exec",
                "-d",
                &self.server,
                "sh",
                "-c",
                "SSHD=$(command -v sshd) && \"$SSHD\" -D -e >/tmp/sshd.log 2>&1",
            ])
            .output();

        for _ in 0..30 {
            let listening = Command::new("docker")
                .args([
                    "exec",
                    &self.server,
                    "sh",
                    "-c",
                    "pgrep -x sshd >/dev/null && echo up",
                ])
                .output();

            if listening.is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("up")) {
                return;
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    fn tear_down(&self) {
        for name in [&self.server, &self.client] {
            let _ = Command::new("docker").args(["rm", "-f", name]).output();
        }
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network])
            .output();
    }
}

impl Drop for TwoHosts {
    fn drop(&mut self) {
        self.tear_down();
    }
}
