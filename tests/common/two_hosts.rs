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

// Only `integration_old_client` builds these hosts, and every test binary that
// says `mod common;` compiles this module whole — so in the other nine it is
// dead by construction. That is the cost of sharing a module across binaries,
// not a sign of a helper nobody calls.
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

/// Seconds to wait for the server's sshd to report itself listening.
///
/// Ninety rather than thirty, because thirty is what CI ran out of. The old
/// wait polled for a pid file openSUSE never writes, so it always ran its full
/// length and then continued regardless — thirty seconds happened to be enough
/// on a quiet machine and was not on a loaded runner, where the login went to a
/// daemon that had not finished starting.
///
/// Then a hundred and eighty, because ninety is what `-j8` ran out of. The
/// note below predicted this in the shape of its own numbers — "over eighty
/// seconds under `-j4`" leaves no headroom at twice the parallelism — and
/// `an_old_client_survives_the_safe_tier::tumbleweed` collected on it twice in
/// two full runs, at 111s and 122s. Measured beside those: the same scenario
/// alone takes **14.9s**, a seven-fold spread that is contention rather than
/// anything about the daemon or the tier under test. Since the wait continues
/// rather than failing, the cost of being short is not a slow test but a
/// scenario that blames `ssh.harden` for a daemon still starting.
///
/// Costs nothing when the daemon is quick: the loop returns on the first try
/// that sees the line, which on every image measured here is the first.
const DAEMON_WAIT_TRIES: u32 = 180;

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
        // `family_tag` rather than `family`, and the difference is a whole
        // failure. openSUSE is two images and `image.family` answers `suse`
        // for both, so Tumbleweed and Leap built the same three container
        // names — and `start` begins by tearing down leftovers under those
        // names. Running in parallel, whichever started second **destroyed the
        // other's containers mid-scenario**.
        //
        // What that looked like is why it took a CI failure to find: the
        // surviving scenario reported `ssh.harden must not lock out an old
        // client (client Error response from daemon: No such container …)`,
        // blaming the tier under test for a pair of containers another test
        // had removed.
        //
        // The identical mistake is recorded on `Image::family_tag` itself,
        // which exists because committed images collided the same way. The
        // lesson was applied there and not here — one file further along.
        let suffix = format!("{}-{}", image.family_tag(), label);
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
        Self::version_reported_by(&self.client, "ssh -V")
    }

    /// The server's OpenSSH version.
    pub fn server_version(&self) -> String {
        Self::version_reported_by(&self.server, "sshd -V || ssh -V")
    }

    /// What a container says its OpenSSH version is.
    ///
    /// Both streams are read and joined, because **OpenSSH prints `-V` on
    /// stderr**. The `2>&1` inside the container redirects it into the shell's
    /// stdout, but only for the process — and `sshd -V` exits non-zero, so on
    /// the server the `||` fallback ran and its output landed wherever the
    /// second command put it. Reading only `Output::stdout` here left both
    /// versions empty, which is exactly how CI reported this scenario:
    ///
    /// ```text
    /// ssh.harden must not lock out an old client (client , server ):
    /// ```
    ///
    /// The whole point of naming the versions is that the scenario's claim is
    /// about a version gap, so a message that omits both says nothing about
    /// what was actually proved — and sent the reader to `ssh.harden` for a
    /// defect that was in the wait above.
    fn version_reported_by(container: &str, command: &str) -> String {
        let output = Command::new("docker")
            .args(["exec", container, "sh", "-c", command])
            .output()
            .expect("docker exec must execute");

        let mut reported = String::from_utf8_lossy(&output.stdout).into_owned();
        reported.push_str(&String::from_utf8_lossy(&output.stderr));

        let reported = reported.trim();

        // Docker's own complaints are not versions, and reading them as one is
        // how a failure message came to say
        // `(client Error response from daemon: No such container …)` — which
        // reads as a version string until somebody looks twice, and buries the
        // actual finding: the containers were gone. Naming that outright is
        // the difference between a message that misleads and one that points
        // at the harness.
        if reported.starts_with("Error response from daemon")
            || reported.contains("No such container")
        {
            return format!("<{container} is gone: {reported}>");
        }

        if reported.is_empty() {
            // Said out loud rather than left blank: an empty version is itself
            // a finding — the container is not answering — and a scenario that
            // prints nothing there reads as though it forgot to.
            return format!("<{container} reported no version>");
        }

        reported.to_owned()
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

        for _ in 0..DAEMON_WAIT_TRIES {
            // The daemon's own words, which is the rule this harness keeps
            // relearning: prefer a condition the program itself produces over a
            // tool that may not be installed. Three probes have now been tried
            // here and the first two degraded silently — `pgrep` is absent from
            // Debian's base image so it never matched, and `/run/sshd.pid` is
            // never written by openSUSE's sshd at all, measured on Tumbleweed
            // where the daemon answers immediately and the file does not exist
            // a minute later. Both turned this into a fixed thirty-second sleep
            // that happened to be long enough locally and was not on a loaded
            // CI runner, where the login then failed against a daemon still
            // starting and the scenario blamed `ssh.harden` for it.
            //
            // `/dev/tcp` was the obvious third choice and is wrong for the same
            // reason as the first two: it is a bash extension, and Debian's
            // `dash` and Alpine's busybox `ash` do not implement it — measured,
            // both report "not listening" forever. `ss`, `nc` and `netstat` are
            // each present in exactly one image.
            //
            // `sshd -D -e` writes "Server listening on ..." at the moment it
            // begins accepting, the harness already redirects that to
            // `/tmp/sshd.log`, and `grep` is in all six. Verified in both
            // directions on every image: `down` before the daemon starts, `up`
            // after, with a real client agreeing.
            let listening = Command::new("docker")
                .args([
                    "exec",
                    &self.server,
                    "sh",
                    "-c",
                    "grep -q 'Server listening' /tmp/sshd.log 2>/dev/null && echo up",
                ])
                .output();

            if listening.is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("up")) {
                return;
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        // Deliberately not a panic, and this is the one place in the harness
        // where silence is the lesser evil. The two openSUSE images take over
        // eighty seconds to answer under `-j4` and 111 to 122 under `-j8`,
        // against 14.9 alone — a seven-fold spread nobody has explained;
        // failing here would turn that unexplained delay into a red suite.
        // What the loop no longer does is give up on a condition that was
        // never going to be met — so a scenario that fails after this fails
        // because the daemon is genuinely not answering.
        //
        // The warning is the part that matters, and it is why this is not
        // simply silence: a scenario failing *after* it reports the tier under
        // test rather than the wait, so the line below is what tells a reader
        // which of the two to believe. Twice now it has been the wait.
        eprintln!(
            "warning: {} did not answer on port 22 within {DAEMON_WAIT_TRIES}s; \
             continuing, and the login below is what will report it",
            self.server
        );
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
