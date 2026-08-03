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
    /// Installs the OpenSSH *client*, needed to prove a session negotiates.
    ///
    /// Separate from [`Self::install_ssh`] because the split is a packaging
    /// decision rather than a fact about OpenSSH: Debian ships
    /// `openssh-client` apart from the server, Arch puts both in `openssh`.
    pub install_ssh_client: &'static str,
    /// Installs whatever provides `useradd`, so a scenario can create the
    /// unprivileged account it logs in as.
    ///
    /// Debian's base image does not ship it — it lives in `passwd` — while
    /// Arch's does. A no-op command rather than an `Option` keeps every field
    /// substitutable into the same script without branching.
    pub install_useradd: &'static str,
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
    install_ssh_client: "apt-get install -y -qq openssh-client",
    install_useradd: "apt-get install -y -qq passwd",
    query_ssh: "dpkg-query -W -f='${Status}' openssh-server",
    installed_needle: "install ok installed",
};

/// Arch and derivatives: `pacman`, `openssh`.
pub const ARCH: Image = Image {
    name: "archlinux:latest",
    family: "arch",
    refresh: "pacman -Sy --noconfirm",
    install_ssh: "pacman -S --needed --noconfirm openssh",
    // The same package: Arch does not split client from server.
    install_ssh_client: "pacman -S --needed --noconfirm openssh",
    // `useradd` is in the base image here, so there is nothing to install.
    install_useradd: "true",
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

/// Marker a scenario greps for when a session authenticated end to end.
pub const CONNECTED: &str = "INITD_SESSION_ESTABLISHED";

/// The unprivileged account the connection scenarios log in as.
///
/// Not root, and not incidentally: `ssh.harden` writes `PermitRootLogin no`,
/// so a scenario connecting as root after hardening would be asking the daemon
/// to do what the task just forbade, and would fail for a reason that has
/// nothing to do with whether hardening broke connectivity.
///
/// Named `initdtest` rather than something ordinary like `operator` because
/// Debian's base image already ships an `operator` *group*, and `useradd` then
/// refuses.
pub const LOGIN_USER: &str = "initdtest";

/// Sets up an unprivileged account with its own key pair, plus the authorised
/// key on root the lockout guard requires.
///
/// Two keys, two purposes, and conflating them is what makes hardening
/// scenarios fail confusingly: [`TEST_KEY`] satisfies the guard so `ssh.harden`
/// will proceed at all, while the generated pair is what actually logs in.
const PREPARE_ACCOUNT: &str = "useradd -m -s /bin/sh initdtest >/dev/null 2>&1; \
     su initdtest -c 'mkdir -p ~/.ssh && \
       ssh-keygen -t ed25519 -N \"\" -f ~/.ssh/id_ed25519 -q && \
       cp ~/.ssh/id_ed25519.pub ~/.ssh/authorized_keys && \
       chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys' >/dev/null 2>&1; ";

/// Runs `configure`, then starts sshd and attempts a real login as root.
///
/// This asks the question `sshd -t` cannot. Validation parses the file; it
/// says nothing about whether a client and this daemon can agree on a cipher,
/// a key exchange and a MAC. A configuration narrowed to an empty or mutually
/// unusable intersection is still perfectly *valid* — `sshd -t` returns
/// success and no one can log in. That is the exact failure `ssh.harden-strict`
/// is documented as the only tier able to cause, so it needs a scenario that
/// can observe it.
///
/// Everything happens inside one container: the daemon listens on localhost
/// and the client connects to it. No privileged container, no systemd, no
/// network between containers. The cost is that client and server are the same
/// OpenSSH release, so this proves a session negotiates — not that an *older*
/// client still can. That second question needs two images and is left to its
/// own scenario.
///
/// The client key is generated in the container rather than reusing
/// [`TEST_KEY`], whose private half is deliberately not in the repository:
/// a key that opens a root session must not be one anybody can read here.
/// [`TEST_KEY`] stays as the authorised key that satisfies the lockout guard.
pub fn run_and_connect(image: &Image, configure: &str) -> std::process::Output {
    run_in_container(
        image,
        &format!(
            "{install_server} >/dev/null 2>&1; \
             {install_client} >/dev/null 2>&1; \
             {install_useradd} >/dev/null 2>&1; \
             ssh-keygen -A >/dev/null 2>&1; \
             mkdir -p /root/.ssh /run/sshd; \
             {PREPARE_ACCOUNT} \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             {configure} >/dev/null 2>&1; \
             {SSHD_START} \
             {SSH_PROBE} \
             {SSH_LOGIN}",
            install_server = image.install_ssh,
            install_client = image.install_ssh_client,
            install_useradd = image.install_useradd,
        ),
    )
}

/// Starts the daemon in the foreground, backgrounded by the shell.
///
/// Started *after* the configuration is written, which is not a detail. The
/// tasks reload the service once they have written the file, and without
/// systemd that reload cannot do what it does on a real host — verified in a
/// container, where a daemon started beforehand stops listening the moment
/// `ssh.harden` runs, and every connection scenario then fails for a reason
/// belonging to the harness rather than to the hardening. Configuring first
/// also models the real sequence better: on a host, systemd brings the service
/// back up already holding the new file.
///
/// Resolved through `PATH` rather than hardcoded: `sshd` lives in `/usr/sbin`
/// on Debian and Arch, but hardcoding either is the mistake this project bans
/// outright. `-e` sends its log to stderr so a refusal to start is diagnosable
/// from the captured output instead of vanishing.
const SSHD_START: &str = r#"SSHD=$(command -v sshd) && "$SSHD" -D -e & "#;

/// Waits for the listener by trying it, rather than sleeping a fixed time.
///
/// A blind `sleep` is either slower than it needs to be or occasionally too
/// short — and too short here would look exactly like the connection failure
/// the scenario is meant to detect, which is the worst way for a test to lie.
const SSH_PROBE: &str = "i=0; while [ $i -lt 30 ]; do \
     su initdtest -c 'ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
         -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 \
         initdtest@localhost true' 2>/dev/null && break; \
     i=$((i + 1)); \
     done; ";

/// The login whose success or failure the scenario reads.
///
/// `BatchMode=yes` is what makes a failure meaningful: without it the client
/// would fall back to prompting for a password, and a scenario checking that
/// key authentication survived hardening would hang instead of failing.
/// The marker it echoes must stay the one [`CONNECTED`] names — a shell string
/// cannot interpolate a constant, so `the_login_echoes_the_marker_scenarios_grep_for`
/// checks it instead. Were they to drift, every connection scenario would look
/// for a line the session never prints and fail as though hardening had broken
/// the daemon.
const SSH_LOGIN: &str = "su initdtest -c 'ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
     -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
     initdtest@localhost \"echo INITD_SESSION_ESTABLISHED\"' 2>&1";

/// Runs `configure`, then asks the running daemon which authentication
/// methods it still offers.
///
/// A refused login names them: OpenSSH answers `Permission denied
/// (publickey,password)` on a default daemon and `Permission denied
/// (publickey)` once password authentication is off. That list comes from the
/// daemon in memory, so unlike grepping `sshd_config` it cannot be satisfied
/// by a directive that was written but never took effect.
///
/// The attempt is made with `PubkeyAuthentication=no` so the authorised key
/// cannot succeed and hide the answer, and with `BatchMode=yes` so the client
/// reports the refusal rather than prompting for a password and hanging.
pub fn run_and_ask_offered_methods(image: &Image, configure: &str) -> std::process::Output {
    run_in_container(
        image,
        &format!(
            "{install_server} >/dev/null 2>&1; \
             {install_client} >/dev/null 2>&1; \
             {install_useradd} >/dev/null 2>&1; \
             ssh-keygen -A >/dev/null 2>&1; \
             mkdir -p /root/.ssh /run/sshd; \
             {PREPARE_ACCOUNT} \
             initd authorize-key root '{TEST_KEY}' >/dev/null 2>&1; \
             {configure} >/dev/null 2>&1; \
             {SSHD_START} \
             {SSH_PROBE} \
             su initdtest -c 'ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
                 -o UserKnownHostsFile=/dev/null \
                 -o PreferredAuthentications=password \
                 -o PubkeyAuthentication=no \
                 -o ConnectTimeout=5 \
                 initdtest@localhost true' 2>&1",
            install_server = image.install_ssh,
            install_client = image.install_ssh_client,
            install_useradd = image.install_useradd,
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

/// Skips the test body when Docker is unavailable — unless `INITD_REQUIRE_DOCKER`
/// is set, in which case its absence is a failure.
///
/// Returning rather than failing keeps the suite usable on a developer machine
/// without Docker, where these tests simply cannot run. That is wrong in CI:
/// a runner whose Docker is misconfigured would report a green suite having
/// executed none of these, which is the one outcome worse than red. CI sets
/// the variable, so there the skip becomes the failure it should be.
#[macro_export]
macro_rules! require_docker {
    () => {
        if !common::docker_available() {
            assert!(
                std::env::var_os("INITD_REQUIRE_DOCKER").is_none(),
                "INITD_REQUIRE_DOCKER is set but docker is unavailable: these \
                 tests would silently pass without running"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_login_echoes_the_marker_scenarios_grep_for() {
        assert!(
            SSH_LOGIN.contains(CONNECTED),
            "SSH_LOGIN must echo {CONNECTED}, or every connection scenario \
             greps for a line that is never printed"
        );
    }
}
