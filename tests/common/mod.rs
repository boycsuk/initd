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
//! # The binaries, and why they are separate
//!
//! `integration_shared` and `integration_connection` run against ordinary
//! ephemeral containers and cover most of the matrix. Two others exist because
//! they need something the ephemeral ones cannot give:
//!
//! - `integration_systemd` boots systemd as PID 1, which is what makes
//!   `systemctl enable` observable at all. It needs `--privileged` and
//!   `--cgroupns=host`, so it skips where a host will not grant them.
//! - `integration_old_client` puts an older client in a second container, to
//!   ask whether hardening locks out a client several releases behind — the
//!   question a single image cannot pose, since client and server there share
//!   one OpenSSH release.
//!
//! Both are slow enough, and demanding enough of the host, to keep out of the
//! shared matrix.
//!
//! # Known limitations
//!
//! `ssh.allow-users` has no coverage here: it
//! is deliberately interactive-only, so there is no subcommand to drive it
//! from a container script. Widening the CLI surface to make it testable would
//! reintroduce the very risk that keeping it out of the CLI avoids, so the gap
//! is accepted and its guards are covered against mocks instead.

// Each integration binary compiles this module in full, so whatever the other
// binary uses looks unused from here. That is inherent to sharing a module
// across test binaries, not a sign of dead code.
#![allow(dead_code)]

pub mod systemd;
pub mod tui;
pub mod two_hosts;

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
    /// Makes the image bootable by systemd, run once before committing the
    /// image the systemd scenarios boot.
    ///
    /// Debian's base image ships no init at all; Arch's already has one, so
    /// there is nothing to install and this is a no-op.
    pub install_systemd: &'static str,
    /// Absolute path to the init this image boots.
    ///
    /// The one place in these tests a binary path is written out, because
    /// `docker run` takes a command rather than something to resolve through
    /// `PATH`, and the container has no shell of ours to resolve it in.
    pub init_path: &'static str,
    /// The systemd unit providing SSH here.
    ///
    /// `ssh.service` on Debian, `sshd.service` on Arch — the divergence the
    /// backend absorbs, and until now only ever checked against a mock.
    pub ssh_unit: &'static str,
    /// Installs `tmux`, which the interface scenarios drive the TUI through.
    ///
    /// ratatui needs a real terminal, and the interface lives in the alternate
    /// screen — so a pipe renders nothing and `script` captures nothing
    /// readable once the program exits. tmux allocates a pty *and* can dump a
    /// live pane, which is what makes the screen assertable while it is drawn.
    /// It also keeps this to a shell tool rather than a new crate to audit.
    pub install_tmux: &'static str,
    /// Installs whatever provides `useradd`, so a scenario can create the
    /// unprivileged account it logs in as.
    ///
    /// Debian's base image does not ship it — it lives in `passwd` — while
    /// Arch's does. A no-op command rather than an `Option` keeps every field
    /// substitutable into the same script without branching.
    pub install_useradd: &'static str,
    /// Installs the nftables front-end, which the firewall drives.
    ///
    /// Absent from both base images: filtering is a kernel feature and `nft`
    /// is the userspace tool for reaching it, packaged separately.
    pub install_nftables: &'static str,
    /// Installs the WireGuard tools, which provide `wg`.
    ///
    /// Both families call the package `wireguard-tools`, which is coincidence
    /// rather than a rule — Debian also has a `wireguard` metapackage that
    /// pulls a DKMS module no current kernel needs.
    pub install_wireguard: &'static str,
    /// Installs `procps`, which provides `sysctl`.
    ///
    /// Debian's base image ships no `sysctl` at all; Arch's does. A no-op on
    /// the family that needs nothing keeps both substitutable into one script.
    pub install_sysctl: &'static str,
    /// Whether this image needs a statically linked binary.
    ///
    /// Alpine has no glibc, so the default build cannot start there at all —
    /// the container reports `initd: not found`, which looks like a mounting
    /// mistake. True here means the scenarios use the musl build and skip when
    /// it has not been made.
    pub needs_static_binary: bool,
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
    install_tmux: "apt-get install -y -qq tmux",
    install_systemd: "apt-get update -qq && apt-get install -y -qq systemd systemd-sysv",
    init_path: "/sbin/init",
    ssh_unit: "ssh.service",
    needs_static_binary: false,
    install_nftables: "apt-get install -y -qq nftables",
    install_wireguard: "apt-get install -y -qq wireguard-tools",
    install_sysctl: "apt-get install -y -qq procps",
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
    install_tmux: "pacman -S --needed --noconfirm tmux",
    // Arch's base image already ships systemd.
    install_systemd: "true",
    init_path: "/usr/lib/systemd/systemd",
    ssh_unit: "sshd.service",
    needs_static_binary: false,
    install_nftables: "pacman -S --needed --noconfirm nftables",
    install_wireguard: "pacman -S --needed --noconfirm wireguard-tools",
    // `sysctl` is in the base image here.
    install_sysctl: "true",
    query_ssh: "pacman -Q openssh",
    installed_needle: "openssh",
};

/// Alpine: `apk`, OpenRC, busybox.
///
/// The family that diverges in more than names, which is why it is worth the
/// third container: no systemd, no shadow suite, no GNU coreutils.
pub const ALPINE: Image = Image {
    name: "alpine:3.23",
    family: "alpine",
    // `apk` fetches the index per call with `--no-cache`, so there is no
    // separate refresh step to run.
    refresh: "true",
    install_ssh: "apk add --no-cache openssh",
    // The same package, as on Arch: Alpine does not split client from server.
    install_ssh_client: "apk add --no-cache openssh",
    // busybox provides `adduser`; there is nothing to install.
    install_useradd: "true",
    install_tmux: "apk add --no-cache tmux",
    // OpenRC rather than systemd, and the base image already has it.
    install_systemd: "true",
    init_path: "/sbin/init",
    ssh_unit: "sshd",
    // No glibc here, so the default build cannot start.
    needs_static_binary: true,
    install_nftables: "apk add --no-cache nftables",
    install_wireguard: "apk add --no-cache wireguard-tools",
    // busybox provides `sysctl`.
    install_sysctl: "true",
    query_ssh: "apk info -e openssh",
    installed_needle: "openssh",
};

/// RHEL, through Rocky: `dnf`, systemd, `wheel`.
///
/// A rebuild rather than Red Hat's own image, because RHEL proper needs a
/// subscription to reach its repositories and a test that cannot install a
/// package proves nothing. Rocky resolves to the same family through its `ID`,
/// which `detects_rhel_by_its_own_id`'s sibling test pins.
///
/// Every command below was run against the base image before being written
/// here, which corrected three that had looked obvious: the base image ships
/// neither `systemctl` nor `/usr/lib/systemd/systemd`, so systemd is genuinely
/// installed rather than declared present; `nft` is absent too, despite
/// nftables being the subsystem firewalld drives; and the client package is
/// `openssh-clients`, plural, where every other family spells it singular or
/// ships one package for both.
pub const RHEL: Image = Image {
    name: "rockylinux/rockylinux:9",
    family: "rhel",
    refresh: "dnf makecache -q",
    install_ssh: "dnf install -y -q openssh-server",
    // Plural, and the one name here a scenario would fail on quietly: without
    // a client there is nothing to connect with, which reads as the daemon
    // refusing rather than as a missing package.
    install_ssh_client: "dnf install -y -q openssh-clients",
    // `useradd` is in the base image, from shadow-utils.
    install_useradd: "true",
    install_tmux: "dnf install -y -q tmux",
    // Not a no-op, unlike the other three: a Rocky base image has no init at
    // all until this runs. It refreshes first because the image build runs this
    // field on its own, without the `refresh` the ephemeral path prepends —
    // which is why Debian's entry carries its own `apt-get update` too.
    install_systemd: "dnf makecache -q && dnf install -y -q systemd",
    init_path: "/usr/lib/systemd/systemd",
    ssh_unit: "sshd.service",
    // Not because glibc is missing, as on Alpine, but because it is older than
    // the one the default build links against: a debug binary built on a
    // current host dies here with `version GLIBC_2.39 not found`. That is the
    // failure musl was chosen to avoid, and this is the first image in the
    // matrix to demonstrate it rather than describe it.
    needs_static_binary: true,
    install_nftables: "dnf install -y -q nftables",
    install_wireguard: "dnf install -y -q wireguard-tools",
    // Two packages where the other families need one or none. `sysctl` comes
    // from procps-ng rather than procps, and `/etc/sysctl.d` — the directory a
    // drop-in has to land in to survive a reboot — is owned by systemd-udev
    // here, not by systemd. Asked of the package database rather than assumed:
    // `dnf provides /etc/sysctl.d` names udev, and installing systemd alone
    // leaves the directory absent.
    install_sysctl: "dnf install -y -q procps-ng systemd-udev",
    query_ssh: "rpm -q openssh-server",
    installed_needle: "openssh-server",
};

/// Every image the shared scenarios run against.
///
/// Only families [`crate::distro::Family`] actually resolves belong here. SUSE
/// is absent because its backend is, and a matrix entry without a backend would
/// fail for code deliberately not written yet.
pub const IMAGES: &[&Image] = &[&DEBIAN, &ARCH, &ALPINE, &RHEL];

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

/// The binary a given image can actually execute.
///
/// The default build links dynamically against glibc, which Alpine does not
/// have — the container reports `initd: not found`, which reads as a mounting
/// mistake rather than as what it is. This is the reason the project ships
/// musl binaries at all, and the reason it is stated here: a scenario that
/// mounted the glibc build on Alpine would fail for a linkage problem while
/// appearing to test a task.
///
/// Falls back to the default build where no musl one has been made, so the
/// glibc images keep working without one. Alpine scenarios skip instead —
/// running them against a binary that cannot start proves nothing.
pub fn binary_for(image: &Image) -> Option<String> {
    if !image.needs_static_binary {
        return Some(binary_path());
    }

    let mut path = std::env::current_exe().expect("the test binary must have a path");
    // target/debug/deps/<test> -> target/x86_64-unknown-linux-musl/debug/initd
    path.pop();
    path.pop();
    path.pop();
    path.push("x86_64-unknown-linux-musl");
    path.push("debug");
    path.push("initd");

    path.exists().then(|| path.to_string_lossy().into_owned())
}

/// Runs a shell command inside a fresh container, with the binary mounted.
///
/// The binary is bind-mounted rather than copied so the container starts from
/// the pristine image every time.
pub fn run_in_container(image: &Image, script: &str) -> std::process::Output {
    let binary = binary_for(image).unwrap_or_else(|| {
        panic!(
            "{} needs a statically linked binary, which has not been built. \
             Run `cargo build --target x86_64-unknown-linux-musl` first — it \
             needs musl-gcc, from `musl-tools` on Debian. Scenarios should call \
             `require_runnable!(image)` so they skip rather than reach here.",
            image.name
        )
    });

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
/// Creates the account with whichever tool the image provides.
///
/// `useradd` comes from the shadow suite and Alpine ships busybox, whose
/// `adduser` takes different flags — `-D` for "no password" where the shadow
/// suite means the same by passing none, and `-h` where it takes `-m`. Trying
/// one and falling back keeps this a single string every scenario substitutes,
/// rather than a branch each of them has to remember.
/// The account also gets a password, which is not incidental. Alpine builds
/// OpenSSH *without* PAM — `UsePAM` is not a directive its `sshd -T` even
/// recognises — so `platform_locked_account()` is compiled in there, and an
/// account whose hash is `!` is refused with "account is locked" despite
/// holding a valid key. `adduser -D` leaves exactly that hash. Debian and Arch
/// build with PAM, where the same check is compiled out and the account logs
/// in regardless, which is why this only surfaced once Alpine joined the
/// matrix.
///
/// The password is never used: every scenario authenticates with a key, and
/// several of them disable password authentication outright.
pub const PREPARE_LOGIN_ACCOUNT: &str = "(useradd -m -s /bin/sh initdtest || adduser -D -s /bin/sh initdtest) >/dev/null 2>&1; \
     echo 'initdtest:initdtest' | chpasswd >/dev/null 2>&1; \
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
             {PREPARE_LOGIN_ACCOUNT} \
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
             {PREPARE_LOGIN_ACCOUNT} \
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

/// Runs a script in a container whose `/etc/os-release` is the named fixture.
///
/// Detection is unit-tested against these files directly, which proves the
/// parser. What it cannot prove is that the binary reads the real path and
/// resolves a backend from what it finds — the step between the parser and
/// everything else. Mounting a fixture over `/etc/os-release` puts a
/// distribution in front of the tool that no image provides: a derivative that
/// must resolve through `ID_LIKE`, or one that must be refused outright.
pub fn run_with_os_release(image: &Image, fixture: &str, script: &str) -> std::process::Output {
    let binary = binary_path();
    let mount = format!("{binary}:/usr/local/bin/initd:ro");

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/os-release")
        .join(fixture);
    let fixture_mount = format!("{}:/etc/os-release:ro", fixture_path.display());

    Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            "-v",
            &fixture_mount,
            image.name,
            "sh",
            "-c",
            script,
        ])
        .output()
        .expect("docker run must execute")
}

/// Runs `initd <args>` in a fresh container and returns its exit code.
///
/// The code is echoed and read back rather than taken from the `Output`'s
/// status, which belongs to `docker run` and to the shell wrapping it — a
/// script that refreshes the package index first would report the refresh's
/// result, not the command's. Echoing it is the only way to get the number the
/// documented contract is about.
///
/// Output is discarded: these scenarios are about the code, and a subcommand
/// that printed the right thing while exiting wrongly is the failure being
/// looked for.
pub fn exit_code_of(image: &Image, args: &str) -> i32 {
    let output = run_in_container(image, &format!("initd {args} >/dev/null 2>&1; echo $?"));

    stdout_of(&output)
        .lines()
        .last()
        .and_then(|line| line.trim().parse().ok())
        .unwrap_or(-1)
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

/// Skips a scenario on an image whose binary has not been built.
///
/// Alpine needs the musl build, since the default one links against glibc and
/// cannot start there at all. Skipping is honest where failing would not be:
/// the scenario has nothing to say about a binary that never ran.
#[macro_export]
macro_rules! require_runnable {
    ($image:expr) => {
        if common::binary_for($image).is_none() {
            eprintln!(
                "skipping {}: no static binary — build with \
                 `cargo build --target x86_64-unknown-linux-musl`",
                $image.name
            );
            return;
        }
    };
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
                $crate::for_each_image!(@image alpine, common::ALPINE, $image, $body);
                $crate::for_each_image!(@image rhel, common::RHEL, $image, $body);
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
            // Applied once here rather than in every scenario: an image whose
            // binary has not been built has nothing to say about a task, and
            // reaching the body would fail on the mount rather than on the
            // behaviour under test.
            require_runnable!(&$konst);

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
