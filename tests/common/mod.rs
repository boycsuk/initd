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
    /// Installs the firewalld front-end, where the family presents one.
    ///
    /// Only RHEL does. Which front-end holds a host's ruleset is a property of
    /// the host rather than of the family — a RHEL server runs firewalld, and
    /// one where the administrator removed it drives `nft` directly — so a
    /// scenario about the firewall has to give the image what a stock host of
    /// that family would have. The other five run `true`: honest, and it
    /// keeps the scenarios from needing a branch.
    pub install_firewalld: &'static str,
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

impl Image {
    /// A tag fragment identifying this *image*, not merely its family.
    ///
    /// Committed images are named after their family, which was unambiguous
    /// while every family had exactly one image. openSUSE has two, and
    /// `image.family` answers `suse` for both — so Tumbleweed and Leap would
    /// share one committed image, and whichever ran second would silently
    /// exercise the other's packages while reporting its own name.
    ///
    /// Derived from the image reference rather than added as a field, so a new
    /// entry cannot forget it: two images can only collide here by being the
    /// same image.
    pub fn family_tag(&self) -> String {
        self.name
            .replace(['/', ':', '.'], "-")
            .trim_matches('-')
            .to_ascii_lowercase()
    }
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
    install_firewalld: "true",
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
    install_firewalld: "true",
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
    install_firewalld: "true",
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
    // Not a no-op, unlike Arch's and Alpine's: a Rocky base image has no init
    // at all until this runs. It refreshes first because the image build runs this
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
    install_firewalld: "dnf install -y -q firewalld",
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

/// openSUSE Tumbleweed: `zypper`, systemd, `wheel` — and a `wheel` that grants
/// nothing until a drop-in says so.
///
/// The rolling variant. Present alongside Leap rather than standing in for the
/// family because the two disagree: Tumbleweed packages Zellij and Leap does
/// not, which is the first divergence inside a family this matrix has had to
/// represent.
pub const TUMBLEWEED: Image = Image {
    name: "opensuse/tumbleweed",
    family: "suse",
    refresh: "zypper --non-interactive refresh",
    // `--non-interactive` before the subcommand, as the backend does: zypper
    // prompts for licence agreements and vendor changes as well as for
    // confirmation, and none of those are answered by a trailing flag.
    install_ssh: "zypper --non-interactive install openssh-server",
    // Split as Debian splits it, and the same quiet failure if omitted: no
    // client means nothing to connect with, which reads as the daemon
    // refusing.
    install_ssh_client: "zypper --non-interactive install openssh-clients",
    // From shadow, in the base image.
    install_useradd: "true",
    install_tmux: "zypper --non-interactive install tmux",
    install_systemd: "zypper --non-interactive install systemd",
    init_path: "/usr/lib/systemd/systemd",
    ssh_unit: "sshd.service",
    // Not measured either way, and `true` is the answer that cannot produce a
    // confusing failure: a static binary runs on a host with a current glibc,
    // where a dynamic one on a host with an older glibc dies with a linker
    // error that reads as a broken image.
    needs_static_binary: true,
    install_nftables: "zypper --non-interactive install nftables",
    // firewalld is packaged but not installed by default, and the backend
    // presents nftables alone — so nothing installs it here. Named rather than
    // left blank because the field is not optional, and `true` is what the
    // other families use for "nothing to do".
    install_firewalld: "true",
    install_wireguard: "zypper --non-interactive install wireguard-tools",
    install_sysctl: "zypper --non-interactive install procps systemd",
    query_ssh: "rpm -q openssh-server",
    installed_needle: "openssh-server",
};

/// openSUSE Leap 16.0: the same family, resolved to a different set of names.
///
/// Carried in the matrix rather than assumed equivalent to Tumbleweed, because
/// the measurement that produced this family found them disagreeing — Zellij is
/// packaged on one and absent from the other. A matrix holding only the rolling
/// variant would have agreed with the backend about a name the stable one does
/// not have.
pub const LEAP: Image = Image {
    name: "opensuse/leap",
    family: "suse",
    refresh: "zypper --non-interactive refresh",
    install_ssh: "zypper --non-interactive install openssh-server",
    install_ssh_client: "zypper --non-interactive install openssh-clients",
    install_useradd: "true",
    install_tmux: "zypper --non-interactive install tmux",
    install_systemd: "zypper --non-interactive install systemd",
    init_path: "/usr/lib/systemd/systemd",
    ssh_unit: "sshd.service",
    needs_static_binary: true,
    install_nftables: "zypper --non-interactive install nftables",
    install_firewalld: "true",
    install_wireguard: "zypper --non-interactive install wireguard-tools",
    install_sysctl: "zypper --non-interactive install procps systemd",
    query_ssh: "rpm -q openssh-server",
    installed_needle: "openssh-server",
};

/// Every image the shared scenarios run against.
///
/// Only families [`crate::distro::Family`] actually resolves belong here. SUSE
/// now appears twice, which is a first: every other family is represented by
/// one image because one set of names describes it. openSUSE needs two because
/// Tumbleweed and Leap resolve Zellij differently, and a matrix that covered
/// only one of them would let the backend's `for_distribution` split go
/// unexercised on the half it was written for.
pub const IMAGES: &[&Image] = &[&DEBIAN, &ARCH, &ALPINE, &RHEL, &TUMBLEWEED, &LEAP];

/// A public key the hardening tasks accept, so the lockout guard lets them
/// proceed. Every scenario that hardens needs one first.
pub const TEST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ test@initd";

/// The group granting administrative rights on an image.
///
/// Five families, two answers: Debian grants sudo through `sudo`, while the
/// rest use `wheel` — Alpine because it ships `doas`, whose default
/// configuration grants that group.
///
/// The name is the whole answer on four of them and not on openSUSE, where
/// `%wheel` ships commented out and membership alone grants nothing. That is
/// the backend's concern rather than this helper's: what is asked for here is
/// the group a scenario should add an account to, which is `wheel` either way.
/// A scenario concluding "this account can escalate" from membership alone
/// would be unsound there, and none does.
///
/// Here rather than in one scenario file because two of them need it now, and
/// the copy that stayed behind would be the one that stopped agreeing.
pub fn admin_group(image: &Image) -> &'static str {
    if image.name.contains("debian") {
        "sudo"
    } else {
        "wheel"
    }
}

/// The command that creates an account on an image.
///
/// `useradd` comes from the shadow suite; busybox provides `adduser` instead,
/// and its flags differ in meaning rather than in spelling.
pub fn create_account(image: &Image) -> &'static str {
    if image.name.contains("alpine") {
        "adduser -D -H"
    } else {
        "useradd -m"
    }
}

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

/// An image of this family with its package metadata already fetched.
///
/// Every scenario starts a fresh container and the harness prepends
/// [`Image::refresh`] so package installation works. A container keeps nothing
/// between runs, so that download is paid once per scenario and thrown away —
/// which is cheap on apt and is not on zypper: measured cold, `apt-get update`
/// takes about a second on `debian:13` and `zypper refresh` about nine on
/// `opensuse/tumbleweed`, which refreshes six repositories. Across the 174
/// openSUSE scenarios that is roughly twenty-six minutes of the run spent
/// re-fetching metadata that never changes.
///
/// So the refresh is done once per family and committed, exactly as
/// [`systemd::build_systemd_image`] already does for the init packages, and for
/// the same reason: no build context and no second source of truth about what a
/// family installs — the command committed here is the family's own
/// [`Image::refresh`] and nothing else.
///
/// Scenarios keep calling refresh; against this image it finds the caches
/// populated and returns immediately. That is deliberate — the alternative,
/// dropping the refresh from the script, would make every scenario depend on
/// this optimisation having worked.
///
/// Returns the base image name where anything goes wrong. A committed cache is
/// a speed-up, and a test run that fails because a speed-up failed would be
/// worse than a slow one.
/// What the cached image has done before any scenario runs on it.
///
/// The refresh, and then every package the scenarios go on to install. Baking
/// them is worth far more than it looks, and the reason is dnf: measured on
/// `rockylinux:9`, `/var/cache/dnf` is 4 KB on the bare image and **69 MB**
/// after one `dnf install` — a solv cache built once and then reused, with the
/// file's mtime unchanged on the second call. The three costs, per scenario:
///
/// | on the bare image             | 6551 ms |
/// | on a metadata-only cache      | 2199 ms |
/// | with the packages baked in    |  313 ms |
///
/// So the harness was already recovering two thirds by committing the refresh;
/// this recovers the rest. Twenty-one times on the image the suite is slowest
/// on, and the whole of it paid once per image rather than once per scenario.
///
/// Failures are ignored on purpose. A package absent from a family — firewalld
/// outside RHEL, systemd on Alpine — leaves the image without it, and the
/// scenario that needs it installs it as it always did. Baking is an
/// optimisation, and an optimisation that could fail a run would be a worse
/// trade than the time it saves.
fn preparation(image: &Image) -> String {
    let steps = [
        image.refresh,
        image.install_ssh,
        image.install_ssh_client,
        image.install_useradd,
        image.install_nftables,
        image.install_wireguard,
        image.install_sysctl,
        image.install_tmux,
    ];

    // `;` rather than `&&`: one absent package must not stop the rest.
    steps
        .iter()
        .map(|step| format!("{step} >/dev/null 2>&1"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Builds every image's cache, so no scenario has to.
///
/// Exposed for the one test that calls it — `prepare_the_images` in
/// `integration_shared` — which exists to move this work out of the scenarios
/// rather than to assert anything. The distinction matters: preparation is not
/// a test, and giving it a test's timeout is what broke CI. Baking Rocky's
/// packages takes 25s on 32 cores and **over 300s on a 2-core runner**, where
/// it tripped the five-minute ceiling and killed the two scenarios that
/// happened to be building it — leaving every other Rocky scenario with no
/// image either.
///
/// Idempotent, and cheap when the images exist: each is skipped on a hit, the
/// same check `cached_image` makes.
pub fn prepare_every_image() {
    for image in IMAGES {
        // The return value is the tag or, on failure, the bare image name.
        // Either is a usable answer — a preparation that could fail the run
        // would be a worse trade than the time it saves — so nothing is
        // asserted here.
        let _ = cached_image(image);
    }
}

/// Serialises building one image's cache across every test process.
///
/// nextest runs each test in its own process, so a `Mutex` reaches none of the
/// others. A lock file does — and the failure it prevents is not subtle: at
/// `-j8`, eight scenarios finding no cache all build one, each downloading the
/// same metadata, and the seven that lose the race have spent minutes on work
/// the winner also did.
fn build_lock(image: &Image) -> std::fs::File {
    let path = std::env::temp_dir().join(format!("initd-cache-{}.lock", image.family_tag()));

    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .unwrap_or_else(|error| panic!("the build lock at {} must open: {error}", path.display()));

    // `flock` through the raw fd rather than a crate: this is a test harness,
    // and a dependency here would be one more thing to audit for a lock held
    // for seconds.
    //
    // Safety: the fd is owned by `file`, which outlives the call and is
    // returned to the caller so the lock is held for as long as it lives.
    let locked = unsafe { libc_flock(std::os::fd::AsRawFd::as_raw_fd(&file)) };

    assert!(
        locked,
        "the build lock at {} must be acquirable",
        path.display()
    );

    file
}

/// `flock(fd, LOCK_EX)`, declared here rather than pulling in a crate.
///
/// # Safety
///
/// `fd` must be a valid, open file descriptor for the duration of the call.
unsafe fn libc_flock(fd: std::os::fd::RawFd) -> bool {
    unsafe extern "C" {
        fn flock(fd: std::os::fd::RawFd, operation: i32) -> i32;
    }

    /// `LOCK_EX` on Linux.
    const LOCK_EX: i32 = 2;

    unsafe { flock(fd, LOCK_EX) == 0 }
}

fn cached_image(image: &Image) -> String {
    let tag = format!("initd-cache-{}:test", image.family_tag());

    let existing = Command::new("docker")
        .args(["image", "inspect", &tag])
        .output();

    if existing.is_ok_and(|out| out.status.success()) {
        return tag;
    }

    // One builder at a time per image. Without this every scenario that
    // reaches a missing cache builds it — eight of them at `-j8`, each
    // downloading the same metadata, and the one that commits last wins. The
    // lock is held across the whole build rather than around the `commit`,
    // since the download is what costs.
    let _guard = build_lock(image);

    // Another thread may have built it while this one waited.
    if Command::new("docker")
        .args(["image", "inspect", &tag])
        .output()
        .is_ok_and(|out| out.status.success())
    {
        return tag;
    }

    let builder = format!("initd-cache-build-{}", image.family_tag());
    let _ = Command::new("docker").args(["rm", "-f", &builder]).output();

    let refreshed = Command::new("docker")
        .args([
            "run",
            "--name",
            &builder,
            image.name,
            "sh",
            "-c",
            &preparation(image),
        ])
        .output();

    let built = refreshed.is_ok_and(|out| out.status.success())
        && Command::new("docker")
            .args(["commit", &builder, &tag])
            .output()
            .is_ok_and(|out| out.status.success());

    let _ = Command::new("docker").args(["rm", "-f", &builder]).output();

    if built { tag } else { image.name.to_owned() }
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

    // No refresh here: `cached_image` ran it before committing, and the index
    // it produced is in the image. Repeating it cost a second per scenario for
    // metadata the container already had — small next to the package installs,
    // and paid roughly 170 times a run.
    let base = cached_image(image);

    let output = Command::new("docker")
        .args(["run", "--rm", "-v", &mount, &base, "sh", "-c", script])
        .output()
        .expect("docker run must execute");

    panic_if_the_container_never_ran(image, &output);

    output
}

/// Docker's own exit code for "the container did not start".
///
/// 125 is the daemon refusing before anything ran — out of memory, a bad flag,
/// an image that will not pull. Distinct by design from the *script's* exit
/// code, which is what every scenario here is actually asking about, and from
/// 126/127, which mean the command was found unrunnable inside a container that
/// did start.
const DOCKER_COULD_NOT_START: i32 = 125;

/// Fails loudly where the container never ran, rather than letting a scenario
/// read the silence as an answer.
///
/// The rule `exit_code_of` already follows, one layer up and learned the same
/// way. A daemon too loaded to start a container returns empty output and 125;
/// the scenario then asserts against that emptiness and reports the tool as
/// broken, sending the reader to `src/` for a defect that is not there. It
/// surfaced when the matrix grew from four images to six, which made a latent
/// fault likely rather than creating one.
///
/// The cause was misread at the time as memory: six large images against a host
/// with more cores than gigabytes. Measured since, that is false — a live
/// container is 4.7 MiB against 13 GB free, and sixteen simultaneous starts of
/// `opensuse/tumbleweed` fail zero times. What recurs is the daemon refusing
/// every start at once, which looks identical from here (exit 125, empty
/// stdout) and is why the wrong remedy survived a year of full runs.
///
/// A panic naming the image and both streams is the right answer because there
/// is no honest value to return: "the question could not be asked" is not a
/// result the caller's assertion can represent.
fn panic_if_the_container_never_ran(image: &Image, output: &std::process::Output) {
    if output.status.code() != Some(DOCKER_COULD_NOT_START) {
        return;
    }

    panic!(
        "{}: the container never started, so this says nothing about the code \
         under test. Docker exited {DOCKER_COULD_NOT_START}.\n\
         Read the stderr below before changing how the suite is run: this \
         message used to recommend `--test-threads 1` on the theory that six \
         images exhaust the host, and that was measured wrong — a live \
         container is 4.7 MiB and sixteen simultaneous starts of the largest \
         image fail zero times. The recurring cause is the daemon refusing \
         every start (`unsupported protocol` on WSL2, cleared by \
         `wsl --shutdown`), which serialising does not fix and which costs an \
         eleven-fold slowdown to pretend otherwise.\n\
         stdout: {}\nstderr: {}",
        image.name,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Runs a shell command inside a fresh `--privileged` container.
///
/// Returns `None` where the host will not grant the capability, so a scenario
/// can skip rather than fail — the rule `integration_systemd` already follows,
/// and for the same reason: a rootless Docker has not found a bug.
///
/// The capability this buys is a writable `/proc/sys`. Docker mounts it
/// read-only in an ordinary container, which is why `sysctl.ip-forward` is
/// pinned there as the refusal it is; with `--privileged` the kernel accepts
/// the write and the success path becomes observable. Unlike
/// [`systemd::SystemdContainer`] this needs no `--cgroupns=host`, because
/// nothing here boots an init — the two flags answer different questions and
/// only one is needed for a sysctl.
pub fn run_in_privileged_container(image: &Image, script: &str) -> Option<std::process::Output> {
    let binary = binary_for(image)?;

    // Asked as its own question, before the scenario runs. Inferring the answer
    // from the scenario's own output cannot work: that stream carries whatever
    // the container's shell wrote as well as whatever Docker did, and one of
    // the tasks under test here is named `sysctl.unprivileged-ports` — so a
    // scenario that failed while naming the task it was running would be read
    // as a host refusing the flag, and a real regression would report itself as
    // a skip. The probe writes nothing and touches nothing.
    if !grants_privileged(image) {
        return None;
    }

    let mount = format!("{binary}:/usr/local/bin/initd:ro");
    let full_script = format!("{} >/dev/null 2>&1; {script}", image.refresh);

    let base = cached_image(image);

    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            "-v",
            &mount,
            &base,
            "sh",
            "-c",
            &full_script,
        ])
        .output()
        .expect("docker run must execute");

    // Not folded into the `grants_privileged` check above: that one asks
    // whether the host *permits* the flag and answers `None` so the scenario
    // skips, which is the right answer to "this host cannot run this test".
    // This asks whether the container started at all, and a skip would be the
    // wrong answer to that — it would hide a matrix too large for the host
    // behind a message saying the host lacks a capability it has.
    panic_if_the_container_never_ran(image, &output);

    Some(output)
}

/// Whether this host will start a `--privileged` container at all.
///
/// `true` is claimed only on a container that started *and* proved the
/// capability the scenarios need, by writing a namespaced sysctl. Docker
/// refusing the flag and a daemon-level policy silently dropping it are not the
/// same failure, and only the write distinguishes them — a container can start
/// with the flag accepted and still present a read-only `/proc/sys`.
fn grants_privileged(image: &Image) -> bool {
    let probe = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            image.name,
            "sh",
            "-c",
            // Namespaced per network namespace, so this writes the container's
            // own value and never the host's. Restored immediately regardless,
            // since a probe that leaves state behind would change what the
            // scenario after it measures.
            "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 \
             && sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 \
             && echo GRANTED",
        ])
        .output()
        .expect("docker run must execute");

    stdout_of(&probe).contains("GRANTED")
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

    // A container that never ran produces no code, and the caller compares
    // whatever comes back against a number from `docs/cli.md`. Returning a
    // sentinel there reports "the contract is broken" for a container the
    // daemon refused to start — which is how a saturated Docker reads as a
    // violated exit-code contract, sending whoever sees it to `main.rs` for a
    // defect that is not there. It was observed once in a full run and never
    // in isolation, which is the shape of the problem rather than a coincidence.
    //
    // Panicking says which of the two happened. A test that cannot ask its
    // question has not answered it.
    let stdout = stdout_of(&output);

    stdout
        .lines()
        .last()
        .and_then(|line| line.trim().parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "{}: no exit code came back from `initd {args}` — the container \
                 did not run, so this says nothing about the contract. \
                 stdout: {stdout:?}, stderr: {:?}",
                image.name,
                String::from_utf8_lossy(&output.stderr)
            )
        })
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
                $crate::for_each_image!(@image tumbleweed, common::TUMBLEWEED, $image, $body);
                $crate::for_each_image!(@image leap, common::LEAP, $image, $body);
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

    /// An `Output` with the given exit code, built without running anything.
    ///
    /// `ExitStatus` cannot be constructed portably, so this borrows the one a
    /// real process leaves behind — `sh -c 'exit N'` is the cheapest way to
    /// obtain a status with a chosen code, and it needs no Docker, which is
    /// what keeps these two tests in the ordinary suite.
    fn output_with_code(code: i32) -> std::process::Output {
        let status = Command::new("sh")
            .args(["-c", &format!("exit {code}")])
            .status()
            .expect("sh must run");

        std::process::Output {
            status,
            stdout: Vec::new(),
            stderr: b"Error response from daemon: cannot allocate memory".to_vec(),
        }
    }

    #[test]
    fn every_image_commits_under_a_tag_of_its_own() {
        // The defect this was written against, which predates the cache and was
        // found while adding it: committed images were named after
        // `image.family`, unambiguous only while every family had one image.
        // openSUSE has two and both answer `suse`, so Tumbleweed and Leap
        // shared one committed image — whichever ran second exercised the
        // other's packages while reporting its own name, which is a test that
        // lies rather than one that fails.
        let tags: Vec<String> = IMAGES.iter().map(|image| image.family_tag()).collect();

        for (index, tag) in tags.iter().enumerate() {
            assert!(
                !tags[index + 1..].contains(tag),
                "two images share the tag {tag}, so one would reuse the other's \
                 committed image: {tags:?}"
            );
        }
    }

    #[test]
    fn a_tag_is_usable_as_a_docker_reference() {
        // `docker tag` rejects slashes, colons and uppercase in the position
        // these are interpolated into, and `opensuse/tumbleweed` carries the
        // first. A tag that Docker refuses would fall back to the base image
        // silently — the cache would simply never work, and nothing would say
        // so, because falling back is the designed behaviour on failure.
        for image in IMAGES {
            let tag = image.family_tag();

            assert!(
                !tag.is_empty()
                    && tag
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "{} yields {tag}, which docker will not accept",
                image.name
            );
        }
    }

    #[test]
    fn a_container_that_never_started_is_a_panic_rather_than_an_answer() {
        // The failure this prevents is a scenario reporting the tool as broken
        // when Docker refused to start anything: stdout is empty either way, so
        // the assertion cannot tell the two apart. Verified against the real
        // shape — `docker run` on a host that cannot allocate exits 125 with no
        // stdout.
        let refused = output_with_code(DOCKER_COULD_NOT_START);

        let panicked = std::panic::catch_unwind(|| {
            panic_if_the_container_never_ran(&DEBIAN, &refused);
        });

        assert!(
            panicked.is_err(),
            "a container that never started must not be read as a result"
        );
    }

    #[test]
    fn a_scenario_that_genuinely_failed_is_left_alone() {
        // The other half, and the one that matters more: 125 is Docker's own
        // code for "did not start", while a script exiting non-zero *inside* a
        // container that ran is exactly what several scenarios assert on.
        // Swallowing those would turn real failures into panics about the
        // harness — a guard worse than the bug.
        for code in [0, 1, 2, 6, 126, 127] {
            let ran = output_with_code(code);

            panic_if_the_container_never_ran(&DEBIAN, &ran);
        }
    }
}
