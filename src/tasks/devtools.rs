//! Tools an administrator wants on the box: a shell, a multiplexer, a version
//! manager, a toolchain.
//!
//! Installing one is a system operation and involves no account. Only three
//! things here are per-user, and each declares the account as a parameter like
//! any other value: changing a login shell, and activating a version manager
//! in someone's shell configuration. Splitting them also keeps the destructive
//! flag honest — putting a binary on the box is not destructive, changing
//! someone's login shell is.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::binaries::{Artefact, Release};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, OutputLine, Stream};
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Task};

/// Families these tasks support.
///
/// RHEL is absent, and only fish is left using this. It is packaged in EPEL —
/// a repository Red Hat does not support, whose `epel-release` is not in any
/// Red Hat repository, and which Red Hat's own RHEL 10 Extensions is
/// documented as conflicting with. fish publishes no static binary either, and
/// its own documentation points RHEL users at the openSUSE Build Service, so
/// there is no route here this tool could verify.
const SUPPORTED: &[Family] = &[Family::Debian, Family::Arch, Family::Alpine];

/// Families the multiplexer reaches, by either mechanism.
///
/// Arch packages it, and everyone else installs the checksummed musl release —
/// the same artefact, since it links against nothing.
const RELEASE_SUPPORTED: &[Family] = &[Family::Debian, Family::Arch, Family::Alpine, Family::Rhel];

/// Families the version manager reaches, by either mechanism.
///
/// Debian and Arch package it; RHEL does not and installs the checksummed musl
/// release instead, which is the same artefact. Alpine is the one absence, and
/// not for want of a package: its own release is glibc-linked where every other
/// family's is musl, so there is nothing here this tool could verify and run.
const MISE_SUPPORTED: &[Family] = &[Family::Debian, Family::Arch, Family::Rhel];

/// Families packaging the Rust toolchain manager.
///
/// Neither Alpine nor RHEL. Both could reach `rustup-init`, which is published
/// with a checksum per architecture — but only from the archive path that pins
/// a version. The current-release path serves a new binary on every rustup
/// release, so a digest compiled into this build would invalidate itself, and
/// pinning a version means choosing which rustup an administrator may install.
/// Neither is decided here yet, so the capability stays where a package
/// provides it.
const PACKAGED_SUPPORTED: &[Family] = &[Family::Debian, Family::Arch];

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Builds the developer environment category.
pub fn category() -> Category {
    Category::new(
        "Developer environment",
        vec![
            Node::Task(Box::new(InstallFish)),
            Node::Task(Box::new(InstallZellij)),
            Node::Task(Box::new(InstallMise)),
            Node::Task(Box::new(InstallRust)),
        ],
    )
}

/// Installs the fish shell.
pub struct InstallFish;

impl Task for InstallFish {
    fn id(&self) -> &'static str {
        "fish.install"
    }

    fn title(&self) -> &'static str {
        "Install the fish shell"
    }

    fn description(&self) -> &'static str {
        "Installs fish and registers it in /etc/shells so an account may adopt \
         it. Set it for a user with users.set-shell."
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn consequences(&self, _values: &ParamValues) -> Vec<Consequence> {
        // Installing a shell gives nobody that shell. Said plainly because the
        // two read as one action and are not.
        vec![Consequence::Invalidates {
            task: "users.set-shell",
            reason: Reason::RequiresSetting {
                setting: "a login shell, which no account has adopted yet",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        backend
            .packages()
            .install(executor, backend.package_for(Capability::Fish))?;

        // Registered in /etc/shells, without which `chsh` refuses it and some
        // PAM configurations refuse a session for an account that uses it.
        // Read back from the system rather than assumed: the path differs
        // between distributions and releases.
        let path = resolve_program(executor, "fish")?;

        register_shell(executor, backend, &path)?;

        report(progress, format!("fish is installed at {path}"));
        report(
            progress,
            "never make it root's shell: a shell that is not POSIX breaks \
             recovery scripts that assume one"
                .to_owned(),
        );

        Ok(Outcome::Done)
    }
}

/// Installs the Zellij multiplexer.
pub struct InstallZellij;

impl InstallZellij {
    /// Name of the parameter holding the version to install.
    pub const VERSION: &'static str = "version";

    /// Releases this build carries a digest for.
    ///
    /// Deliberately short: each entry is a promise that this project verified
    /// that artefact, so the table grows by someone downloading a release and
    /// computing its digest rather than by copying a number from a page.
    ///
    /// Both digests below were computed from the archives at these URLs on
    /// 2026-08-04. Two versions rather than one so that this project's release
    /// cadence does not decide which upstream version an administrator may
    /// install; two architectures because the digest belongs to the artefact,
    /// and the two builds of one release hash differently.
    pub const RELEASES: &[Release] = &[
        Release {
            version: "0.44.3",
            archive_member: "zellij",
            artefacts: &[
                Artefact {
                    arch: "x86_64",
                    url: "https://github.com/zellij-org/zellij/releases/download/v0.44.3/zellij-x86_64-unknown-linux-musl.tar.gz",
                    sha256: "0f7c346788627f506c0a28296517768633cff24fc822a739f8264b640ecad751",
                },
                Artefact {
                    arch: "aarch64",
                    url: "https://github.com/zellij-org/zellij/releases/download/v0.44.3/zellij-aarch64-unknown-linux-musl.tar.gz",
                    sha256: "15e6534d42644d66973d136c590c49739dcfd6a1a2a0d3d917973f16c81b45fb",
                },
            ],
        },
        Release {
            version: "0.43.1",
            archive_member: "zellij",
            artefacts: &[
                Artefact {
                    arch: "x86_64",
                    url: "https://github.com/zellij-org/zellij/releases/download/v0.43.1/zellij-x86_64-unknown-linux-musl.tar.gz",
                    sha256: "541d98efef5558293ef85ad9acd29e4d920b6e881513b9e77255d8207020d75a",
                },
                Artefact {
                    arch: "aarch64",
                    url: "https://github.com/zellij-org/zellij/releases/download/v0.43.1/zellij-aarch64-unknown-linux-musl.tar.gz",
                    sha256: "32321ad5f61c2c62d156162d1df95dc823666f84e4a0d7cd79b0fef02930b165",
                },
            ],
        },
    ];
}

impl Task for InstallZellij {
    fn id(&self) -> &'static str {
        "zellij.install"
    }

    fn title(&self) -> &'static str {
        "Install the Zellij multiplexer"
    }

    fn description(&self) -> &'static str {
        "Installs Zellij, so a session survives a dropped connection. Arch has \
         a package; Debian and Ubuntu have none, so a release archive is \
         downloaded and its checksum verified."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::VERSION, "Version", ParamKind::Version)
                .with_hint("a version this build can verify"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        RELEASE_SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // Arch packages it; Debian and Ubuntu do not, in any suite. The
        // backend answers which mechanism applies, so the task does not ask
        // which distribution it is on.
        if backend.has_package_for(Capability::Zellij) {
            backend
                .packages()
                .install(executor, backend.package_for(Capability::Zellij))?;

            report(
                progress,
                "zellij installed from the distribution".to_owned(),
            );

            return Ok(Outcome::Done);
        }

        // Asked before a version is even resolved: a host that already has the
        // binary needs no download, and re-installing over it would replace a
        // build the administrator may have chosen deliberately.
        if backend.binaries().is_installed(executor, "zellij")? {
            report(progress, "zellij is already installed".to_owned());

            return Ok(Outcome::Done);
        }

        let version = values.get(Self::VERSION)?;
        let release = crate::backend::release_installer::release_for(Self::RELEASES, version)?;

        report(progress, format!("downloading zellij {version}"));

        backend.binaries().install(executor, "zellij", release)?;

        report(
            progress,
            "zellij installed and its checksum verified".to_owned(),
        );

        Ok(Outcome::Done)
    }
}

/// Installs the mise version manager.
pub struct InstallMise;

impl InstallMise {
    /// Releases this build carries a digest for.
    ///
    /// Computed from the archives at these URLs on 2026-08-05, by the same rule
    /// the Zellij table follows: a digest served by the host serving the
    /// artefact proves only that the transfer completed.
    ///
    /// The musl builds rather than the gnu ones, and the archive member is a
    /// path rather than a bare name — `mise/bin/mise`, read out of the tarball
    /// rather than guessed, since an installer that extracted the wrong member
    /// would fail after the digest had already been checked.
    ///
    /// mise does publish an RPM repository, which this declines: its `baseurl`
    /// carries neither `$basearch` nor an EL version, so one flat path serves
    /// every architecture and release.
    pub const RELEASES: &[Release] = &[Release {
        version: "2026.8.2",
        archive_member: "mise/bin/mise",
        artefacts: &[
            Artefact {
                arch: "x86_64",
                url: "https://github.com/jdx/mise/releases/download/v2026.8.2/mise-v2026.8.2-linux-x64-musl.tar.gz",
                sha256: "065b34faf429b4b58e1bf510f5ef42f3729b8d4f04b70d2d20aa6afea2527027",
            },
            Artefact {
                arch: "aarch64",
                url: "https://github.com/jdx/mise/releases/download/v2026.8.2/mise-v2026.8.2-linux-arm64-musl.tar.gz",
                sha256: "3cf8b7d81d6405ffde72d529af5541b6b107d36101ca6b5a44c1242ff275a876",
            },
        ],
    }];
}

impl Task for InstallMise {
    fn id(&self) -> &'static str {
        "mise.install"
    }

    fn title(&self) -> &'static str {
        "Install the mise version manager"
    }

    fn description(&self) -> &'static str {
        "Installs mise, which pins language runtimes per project. On a server \
         it is used through shims or `mise exec`, since its shell activation \
         does not run in a non-interactive session."
    }

    fn supported_families(&self) -> &'static [Family] {
        MISE_SUPPORTED
    }

    fn consequences(&self, _values: &ParamValues) -> Vec<Consequence> {
        // The failure this prevents: activation is a prompt hook, so a deploy
        // script or a systemd unit sees none of the versions mise manages, and
        // the tool appears to work everywhere except where it matters.
        vec![Consequence::Invalidates {
            task: "mise.activate",
            reason: Reason::RequiresSetting {
                setting: "shims on PATH — activation does not run non-interactively",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // Which mechanism applies is asked of the backend, never of the
        // family: Debian and Arch package this and Red Hat's repositories do
        // not, so the empty name routes to the verified release instead —
        // the same artefact, since it is musl and links against nothing.
        if backend.has_package_for(Capability::Mise) {
            backend
                .packages()
                .install(executor, backend.package_for(Capability::Mise))?;
        } else if backend.binaries().is_installed(executor, "mise")? {
            report(progress, "mise is already installed".to_owned());

            return Ok(Outcome::Done);
        } else {
            let release = crate::backend::release_installer::release_for(
                Self::RELEASES,
                Self::RELEASES
                    .first()
                    .map(|release| release.version)
                    .unwrap_or_default(),
            )?;

            report(
                progress,
                format!(
                    "Installing mise {} from a verified release...",
                    release.version
                ),
            );

            backend.binaries().install(executor, "mise", release)?;
        }

        report(progress, "mise is installed".to_owned());
        report(
            progress,
            "on a server, reach it through shims or `mise exec --` rather than \
             shell activation"
                .to_owned(),
        );

        Ok(Outcome::Done)
    }
}

/// Installs the Rust toolchain.
pub struct InstallRust;

impl InstallRust {
    /// Name of the parameter holding the account the toolchain belongs to.
    pub const USER: &'static str = "user";
}

impl Task for InstallRust {
    fn id(&self) -> &'static str {
        "rust.install"
    }

    fn title(&self) -> &'static str {
        "Install the Rust toolchain"
    }

    fn description(&self) -> &'static str {
        "Installs rustup and a stable toolchain for one account. A toolchain \
         belongs to whoever builds with it, not to the machine."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the toolchain belongs to"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        PACKAGED_SUPPORTED
    }

    fn consequences(&self, _values: &ParamValues) -> Vec<Consequence> {
        // rustup installs no C linker, and this is the single most common
        // first-build failure. It surfaces at link time, long after the
        // toolchain reported itself installed.
        vec![Consequence::Invalidates {
            task: "rust.install",
            reason: Reason::RequiresSetting {
                setting: "a C linker — rustup does not install one",
            },
            check: Some(crate::tasks::consequence::Check {
                command: Command::new("sh").args(["-c", "command -v cc"]),
                resolved_when_stdout_contains: "cc".to_owned(),
            }),
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();

        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        backend
            .packages()
            .install(executor, backend.package_for(Capability::Rust))?;

        report(progress, format!("rust is available to {user}"));

        Ok(Outcome::Done)
    }
}

/// The absolute path of a program, as the system resolves it.
///
/// Read from the host rather than assumed: fish lives at `/usr/bin/fish` on
/// Arch and at either `/usr/bin/fish` or `/bin/fish` on Debian depending on
/// the release, and a path that does not match what is installed produces a
/// login shell nobody can use.
fn resolve_program(executor: &dyn Executor, program: &str) -> Result<String> {
    let command = Command::new("sh").args(["-c", &format!("command -v {program}")]);
    let output = executor.run(&command)?;

    if !output.success() {
        return Err(Error::ProgramNotFound {
            program: program.to_owned(),
        });
    }

    Ok(output.stdout.trim().to_owned())
}

/// Adds a shell to `/etc/shells` if it is not already listed.
fn register_shell(executor: &dyn Executor, backend: &dyn Backend, path: &str) -> Result<()> {
    const SHELLS: &str = "/etc/shells";

    let files = backend.files();
    let existing = files.read(executor, SHELLS)?;

    // Compared line by line rather than as a substring: `/bin/fish` is a
    // substring of `/usr/bin/fish`, so a careless check would decide the wrong
    // one was already registered.
    if existing.lines().any(|line| line.trim() == path) {
        return Ok(());
    }

    files.write(executor, SHELLS, &format!("{existing}{path}\n"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn zellij_is_packaged_on_one_family_and_not_the_other() {
        // The divergence that earned `BinaryInstaller`: not a different package
        // name, a different installation mechanism. Verified against the
        // package databases — no Debian or Ubuntu suite carries zellij.
        assert!(for_family(Family::Arch).has_package_for(Capability::Zellij));
        assert!(!for_family(Family::Debian).has_package_for(Capability::Zellij));
    }

    #[test]
    fn a_packaging_family_installs_mise_from_its_repository() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);
        let backend = for_family(Family::Debian);

        InstallMise
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("Debian packages it");

        assert!(
            mock.recorded_lines()[0].contains("apt-get"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_family_without_a_mise_package_installs_the_verified_release() {
        // The gap this closes: the task went straight to `packages().install`,
        // so on a family whose package name is empty it would have asked the
        // package manager to install nothing at all.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""), // command -v mise
            Reply::ok("x86_64\n"), // uname -m
            Reply::ok(""),         // the download-and-verify script
        ]);
        let backend = for_family(Family::Rhel);

        InstallMise
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("the release must install");

        let script = mock
            .recorded()
            .into_iter()
            .find_map(|command| {
                command
                    .args
                    .into_iter()
                    .find(|arg| arg.contains("sha256sum"))
            })
            .expect("the artefact must be checksummed before it is extracted");

        assert!(
            script.contains("065b34faf429b4b58e1bf510f5ef42f3729b8d4f04b70d2d20aa6afea2527027"),
            "the compiled-in digest must be the one checked: {script}"
        );
    }

    #[test]
    fn an_already_installed_mise_is_left_alone() {
        // Asked before a version is resolved, so re-running the task on a host
        // that has it does not re-download an archive.
        let mock = MockExecutor::with_replies([Reply::ok("/usr/local/bin/mise")]);
        let backend = for_family(Family::Rhel);

        InstallMise
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("a second run must succeed");

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "only the check must run: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn arch_installs_zellij_from_its_repository() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);
        let backend = for_family(Family::Arch);

        InstallZellij
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("Arch packages it, so no version is needed");

        assert!(
            mock.recorded_lines()[0].contains("pacman"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn every_published_release_has_a_build_for_both_targets() {
        // The two architectures this project ships for. A release listed with
        // only one leaves the other machine refused at install time, long
        // after the version looked available.
        for release in InstallZellij::RELEASES {
            for arch in ["x86_64", "aarch64"] {
                let artefact = release
                    .artefact_for(arch)
                    .unwrap_or_else(|| panic!("{} has no {arch} build", release.version));

                assert_eq!(artefact.sha256.len(), 64, "{artefact:?}");
                assert!(
                    artefact.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                    "a digest is hex: {artefact:?}"
                );
            }
        }
    }

    #[test]
    fn a_url_names_the_version_and_architecture_it_carries() {
        // The pairing that silently breaks: a digest computed from one archive
        // beside a URL pointing at another. Verification would fail and read
        // as tampering rather than as a typo.
        for release in InstallZellij::RELEASES {
            for artefact in release.artefacts {
                assert!(
                    artefact.url.contains(release.version),
                    "{artefact:?} does not name {}",
                    release.version
                );
                assert!(
                    artefact.url.contains(artefact.arch),
                    "{artefact:?} does not name its architecture"
                );
                assert!(
                    artefact.url.starts_with("https://"),
                    "an unencrypted download would defeat the digest: {artefact:?}"
                );
            }
        }
    }

    #[test]
    fn no_two_artefacts_share_a_digest() {
        // Copying a digest between rows is the mistake this catches: every
        // archive here is a distinct build, so a repeat means one row was
        // filled in from another rather than from the file it names.
        let digests: Vec<&str> = InstallZellij::RELEASES
            .iter()
            .flat_map(|release| release.artefacts.iter().map(|a| a.sha256))
            .collect();

        let mut unique = digests.clone();
        unique.sort_unstable();
        unique.dedup();

        assert_eq!(digests.len(), unique.len(), "duplicate digest: {digests:?}");
    }

    #[test]
    fn debian_refuses_a_version_this_build_cannot_verify() {
        // The release table is empty until real digests are filled in, so every
        // version is refused. Installing an unverified binary as root is the
        // failure the whole capability exists to prevent.
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(InstallZellij::VERSION, "0.1.0".to_owned());

        let err = InstallZellij
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect_err("an unverifiable version must be refused");

        assert!(matches!(err, Error::UnknownRelease { .. }), "{err:?}");
        assert!(
            !mock.recorded_lines().iter().any(|c| c.contains("curl")),
            "nothing must be downloaded: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_host_that_already_has_zellij_downloads_nothing() {
        // Re-installing would replace a build the administrator may have
        // chosen deliberately, and there is nothing to gain by it.
        let mock = MockExecutor::with_replies([Reply::ok("/usr/local/bin/zellij")]);
        let backend = for_family(Family::Debian);

        InstallZellij
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("an installed binary is the desired state");

        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "only the check must run: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_shell_is_registered_at_the_path_the_system_resolves() {
        // fish is at /usr/bin/fish on Arch and either path on Debian depending
        // on the release. A guessed path produces a login shell nobody can use.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                     // install
            Reply::ok("/usr/bin/fish\n"),      // command -v
            Reply::ok("/bin/sh\n/bin/bash\n"), // read /etc/shells
            Reply::ok(""),                     // backup
            Reply::ok(""),                     // write
        ]);
        let backend = for_family(Family::Debian);

        InstallFish
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("installing must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find_map(|c| c.stdin)
            .expect("/etc/shells must be written");

        assert!(written.contains("/usr/bin/fish"), "{written}");
    }

    #[test]
    fn a_shell_already_registered_is_not_added_twice() {
        // `/bin/fish` is a substring of `/usr/bin/fish`, so the comparison is
        // line by line rather than by substring.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok("/usr/bin/fish\n"),
            Reply::ok("/bin/sh\n/usr/bin/fish\n"),
        ]);
        let backend = for_family(Family::Debian);

        InstallFish
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("installing must succeed");

        assert!(
            mock.recorded().iter().all(|c| c.stdin.is_none()),
            "nothing must be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn installing_a_shell_gives_nobody_that_shell() {
        // The two read as one action and are not: an administrator who installs
        // fish and stops there has changed nothing about how anyone logs in.
        let consequences = InstallFish.consequences(&ParamValues::new());

        assert_eq!(consequences[0].task(), Some("users.set-shell"));
    }

    #[test]
    fn mise_warns_that_activation_does_not_run_non_interactively() {
        // Activation is a prompt hook, so a deploy script or a systemd unit
        // sees none of the versions mise manages.
        let consequences = InstallMise.consequences(&ParamValues::new());

        assert_eq!(consequences[0].task(), Some("mise.activate"));
    }

    #[test]
    fn rust_warns_about_the_linker_it_does_not_install() {
        // The most common first-build failure, and it surfaces at link time —
        // long after the toolchain reported itself installed.
        let consequences = InstallRust.consequences(&ParamValues::new());

        assert!(
            consequences[0].check().is_some(),
            "a linker on PATH is answerable from here"
        );
    }

    #[test]
    fn a_toolchain_needs_an_account_that_exists() {
        let mock = MockExecutor::with_replies([Reply::failure(2, "")]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(InstallRust::USER, "ghost".to_owned());

        let err = InstallRust
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect_err("a missing account must be refused");

        assert!(matches!(err, Error::NoSuchAccount { .. }), "{err:?}");
    }

    #[test]
    fn installing_a_tool_is_not_destructive() {
        // Putting a binary on the box changes nothing about how anyone logs in
        // or what the machine serves. Changing a login shell does, and that
        // task is flagged accordingly.
        assert!(!InstallFish.is_destructive());
        assert!(!InstallZellij.is_destructive());
        assert!(!InstallMise.is_destructive());
        assert!(!InstallRust.is_destructive());
    }
}
