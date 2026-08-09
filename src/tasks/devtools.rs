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
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Support, Task, report, supported_everywhere};

/// Builds the developer environment category.
pub fn category() -> Category {
    Category::new(
        "Developer environment",
        vec![
            Node::Reversible {
                forward: Box::new(InstallFish),
                inverse: Box::new(UninstallFish),
            },
            Node::Reversible {
                forward: Box::new(InstallZellij),
                inverse: Box::new(UninstallZellij),
            },
            Node::Reversible {
                forward: Box::new(InstallMise),
                inverse: Box::new(UninstallMise),
            },
            Node::Reversible {
                forward: Box::new(InstallRust),
                inverse: Box::new(UninstallRust),
            },
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

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fish)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fish.install"]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // openSUSE packages fish in its own repositories, on both
            // Tumbleweed and Leap 16.0 — which is the same Build Service the
            // refusal below sends RHEL users to, reached here as a first-party
            // package rather than a third-party one.
            Family::Debian | Family::Arch | Family::Alpine | Family::Suse => Support::Yes,
            Family::Rhel => Support::No(
                "EPEL-only, and unlike Caddy there is no verifiable \
                 alternative — fish publishes source rather than static \
                 binaries, and its own documentation points RHEL users at the \
                 openSUSE Build Service rather than at EPEL",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
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

        report(progress, &Msg::TaskFishInstalledAt { path: path.clone() });
        report(progress, &Msg::TaskFishNotForRoot);

        Ok(Outcome::Done)
    }
}

/// Installs the Zellij multiplexer.
pub struct InstallZellij;

impl InstallZellij {
    /// Name of the parameter holding the version to install.
    pub const VERSION: &'static str = "version";

    /// The newest release this build can verify.
    ///
    /// The first entry, because [`RELEASES`](Self::RELEASES) is declared newest
    /// first — a claim its own test enforces rather than one this relies on
    /// quietly. Sorting here instead would mean comparing version numbers, and
    /// `0.10.0` sorts before `0.9.0` as text: the ordering is cheaper to state
    /// and to check than to compute.
    fn latest() -> &'static Release {
        // Unreachable while the table has entries, which a test requires. An
        // empty-table fallback rather than an index, because this runs as root
        // and a panic here would be one more way to leave a machine half done.
        Self::RELEASES.first().unwrap_or(&Release {
            version: "",
            archive_member: "zellij",
            artefacts: &[],
        })
    }

    /// Releases this build carries a digest for.
    ///
    /// Deliberately short: each entry is a promise that this project verified
    /// that artefact, so the table grows by someone downloading a release and
    /// computing its digest rather than by copying a number from a page.
    ///
    /// **Declared newest first**, which is what [`latest`](Self::latest) reads
    /// and what the form offers: the field opens on the first entry, so the
    /// order here decides what an operator installs by pressing Enter.
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

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Zellij)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["zellij.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // Filled with the newest release this build can verify, and
            // offering the rest. The field used to open empty under a hint
            // that said "a version this build can verify" without saying
            // which — so the operator either knew the table by heart or
            // guessed, and a guess is refused after the form is submitted.
            //
            // What it cannot offer is whatever upstream released this morning:
            // a version with no compiled-in digest is one the task refuses, and
            // a field that suggested it would be proposing the failure.
            Param::new(Self::VERSION, "Version", ParamKind::Version)
                .with_initial(Self::latest().version)
                .with_hint("a version this build can verify")
                .suggesting_releases(Self::RELEASES),
        ]
    }

    supported_everywhere!();

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

            report(progress, &Msg::TaskZellijFromDistribution);

            return Ok(Outcome::Done);
        }

        // Asked before a version is even resolved: a host that already has the
        // binary needs no download, and re-installing over it would replace a
        // build the administrator may have chosen deliberately.
        if backend.binaries().is_installed(executor, "zellij")? {
            report(
                progress,
                &Msg::TaskAlreadyInstalled {
                    what: "zellij".to_owned(),
                },
            );

            return Ok(Outcome::Done);
        }

        let version = values.get(Self::VERSION)?;
        let release = crate::backend::release_installer::release_for(Self::RELEASES, version)?;

        report(
            progress,
            &Msg::TaskZellijDownloading {
                version: version.to_owned(),
            },
        );

        backend.binaries().install(executor, "zellij", release)?;

        report(progress, &Msg::TaskZellijVerified);

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

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Mise)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["mise.install"]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // Unpackaged on openSUSE too, and reached the same way it is on
            // RHEL: the musl release with a checksummed manifest, which is the
            // same artefact Debian installs.
            Family::Debian | Family::Arch | Family::Rhel | Family::Suse => Support::Yes,
            Family::Alpine => Support::No(
                "Alpine packages neither this nor the Rust toolchain. Both are \
                 installable there by their own installers, but this tool \
                 declines to run an installer it cannot verify",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
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
            report(
                progress,
                &Msg::TaskAlreadyInstalled {
                    what: "mise".to_owned(),
                },
            );

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
                &Msg::TaskInstalling {
                    what: format!("mise {}", release.version),
                },
            );

            backend.binaries().install(executor, "mise", release)?;
        }

        report(
            progress,
            &Msg::TaskInstalling {
                what: "mise".to_owned(),
            },
        );
        report(progress, &Msg::TaskMiseUseShims);

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

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Rust)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["rust.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the toolchain belongs to")
                .suggesting_accounts()
                .naming_an_existing_account(),
        ]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // openSUSE packages `rustup` itself, on both variants — the
            // toolchain manager rather than the compiler-under-a-similar-name
            // that makes this unsupported on RHEL, so no digest has to be
            // pinned and no installer run.
            Family::Debian | Family::Arch | Family::Suse => Support::Yes,
            Family::Alpine => Support::No(
                "same as mise: unpackaged on Alpine, and rustup is an \
                 installer this tool cannot verify",
            ),
            Family::Rhel => Support::No(
                "AppStream ships `rust-toolset`, which is a compiler rather \
                 than a toolchain manager — a different capability under a \
                 similar name. `rustup-init` is checksummed per architecture \
                 but only the archive path pins a version; the current-release \
                 path would invalidate a compiled digest on every rustup \
                 release",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // rustup installs no C linker, and this is the single most common
        // first-build failure. It surfaces at link time, long after the
        // toolchain reported itself installed.
        vec![Consequence::Invalidates {
            task: "rust.install",
            reason: Reason::RequiresSetting {
                setting: "a C linker — rustup does not install one",
            },
            check: Some(crate::tasks::consequence::Check {
                command: Command::locating("cc"),
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

        report(progress, &Msg::TaskRustAvailableTo { user: user.clone() });

        Ok(Outcome::Done)
    }
}

/// The absolute path of a program, as the system resolves it.
///
/// Read from the host rather than assumed: fish lives at `/usr/bin/fish` on
/// Arch and at either `/usr/bin/fish` or `/bin/fish` on Debian depending on
/// the release, and a path that does not match what is installed produces a
/// login shell nobody can use.
fn resolve_program(executor: &dyn Executor, program: &'static str) -> Result<String> {
    let output = executor.run(&Command::locating(program))?;

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

    let backup = files.write(executor, SHELLS, &format!("{existing}{path}\n"))?;

    // No unit to reload: `/etc/shells` is consulted by `chsh` and by PAM at
    // the next login, so nothing is holding a stale copy. Recorded all the
    // same — this is a file the distribution owns and this tool appended to,
    // which makes it exactly the kind of edit somebody may want undone.
    if let Some(ref backup) = backup {
        crate::backend::backup_index::record_existing(executor, files, "fish.install", backup, "");
    }

    Ok(())
}

/// Removes the fish shell.
pub struct UninstallFish;

impl Task for UninstallFish {
    fn id(&self) -> &'static str {
        "fish.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the fish shell"
    }

    fn description(&self) -> &'static str {
        "Removes fish. Its entry in /etc/shells is left in place: an account \
         still set to it would otherwise have a login shell no file admits, \
         and the entry alone is harmless."
    }

    /// The same families the install runs on, for the same measured reasons.
    ///
    /// Written out rather than inherited: a task that offered to remove what
    /// it could never have installed would be a row promising an operation
    /// with nothing to operate on.
    fn support(&self, family: Family) -> Support {
        InstallFish.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Fish)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["fish.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Fish)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // An account whose login shell is about to stop existing cannot log
        // in. The mirror of what installing says, and the more urgent of the
        // two: the forward direction leaves an account working.
        vec![Consequence::Invalidates {
            task: "users.set-shell",
            reason: Reason::RequiresSetting {
                setting: "a login shell that still exists, for any account set to fish",
            },
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Fish,
            "fish",
        )
    }
}

/// Removes the Zellij multiplexer.
pub struct UninstallZellij;

impl Task for UninstallZellij {
    fn id(&self) -> &'static str {
        "zellij.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the Zellij multiplexer"
    }

    fn description(&self) -> &'static str {
        "Removes Zellij. Where it came from a release rather than a package, \
         removes the binary this tool installed — and only that one: a copy \
         found elsewhere on PATH is named and left where it is."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Zellij)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["zellij.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Zellij)
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Zellij,
            "zellij",
        )
    }
}

/// Removes the mise version manager.
pub struct UninstallMise;

impl Task for UninstallMise {
    fn id(&self) -> &'static str {
        "mise.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the mise version manager"
    }

    fn description(&self) -> &'static str {
        "Removes mise. Toolchains it installed under each account's own \
         directory stay: they are the operator's files, not this tool's, and \
         nothing here wrote them."
    }

    fn support(&self, family: Family) -> Support {
        InstallMise.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Mise)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["mise.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Mise)
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Mise,
            "mise",
        )
    }
}

/// Removes the Rust toolchain manager.
pub struct UninstallRust;

impl Task for UninstallRust {
    fn id(&self) -> &'static str {
        "rust.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the Rust toolchain manager"
    }

    fn description(&self) -> &'static str {
        "Removes rustup. Toolchains under an account's own ~/.rustup and \
         ~/.cargo stay where they are: this tool installed the manager, not \
         what each account then built with it."
    }

    fn support(&self, family: Family) -> Support {
        InstallRust.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Rust)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["rust.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Rust)
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Rust,
            "rustup",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::Confirmation;
    use crate::tasks::params::Suggestions;

    #[test]
    fn zellij_is_packaged_on_one_family_and_not_the_other() {
        // The divergence that earned `BinaryInstaller`: not a different package
        // name, a different installation mechanism. Verified against the
        // package databases — no Debian or Ubuntu suite carries zellij.
        assert!(for_family(Family::Arch).has_package_for(Capability::Zellij));
        assert!(!for_family(Family::Debian).has_package_for(Capability::Zellij));
    }

    #[test]
    fn the_release_table_is_ordered_newest_first() {
        // `latest` reads the first entry and the form opens on it, so this
        // ordering decides what an operator installs by pressing Enter. Stated
        // rather than computed — `0.10.0` sorts before `0.9.0` as text — which
        // makes it a claim something has to check.
        //
        // Compared field by field rather than as strings, since `10` is both
        // greater than `9` and earlier alphabetically.
        let parsed: Vec<Vec<u32>> = InstallZellij::RELEASES
            .iter()
            .map(|release| {
                release
                    .version
                    .split('.')
                    .map(|part| part.parse().unwrap_or_default())
                    .collect()
            })
            .collect();

        assert!(
            parsed.windows(2).all(|pair| pair[0] > pair[1]),
            "newest first, and strictly: {:?}",
            InstallZellij::RELEASES
                .iter()
                .map(|release| release.version)
                .collect::<Vec<_>>()
        );

        assert!(
            !InstallZellij::RELEASES.is_empty(),
            "an empty table would leave `latest` with nothing to return"
        );
    }

    #[test]
    fn the_version_field_opens_on_the_newest_verifiable_release() {
        // The field used to open empty under a hint that named no versions, so
        // the operator either knew the table by heart or guessed — and a guess
        // is refused only after the form is submitted.
        let params = InstallZellij.params();
        let version = params
            .iter()
            .find(|param| param.name == InstallZellij::VERSION)
            .expect("the task collects a version");

        assert_eq!(version.initial, InstallZellij::latest().version);
        assert_eq!(version.initial, "0.44.3", "the newest entry in the table");
    }

    #[test]
    fn the_version_field_offers_every_release_this_build_can_verify() {
        // Offering the table is the whole point: what it must not offer is
        // whatever upstream released this morning, since a version with no
        // compiled-in digest is one the task refuses. A field suggesting it
        // would be proposing the failure.
        let params = InstallZellij.params();
        let version = params
            .iter()
            .find(|param| param.name == InstallZellij::VERSION)
            .expect("the task collects a version");

        let Some(Suggestions::Releases(offered)) = version.suggestions else {
            panic!("the version field must offer the releases: {version:?}");
        };

        assert_eq!(
            offered.len(),
            InstallZellij::RELEASES.len(),
            "every entry, so nothing verifiable is hidden from the operator"
        );

        // Each offered version has to be one `release_for` will accept, or the
        // form would suggest a value the task rejects.
        for release in offered {
            assert!(
                InstallZellij::RELEASES
                    .iter()
                    .any(|known| known.version == release.version),
                "{} is offered and not in the table",
                release.version
            );
        }
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
        let consequences =
            InstallFish.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        assert_eq!(consequences[0].task(), Some("users.set-shell"));
    }

    #[test]
    fn mise_warns_that_activation_does_not_run_non_interactively() {
        // Activation is a prompt hook, so a deploy script or a systemd unit
        // sees none of the versions mise manages.
        let consequences =
            InstallMise.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

        assert_eq!(consequences[0].task(), Some("mise.activate"));
    }

    #[test]
    fn rust_warns_about_the_linker_it_does_not_install() {
        // The most common first-build failure, and it surfaces at link time —
        // long after the toolchain reported itself installed.
        let consequences =
            InstallRust.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

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
        assert!(InstallFish.confirmation() == Confirmation::Change);
        assert!(InstallZellij.confirmation() == Confirmation::Change);
        assert!(InstallMise.confirmation() == Confirmation::Change);
        assert!(InstallRust.confirmation() == Confirmation::Change);
    }
}
