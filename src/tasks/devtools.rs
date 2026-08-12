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
use crate::domain::binaries::{Artefact, Payload, Release};
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
            Node::Reversible {
                forward: Box::new(InstallGit),
                inverse: Box::new(UninstallGit),
            },
            Node::Reversible {
                forward: Box::new(InstallGithubCli),
                inverse: Box::new(UninstallGithubCli),
            },
            // Configuration rather than installation, so no inverse: undoing
            // "this account commits as Ada" is not removing the setting, it is
            // deciding who else it should be — which is the same task run
            // again.
            Node::Task(Box::new(SetGitIdentity)),
            Node::Task(Box::new(SetGitDefaultBranch)),
            Node::Task(Box::new(SetGitSafeDirectory)),
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
            payload: Payload::Member("zellij"),
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
            payload: Payload::Member("zellij"),
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
            payload: Payload::Member("zellij"),
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

/// Installs git.
pub struct InstallGit;

impl Task for InstallGit {
    fn id(&self) -> &'static str {
        "git.install"
    }

    fn title(&self) -> &'static str {
        "Install git"
    }

    fn description(&self) -> &'static str {
        "Installs git. It will refuse to commit until an account has a name and \
         an email address — set those with git.identity."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Git)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["git.install"]
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Measured rather than inferred: on git 2.47.3 with an empty HOME,
        // `git commit` exits 128 with `*** Please tell me who you are.` A
        // freshly installed git is not a working git, and the row that installs
        // it should not imply otherwise.
        vec![Consequence::Invalidates {
            task: "git.identity",
            reason: Reason::RequiresSetting {
                setting: "user.name and user.email — git refuses to commit without them",
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
            .install(executor, backend.package_for(Capability::Git))?;

        report(progress, &Msg::TaskGitNeedsIdentity);

        Ok(Outcome::Done)
    }
}

/// Sets a git identity for one account.
pub struct SetGitIdentity;

impl SetGitIdentity {
    /// Name of the parameter holding the account being configured.
    pub const USER: &'static str = "user";
    /// Name of the parameter holding the name commits are attributed to.
    pub const NAME: &'static str = "name";
    /// Name of the parameter holding the email commits are attributed to.
    pub const EMAIL: &'static str = "email";
}

impl Task for SetGitIdentity {
    fn id(&self) -> &'static str {
        "git.identity"
    }

    fn title(&self) -> &'static str {
        "Set a git identity for a user"
    }

    fn description(&self) -> &'static str {
        "Writes user.name and user.email into an account's own ~/.gitconfig. \
         Without them git refuses to commit at all."
    }

    supported_everywhere!();

    fn affects(&self) -> &'static [&'static str] {
        &["git.identity"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account whose identity this is")
                .suggesting_accounts()
                .naming_an_existing_account(),
            Param::new(Self::NAME, "Name", ParamKind::PersonName)
                .with_hint("what commits are attributed to, e.g. Ada Lovelace"),
            Param::new(Self::EMAIL, "Email", ParamKind::Email)
                .with_hint("the address commits are attributed to"),
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();
        let name = values.get(Self::NAME)?.to_owned();
        let email = values.get(Self::EMAIL)?.to_owned();

        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        // `--global` is per account, which is the only scope an identity has:
        // a system-wide `user.email` would attribute every account's commits to
        // one person. Written through the owned-directory path rather than by
        // running `git config` as the user, because it is the same write with
        // one fewer program involved — and because a `~/.gitconfig` that is a
        // symlink to somewhere else must not have root follow it.
        let home = backend.accounts().home_dir(executor, &user)?;
        let path = format!("{home}/.gitconfig");

        // Read first so an existing file keeps everything else it holds. A
        // `git config` invocation would merge; a whole-file write must be told
        // to.
        let existing = if backend.files().exists(executor, &path)? {
            backend.files().read(executor, &path)?
        } else {
            String::new()
        };

        let contents = crate::tasks::gitconfig::with_identity(&existing, &name, &email);

        backend.files().write_in_owned_dir(
            executor,
            &crate::domain::files::OwnedDirWrite {
                dir: &home,
                dir_mode: 0o755,
                path: &path,
                file_mode: 0o644,
                owner: &user,
                contents: &contents,
            },
        )?;

        report(
            progress,
            &Msg::TaskGitIdentitySet {
                user: user.clone(),
                email,
            },
        );

        Ok(Outcome::Done)
    }
}

/// Marks a directory as safe for git to read whoever owns it.
pub struct SetGitSafeDirectory;

impl SetGitSafeDirectory {
    /// Name of the parameter holding the directory to trust.
    pub const PATH: &'static str = "path";
}

impl Task for SetGitSafeDirectory {
    fn id(&self) -> &'static str {
        "git.safe-directory"
    }

    fn title(&self) -> &'static str {
        "Trust a repository owned by another account"
    }

    fn description(&self) -> &'static str {
        "Adds a path to safe.directory system-wide. Since CVE-2022-24765 git \
         refuses to read a repository owned by somebody else, which is what a \
         deploy checkout usually is."
    }

    supported_everywhere!();

    fn affects(&self) -> &'static [&'static str] {
        &["git.safe-directory"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::PATH, "Directory", ParamKind::Path)
                .with_hint("an absolute path, e.g. /srv/www/site"),
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let path = values.get(Self::PATH)?.to_owned();

        // Refused rather than accepted and quietly useless: git matches
        // `safe.directory` literally, so a relative path never matches
        // anything and the operator would be left with a setting that appears
        // applied and does nothing.
        if !path.starts_with('/') {
            return Err(Error::PathNotAbsolute { path });
        }

        // `--system` rather than `--global`: the whole point is a checkout one
        // account owns and another reads, so a setting written into one
        // account's file answers the wrong half.
        let config = backend.path_for(Capability::Git);

        let existing = if backend.files().exists(executor, config)? {
            backend.files().read(executor, config)?
        } else {
            String::new()
        };

        // `*` is refused by the same reasoning: it opts out of the check
        // entirely rather than trusting one path, and a task named for
        // trusting a directory should not be the way that happens.
        let contents = crate::tasks::gitconfig::with_safe_directory(&existing, &path);

        backend.files().write(executor, config, &contents)?;

        report(progress, &Msg::TaskGitDirectoryTrusted { path });

        Ok(Outcome::Done)
    }
}

/// Sets the branch name `git init` starts a repository on.
pub struct SetGitDefaultBranch;

impl SetGitDefaultBranch {
    /// Name of the parameter holding the branch name.
    pub const BRANCH: &'static str = "branch";
}

impl Task for SetGitDefaultBranch {
    fn id(&self) -> &'static str {
        "git.default-branch"
    }

    fn title(&self) -> &'static str {
        "Set the default branch for new repositories"
    }

    fn description(&self) -> &'static str {
        "Sets init.defaultBranch system-wide. Without it every `git init` prints \
         a ten-line hint saying the name is subject to change."
    }

    supported_everywhere!();

    fn affects(&self) -> &'static [&'static str] {
        &["git.default-branch"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::BRANCH, "Branch", ParamKind::BranchName)
                .with_hint("the name `git init` starts on, e.g. main"),
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let branch = values.get(Self::BRANCH)?.to_owned();
        let config = backend.path_for(Capability::Git);

        let existing = if backend.files().exists(executor, config)? {
            backend.files().read(executor, config)?
        } else {
            String::new()
        };

        let contents = crate::tasks::gitconfig::with_default_branch(&existing, &branch);

        backend.files().write(executor, config, &contents)?;

        report(progress, &Msg::TaskGitDefaultBranchSet { branch });

        Ok(Outcome::Done)
    }
}

/// Installs the GitHub CLI.
pub struct InstallGithubCli;

impl InstallGithubCli {
    /// Releases this build carries a digest for.
    ///
    /// Both were computed on 2026-08-12 by downloading the archive and hashing
    /// it, then compared against the `checksums.txt` the release publishes; the
    /// two agree. As everywhere here, the compiled-in value is the defence and
    /// the published one only says the transfer completed.
    ///
    /// **The release rather than GitHub's own repository, and the reason is
    /// timing.** That repository is signed by a key being rotated: the
    /// certificate this project would have pinned expires 2026-09-05, and its
    /// replacement appears on `keyserver.ubuntu.com` and not on
    /// `keys.openpgp.org` — and that keyserver accepts unverified uploads, so
    /// its copy corroborates nothing. Pinning either would be wrong in a
    /// different way: the old one stops working within weeks, the new one was
    /// never independently published.
    ///
    /// The releases carry no PGP signature either, but they do carry Sigstore
    /// build attestations, and the digests below are measured. That is the same
    /// standard `rustup-init` is held to and better than the alternative.
    pub const RELEASES: &[Release] = &[Release {
        version: "2.97.0",
        payload: Payload::Member("gh_2.97.0_linux_amd64/bin/gh"),
        artefacts: &[
            Artefact {
                arch: "x86_64",
                url: "https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_amd64.tar.gz",
                sha256: "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
            },
            Artefact {
                arch: "aarch64",
                url: "https://github.com/cli/cli/releases/download/v2.97.0/gh_2.97.0_linux_arm64.tar.gz",
                sha256: "73ea440ecad9c9e284429997ee6f93577bc6f7bc6fba357ef62c53ad8fb641a5",
            },
        ],
    }];
}

impl Task for InstallGithubCli {
    fn id(&self) -> &'static str {
        "gh.install"
    }

    fn title(&self) -> &'static str {
        "Install the GitHub CLI"
    }

    fn description(&self) -> &'static str {
        "Installs gh. Authenticating is a separate step, and on a server it is \
         a token rather than a browser: run `gh auth login --with-token` as the \
         account that will use it."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::GithubCli)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["gh.install"]
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // An unauthenticated `gh` runs and does almost nothing, which reads as
        // the install having failed. There is no task to point at because
        // authentication is not something this tool can do for somebody: the
        // token is theirs, and the documented headless flow reads it from
        // stdin or the environment.
        vec![Consequence::Invalidates {
            task: "gh.install",
            reason: Reason::RequiresSetting {
                setting: "a token — `gh auth login --with-token`, or GH_TOKEN in the environment",
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
        // Four of the five families package it, under two different names —
        // `gh` on Debian, Ubuntu and openSUSE, `github-cli` on Arch and
        // Alpine. Red Hat packages it nowhere, so the empty name routes to the
        // verified release, as it does for mise and the Rust toolchain.
        if backend.has_package_for(Capability::GithubCli) {
            backend
                .packages()
                .install(executor, backend.package_for(Capability::GithubCli))?;
        } else if backend.binaries().is_installed(executor, "gh")? {
            report(
                progress,
                &Msg::TaskAlreadyInstalled {
                    what: "gh".to_owned(),
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
                    what: format!("gh {}", release.version),
                },
            );

            backend.binaries().install(executor, "gh", release)?;
        }

        report(progress, &Msg::TaskGithubCliNeedsToken);

        Ok(Outcome::Done)
    }
}

/// Removes the GitHub CLI.
pub struct UninstallGithubCli;

impl Task for UninstallGithubCli {
    fn id(&self) -> &'static str {
        "gh.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the GitHub CLI"
    }

    fn description(&self) -> &'static str {
        "Removes gh. Any token an account authenticated with stays where gh put \
         it — this tool did not store it and does not know where it went."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::GithubCli)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["gh.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::GithubCli)
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
            Capability::GithubCli,
            "gh",
        )
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
        payload: Payload::Member("mise/bin/mise"),
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
        // family: Arch packages this and Debian, Red Hat and openSUSE do not,
        // so the empty name routes to the verified release instead — the same
        // artefact, since it is musl and links against nothing.
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

    /// What the installer is asked to do.
    ///
    /// `--no-modify-path` because editing somebody's shell profile is a change
    /// this tool was not asked to make and does not record in
    /// `backups.jsonl` — every other file this project edits it can put back.
    /// The account adds `~/.cargo/bin` to its own `PATH`, and the task says so.
    const INSTALLER_ARGS: &'static str = "-y --no-modify-path --profile default";

    /// Releases this build carries a digest for.
    ///
    /// Both digests were computed on 2026-08-12 by downloading the artefact and
    /// hashing it, then compared against the `.sha256` the archive path serves;
    /// the two agree. The comparison is the weaker half — a digest served by
    /// the host serving the artefact proves only that the transfer completed —
    /// and the compiled-in value is the defence.
    ///
    /// **rustup signs nothing here, and that is worth stating rather than
    /// implying.** The toolchain is signed; `rustup-init` is not, and the
    /// request to sign it has been open since 2016 with a second closed as not
    /// planned. So unlike Docker's repository key there is no independently
    /// published fingerprint to check against, and what this table claims is
    /// narrower: that the artefact installed is byte-identical to the one this
    /// project inspected. That is strictly more than `sh.rustup.rs` offers,
    /// which verifies nothing at all — its only mention of `sha256` is the name
    /// of a TLS ciphersuite.
    ///
    /// The **archive** path rather than `dist/`: the latter serves a new binary
    /// on every rustup release, so a digest compiled into this build would
    /// invalidate itself. musl rather than gnu, for the reason this project
    /// ships its own binary that way — `file` reports `static-pie linked`.
    pub const RELEASES: &[Release] = &[Release {
        version: "1.29.0",
        payload: Payload::Bare("rustup-init"),
        artefacts: &[
            Artefact {
                arch: "x86_64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.0/x86_64-unknown-linux-musl/rustup-init",
                sha256: "9cd3fda5fd293890e36ab271af6a786ee22084b5f6c2b83fd8323cec6f0992c1",
            },
            Artefact {
                arch: "aarch64",
                url: "https://static.rust-lang.org/rustup/archive/1.29.0/aarch64-unknown-linux-musl/rustup-init",
                sha256: "88761caacddb92cd79b0b1f939f3990ba1997d701a38b3e8dd6746a562f2a759",
            },
        ],
    }];
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
            // RHEL joins the three that package it, by the route its own
            // refusal named: `rustup-init` is checksummed per architecture and
            // the archive path pins a version, so a digest can be compiled in
            // without invalidating itself on the next rustup release. Debian
            // reaches the same route on bookworm, which packages no `rustup`,
            // and the backend answers for both without this having to ask.
            Family::Debian | Family::Arch | Family::Suse | Family::Rhel => Support::Yes,
            Family::Alpine => Support::No(
                "no `runuser`, which is how the installer is run as the account \
                 that will own the toolchain — busybox ships `su`, whose \
                 session semantics differ, and rustup writes wherever the \
                 environment points it",
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

        // Which mechanism applies is asked of the backend, never of the family:
        // Arch and openSUSE package `rustup`, Debian packages it on trixie and
        // not on bookworm, and RHEL packages a compiler under a similar name
        // rather than the manager. The empty name routes to the verified
        // installer, as it does for mise.
        if backend.has_package_for(Capability::Rust) {
            backend
                .packages()
                .install(executor, backend.package_for(Capability::Rust))?;
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
                    what: format!("rustup {}", release.version),
                },
            );

            // Run as the account rather than as root, which is the whole of
            // where this differs from installing a binary. rustup resolves
            // `~/.cargo` and `~/.rustup` from the environment at run time, so
            // the same artefact run by root installs root's toolchain and
            // reports success — its own anti-root check does not fire on a
            // genuine root login, and `-y` makes its error path exit zero.
            backend.binaries().run_installer(
                executor,
                "rustup-init",
                release,
                &user,
                Self::INSTALLER_ARGS,
            )?;

            // Said because `--no-modify-path` means it is true: the proxies are
            // in the account's own `~/.cargo/bin`, which no shell has been told
            // about. Without this the toolchain is installed and `cargo` is
            // not found, which reads as a failed install.
            let home = backend.accounts().home_dir(executor, &user)?;

            report(progress, &Msg::TaskRustPathHint { home });
        }

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
pub struct UninstallGit;

impl Task for UninstallGit {
    fn id(&self) -> &'static str {
        "git.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall git"
    }

    fn description(&self) -> &'static str {
        "Removes git. Repositories on this host stay where they are: a checkout \
         is somebody's work, and nothing here created one."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Git)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["git.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Git)
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(executor, backend, values, progress, Capability::Git, "git")
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
        "Removes rustup. Where the distribution packages it, toolchains under \
         an account's own ~/.rustup and ~/.cargo stay where they are. Where it \
         was installed for one account instead, rustup's own uninstaller takes \
         those directories with it and offers no way to keep them."
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
        // Where there is no package, the manager belongs to an account rather
        // than to the machine, so the account is what has to be named — and the
        // removal-depth field means nothing, since no package manager is
        // involved.
        if !backend.has_package_for(Capability::Rust) {
            return vec![
                Param::new(InstallRust::USER, "Username", ParamKind::Username)
                    .with_hint("the account whose toolchain manager is removed")
                    .suggesting_accounts()
                    .naming_an_existing_account(),
            ];
        }

        crate::tasks::uninstall::removal_param_here(backend, Capability::Rust)
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // The installed-by-release path is not `undo`'s to handle: that removes
        // `/usr/local/bin/rustup`, and this route never wrote there. It would
        // report the manager as "installed elsewhere" and stop — true, and
        // useless, since the operator asked for it gone and is told only where
        // it is.
        //
        // rustup removes itself, and it is the only thing that can: it owns
        // thirteen symlinks in `~/.cargo/bin` and a `~/.rustup` this tool never
        // created and does not track.
        if !backend.has_package_for(Capability::Rust) {
            let user = values.get(InstallRust::USER)?.to_owned();

            if !backend.accounts().exists(executor, &user)? {
                return Err(Error::NoSuchAccount { user });
            }

            let removal = Command::new("runuser")
                .args(["-l", &user, "-c", "rustup self uninstall -y"])
                .privileged();

            crate::backend::systemd::run_checked(executor, &removal)?;

            report(
                progress,
                &Msg::TaskRustManagerRemoved { user: user.clone() },
            );

            return Ok(Outcome::Done);
        }

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
        // Arch, and now only Arch: this read `Family::Debian` while no Debian
        // or Ubuntu suite has ever carried a package called `mise`. The mock
        // answered `apt-get` because a mock answers whatever it is asked, so
        // the test passed against a name `apt-get install` cannot resolve.
        let mock = MockExecutor::with_replies([Reply::ok("")]);
        let backend = for_family(Family::Arch);

        InstallMise
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |_| {})
            .expect("Arch packages it");

        assert!(
            mock.recorded_lines()[0].contains("pacman"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    /// The values `rust.install` needs, for an account that exists.
    fn rust_values(user: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(InstallRust::USER, user.to_owned());
        values
    }

    #[test]
    fn the_github_cli_is_packaged_under_two_names() {
        // The split is by family and by nothing else: `gh` on Debian, Ubuntu
        // and openSUSE, `github-cli` on Arch and Alpine. Asking the wrong one
        // is the failure the capability indirection exists to prevent, and a
        // mock would answer either happily.
        for (family, expected) in [
            (Family::Debian, "gh"),
            (Family::Suse, "gh"),
            (Family::Arch, "github-cli"),
            (Family::Alpine, "github-cli"),
        ] {
            assert_eq!(
                for_family(family).package_for(Capability::GithubCli),
                expected,
                "{family} packages it as {expected}"
            );
        }
    }

    #[test]
    fn red_hat_reaches_the_github_cli_through_a_verified_release() {
        // The one family packaging it nowhere — absent from BaseOS, AppStream
        // and Extras. EPEL carries it and is declined, as it is for fail2ban:
        // here the alternative is better than the package, since the release
        // is an artefact this build verified rather than one a third-party
        // repository vouches for.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""), // command -v gh
            Reply::ok("x86_64\n"), // uname -m
            Reply::ok(""),         // the download-and-verify script
        ]);
        let backend = for_family(Family::Rhel);

        assert!(!backend.has_package_for(Capability::GithubCli));

        InstallGithubCli
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
            script.contains("a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112"),
            "the compiled-in digest must be the one checked: {script}"
        );
    }

    #[test]
    fn every_family_packages_git() {
        // The one capability in the tree that is the same everywhere. Worth an
        // assertion rather than a comment: it is the claim that lets
        // `git.install` say `supported_everywhere!`.
        for family in Family::ALL {
            assert!(
                for_family(*family).has_package_for(Capability::Git),
                "{family} must package git"
            );
        }
    }

    #[test]
    fn a_relative_path_is_refused_before_anything_is_written() {
        // git matches `safe.directory` literally, so a relative path is not a
        // near miss: it never matches, and the setting would read as applied.
        let mock = MockExecutor::with_replies([]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(SetGitSafeDirectory::PATH, "relative/path".to_owned());

        let result = SetGitSafeDirectory.run(&mock, backend.as_ref(), &values, &mut |_| {});

        assert!(matches!(result, Err(Error::PathNotAbsolute { .. })));
        assert!(
            mock.recorded_lines().is_empty(),
            "nothing may be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn an_identity_is_written_into_the_accounts_own_file() {
        // `--global` rather than `--system`, and the difference is the whole
        // point: one `user.email` for the machine would attribute every
        // account's commits to one person.
        let mock = MockExecutor::with_replies([
            Reply::ok("dev:x:1001:1001::/home/dev:/bin/sh"), // getent, for `exists`
            Reply::ok("dev:x:1001:1001::/home/dev:/bin/sh"), // getent again, for `home_dir`
            Reply::failure(1, ""),                           // no ~/.gitconfig yet
            Reply::ok(""),                                   // the owned-directory write
        ]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(SetGitIdentity::USER, "dev".to_owned());
        values.set(SetGitIdentity::NAME, "Ada Lovelace".to_owned());
        values.set(SetGitIdentity::EMAIL, "ada@example.com".to_owned());

        SetGitIdentity
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect("the identity must be written");

        let lines = mock.recorded_lines();

        assert!(
            lines
                .iter()
                .any(|line| line.contains("/home/dev/.gitconfig")),
            "{lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line.contains("/etc/gitconfig")),
            "an identity is never system-wide: {lines:?}"
        );
    }

    #[test]
    fn a_family_that_packages_rustup_installs_the_package() {
        let mock = MockExecutor::with_replies([
            Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Arch);

        InstallRust
            .run(&mock, backend.as_ref(), &rust_values("deploy"), &mut |_| {})
            .expect("Arch packages rustup");

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line.contains("pacman")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_family_without_a_rustup_package_runs_the_verified_installer() {
        // RHEL's refusal named the condition this meets: the archive path pins
        // a version, so a digest compiled in does not invalidate itself on the
        // next rustup release.
        let mock = MockExecutor::with_replies([
            Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"), // the account exists
            Reply::ok("x86_64\n"),                                   // uname -m
            Reply::ok("/tmp/tmp.abc/rustup-init"),                   // stage and verify
            Reply::ok(""),                                           // runuser
            Reply::ok(""),                                           // rm -rf
            Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"), // home_dir
        ]);
        let backend = for_family(Family::Rhel);

        InstallRust
            .run(&mock, backend.as_ref(), &rust_values("deploy"), &mut |_| {})
            .expect("the verified installer must run");

        let script = mock
            .recorded()
            .into_iter()
            .find_map(|command| {
                command
                    .args
                    .into_iter()
                    .find(|arg| arg.contains("sha256sum"))
            })
            .expect("the artefact must be checksummed before it is run");

        assert!(
            script.contains("9cd3fda5fd293890e36ab271af6a786ee22084b5f6c2b83fd8323cec6f0992c1"),
            "the compiled-in digest must be the one checked: {script}"
        );
    }

    #[test]
    fn the_toolchain_is_installed_for_the_account_rather_than_for_root() {
        // rustup resolves `~/.cargo` and `~/.rustup` from the environment at
        // run time, so the same artefact run by root installs root's toolchain
        // and reports success. Its own anti-root check does not fire on a
        // genuine root login, and `-y` makes that path exit zero — so where the
        // toolchain lands is this tool's decision, not the artefact's.
        let mock = MockExecutor::with_replies([
            Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
            Reply::ok("x86_64\n"),
            Reply::ok("/tmp/tmp.abc/rustup-init"),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
        ]);
        let backend = for_family(Family::Rhel);

        InstallRust
            .run(&mock, backend.as_ref(), &rust_values("deploy"), &mut |_| {})
            .expect("the installer must run");

        let run = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "runuser")
            .expect("the installer must be run as the account");

        assert_eq!(run.args.get(1).map(String::as_str), Some("deploy"));

        // `--no-modify-path`, because editing somebody's shell profile is a
        // change this tool was not asked for and could not put back: nothing
        // records it in `backups.jsonl`.
        let script = run.args.get(3).expect("the -c script");

        assert!(script.contains("--no-modify-path"), "{script}");
    }

    #[test]
    fn debian_resolves_rustup_by_suite() {
        // Trixie carries `rustup` and bookworm does not, so an unconditional
        // name fails on oldstable exactly as `mise` failed on trixie. Verified
        // per suite against the package database and reproduced in a container.
        let trixie =
            crate::backend::debian::DebianBackend::for_distribution("debian", Some("trixie"));
        let bookworm =
            crate::backend::debian::DebianBackend::for_distribution("debian", Some("bookworm"));

        assert!(trixie.has_package_for(Capability::Rust));
        assert!(
            !bookworm.has_package_for(Capability::Rust),
            "bookworm packages no rustup and must route to the release"
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
