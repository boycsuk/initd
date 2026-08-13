//! git, and the configuration it needs before it will commit.
//!
//! The one capability every family packages under the same name — which is
//! the shape most of this tree does *not* have, and worth noticing rather
//! than taking for granted.

use crate::backend::{Backend, Capability};
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Task, report, supported_everywhere};

/// The program every task in this file configures.
const GIT_BINARY: &str = "git";

/// Says so when git is not here yet, without refusing the write.
///
/// The three configuration tasks write files rather than running `git config`
/// — deliberately, since it is the same write with one fewer program involved
/// and keeps root from following a symlinked `~/.gitconfig`. The cost of that
/// choice is that none of them can *discover* git is missing: they wrote their
/// line, reported "identity set", and were entirely inert on a host with no
/// git. A true sentence that reads as a working setup.
///
/// A note rather than a refusal, because writing ahead of the install is
/// harmless and may be deliberate — the file is read when git arrives. What was
/// wrong was the silence, not the write.
fn note_if_git_is_absent(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    if !backend.binaries().is_installed(executor, GIT_BINARY)? {
        report(progress, &Msg::TaskGitNotInstalledYet);
    }

    Ok(())
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
            .install(executor, &[backend.package_for(Capability::Git)])?;

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
            &mut *progress,
            &Msg::TaskGitIdentitySet {
                user: user.clone(),
                email,
            },
        );

        note_if_git_is_absent(executor, backend, progress)?;

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

        report(&mut *progress, &Msg::TaskGitDirectoryTrusted { path });

        note_if_git_is_absent(executor, backend, progress)?;

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

        report(&mut *progress, &Msg::TaskGitDefaultBranchSet { branch });

        note_if_git_is_absent(executor, backend, progress)?;

        Ok(Outcome::Done)
    }
}
/// Removes git.
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
