//! The GitHub CLI.
//!
//! `gh` on Debian, Ubuntu and openSUSE, `github-cli` on Arch and Alpine, and
//! nothing at all in Red Hat's repositories — which is why RHEL reaches it
//! through a checksum-verified release.

use crate::backend::{Backend, Capability};
use crate::domain::binaries::{Artefact, Payload, Release};
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Task, report, supported_everywhere};

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
            let release = crate::backend::release_installer::newest(Self::RELEASES)?;

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
