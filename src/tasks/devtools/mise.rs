//! The mise version manager.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::binaries::{Artefact, Payload, Release};
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Support, Task, report};

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
        // Named as this task rather than as `mise.activate`, which does not
        // exist and never did: activation is a line in the operator's own shell
        // configuration, which this tool does not edit. The pointer sent anyone
        // who read it looking through the tree for a row that was never built,
        // and the unit test beside it asserted the broken name rather than the
        // property. Same shape as `gh.install`, which names itself because the
        // token it needs is not this tool's to supply.
        vec![Consequence::Invalidates {
            task: "mise.install",
            reason: Reason::RequiresSetting {
                setting: "shims on PATH — add `mise activate` to your shell's \
                          configuration; it does not run non-interactively",
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
                .install(executor, &[backend.package_for(Capability::Mise)])?;
        } else if backend.binaries().is_installed(executor, "mise")? {
            report(
                progress,
                &Msg::TaskAlreadyInstalled {
                    what: "mise".to_owned(),
                },
            );

            return Ok(Outcome::Done);
        } else {
            let release = crate::backend::release_installer::newest(Self::RELEASES)?;

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
