//! The Zellij multiplexer.
//!
//! Packaged on Arch, openSUSE and Alpine; installed from a
//! checksum-verified release everywhere else.

use crate::backend::{Backend, Capability};
use crate::domain::binaries::{Artefact, Payload, Release};
use crate::error::Result;
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Task, report, supported_everywhere};

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
    pub(super) fn latest() -> &'static Release {
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
