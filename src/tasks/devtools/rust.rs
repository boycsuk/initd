//! The Rust toolchain, through rustup.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::binaries::{Artefact, Payload, Release};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{Consequence, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Support, Task, report};

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
