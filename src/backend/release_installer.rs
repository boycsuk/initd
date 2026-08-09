//! Verified-release implementation of [`BinaryInstaller`].
//!
//! Shared by every family: `curl`, `sha256sum`, `tar` and `install` are
//! coreutils or near enough, and all resolve through `PATH`.
//!
//! `sha256sum` rather than `cmp` against a second download, and `install`
//! rather than `mv` followed by `chmod`: this project has already been bitten
//! by a container image missing a tool it assumed, where the missing tool made
//! a test lie rather than fail.

use crate::domain::binaries::{BinaryInstaller, Release};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Where installed binaries land.
///
/// `/usr/local/bin` rather than `/usr/bin`: the latter belongs to the package
/// manager, and a file this tool put there is one a distribution upgrade may
/// overwrite or complain about.
const INSTALL_DIR: &str = "/usr/local/bin";

/// Mode for an installed binary.
const BINARY_MODE: &str = "0755";

/// Installs binaries from checksum-verified release archives.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReleaseInstaller;

impl ReleaseInstaller {
    pub const fn new() -> Self {
        Self
    }

    /// The line that checks a downloaded archive against its compiled-in
    /// digest.
    ///
    /// The two halves need opposite quoting, which is the whole of its
    /// correctness. The digest is a constant that must reach `sha256sum`
    /// verbatim, so it is single-quoted; the path is a shell variable that must
    /// be expanded first, so it must not be.
    ///
    /// Writing both inside one pair of single quotes — `'<digest>
    /// $dir/archive'` — is what this used to do. The shell left `$dir`
    /// unexpanded, `sha256sum` looked for a file of that literal name and
    /// answered `FAILED open or read`, and [`install`](Self::install)
    /// classifies a failure mentioning `sha256sum` as a mismatch. So every
    /// download of every tool this installs failed as tampering, whatever the
    /// archive contained, and the message sent the operator looking for an
    /// attack instead of a quoting mistake.
    ///
    /// Extracted rather than inlined so a test can run the real line against a
    /// real shell. Every test around it reads the script's *text*, and this
    /// bug was invisible to reading: the difference is not in what the script
    /// says but in what a shell does with it.
    ///
    /// `sha256sum -c` wants exactly two spaces between the digest and the
    /// path. `echo 'a' " b"` supplies one from `echo`'s own separator and one
    /// from the string, which is measured by the tests rather than assumed.
    fn verification_line(sha256: &str, path: &str) -> String {
        format!("echo '{sha256}' \" {path}\" | sha256sum -c -")
    }

    /// Where [`install`](BinaryInstaller::install) puts a program.
    ///
    /// The one place this path is spelled, so that asking whether the tool's
    /// copy is present and removing it cannot disagree about where to look. A
    /// second literal is what would let a removal miss — or worse, delete
    /// something at a path the installer never wrote.
    fn installed_path(program: &str) -> String {
        format!("{INSTALL_DIR}/{program}")
    }
}

impl BinaryInstaller for ReleaseInstaller {
    fn is_installed(&self, executor: &dyn Executor, program: &'static str) -> Result<bool> {
        Ok(executor.run(&Command::locating(program))?.success())
    }

    fn is_installed_here(&self, executor: &dyn Executor, program: &'static str) -> Result<bool> {
        // `test -f` on the one path `install` writes, rather than asking the
        // shell where the program is. A host can satisfy both questions, one,
        // or neither, and only this one answers "is there something here that
        // this tool put here".
        let command = Command::new("test").args(["-f", &Self::installed_path(program)]);

        Ok(executor.run(&command)?.success())
    }

    fn location_of(
        &self,
        executor: &dyn Executor,
        program: &'static str,
    ) -> Result<Option<String>> {
        // The same lookup `is_installed` runs, reading its output rather than
        // only its exit code: the interface names the copy it found so the
        // operator can tell which zellij the row is talking about.
        let output = executor.run(&Command::locating(program))?;

        if !output.success() {
            return Ok(None);
        }

        let path = output.stdout.trim();

        Ok(if path.is_empty() {
            None
        } else {
            Some(path.to_owned())
        })
    }

    fn remove(&self, executor: &dyn Executor, program: &'static str) -> Result<()> {
        // Built from `INSTALL_DIR`, never from `location_of`. A removal that
        // deleted whatever the shell resolved would delete a binary somebody
        // else installed somewhere else, which is the one thing the split
        // between these two questions exists to prevent.
        //
        // `-f` so removing what is already gone succeeds: an uninstall whose
        // subject vanished between the probe and the keystroke has arrived at
        // the state it was asked for.
        let path = Self::installed_path(program);
        let command = Command::new("rm").args(["-f", &path]).privileged();
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::CommandFailed {
                command: format!("rm -f {path}"),
                code: output.code,
                stderr: output.stderr,
            });
        }

        Ok(())
    }

    fn install(&self, executor: &dyn Executor, program: &str, release: &Release) -> Result<()> {
        // Asked of the machine rather than resolved at compile time: this
        // binary is built for one architecture and may administer a host of
        // another once a remote executor exists, and a digest chosen from the
        // wrong one fails verification for a reason nobody would guess.
        let arch = machine_architecture(executor)?;

        let artefact =
            release
                .artefact_for(&arch)
                .ok_or_else(|| Error::UnsupportedArchitecture {
                    program: program.to_owned(),
                    version: release.version.to_owned(),
                    arch: arch.clone(),
                })?;

        // One shell invocation, in a directory that is removed whatever
        // happens. Split across several commands, a failure between them would
        // leave a half-extracted archive in /tmp with no owner.
        //
        // The digest is checked before `tar` runs. An archive extracted and
        // then verified has already written whatever it contained, which makes
        // the check a report rather than a defence.
        let script = format!(
            "set -eu\n\
             dir=$(mktemp -d)\n\
             trap 'rm -rf \"$dir\"' EXIT\n\
             curl -fsSL --proto '=https' --tlsv1.2 -o \"$dir/archive\" '{url}'\n\
             {verify}\n\
             tar -xf \"$dir/archive\" -C \"$dir\" '{member}'\n\
             install -m {mode} \"$dir/{member}\" '{install_dir}/{program}'\n",
            url = artefact.url,
            verify = Self::verification_line(artefact.sha256, "$dir/archive"),
            member = release.archive_member,
            mode = BINARY_MODE,
            install_dir = INSTALL_DIR,
        );

        let command = Command::new("sh").args(["-c", &script]).privileged();
        let output = executor.run(&command)?;

        if !output.success() {
            // A checksum mismatch is named for what it is rather than reported
            // as a shell failure: it is the one outcome here that means the
            // artefact was not what this build expects.
            if output.stderr.contains("sha256sum") || output.stdout.contains("FAILED") {
                return Err(Error::ChecksumMismatch {
                    program: program.to_owned(),
                    version: release.version.to_owned(),
                });
            }

            return Err(Error::CommandFailed {
                command: format!("install {program} {}", release.version),
                code: output.code,
                stderr: output.stderr,
            });
        }

        Ok(())
    }
}

/// The machine's architecture, as `uname -m` names it.
///
/// The same spelling upstream projects use in their release filenames —
/// `x86_64` and `aarch64` — so an artefact table reads like the URLs it holds.
fn machine_architecture(executor: &dyn Executor) -> Result<String> {
    let command = Command::new("uname").arg("-m");
    let output = executor.run(&command)?;

    if !output.success() {
        return Err(Error::CommandFailed {
            command: command.to_string(),
            code: output.code,
            stderr: output.stderr,
        });
    }

    Ok(output.stdout.trim().to_owned())
}

/// Finds a release by version among those this build knows.
///
/// A version absent from the table is not installable, which is the intended
/// limit: this build can only verify what it carries a digest for.
pub fn release_for(releases: &'static [Release], version: &str) -> Result<&'static Release> {
    releases
        .iter()
        .find(|release| release.version == version)
        .ok_or_else(|| Error::UnknownRelease {
            version: version.to_owned(),
            known: releases
                .iter()
                .map(|release| release.version)
                .collect::<Vec<_>>()
                .join(", "),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    use crate::domain::binaries::Artefact;

    const RELEASES: &[Release] = &[
        Release {
            version: "0.44.0",
            archive_member: "zellij",
            artefacts: &[
                Artefact {
                    arch: "x86_64",
                    url: "https://example.invalid/zellij-0.44.0-x86_64.tar.gz",
                    sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                },
                Artefact {
                    arch: "aarch64",
                    url: "https://example.invalid/zellij-0.44.0-aarch64.tar.gz",
                    sha256: "2222222222222222222222222222222222222222222222222222222222222222",
                },
            ],
        },
        Release {
            version: "0.43.1",
            archive_member: "zellij",
            artefacts: &[Artefact {
                arch: "x86_64",
                url: "https://example.invalid/zellij-0.43.1-x86_64.tar.gz",
                sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            }],
        },
    ];

    #[test]
    fn the_digest_is_checked_before_the_archive_is_extracted() {
        // An archive extracted and then verified has already written whatever
        // it contained, which makes the check a report rather than a defence.
        let mock = MockExecutor::with_replies([Reply::ok("x86_64"), Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.recorded()[1].args.join(" ");

        let checked = script
            .find("sha256sum")
            .expect("the digest must be checked");
        let extracted = script
            .find("tar -xf")
            .expect("the archive must be extracted");

        assert!(checked < extracted, "verify before extracting: {script}");
    }

    #[test]
    fn the_verification_line_expands_the_path_and_not_the_digest() {
        // The bug every mock here missed: `echo '<digest>  $dir/archive'` put
        // the variable inside single quotes, so the shell never expanded it and
        // `sha256sum` looked for a file named `$dir/archive`. It answered
        // `FAILED open or read`, which the caller classified as a mismatch — so
        // every download of every tool failed as tampering, whatever the
        // archive held. Reproduced on debian:13 before this existed.
        //
        // Run rather than read. The tests around this one inspect the script's
        // text and would pass against either quoting, because the difference is
        // not in what the script *says* but in what a shell does with it.
        // Sixty-four hex characters, because `sha256sum -c` rejects anything
        // else as "no properly formatted checksum lines" before it opens a
        // file — which would pass the assertion below for the wrong reason.
        let script = ReleaseInstaller::verification_line(&"a".repeat(64), "$dir/archive");

        let staged = format!(
            "set -eu\n\
             dir=$(mktemp -d)\n\
             trap 'rm -rf \"$dir\"' EXIT\n\
             printf '' > \"$dir/archive\"\n\
             {script}\n"
        );

        let output = std::process::Command::new("sh")
            .args(["-c", &staged])
            .output()
            .expect("sh must run");

        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !stderr.contains("No such file"),
            "the path must reach sha256sum expanded: {stderr}"
        );

        // The digest above is a real prefix of the empty file's, so the check
        // gets far enough to disagree about the *contents* rather than failing
        // to find them. Either outcome proves the expansion; only this one
        // proves the digest survived unexpanded too.
        assert!(
            stderr.contains("did NOT match") || output.status.success(),
            "sha256sum must have compared something: {stderr}"
        );
    }

    #[test]
    fn a_verified_archive_is_accepted_by_the_real_shell() {
        // The other half, and the one that would have caught the bug outright:
        // a digest that matches must be accepted. Built from a local file so
        // nothing here touches the network.
        let dir = std::env::temp_dir().join(format!("initd-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let archive = dir.join("archive");
        std::fs::write(&archive, b"the archive contents").expect("write");

        let digest = std::process::Command::new("sha256sum")
            .arg(&archive)
            .output()
            .expect("sha256sum must run");
        let digest = String::from_utf8_lossy(&digest.stdout);
        let digest = digest.split_whitespace().next().expect("a digest");

        // Through a variable, the way the real script does. A literal path
        // would verify under either quoting, so this would pass against the
        // bug it exists to catch.
        let line = ReleaseInstaller::verification_line(digest, "$dir/archive");

        let staged = format!("set -eu\ndir='{}'\n{line}\n", dir.to_string_lossy());

        let output = std::process::Command::new("sh")
            .args(["-c", &staged])
            .output()
            .expect("sh must run");

        std::fs::remove_dir_all(&dir).ok();

        assert!(
            output.status.success(),
            "a matching digest must verify: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_mismatched_checksum_is_named_for_what_it_is() {
        // The one outcome here that means the artefact was not what this build
        // expects, rather than that a command failed.
        let mock = MockExecutor::with_replies([
            Reply::ok("x86_64"),
            Reply::failure(1, "sha256sum: WARNING: 1 computed checksum did NOT match"),
        ]);

        let err = ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect_err("a bad digest must fail");

        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err:?}");
    }

    #[test]
    fn the_download_refuses_plaintext_and_old_tls() {
        let mock = MockExecutor::with_replies([Reply::ok("x86_64"), Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.recorded()[1].args.join(" ");

        assert!(script.contains("--proto '=https'"), "{script}");
        assert!(script.contains("--tlsv1.2"), "{script}");
    }

    #[test]
    fn the_temporary_directory_is_removed_however_it_ends() {
        // A failure between two separate commands would leave a half-extracted
        // archive in /tmp with nobody responsible for it.
        let mock = MockExecutor::with_replies([Reply::ok("x86_64"), Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        assert!(
            mock.recorded()[1].args.join(" ").contains("trap 'rm -rf"),
            "the directory must be cleaned up on any exit"
        );
    }

    #[test]
    fn a_binary_lands_outside_the_package_managers_territory() {
        let mock = MockExecutor::with_replies([Reply::ok("x86_64"), Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.recorded()[1].args.join(" ");

        assert!(script.contains("/usr/local/bin/zellij"), "{script}");
        assert!(!script.contains("/usr/bin/zellij"), "{script}");
    }

    #[test]
    fn a_binary_installed_elsewhere_is_not_this_tools_to_remove() {
        // The failure this split exists to prevent, reproduced. An operator
        // with `~/.cargo/bin/zellij` satisfies `is_installed`, so a row keyed
        // on that answer would offer to uninstall a binary `/usr/local/bin`
        // does not hold — and removing it would delete somebody else's file
        // from a directory this tool does not own.
        let on_path = MockExecutor::with_replies([Reply::ok("/home/op/.cargo/bin/zellij")]);
        assert!(
            ReleaseInstaller::new()
                .is_installed(&on_path, "zellij")
                .expect("the lookup must succeed"),
            "a binary anywhere on PATH counts as installed"
        );

        // `test -f /usr/local/bin/zellij` fails: nothing is there.
        let here = MockExecutor::with_replies([Reply::failure(1, "")]);
        assert!(
            !ReleaseInstaller::new()
                .is_installed_here(&here, "zellij")
                .expect("the lookup must succeed"),
            "a binary this tool did not install is not installed here"
        );
    }

    #[test]
    fn the_copy_this_tool_installed_is_the_only_one_it_removes() {
        // Built from INSTALL_DIR rather than from wherever the shell resolved
        // the program, which is what keeps a foreign copy safe even when the
        // caller got the two questions the wrong way round.
        let mock = MockExecutor::new();

        ReleaseInstaller::new()
            .remove(&mock, "zellij")
            .expect("the removal must succeed");

        assert_eq!(mock.recorded_lines(), ["rm -f /usr/local/bin/zellij"]);
        assert!(mock.any_privileged());
    }

    #[test]
    fn removing_what_is_already_gone_succeeds() {
        // The probe and the keystroke are not simultaneous. A subject that
        // vanished in between has arrived at the state the operator asked for,
        // so `rm -f` reports success rather than failing the task.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ReleaseInstaller::new()
            .remove(&mock, "mise")
            .expect("removing an absent binary must succeed");

        assert!(mock.single_command().args.contains(&"-f".to_owned()));
    }

    #[test]
    fn the_located_path_is_reported_so_the_interface_can_name_it() {
        let found = MockExecutor::with_replies([Reply::ok("/home/op/.cargo/bin/zellij\n")]);

        assert_eq!(
            ReleaseInstaller::new()
                .location_of(&found, "zellij")
                .expect("the lookup must succeed"),
            Some("/home/op/.cargo/bin/zellij".to_owned()),
            "the trailing newline is the shell's, not part of the path"
        );

        let missing = MockExecutor::with_replies([Reply::failure(1, "")]);

        assert_eq!(
            ReleaseInstaller::new()
                .location_of(&missing, "zellij")
                .expect("the lookup must succeed"),
            None
        );
    }

    #[test]
    fn a_version_this_build_cannot_verify_is_not_installable() {
        // The intended limit: this build can only vouch for what it carries a
        // digest for.
        let err = release_for(RELEASES, "0.99.0").expect_err("an unknown version must fail");

        match err {
            Error::UnknownRelease { known, .. } => {
                assert!(
                    known.contains("0.44.0"),
                    "the known ones must be named: {known}"
                );
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn a_known_version_resolves_to_its_own_digest() {
        // Two versions with different digests: picking one must not silently
        // fetch the other.
        let release = release_for(RELEASES, "0.43.1").expect("a known version must resolve");
        let artefact = release
            .artefact_for("x86_64")
            .expect("the release has an x86_64 build");

        assert!(artefact.sha256.starts_with("1111"), "{artefact:?}");
        assert!(artefact.url.contains("0.43.1"), "{artefact:?}");
    }

    #[test]
    fn each_architecture_carries_its_own_digest() {
        // The digest is a property of the artefact, not the version: the two
        // builds of one release hash differently, so a single digest would
        // fail verification on whichever machine it was not computed from.
        let release = release_for(RELEASES, "0.44.0").expect("a known version must resolve");

        let x86 = release.artefact_for("x86_64").expect("x86_64 is published");
        let arm = release
            .artefact_for("aarch64")
            .expect("aarch64 is published");

        assert_ne!(x86.sha256, arm.sha256);
        assert_ne!(x86.url, arm.url);
    }

    #[test]
    fn a_machine_with_no_published_build_is_refused() {
        // Refused rather than served another machine's binary — the same limit
        // pinned digests impose on versions.
        let mock = MockExecutor::with_replies([Reply::ok("riscv64")]);

        let err = ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect_err("an unpublished architecture must be refused");

        assert!(
            matches!(err, Error::UnsupportedArchitecture { .. }),
            "{err:?}"
        );
        assert_eq!(
            mock.recorded_lines().len(),
            1,
            "nothing must be downloaded: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn the_architecture_decides_which_artefact_is_fetched() {
        // An aarch64 host must not be handed the x86_64 archive, which would
        // verify against the wrong digest and fail for a reason that looks
        // like tampering.
        let mock = MockExecutor::with_replies([Reply::ok("aarch64"), Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("aarch64 is published for this release");

        let script = mock.recorded()[1].args.join(" ");

        assert!(script.contains("aarch64"), "{script}");
        assert!(!script.contains("x86_64"), "{script}");
    }
}
