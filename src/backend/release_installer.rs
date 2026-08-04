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
}

impl BinaryInstaller for ReleaseInstaller {
    fn is_installed(&self, executor: &dyn Executor, program: &str) -> Result<bool> {
        // `command -v` rather than `which`, which is not installed everywhere
        // and whose exit codes differ between implementations.
        let command = Command::new("sh").args(["-c", &format!("command -v {program}")]);

        Ok(executor.run(&command)?.success())
    }

    fn install(&self, executor: &dyn Executor, program: &str, release: &Release) -> Result<()> {
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
             echo '{sha256}  {archive}' | sha256sum -c -\n\
             tar -xf \"$dir/archive\" -C \"$dir\" '{member}'\n\
             install -m {mode} \"$dir/{member}\" '{install_dir}/{program}'\n",
            url = release.url,
            sha256 = release.sha256,
            archive = "$dir/archive",
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

    const RELEASES: &[Release] = &[
        Release {
            version: "0.44.0",
            url: "https://example.invalid/zellij-0.44.0.tar.gz",
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            archive_member: "zellij",
        },
        Release {
            version: "0.43.1",
            url: "https://example.invalid/zellij-0.43.1.tar.gz",
            sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            archive_member: "zellij",
        },
    ];

    #[test]
    fn the_digest_is_checked_before_the_archive_is_extracted() {
        // An archive extracted and then verified has already written whatever
        // it contained, which makes the check a report rather than a defence.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.single_command().args.join(" ");

        let checked = script
            .find("sha256sum")
            .expect("the digest must be checked");
        let extracted = script
            .find("tar -xf")
            .expect("the archive must be extracted");

        assert!(checked < extracted, "verify before extracting: {script}");
    }

    #[test]
    fn a_mismatched_checksum_is_named_for_what_it_is() {
        // The one outcome here that means the artefact was not what this build
        // expects, rather than that a command failed.
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "sha256sum: WARNING: 1 computed checksum did NOT match",
        )]);

        let err = ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect_err("a bad digest must fail");

        assert!(matches!(err, Error::ChecksumMismatch { .. }), "{err:?}");
    }

    #[test]
    fn the_download_refuses_plaintext_and_old_tls() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.single_command().args.join(" ");

        assert!(script.contains("--proto '=https'"), "{script}");
        assert!(script.contains("--tlsv1.2"), "{script}");
    }

    #[test]
    fn the_temporary_directory_is_removed_however_it_ends() {
        // A failure between two separate commands would leave a half-extracted
        // archive in /tmp with nobody responsible for it.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        assert!(
            mock.single_command()
                .args
                .join(" ")
                .contains("trap 'rm -rf"),
            "the directory must be cleaned up on any exit"
        );
    }

    #[test]
    fn a_binary_lands_outside_the_package_managers_territory() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        ReleaseInstaller::new()
            .install(&mock, "zellij", &RELEASES[0])
            .expect("the install must succeed");

        let script = mock.single_command().args.join(" ");

        assert!(script.contains("/usr/local/bin/zellij"), "{script}");
        assert!(!script.contains("/usr/bin/zellij"), "{script}");
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

        assert!(release.sha256.starts_with("1111"), "{release:?}");
        assert!(release.url.contains("0.43.1"), "{release:?}");
    }
}
