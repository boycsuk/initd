//! Tools an administrator wants on the box: a shell, a multiplexer, a version
//! manager, a toolchain, and the two most people reach for first.
//!
//! One file per tool, following `ssh/`: this was a single file until it held
//! six tools and twelve tasks, at which point finding anything meant scrolling
//! past everything else. Nothing about the tasks changed in the move.
//!
//! Installing a tool is a system operation and involves no account. What is
//! per-user declares the account as a parameter like any other value —
//! changing a login shell, setting a git identity — which also keeps the
//! destructive flag honest: putting a binary on the box is not destructive,
//! changing someone's login shell is.

pub mod fish;
pub mod git;
pub mod github_cli;
pub mod mise;
pub mod rust;
pub mod zellij;

pub use fish::{InstallFish, UninstallFish};
pub use git::{InstallGit, SetGitDefaultBranch, SetGitIdentity, SetGitSafeDirectory, UninstallGit};
pub use github_cli::{InstallGithubCli, UninstallGithubCli};
pub use mise::{InstallMise, UninstallMise};
pub use rust::{InstallRust, UninstallRust};
pub use zellij::{InstallZellij, UninstallZellij};

use crate::tasks::{Category, Node};

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
            // Two categories rather than one, because they are two tools.
            // Grouping them together would be grouping by the word they share:
            // git is a program that runs on this machine and needs configuring
            // before it will commit, and `gh` is a client for somebody else's
            // service that needs a token. An operator installing git on a
            // build server has no business being shown GitHub.
            //
            // Each is a category rather than five flat rows for the reason the
            // SSH and WireGuard split exists: git alone contributes five, three
            // of which configure rather than install, and flat they crowded out
            // the four tools above and read as though "set a git identity" were
            // a peer of "install the fish shell".
            Node::Category(Category::new(
                "Git",
                vec![
                    Node::Reversible {
                        forward: Box::new(InstallGit),
                        inverse: Box::new(UninstallGit),
                    },
                    // Configuration rather than installation, so no inverse:
                    // undoing "this account commits as Ada" is not removing
                    // the setting, it is deciding who else it should be —
                    // which is the same task run again.
                    Node::Task(Box::new(SetGitIdentity)),
                    Node::Task(Box::new(SetGitDefaultBranch)),
                    Node::Task(Box::new(SetGitSafeDirectory)),
                ],
            )),
            Node::Category(Category::new(
                "GitHub",
                vec![Node::Reversible {
                    forward: Box::new(InstallGithubCli),
                    inverse: Box::new(UninstallGithubCli),
                }],
            )),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;
    use crate::backend::{Capability, for_family};
    use crate::distro::Family;
    use crate::error::Error;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::Confirmation;
    use crate::tasks::Task;
    use crate::tasks::params::ParamValues;
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
