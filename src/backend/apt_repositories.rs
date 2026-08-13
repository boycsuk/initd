//! deb822 implementation of [`RepositoryManager`].
//!
//! The order is the same one [`super::rpm_repositories`] documents and for the
//! same reason: the key is fetched, its fingerprint derived on the host, and
//! compared with the value compiled into this build; only then is anything
//! written that would make the repository usable. Registering first and
//! checking after leaves a window in which an unverified repository is
//! installable.
//!
//! One thing does run before that check, and it is the reason the sentence
//! above says *usable* rather than *anything*: `curl`, `gpg` and the CA bundle
//! are absent from a bare `debian:13`, so this installs them first. Without
//! them the check cannot read a key at all and reports every one as unreadable,
//! which reads as the key being bad rather than as the host having no tool to
//! read it with. A refused fingerprint therefore leaves three ordinary tools
//! and no repository — no source, no keyring, no key.
//!
//! Two things differ from the rpm side, both measured rather than assumed.
//!
//! APT expands `$(ARCH)` in a source and nothing else — `sources.list(5)` names
//! that one substitution — so unlike `dnf`'s `$releasever` the suite cannot be
//! deferred to the package manager. It arrives on [`Repository::suite`], read
//! from the host's `/etc/os-release`, and a repository that reaches here
//! without one is refused rather than guessed at: a definition naming the wrong
//! suite registers successfully and then serves nothing, which surfaces as the
//! package being missing rather than as the repository being wrong.
//!
//! And the key is not imported into a keyring shared by every source. `apt-key`
//! is gone, and a key in `trusted.gpg.d` signs *any* repository on the machine
//! rather than the one it came with. `Signed-By` binds this key to this source,
//! so a compromised third-party repository cannot vouch for a Debian one.

use super::systemd::run_checked;
use crate::domain::repositories::{Repository, RepositoryManager, verify_key};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Where APT reads deb822 source definitions.
const SOURCES_DIR: &str = "/etc/apt/sources.list.d";

/// Where the keys those definitions point at are kept.
///
/// Not `trusted.gpg.d`: a key there is trusted for every repository on the
/// machine. This directory holds keys a source names explicitly through
/// `Signed-By`.
const KEYRING_DIR: &str = "/etc/apt/keyrings";

/// Registers repositories by writing deb822 sources, key first.
#[derive(Debug, Clone, Copy, Default)]
pub struct AptRepositories;

impl AptRepositories {
    pub const fn new() -> Self {
        Self
    }

    /// Where a repository's definition lives once registered.
    fn sources_path(repository: &Repository) -> String {
        format!("{SOURCES_DIR}/{}.sources", repository.name)
    }

    /// Where its signing key lives.
    ///
    /// `.asc` rather than `.gpg`: APT reads both, and the armoured form is what
    /// Docker serves, so storing it as it arrives avoids a dearmour step that
    /// could only fail.
    fn keyring_path(repository: &Repository) -> String {
        format!("{KEYRING_DIR}/{}.asc", repository.name)
    }
}

impl RepositoryManager for AptRepositories {
    fn is_registered(&self, executor: &dyn Executor, repository: &Repository) -> Result<bool> {
        let command = Command::new("test").args(["-f", &Self::sources_path(repository)]);

        Ok(executor.run(&command)?.success())
    }

    fn register(&self, executor: &dyn Executor, repository: &Repository) -> Result<()> {
        // Refused before the key is even fetched. A suite is not something this
        // layer may default: `stable` is a moving target and a codename this
        // host does not run is a repository that resolves to nothing.
        let Some(suite) = repository.suite.as_deref().filter(|s| !s.is_empty()) else {
            return Err(Error::RepositoryUnknownSuite {
                repository: repository.name.to_owned(),
            });
        };

        // What the check below and the fetch after it are about to run with.
        // `curl`, `gpg` and the CA bundle are the first step of Docker's own
        // installation page for a reason: none of the three is on a bare
        // `debian:13` — measured, `command -v` finds no curl, no gpg, no gpgv
        // and no ca-certificates. Without them `verify_key` reports the key as
        // unreadable, which reads as Docker having published a bad key rather
        // than as this host having no tool to read it with.
        //
        // Before `verify_key` rather than after, because that is the call that
        // needs them. Installing packages is not "nothing changed", so this is
        // the one thing a failed registration can leave behind — three tools
        // whose presence is unremarkable on a server, against a check that
        // cannot run at all without them.
        //
        // The index first, for the reason `AptPackages::install` records: a
        // name resolved against lists that were never fetched answers "unable
        // to locate package", which reads as the name being wrong.
        run_checked(
            executor,
            &Command::new("env")
                .args(["DEBIAN_FRONTEND=noninteractive", "apt-get", "update"])
                .privileged(),
        )?;

        run_checked(
            executor,
            &Command::new("env")
                .args([
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "-y",
                    "ca-certificates",
                    "curl",
                    "gnupg",
                ])
                .privileged(),
        )?;

        verify_key(executor, repository)?;

        // The key is placed first, because the source below refers to it: a
        // source naming a keyring that does not exist makes every `apt update`
        // report an error until it does.
        let keyring = Self::keyring_path(repository);

        run_checked(
            executor,
            &Command::new("install")
                .args(["-d", "-m", "0755", KEYRING_DIR])
                .privileged(),
        )?;

        // Fetched again rather than carried over from the check: the value that
        // decides trust is the fingerprint, and re-fetching keeps the key off
        // this process's memory and out of any argument list. A key that
        // changed between the two fetches fails at `apt update` against the
        // signature, rather than being silently accepted here.
        let fetch = format!(
            "set -eu\n\
             curl -fsSL --proto '=https' --tlsv1.2 '{url}' -o '{keyring}'\n\
             chmod 0644 '{keyring}'\n",
            url = repository.key_url
        );

        run_checked(
            executor,
            &Command::new("sh").args(["-c", &fetch]).privileged(),
        )?;

        // deb822 rather than the one-line format: it is what Docker documents
        // today, and it names `Signed-By` as a field rather than as an option
        // buried in brackets.
        //
        // No `Architectures` field, which is not an omission. `sources.list(5)`
        // documents `$(ARCH)` as a substitution in the *path*, and it is not
        // expanded in this field: measured on `debian:13`, a source written
        // with `Architectures: $(ARCH)` registers, updates without complaint
        // and resolves the package to `Candidate: (none)` — the same symptom as
        // having no repository at all, arrived at through a repository that is
        // there. Naming the real architecture works, and omitting the field
        // works too, because APT then uses the ones the host is configured for.
        // Omitting is the better of the two: a host with foreign architectures
        // added keeps them, and there is one less thing to resolve correctly.
        let definition = format!(
            "Types: deb\n\
             URIs: {base_url}\n\
             Suites: {suite}\n\
             Components: stable\n\
             Signed-By: {keyring}\n",
            base_url = repository.base_url,
        );

        // On stdin rather than as an argument: it holds newlines, and anything
        // needing shell escaping is a command injection waiting to happen on a
        // tool that runs as root.
        let write = Command::new("tee")
            .arg(Self::sources_path(repository))
            .stdin(definition)
            .privileged();

        run_checked(executor, &write)?;

        // The package lists are refreshed here rather than left to the install:
        // `apt-get install` does not read a source it has never fetched, so the
        // package would be reported missing by the very command that just
        // registered where it comes from.
        run_checked(
            executor,
            &Command::new("apt-get").arg("update").privileged(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Docker's, as the Debian backend declares it.
    fn docker() -> Repository {
        Repository {
            name: "docker",
            base_url: "https://download.docker.com/linux/debian",
            key_url: "https://download.docker.com/linux/debian/gpg",
            fingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            suite: Some("trixie".to_owned()),
        }
    }

    /// A verified key, a written keyring, a written source, an `apt-get update`.
    fn registering() -> MockExecutor {
        MockExecutor::with_replies([
            // The two calls `register` now makes before the key check:
            // `curl` and `gpg` are absent from a bare debian:13, so it
            // installs them rather than reporting a readable key as unreadable.
            Reply::ok(""), // apt-get update
            Reply::ok(""), // apt-get install ca-certificates curl gnupg
            Reply::ok("9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n"),
            Reply::ok(""), // install -d
            Reply::ok(""), // curl the key
            Reply::ok(""), // tee
            Reply::ok(""), // apt-get update
        ])
    }

    #[test]
    fn a_matching_fingerprint_registers_the_repository() {
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("a verified key must register");

        let written = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .and_then(|command| command.stdin)
            .expect("the definition must be written");

        assert!(written.contains("Suites: trixie"), "{written}");
        assert!(
            written.contains("URIs: https://download.docker.com"),
            "{written}"
        );
    }

    #[test]
    fn the_source_names_no_architecture() {
        // `$(ARCH)` is expanded in a source's *path* and not in this field.
        // Measured on `debian:13`: a source carrying `Architectures: $(ARCH)`
        // registers, `apt-get update` reports no error, and the package
        // resolves to `Candidate: (none)` — indistinguishable from having no
        // repository, which is the bug this whole module exists to fix. The
        // field is left out so APT uses the host's configured architectures.
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .and_then(|command| command.stdin)
            .expect("the definition must be written");

        assert!(
            !written.contains("Architectures:"),
            "a named architecture is either wrong or redundant: {written}"
        );
    }

    #[test]
    fn a_mismatched_fingerprint_registers_nothing() {
        // The case the whole capability exists for: a key that is not the one
        // this build expects must leave no repository behind.
        //
        // This asserted that *nothing* ran, and that is no longer the claim:
        // `register` installs `curl` and `gnupg` first, because neither is on a
        // bare `debian:13` and without them the check cannot read a key at all.
        // So the property is stated as what it protects rather than as a
        // command count — no source, no keyring, no key on disk. Those three
        // are what make a repository usable, and none of them is written.
        //
        // The weaker half is deliberate and worth naming: a refused
        // registration can leave three tools installed. They are ordinary on a
        // server, they grant nothing, and the alternative is a check that
        // reports every key unreadable on a host that has no gpg.
        let mock = MockExecutor::with_replies([
            Reply::ok(""), // apt-get update
            Reply::ok(""), // apt-get install ca-certificates curl gnupg
            Reply::ok("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\n"),
        ]);

        let result = AptRepositories::new().register(&mock, &docker());

        assert!(matches!(result, Err(Error::RepositoryKeyMismatch { .. })));

        for forbidden in ["tee", "install -d", KEYRING_DIR] {
            assert!(
                !mock
                    .recorded_lines()
                    .iter()
                    .any(|line| line.contains(forbidden)),
                "a refused key must leave no repository: `{forbidden}` ran: {:?}",
                mock.recorded_lines()
            );
        }
    }

    #[test]
    fn the_key_is_checked_before_anything_is_written() {
        // Ordering, not just outcome: a source written before the check would
        // leave an unverified repository installable in the window between the
        // two. Asserted on what the commands *are* rather than on how they
        // render, since a multi-line script renders as a summary.
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let recorded = mock.recorded();
        let checked = recorded
            .iter()
            .position(|command| {
                command
                    .args
                    .iter()
                    .any(|arg| arg.contains("gpg --show-keys"))
            })
            .expect("the key must be checked");
        let written = recorded
            .iter()
            .position(|command| command.program == "tee")
            .expect("the definition must be written");

        assert!(checked < written, "{:?}", mock.recorded_lines());
    }

    #[test]
    fn the_keyring_is_in_place_before_the_source_names_it() {
        // A source naming a keyring that does not exist makes every `apt
        // update` on the machine report an error, including the one below.
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let recorded = mock.recorded();
        let fetched = recorded
            .iter()
            .position(|command| {
                command
                    .args
                    .iter()
                    .any(|arg| arg.contains("/etc/apt/keyrings/docker.asc"))
            })
            .expect("the key must be fetched");
        let written = recorded
            .iter()
            .position(|command| command.program == "tee")
            .expect("the definition must be written");

        assert!(fetched < written, "{:?}", mock.recorded_lines());
    }

    #[test]
    fn the_key_is_bound_to_this_source_rather_than_trusted_globally() {
        // `trusted.gpg.d` would let Docker's key vouch for a Debian repository.
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .and_then(|command| command.stdin)
            .expect("the definition must be written");

        assert!(
            written.contains("Signed-By: /etc/apt/keyrings/docker.asc"),
            "{written}"
        );
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.contains("trusted.gpg.d")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_repository_without_a_suite_is_refused_before_the_key_is_fetched() {
        // APT expands `$(ARCH)` and nothing else, so a missing suite cannot be
        // deferred to the package manager the way `$releasever` can. Guessing
        // one registers a repository that serves nothing.
        let mock = MockExecutor::with_replies([]);

        let result = AptRepositories::new().register(
            &mock,
            &Repository {
                suite: None,
                ..docker()
            },
        );

        assert!(matches!(result, Err(Error::RepositoryUnknownSuite { .. })));
        assert!(
            mock.recorded_lines().is_empty(),
            "nothing may run: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn the_package_lists_are_refreshed_after_the_source_is_written() {
        // `apt-get install` does not read a source it has never fetched, so
        // without this the package is reported missing by the command that
        // just registered where it comes from.
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let recorded = mock.recorded();
        let written = recorded
            .iter()
            .position(|command| command.program == "tee")
            .expect("the definition must be written");
        let refreshed = recorded
            .iter()
            .position(|command| command.program == "apt-get")
            .expect("the lists must be refreshed");

        assert!(written < refreshed, "{:?}", mock.recorded_lines());
    }

    #[test]
    fn a_fingerprint_is_compared_without_regard_to_case() {
        let mock = MockExecutor::with_replies([
            // The two calls `register` now makes before the key check:
            // `curl` and `gpg` are absent from a bare debian:13, so it
            // installs them rather than reporting a readable key as unreadable.
            Reply::ok(""), // apt-get update
            Reply::ok(""), // apt-get install ca-certificates curl gnupg
            Reply::ok("9dc858229fc7dd38854ae2d88d81803c0ebfcd88\n"),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("case must not decide whether a key is trusted");
    }

    #[test]
    fn a_key_that_cannot_be_fetched_is_an_error_not_a_registration() {
        let mock = MockExecutor::with_replies([
            // The two calls `register` now makes before the key check:
            // `curl` and `gpg` are absent from a bare debian:13, so it
            // installs them rather than reporting a readable key as unreadable.
            Reply::ok(""), // apt-get update
            Reply::ok(""), // apt-get install ca-certificates curl gnupg
            Reply::failure(1, "curl: (6) could not resolve"),
        ]);

        let result = AptRepositories::new().register(&mock, &docker());

        assert!(matches!(
            result,
            Err(Error::RepositoryKeyUnverifiable { .. })
        ));
    }

    #[test]
    fn the_key_file_does_not_survive_the_check() {
        let mock = registering();

        AptRepositories::new()
            .register(&mock, &docker())
            .expect("registration must succeed");

        let script = mock
            .recorded()
            .into_iter()
            .find(|command| {
                command
                    .args
                    .iter()
                    .any(|arg| arg.contains("gpg --show-keys"))
            })
            .and_then(|command| command.args.into_iter().nth(1))
            .expect("the check runs as a script");

        assert!(
            script.contains("trap"),
            "the key must be cleaned up: {script}"
        );
    }

    #[test]
    fn an_unregistered_repository_reports_itself_missing() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        assert!(
            !AptRepositories::new()
                .is_registered(&mock, &docker())
                .expect("the query must succeed")
        );
    }
}
