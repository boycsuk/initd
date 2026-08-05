//! `.repo` implementation of [`RepositoryManager`].
//!
//! Verification happens before anything is written, and the order is the point.
//! The key is fetched, its fingerprint derived on the host, and compared with
//! the value compiled into this build; only then does a `.repo` file appear in
//! `/etc/yum.repos.d`. Registering first and checking after would leave a
//! window in which an unverified repository is installable, which is the whole
//! of what this exists to prevent.
//!
//! `gpg` does the deriving, and is present on a stock Rocky image — checked
//! rather than assumed, along with `rpm`, `rpmkeys` and `curl`. What is not
//! assumed is that it stays present: a host without it cannot verify, so it
//! cannot register, and says so.

use super::systemd::run_checked;
use crate::domain::repositories::{Repository, RepositoryManager};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Where `dnf` reads repository definitions.
const REPO_DIR: &str = "/etc/yum.repos.d";

/// Registers repositories by writing `.repo` files, key first.
#[derive(Debug, Clone, Copy, Default)]
pub struct RpmRepositories;

impl RpmRepositories {
    pub const fn new() -> Self {
        Self
    }

    /// Where a repository's definition lives once registered.
    fn repo_path(repository: &Repository) -> String {
        format!("{REPO_DIR}/{}.repo", repository.name)
    }

    /// Fetches the signing key and reports the fingerprint it actually has.
    ///
    /// Derived on the host rather than trusted from anywhere: the point of the
    /// comparison is that the value in this binary came from somewhere the
    /// serving host does not control, so the other side of it has to be
    /// computed from the bytes that arrived.
    fn fingerprint_of(executor: &dyn Executor, repository: &Repository) -> Result<String> {
        // One script, because the key must not survive the check: a key file
        // left behind after a mismatch is one a later run could import.
        let script = format!(
            "set -eu\n\
             key=$(mktemp)\n\
             trap 'rm -f \"$key\"' EXIT\n\
             curl -fsSL --proto '=https' --tlsv1.2 -o \"$key\" '{url}'\n\
             gpg --show-keys --with-fingerprint --with-colons \"$key\" \
               | awk -F: '$1 == \"fpr\" {{ print $10; exit }}'\n",
            url = repository.key_url
        );

        let command = Command::new("sh").args(["-c", &script]);
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::RepositoryKeyUnverifiable {
                repository: repository.name.to_owned(),
            });
        }

        Ok(output.stdout.trim().to_ascii_uppercase())
    }
}

impl RepositoryManager for RpmRepositories {
    fn is_registered(&self, executor: &dyn Executor, repository: &Repository) -> Result<bool> {
        let command = Command::new("test").args(["-f", &Self::repo_path(repository)]);

        Ok(executor.run(&command)?.success())
    }

    fn register(&self, executor: &dyn Executor, repository: &Repository) -> Result<()> {
        let found = Self::fingerprint_of(executor, repository)?;
        let expected = repository.fingerprint.to_ascii_uppercase();

        // Refused rather than warned about. A warning about a key that is not
        // the expected one is a warning nobody can act on, and the packages it
        // would sign are the ones this check exists to keep off the machine.
        if found != expected {
            return Err(Error::RepositoryKeyMismatch {
                repository: repository.name.to_owned(),
                expected,
                found,
            });
        }

        // Only now, with the key established as the right one, is the
        // repository made usable. `gpgcheck=1` so every package it serves is
        // checked against that key.
        let definition = format!(
            "[{name}]\n\
             name={name}\n\
             baseurl={base_url}\n\
             enabled=1\n\
             gpgcheck=1\n\
             gpgkey={key_url}\n",
            name = repository.name,
            base_url = repository.base_url,
            key_url = repository.key_url,
        );

        // The definition travels on stdin rather than as an argument: it holds
        // newlines, and anything needing shell escaping is a command injection
        // waiting to happen on a tool that runs as root.
        let write = Command::new("tee")
            .arg(Self::repo_path(repository))
            .stdin(definition)
            .privileged();

        run_checked(executor, &write)?;

        // Imported into rpm's own keyring as well, so the first install does
        // not stop on a prompt asking whether to trust a key this tool has
        // already established.
        let import = Command::new("rpm")
            .args(["--import", repository.key_url])
            .privileged();

        run_checked(executor, &import)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Docker's, as the task declares it.
    const DOCKER: Repository = Repository {
        name: "docker-ce",
        base_url: "https://download.docker.com/linux/rhel/9/x86_64/stable",
        key_url: "https://download.docker.com/linux/rhel/gpg",
        fingerprint: "060A61C51B558A7F742B77AAC52FEB6B621E9F35",
    };

    #[test]
    fn a_matching_fingerprint_registers_the_repository() {
        let mock = MockExecutor::with_replies([
            Reply::ok("060A61C51B558A7F742B77AAC52FEB6B621E9F35\n"),
            Reply::ok(""), // tee
            Reply::ok(""), // rpm --import
        ]);

        RpmRepositories::new()
            .register(&mock, &DOCKER)
            .expect("a verified key must register");

        let written = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .and_then(|command| command.stdin)
            .expect("the definition must be written");

        assert!(written.contains("gpgcheck=1"), "{written}");
        assert!(written.contains(DOCKER.base_url), "{written}");
    }

    #[test]
    fn a_mismatched_fingerprint_registers_nothing() {
        // The case the whole capability exists for: a key that is not the one
        // this build expects must leave the machine as it found it.
        let mock =
            MockExecutor::with_replies([Reply::ok("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF\n")]);

        let result = RpmRepositories::new().register(&mock, &DOCKER);

        assert!(matches!(result, Err(Error::RepositoryKeyMismatch { .. })));
        assert!(
            !mock
                .recorded_lines()
                .iter()
                .any(|line| line.starts_with("tee")),
            "nothing may be written: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn the_key_is_checked_before_anything_is_written() {
        // Ordering, not just outcome: a definition written before the check
        // would leave an unverified repository installable in the window
        // between the two.
        let mock = MockExecutor::with_replies([
            Reply::ok("060A61C51B558A7F742B77AAC52FEB6B621E9F35\n"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        RpmRepositories::new()
            .register(&mock, &DOCKER)
            .expect("registration must succeed");

        let lines = mock.recorded_lines();
        let checked = lines
            .iter()
            .position(|line| line.contains("gpg"))
            .expect("the key must be checked");
        let written = lines
            .iter()
            .position(|line| line.starts_with("tee"))
            .expect("the definition must be written");

        assert!(checked < written, "{lines:?}");
    }

    #[test]
    fn a_key_that_cannot_be_fetched_is_an_error_not_a_registration() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "curl: (6) could not resolve")]);

        let result = RpmRepositories::new().register(&mock, &DOCKER);

        assert!(matches!(
            result,
            Err(Error::RepositoryKeyUnverifiable { .. })
        ));
    }

    #[test]
    fn a_fingerprint_is_compared_without_regard_to_case() {
        // `gpg` prints uppercase and documentation is written both ways; a
        // comparison that failed on case would refuse a key that is correct.
        let mock = MockExecutor::with_replies([
            Reply::ok("060a61c51b558a7f742b77aac52feb6b621e9f35\n"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        RpmRepositories::new()
            .register(&mock, &DOCKER)
            .expect("case must not decide whether a key is trusted");
    }

    #[test]
    fn the_key_file_does_not_survive_the_check() {
        // A key left on disk after a mismatch is one a later run could import.
        let mock = MockExecutor::with_replies([
            Reply::ok("060A61C51B558A7F742B77AAC52FEB6B621E9F35\n"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        RpmRepositories::new()
            .register(&mock, &DOCKER)
            .expect("registration must succeed");

        let script = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "sh")
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
            !RpmRepositories::new()
                .is_registered(&mock, &DOCKER)
                .expect("the query must succeed")
        );
    }
}
