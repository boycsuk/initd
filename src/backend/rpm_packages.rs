//! What the rpm families answer identically about an installed package.
//!
//! Shared by RHEL and SUSE, whose package managers differ — `dnf install -y`
//! against `zypper --non-interactive install` — while the database beneath them
//! does not. Asking whether a package is present is a question about rpm rather
//! than about the distribution, so it is answered once here.
//!
//! Only what is genuinely the same lives here. `install`, `remove` and the
//! repository handling stay in their own backends: those differ in flags,
//! ordering and behaviour, and folding them together would hide real
//! differences behind a shared name.

use crate::error::Result;
use crate::exec::{Command, Executor};

/// Whether rpm's database says the package is installed.
///
/// `rpm -q` rather than the package manager's own query — `dnf list installed`,
/// `zypper se -i` — because it reads the local database: it neither touches the
/// network nor depends on repository metadata being cached, and its exit code
/// answers for one package without parsing a table. Red Hat also documents
/// `dnf` reporting success for an install that did not happen, which makes
/// querying the database afterwards the reliable answer rather than a redundant
/// one.
///
/// Unprivileged: reading the database needs no root, and a query that asked for
/// it would prompt for a password to answer a question about what is already
/// there.
pub fn is_installed(executor: &dyn Executor, package: &str) -> Result<bool> {
    let command = Command::new("rpm").args(["-q", package]);

    Ok(executor.run(&command)?.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_present_package_is_reported_installed() {
        let mock = MockExecutor::with_replies([Reply::ok("openssh-server-9.6p1-1.fc40.x86_64")]);

        assert!(is_installed(&mock, "openssh-server").expect("the query must run"));
        assert_eq!(mock.recorded_lines(), ["rpm -q openssh-server"]);
    }

    #[test]
    fn an_absent_package_is_an_answer_rather_than_a_failure() {
        // `rpm -q` exits non-zero for "not installed". Treating that as a
        // command failure would turn every "is it there?" into an error on the
        // majority of hosts, where the answer is legitimately no.
        let mock = MockExecutor::with_replies([Reply::failure(1, "package foo is not installed")]);

        assert!(!is_installed(&mock, "foo").expect("a negative answer is not an error"));
    }

    #[test]
    fn asking_does_not_request_privileges() {
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        is_installed(&mock, "vim").expect("the query must run");

        assert!(
            mock.recorded().iter().all(|command| !command.needs_root),
            "reading the rpm database needs no root"
        );
    }
}
