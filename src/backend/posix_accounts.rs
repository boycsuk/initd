//! Account questions answered the same way wherever POSIX tools exist.
//!
//! Not a [`crate::domain::account_writer::AccountWriter`] implementation and
//! deliberately not one: the two families that write accounts do so through
//! different suites — shadow-utils on Debian, Arch and RHEL, busybox applets on
//! Alpine — and that difference is the reason both modules exist. What lives
//! here is the part that is *not* different. `/etc/shells` is POSIX and `id`
//! is in every base image, so both suites had written these twice, identically
//! enough that the only divergence was the name of a constant.
//!
//! Free functions rather than default methods on the trait, because neither
//! answer needs `&self`: they ask the host, not the implementation.

use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// The list of shells a login is allowed to use.
const SHELLS_FILE: &str = "/etc/shells";

/// Reads `/etc/shells`, dropping what is not a shell.
///
/// Read through the executor rather than `std::fs` so it works under privilege
/// escalation and, later, over a remote transport.
pub fn valid_shells(executor: &dyn Executor) -> Result<Vec<String>> {
    let command = Command::new("cat").arg(SHELLS_FILE);
    let output = executor.run(&command)?;

    if !output.success() {
        return Err(Error::CommandFailed {
            command: command.to_string(),
            code: output.code,
            stderr: output.stderr,
        });
    }

    Ok(output
        .stdout
        .lines()
        .map(str::trim)
        // Comments and blank lines are not shells. A `#` line offered as a
        // choice would be accepted by the form and refused by the system.
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

/// Whether an account belongs to a group.
///
/// `id -nG` lists the groups by name, space separated. Matching whole words
/// rather than a substring: `sudo` is a substring of `sudoers` and `wheel` of
/// `wheelgroup`, and a membership check that answers yes for the wrong group is
/// how an account gets reported as an administrator when it is not.
///
/// A failed lookup is `false` rather than an error: the question is whether
/// this account is in that group, and an account that does not exist is not.
pub fn is_in_group(executor: &dyn Executor, user: &str, group: &str) -> Result<bool> {
    let output = executor.run(&Command::new("id").args(["-nG", user]))?;

    if !output.success() {
        return Ok(false);
    }

    Ok(output.stdout.split_whitespace().any(|name| name == group))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn comments_and_blank_lines_are_not_shells() {
        let mock = MockExecutor::with_replies([Reply::ok(
            "# /etc/shells: valid login shells\n/bin/sh\n\n/bin/bash\n",
        )]);

        let shells = valid_shells(&mock).expect("a readable file lists its shells");

        assert_eq!(shells, vec!["/bin/sh", "/bin/bash"]);
    }

    #[test]
    fn an_unreadable_shells_file_is_an_error_rather_than_an_empty_list() {
        // An empty list would be read as "this host allows no shells", which
        // makes `users.set-shell` refuse every value it is given.
        let mock =
            MockExecutor::with_replies([Reply::failure(1, "cat: /etc/shells: No such file")]);

        assert!(valid_shells(&mock).is_err());
    }

    #[test]
    fn a_group_is_matched_as_a_whole_word() {
        // The finding this pins: `sudo` is a substring of `sudoers`, so a
        // `contains` check reports an ordinary account as an administrator.
        let mock = MockExecutor::with_replies([Reply::ok("alice sudoers staff")]);

        assert!(
            !is_in_group(&mock, "alice", "sudo").expect("the lookup succeeded"),
            "`sudoers` must not satisfy a check for `sudo`"
        );
    }

    #[test]
    fn membership_is_reported_when_the_group_is_listed() {
        let mock = MockExecutor::with_replies([Reply::ok("alice sudo staff")]);

        assert!(is_in_group(&mock, "alice", "sudo").expect("the lookup succeeded"));
    }

    #[test]
    fn an_account_that_does_not_exist_is_in_no_group() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "id: 'ghost': no such user")]);

        assert!(!is_in_group(&mock, "ghost", "sudo").expect("a missing account is an answer"));
    }
}
