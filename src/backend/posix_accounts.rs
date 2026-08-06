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

/// Where the account database lives.
const PASSWD_FILE: &str = "/etc/passwd";

/// Lowest uid a distribution hands to an account a person logs in as.
///
/// The convention on all four families, and a convention rather than a rule —
/// which is why it only *orders* the list and never filters it. A site that
/// numbers a real account below this still finds it, further down.
const FIRST_HUMAN_UID: u32 = 1000;

/// Shells that mean "this account does not log in".
///
/// Named rather than pattern-matched on `nologin`, because `/bin/false` shares
/// none of its spelling and does the same job.
const NON_LOGIN_SHELLS: [&str; 4] = [
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

/// Every account on the host, the ones a person logs in as first.
///
/// Read from `/etc/passwd` rather than through `getent`, and so shared by both
/// account suites: busybox has no `getent`, and the file it would have read is
/// the file this reads. Listing is not one of the operations the two suites
/// disagree about.
///
/// Ordered rather than filtered. A system account is a legitimate answer —
/// `www-data` owns a home a key can be installed into — so hiding it would
/// leave the form refusing to offer something the system accepts. But there
/// are forty of them on a stock Debian and two of the other kind, and a
/// chooser that opens on `_apt` is one nobody reads to the end.
pub fn list_accounts(executor: &dyn Executor) -> Result<Vec<String>> {
    let command = Command::new("cat").arg(PASSWD_FILE);
    let output = executor.run(&command)?;

    if !output.success() {
        return Err(Error::CommandFailed {
            command: command.to_string(),
            code: output.code,
            stderr: output.stderr,
        });
    }

    let mut accounts: Vec<(Rank, String)> = output
        .stdout
        .lines()
        .filter_map(parse_passwd_entry)
        .collect();

    // Sorted by rank first and name second, so the order is total: two runs
    // over the same file must not differ, or the position an operator learned
    // is not the position they find next time.
    accounts.sort_by(|(rank, name), (other_rank, other_name)| {
        rank.cmp(other_rank).then_with(|| name.cmp(other_name))
    });

    Ok(accounts.into_iter().map(|(_, name)| name).collect())
}

/// How near the front of the list an account belongs.
///
/// Three ranks rather than a boolean, because `root` is neither of the other
/// two: its uid is 0, below every threshold that identifies a person's
/// account, and it is nonetheless the account an administrator is likeliest to
/// be reaching for. Ordered by declaration, which is what `derive(Ord)` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rank {
    /// The superuser, wherever its uid would otherwise put it.
    Root,
    /// An account a person logs in as.
    Human,
    /// An account that exists to own files and run a service.
    System,
}

/// Splits one passwd entry into its name and where it belongs in the list.
fn parse_passwd_entry(entry: &str) -> Option<(Rank, String)> {
    let fields: Vec<&str> = entry.split(':').collect();

    // Seven fields, and a line with fewer is not an entry. Indexing without
    // this check is what turns a truncated file into a panic.
    let [name, _, uid, _, _, _, shell] = fields.as_slice() else {
        return None;
    };

    if name.is_empty() {
        return None;
    }

    let uid: u32 = uid.parse().ok()?;

    let rank = if *name == "root" {
        Rank::Root
    } else if uid >= FIRST_HUMAN_UID && !NON_LOGIN_SHELLS.contains(&shell.trim()) {
        Rank::Human
    } else {
        Rank::System
    };

    Some((rank, (*name).to_owned()))
}

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

    /// A passwd file shaped like a stock Debian's: a couple of login accounts
    /// among the service ones, and the login accounts not written first.
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
         nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
         cosmin:x:1000:1000::/home/cosmin:/bin/bash\n\
         backup:x:34:34:backup:/var/backups:/bin/false\n\
         alice:x:1001:1001::/home/alice:/bin/sh\n";

    #[test]
    fn the_accounts_a_person_logs_in_as_are_offered_first() {
        // Forty service accounts and two of the other kind is the ratio on a
        // stock Debian, so a chooser that opens on `_apt` is one nobody reads
        // to the end.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        let accounts = list_accounts(&mock).expect("a readable file lists its accounts");

        assert_eq!(
            &accounts[..3],
            &["root", "alice", "cosmin"],
            "root leads, then the login accounts alphabetically among themselves"
        );
    }

    #[test]
    fn a_system_account_is_ordered_down_rather_than_hidden() {
        // `www-data` owns a home a key can be installed into, so refusing to
        // offer it would leave the form rejecting what the system accepts.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        let accounts = list_accounts(&mock).expect("a readable file lists its accounts");

        assert!(
            accounts.contains(&"www-data".to_owned()),
            "got {accounts:?}"
        );
        assert!(accounts.contains(&"nobody".to_owned()), "got {accounts:?}");
        assert_eq!(accounts.len(), 7, "every entry survives: {accounts:?}");
    }

    #[test]
    fn root_leads_despite_its_uid_being_below_every_threshold() {
        // uid 0 is under the human threshold, and root is the account an
        // administrator is likeliest to be reaching for.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        let accounts = list_accounts(&mock).expect("a readable file lists its accounts");

        assert_eq!(accounts.first().map(String::as_str), Some("root"));
    }

    #[test]
    fn a_login_shell_of_false_counts_as_no_login() {
        // `/bin/false` shares none of `nologin`'s spelling and does the same
        // job, which is why the list names shells rather than matching a
        // substring. `backup` has one, so it must not lead.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        let accounts = list_accounts(&mock).expect("a readable file lists its accounts");
        let backup = accounts.iter().position(|name| name == "backup");
        let alice = accounts.iter().position(|name| name == "alice");

        assert!(backup > alice, "got {accounts:?}");
    }

    #[test]
    fn a_truncated_entry_is_skipped_rather_than_panicking() {
        // This runs as root on someone's server; a passwd file with a short
        // line must not take the interface down with it.
        let mock = MockExecutor::with_replies([Reply::ok(
            "root:x:0:0:root:/root:/bin/bash\nbroken:x:1\n\ncosmin:x:1000:1000::/home/cosmin:/bin/bash\n",
        )]);

        let accounts = list_accounts(&mock).expect("a short line is not a failure");

        assert_eq!(accounts, vec!["root", "cosmin"]);
    }

    #[test]
    fn an_unreadable_passwd_file_is_an_error_rather_than_an_empty_list() {
        // An empty list would be drawn as "this host has no accounts", which
        // reads as a broken host rather than as an unreadable file.
        let mock =
            MockExecutor::with_replies([Reply::failure(1, "cat: /etc/passwd: No such file")]);

        assert!(list_accounts(&mock).is_err());
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
