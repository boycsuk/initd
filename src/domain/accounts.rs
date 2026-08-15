//! Account lookup capability.
//!
//! Restricting SSH to a named set of accounts is only safe if those accounts
//! exist: `AllowUsers admn` is a configuration `sshd -t` accepts and that
//! matches nobody, so every login is refused. The check needs a capability of
//! its own because the command that answers it is not universal — `getent` is
//! absent from busybox, which Alpine ships.

use crate::backend::posix_accounts::RankedAccount;
use crate::error::Result;
use crate::exec::Executor;

/// Queries the accounts defined on the administered system.
pub trait AccountReader {
    /// Whether an account with this name exists.
    fn exists(&self, executor: &dyn Executor, user: &str) -> Result<bool>;

    /// The accounts a person logs in as: `root` and the uids above the
    /// distributions' threshold, service accounts left out.
    ///
    /// A default rather than a method each family answers, unlike the two
    /// above it: those differ because `getent` is absent from busybox, and the
    /// file busybox would fall back to reading is the same `/etc/passwd` the
    /// shadow suite records. Listing is not one of the operations the two
    /// suites disagree about, so answering it twice would be answering it
    /// identically. The trait already uses this shape where a capability is
    /// genuinely shared.
    ///
    /// Offered to the operator as suggestions, never as the permitted set: an
    /// account can be created between one form opening and the next, and a
    /// chooser that refused what it had not listed would be wrong exactly when
    /// the operator knows more than the file does. That is what makes the
    /// filtering safe — a service account stays reachable by typing its name,
    /// and only stops being *offered*. Anything that has to reason about the
    /// accounts rather than suggest one wants [`AccountReader::list_ranked`],
    /// which filters by nothing.
    fn list(&self, executor: &dyn Executor) -> Result<Vec<String>> {
        crate::backend::posix_accounts::list_accounts(executor)
    }

    /// Every account on the host, each with the rank that ordered it.
    ///
    /// Separate from [`AccountReader::list`] rather than replacing it, because
    /// the two answer different questions and only one of them is a contract.
    /// `list` offers suggestions to a chooser and says so; this one is what a
    /// caller uses when it has to *reason* about the accounts — today
    /// `users.lock-root`, which asks every one of them whether it can still get
    /// into the machine.
    ///
    /// The rank orders and never filters, which is the rule
    /// [`crate::backend::posix_accounts::list_ranked_accounts`] states and this
    /// inherits: a caller may consult the human accounts first, and must still
    /// reach the rest.
    ///
    /// A default for the reason `list` gives above: the file is the same file
    /// on every family, so answering it per-family would be answering it
    /// identically.
    fn list_ranked(&self, executor: &dyn Executor) -> Result<Vec<RankedAccount>> {
        crate::backend::posix_accounts::list_ranked_accounts(executor)
    }

    /// The account's home directory, as the passwd database records it.
    ///
    /// Asked rather than assumed. `/home/<user>` is a convention, not a rule:
    /// system accounts live under `/var/lib`, `/srv` and `/nonexistent`, and a
    /// site can put ordinary accounts wherever it likes. Guessing matters here
    /// because the caller is about to write `~/.ssh/authorized_keys` — a key
    /// written to a path sshd never reads is a key that silently grants
    /// nothing, and `ssh.harden` may then disable passwords for an account
    /// whose key did not land where it was needed.
    fn home_dir(&self, executor: &dyn Executor, user: &str) -> Result<String>;

    /// How much a directory holds, in bytes.
    ///
    /// Asked so a confirmation can name what it is about to destroy. "Delete
    /// /home/deploy" and "delete /home/deploy (2.4 GB)" are different
    /// questions, and only the second one an operator can answer without going
    /// to another terminal to look.
    ///
    /// Answers `None` when the path does not exist or cannot be measured,
    /// rather than zero: a directory that is genuinely empty and one nobody
    /// could read are different facts, and reporting "(0 B)" for the second
    /// would understate what is at stake by exactly the amount that matters.
    ///
    /// A default rather than a per-family method, for the reason `list` gives
    /// above it: `du` is in coreutils and in busybox, and the two do not
    /// disagree about it.
    fn size_of(&self, executor: &dyn Executor, path: &str) -> Result<Option<u64>> {
        // `-s` for the total rather than a line per subdirectory, `-B1` for
        // bytes rather than whatever block size the host defaults to — `du -s`
        // alone answers in kibibytes on some systems and 512-byte blocks on
        // others, and a number whose unit depends on the host is worse than no
        // number in a sentence that will be read as gigabytes.
        let command = crate::exec::Command::new("du").args(["-sB1", path]);
        let output = executor.run(&command)?;

        if !output.success() {
            return Ok(None);
        }

        Ok(output
            .stdout
            .split_whitespace()
            .next()
            .and_then(|bytes| bytes.parse().ok()))
    }
}

/// The home directory field of a passwd entry.
///
/// Shared by both implementations because the format is the format — the
/// difference between them is which command produces the line, not how it is
/// laid out. Field six of seven, colon-separated; the GECOS field before it is
/// routinely empty, which is why the parse counts fields rather than splitting
/// on the first few.
pub fn home_from_passwd_line(line: &str, user: &str) -> Option<String> {
    line.lines()
        .find(|entry| entry.starts_with(&format!("{user}:")))
        .and_then(|entry| entry.split(':').nth(5))
        .filter(|home| !home.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::posix_accounts::Rank;
    use crate::backend::unix_accounts::UnixAccounts;
    use crate::exec::mock::{MockExecutor, Reply};

    /// A passwd file with one of each rank in it.
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
         www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
         alice:x:1000:1000::/home/alice:/bin/sh\n";

    #[test]
    fn the_trait_offers_the_rank_alongside_the_name() {
        // Reached through the trait rather than the free function, because what
        // the caller holds is a `&dyn AccountReader` and a default that did not
        // compile through it would be a method nobody can call.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        let accounts = UnixAccounts
            .list_ranked(&mock)
            .expect("a readable file lists its accounts");

        assert_eq!(
            accounts
                .iter()
                .map(|account| (account.name.as_str(), account.rank))
                .collect::<Vec<_>>(),
            vec![
                ("root", Rank::Root),
                ("alice", Rank::Human),
                ("www-data", Rank::System),
            ]
        );
    }

    #[test]
    fn the_chooser_offers_the_accounts_a_person_logs_in_as() {
        // `list` is what the form offers as suggestions, and it leaves out the
        // service accounts: a stock host carries fourteen to eighteen entries
        // and one of them is ever the answer. The contract it does *not*
        // change is that these are suggestions rather than the permitted set,
        // so a name left out here is still accepted when typed.
        //
        // Reached through the trait rather than the free function, because
        // what the interface holds is a `&dyn AccountReader`.
        let mock = MockExecutor::with_replies([Reply::ok(PASSWD)]);

        assert_eq!(
            UnixAccounts.list(&mock).expect("the names must list"),
            vec!["root", "alice"]
        );
    }

    #[test]
    fn the_home_is_the_sixth_field() {
        assert_eq!(
            home_from_passwd_line("alice:x:1000:1000::/home/alice:/bin/sh", "alice"),
            Some("/home/alice".to_owned())
        );
    }

    #[test]
    fn a_home_somewhere_other_than_slash_home_is_read_as_written() {
        // The whole reason this is asked rather than assumed. System accounts
        // and relocated ones are ordinary, and `/home/<user>` is a convention.
        for (entry, expected) in [
            ("root:x:0:0:root:/root:/bin/bash", "/root"),
            ("git:x:998:998::/var/lib/git:/bin/sh", "/var/lib/git"),
            ("deploy:x:1001:1001::/srv/deploy:/bin/sh", "/srv/deploy"),
        ] {
            let user = entry.split(':').next().expect("the fixture names a user");

            assert_eq!(
                home_from_passwd_line(entry, user).as_deref(),
                Some(expected),
                "for {entry}"
            );
        }
    }

    #[test]
    fn a_gecos_field_with_colons_does_not_shift_the_home() {
        // GECOS is comma-separated by convention but the parse must not depend
        // on that; counting fields is what keeps a populated one from moving
        // the home along.
        assert_eq!(
            home_from_passwd_line("bob:x:1002:1002:Bob,Room 1,,:/home/bob:/bin/sh", "bob"),
            Some("/home/bob".to_owned())
        );
    }

    #[test]
    fn a_name_that_merely_starts_the_same_is_not_matched() {
        // `admin` must not be answered by `administrator`, which is the same
        // anchoring the existence check needs.
        assert_eq!(
            home_from_passwd_line(
                "administrator:x:1000:1000::/home/administrator:/bin/sh",
                "admin"
            ),
            None
        );
    }

    #[test]
    fn the_right_entry_is_picked_out_of_several() {
        let database = "root:x:0:0:root:/root:/bin/bash\n\
                        alice:x:1000:1000::/home/alice:/bin/sh\n\
                        bob:x:1001:1001::/srv/bob:/bin/sh\n";

        assert_eq!(
            home_from_passwd_line(database, "bob"),
            Some("/srv/bob".to_owned())
        );
    }

    #[test]
    fn an_entry_with_no_home_is_no_answer() {
        // Rather than an empty path, which would be joined into `/.ssh` and
        // written somewhere nobody meant.
        assert_eq!(
            home_from_passwd_line("nobody:x:65534:65534:::/usr/sbin/nologin", "nobody"),
            None
        );
    }

    #[test]
    fn a_truncated_entry_is_no_answer() {
        assert_eq!(home_from_passwd_line("broken:x:1000", "broken"), None);
        assert_eq!(home_from_passwd_line("", "alice"), None);
    }
}
