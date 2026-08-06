//! Account lookup capability.
//!
//! Restricting SSH to a named set of accounts is only safe if those accounts
//! exist: `AllowUsers admn` is a configuration `sshd -t` accepts and that
//! matches nobody, so every login is refused. The check needs a capability of
//! its own because the command that answers it is not universal — `getent` is
//! absent from busybox, which Alpine ships.

use crate::error::Result;
use crate::exec::Executor;

/// Queries the accounts defined on the administered system.
pub trait AccountReader {
    /// Whether an account with this name exists.
    fn exists(&self, executor: &dyn Executor, user: &str) -> Result<bool>;

    /// Every account on the host, the ones a person logs in as first.
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
    /// the operator knows more than the file does.
    fn list(&self, executor: &dyn Executor) -> Result<Vec<String>> {
        crate::backend::posix_accounts::list_accounts(executor)
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
