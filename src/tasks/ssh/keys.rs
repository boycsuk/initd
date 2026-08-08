//! Authorising a public key, and deciding whether one is a key at all.
//!
//! Split out of the SSH module because `authorized_keys` is a subject of its
//! own: it is the file that decides who may log in, the one place a mode
//! matters as much as a content, and the thing every hardening tier checks
//! before it will run. The rest of the module edits `sshd_config`.
//!
//! Validation lives here rather than beside the form because both interfaces
//! reach it — the TUI as a keystroke filter and the CLI as an argument check —
//! and because a malformed key is not merely rejected input: sshd ignores the
//! whole file when it cannot parse a line, so a bad entry disables the keys
//! that were already working.

use crate::backend::Backend;
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Progress, Task, supported_everywhere};

use super::{
    AUTHORIZED_KEYS_MODE, AUTHORIZED_KEYS_RELATIVE, SSH_DIR_MODE, VALID_KEY_PREFIXES, report,
};

/// Adds a public key to a user's `authorized_keys`.
///
/// Fieldless: the user and the key are declared as parameters and collected
/// when the task is run, so the tree can offer it without inventing values.
pub struct AuthorizeKey;

impl AuthorizeKey {
    /// Name of the parameter holding the account to authorise the key for.
    pub const USER: &'static str = "user";
    /// Name of the parameter holding the key itself.
    pub const KEY: &'static str = "key";
}

impl Task for AuthorizeKey {
    fn id(&self) -> &'static str {
        "ssh.authorize-key"
    }

    fn title(&self) -> &'static str {
        "Authorise a public key"
    }

    fn description(&self) -> &'static str {
        "Appends a public key to the user's authorized_keys, creating ~/.ssh \
         with the strict permissions sshd requires."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            // root is offered because it is the account that always exists,
            // not because it is the one to prefer.
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_initial("root")
                .with_hint("the account the key authorises")
                .suggesting_accounts()
                .naming_an_existing_account(),
            Param::new(Self::KEY, "Public key", ParamKind::PublicKey)
                .with_hint("paste the contents of a .pub file"),
        ]
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();
        let key = values.get(Self::KEY)?.trim().to_owned();
        let key = key.as_str();

        is_valid_public_key(key)?;

        let files = backend.files();
        // Asked of the passwd database rather than assumed to be `/home/<user>`:
        // a key written where sshd does not read it grants nothing, silently.
        let home = backend.accounts().home_dir(executor, &user)?;
        let ssh_dir = format!("{home}/.ssh");
        let path = format!("{home}/{AUTHORIZED_KEYS_RELATIVE}");

        // Refused before anything is created, because everything below follows
        // links and this directory sits inside a home the account itself
        // controls. Replacing `~/.ssh` with a link elsewhere has root apply the
        // mode, the ownership and the key to wherever it points — reproduced on
        // `debian:13`, where a directory owned by root came back owned by the
        // account that planted the link, with a file written inside it.
        //
        // Checked rather than defended against with `mkdir` alone: `mkdir` does
        // fail on a link, but `install -d` is what gives the directory its mode
        // in one step, and the file write below would still follow a link put
        // in place of `authorized_keys` itself.
        for candidate in [&ssh_dir, &path] {
            if files.is_symlink(executor, candidate)? {
                return Err(Error::UnsafeSymlink {
                    path: candidate.clone(),
                });
            }
        }

        // sshd silently ignores authorized_keys when the directory or file is
        // group- or world-accessible, so the modes are part of the operation
        // rather than an afterthought.
        files.create_dir(executor, &ssh_dir, SSH_DIR_MODE)?;
        files.set_owner(executor, &ssh_dir, &user)?;

        let present = files.exists(executor, &path)?;

        let existing = if present {
            files.read(executor, &path)?
        } else {
            String::new()
        };

        if key_is_present(&existing, key) {
            report(progress, &Msg::TaskSshKeyAlreadyAuthorised);
            return Ok(Outcome::Done);
        }

        report(progress, &Msg::TaskSshAddingKey { path: path.clone() });

        // Append rather than replace: other keys in the file are other
        // people's access.
        let mut updated = existing;
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(key);
        updated.push('\n');

        // A new file is created empty, restricted, and only then written. The
        // other order leaves the file world-readable for as long as the two
        // privileged commands take — brief, and long enough for any account on
        // the box to read it or, worse, to hold it open and influence which
        // keys sshd honours. An empty file discloses nothing, which is what
        // makes the ordering possible. Same lesson as `wg0.conf`.
        //
        // An existing file keeps its own mode: it was created this way, and
        // rewriting it is what the append below is for.
        if !present {
            files.write(executor, &path, "")?;
            files.set_mode(executor, &path, AUTHORIZED_KEYS_MODE)?;
            files.set_owner(executor, &path, &user)?;
        }

        files.write(executor, &path, &updated)?;

        // Re-stated for a file that already existed, since a file left by
        // something else may carry a mode sshd refuses to read.
        if present {
            files.set_mode(executor, &path, AUTHORIZED_KEYS_MODE)?;
            files.set_owner(executor, &path, &user)?;
        }

        report(progress, &Msg::TaskSshKeyAuthorised);

        // Authorising a key only ever grants access; undoing it is the
        // dangerous direction, so it is not offered here.
        Ok(Outcome::Done)
    }
}

/// Whether the key is already present, comparing the type and body only.
///
/// The trailing comment is ignored: the same key added from two machines
/// carries two different comments but grants identical access.
fn key_is_present(contents: &str, key: &str) -> bool {
    let fingerprint = key_fingerprint(key);

    contents
        .lines()
        .any(|line| key_fingerprint(line.trim()) == fingerprint)
}

/// The identifying part of a key line: its type and body, without the comment.
fn key_fingerprint(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.split_whitespace();

    Some((parts.next()?, parts.next()?))
}

/// Validates the shape of an `authorized_keys` entry.
///
/// Only structural validation: type prefix plus a base64-looking body. Full
/// cryptographic verification is `ssh-keygen`'s job, and a malformed key would
/// make sshd ignore the whole file.
pub fn is_valid_public_key(line: &str) -> Result<()> {
    let invalid = |reason: &str| Error::InvalidPublicKey {
        reason: reason.to_owned(),
    };

    // Before anything else: `split_whitespace` treats a line break like any
    // other separator, so a value carrying one would validate as a single key
    // and then be written verbatim as two entries in `authorized_keys` — the
    // second of them never approved. `AuthorizeKey` only trims the outer
    // whitespace, and the CLI hands its argument straight here without passing
    // through the interface's per-keystroke filter, so this is the barrier.
    if line.contains(['\n', '\r']) {
        return Err(invalid("a key cannot span more than one line"));
    }

    let mut parts = line.split_whitespace();
    let key_type = parts.next().ok_or_else(|| invalid("the line is empty"))?;

    if !VALID_KEY_PREFIXES.contains(&key_type) {
        return Err(invalid(&format!("unrecognised key type: {key_type}")));
    }

    let body = parts
        .next()
        .ok_or_else(|| invalid("the key has no body after its type"))?;

    if body.len() < 32 || !body.bytes().all(is_base64_byte) {
        return Err(invalid("the key body is not valid base64"));
    }

    Ok(())
}

/// Whether a byte may appear in base64 content.
const fn is_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::mock::{MockExecutor, Reply};
    use crate::tasks::ssh::fixtures::{ROOT_PASSWD, TEST_KEY};

    /// The values `AuthorizeKey` declares, as the interface would collect them.
    fn key_values(user: &str, key: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(AuthorizeKey::USER, user);
        values.set(AuthorizeKey::KEY, key);
        values
    }

    #[test]
    fn accepts_well_formed_public_keys() {
        for key_type in ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"] {
            let key = format!("{key_type} AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH x");
            assert!(
                is_valid_public_key(&key).is_ok(),
                "{key_type} must be valid"
            );
        }
    }

    #[test]
    fn rejects_malformed_public_keys() {
        // A malformed key makes sshd ignore the entire authorized_keys file.
        for bad in [
            "",
            "not-a-key-type AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH",
            "ssh-ed25519",
            "ssh-ed25519 short",
            "ssh-ed25519 has spaces and!invalid$chars@@@@@@@@@@@@@@@@@@@@",
        ] {
            assert!(
                is_valid_public_key(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_key_smuggling_a_second_line() {
        // `split_whitespace` treats a newline like any other separator, so a
        // value carrying one reads as a single key while `authorized_keys`
        // receives two entries — the second one nobody approved. The CLI hands
        // its argument straight to this check, so it is the only barrier.
        let smuggled = format!(
            "{TEST_KEY}\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH attacker"
        );

        assert!(
            is_valid_public_key(&smuggled).is_err(),
            "a value spanning two lines is two keys, not one"
        );
    }

    #[test]
    fn rejects_a_key_carrying_a_carriage_return() {
        // sshd splits on \r as well, so it smuggles an entry the same way.
        let smuggled = format!(
            "{TEST_KEY}\rssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcH attacker"
        );

        assert!(is_valid_public_key(&smuggled).is_err());
    }

    #[test]
    fn a_home_whose_ssh_directory_is_a_link_is_refused() {
        // The escalation this closes, reproduced on debian:13 before it was
        // fixed: an unprivileged account owns its own home, so replacing
        // `~/.ssh` with a link to somewhere else has root run `install -d`,
        // `chown` and `tee` against the target instead. A directory owned by
        // root came back owned by the account that planted the link.
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where the home is
            Reply::ok(""),          // test -L: it is a link
        ]);
        let backend = for_family(Family::Debian);

        let err = AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect_err("a link in place of ~/.ssh must be refused");

        assert!(matches!(err, Error::UnsafeSymlink { .. }), "{err:?}");

        // Nothing may have been created before the refusal: the point is that
        // root never touches the target at all.
        let lines = mock.recorded_lines();

        assert!(
            !lines.iter().any(|line| line.starts_with("install")
                || line.starts_with("chown")
                || line.starts_with("tee")),
            "the refusal must come before anything is written: {lines:?}"
        );
    }

    #[test]
    fn a_planted_authorized_keys_link_is_refused_too() {
        // The directory can be genuine while the file inside it is the link —
        // the same trick one level down, and the write is what follows it.
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD),
            Reply::failure(1, ""), // test -L on ~/.ssh: not a link
            Reply::ok(""),         // test -L on authorized_keys: it is
        ]);
        let backend = for_family(Family::Debian);

        let err = AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect_err("a link in place of authorized_keys must be refused");

        assert!(matches!(err, Error::UnsafeSymlink { .. }), "{err:?}");
    }

    #[test]
    fn authorising_a_key_sets_the_permissions_sshd_requires() {
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::ok(""),          // install -d
            Reply::ok(""),          // chown dir
            Reply::failure(1, ""),  // authorized_keys absent
            Reply::ok(""),          // test -e inside write
            Reply::ok(""),          // tee
            Reply::ok(""),          // chmod
            Reply::ok(""),          // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let commands = mock.recorded_lines();
        assert!(
            commands.iter().any(|c| c == "install -d -m 700 /root/.ssh"),
            "~/.ssh must be 700: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "chmod 600 /root/.ssh/authorized_keys"),
            "authorized_keys must be 600: {commands:?}"
        );
    }

    #[test]
    fn a_new_authorized_keys_is_restricted_before_it_holds_a_key() {
        // The property, and the reason it is asserted on the order rather than
        // on the final mode: `tee` creates a file with the shell's umask, so
        // writing the key first leaves it world-readable until the chmod lands
        // one privileged command later. A local account can read it in that
        // window, or hold it open and influence which keys sshd honours. The
        // fix is the one `wg0.conf` already carries — create empty, restrict,
        // then write — and a test that only checks the mode at the end passes
        // against both orders.
        // Strict: the subject is the order, so a command appearing between the
        // chmod and the write must fail this rather than answer success from
        // nowhere.
        let mock = MockExecutor::with_exact_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::ok(""),          // install -d
            Reply::ok(""),          // chown dir
            Reply::failure(1, ""),  // test -e: authorized_keys absent
            Reply::failure(1, ""),  // test -e, opening the empty write
            Reply::ok(""),          // tee: stage the empty file
            Reply::ok(""),          // mv: publish it
            Reply::ok(""),          // chmod 600, before any key exists
            Reply::ok(""),          // chown file
            Reply::ok(""),          // test -e, opening the real write
            Reply::ok(""),          // cp -p: backup
            Reply::ok(""),          // tee: stage the key
            Reply::ok("600"),       // stat -c %a: the mode just set
            Reply::ok(""),          // chmod: carry it onto the staging file
            Reply::ok(""),          // mv: publish it
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let commands = mock.recorded_lines();
        let chmod = commands
            .iter()
            .position(|c| c == "chmod 600 /root/.ssh/authorized_keys")
            .expect("the file must be restricted");
        let wrote_key = mock
            .recorded()
            .iter()
            .position(|c| {
                c.program == "tee"
                    && c.stdin
                        .as_deref()
                        .is_some_and(|data| data.contains(TEST_KEY))
            })
            .expect("the key must be written");

        assert!(
            chmod < wrote_key,
            "the mode must be set before the key is written: {commands:?}"
        );
    }

    #[test]
    fn an_existing_authorized_keys_keeps_the_keys_already_in_it() {
        // The other direction of the same change: a file that already exists
        // is appended to, never truncated first — the keys in it are other
        // people's access.
        const OTHER_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther other@host";

        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::ok(""),          // install -d
            Reply::ok(""),          // chown dir
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(OTHER_KEY),   // holding somebody else's key
            Reply::ok(""),          // test -e inside write
            Reply::ok(""),          // tee
            Reply::ok(""),          // chmod
            Reply::ok(""),          // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let written = mock
            .recorded()
            .iter()
            .find_map(|c| (c.program == "tee").then(|| c.stdin.clone()).flatten())
            .expect("the file must be written");

        assert!(written.contains(OTHER_KEY), "{written:?}");
        assert!(written.contains(TEST_KEY), "{written:?}");
    }

    #[test]
    fn a_key_is_written_where_passwd_says_the_home_is() {
        // The bug: the path was built as `/home/<user>`, with `/root` as the
        // one exception. That is a convention, not a rule — a relocated or
        // system account has its home elsewhere — and a key written to a path
        // sshd never reads grants nothing while reporting success. `ssh.harden`
        // may then disable passwords for an account whose key did not land.
        let mock = MockExecutor::with_exact_replies([
            Reply::ok("deploy:x:1001:1001::/srv/deploy:/bin/sh"),
            Reply::failure(1, ""), // test -L: ~/.ssh is not a link
            Reply::failure(1, ""), // test -L: nor is authorized_keys
            Reply::ok(""),         // install -d
            Reply::ok(""),         // chown dir
            Reply::failure(1, ""), // test -e: authorized_keys absent
            Reply::failure(1, ""), // test -e, opening the empty write
            Reply::ok(""),         // tee: stage the empty file
            Reply::ok(""),         // mv: publish it
            Reply::ok(""),         // chmod
            Reply::ok(""),         // chown file
            Reply::ok(""),         // test -e, opening the real write
            Reply::ok(""),         // cp -p: backup
            Reply::ok(""),         // tee: stage the key
            Reply::ok("600"),      // stat -c %a
            Reply::ok(""),         // chmod: carry the mode over
            Reply::ok(""),         // mv: publish it
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("deploy", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let commands = mock.recorded_lines();

        assert!(
            commands
                .iter()
                .any(|c| c.contains("/srv/deploy/.ssh/authorized_keys")),
            "the key must go where passwd says: {commands:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("/home/deploy")),
            "and never to the guessed path: {commands:?}"
        );
    }

    #[test]
    fn authorising_the_same_key_twice_does_not_duplicate_it() {
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::ok(""),          // install -d
            Reply::ok(""),          // chown
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // and already holds the key
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("a duplicate key must be a no-op");

        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "an already-present key must not be written again"
        );
    }

    #[test]
    fn authorising_a_key_keeps_existing_ones() {
        let existing = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQfakebodyvaluehere someone@else";
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::ok(""),          // install -d
            Reply::ok(""),          // chown dir
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(existing),    // holding somebody else's key
            Reply::ok(""),          // test -e, opening the write
            Reply::ok(""),          // cp -p: backup
            Reply::ok(""),          // tee
            Reply::ok(""),          // chmod
            Reply::ok(""),          // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect("authorising must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the file must be written");

        assert!(
            written.contains(existing),
            "existing keys are other people's access"
        );
        assert!(written.contains(TEST_KEY));
    }

    #[test]
    fn authorising_rejects_an_invalid_key_before_touching_the_system() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        let err = AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", "definitely not a key"),
                &mut |_| {},
            )
            .expect_err("an invalid key must be rejected");

        assert!(matches!(err, Error::InvalidPublicKey { .. }), "{err:?}");
        assert!(
            mock.recorded().is_empty(),
            "validation must happen before any command runs"
        );
    }
}
