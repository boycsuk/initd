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
use crate::domain::files::OwnedDirWrite;
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::users::escalated_from;
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
            // No starting value, for the reason `ssh.allow-users` records
            // about its own field: seeding `root` points at the configuration
            // `ssh.harden` exists to disable. The comment that stood here said
            // root was offered "because it is the account that always exists,
            // not because it is the one to prefer" — but a pre-filled field is
            // the recommendation, whatever a comment nobody reads says about
            // it.
            //
            // What that cost became a loop once the hardening guard stopped
            // counting root: `ssh.harden` refuses and says to authorise a key
            // first, this field offers root again, and accepting it a second
            // time reproduces the same refusal. Reproduced on `debian:13`.
            //
            // `params_here` fills it from the account this session escalated
            // through, which is the one answer that is right more often than
            // any constant.
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the key authorises")
                .suggesting_accounts()
                .naming_an_existing_account(),
            Param::new(Self::KEY, "Public key", ParamKind::PublicKey)
                .with_hint("paste the contents of a .pub file"),
        ]
    }

    /// Opens the account field on whoever is administering this session.
    ///
    /// `SUDO_USER`/`DOAS_USER` name the account that escalated into this
    /// process, which is the account an operator authorising a key is most
    /// often authorising it *for* — themselves, on the machine they are
    /// already logged into. It is also the one that keeps working after
    /// `ssh.harden`, which root does not.
    ///
    /// Left empty where nothing answers, rather than falling back to a
    /// constant. A direct root login, `su -` and `run0` leave no such
    /// variable, and the honest answer there is to ask: the previous constant
    /// was `root`, which is exactly the value that produced the loop this
    /// removes. An empty field asks a question; a wrong one answers it.
    fn params_here(&self, _backend: &dyn Backend) -> Vec<Param> {
        let Some(session) = escalated_from() else {
            return self.params();
        };

        self.params()
            .into_iter()
            .map(|param| {
                if param.name == Self::USER {
                    param.with_initial(session.clone())
                } else {
                    param
                }
            })
            .collect()
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

        // Refused before anything is read, because this directory sits inside a
        // home the account itself controls and the tools that follow all follow
        // links. Replacing `~/.ssh` with a link elsewhere has root apply the
        // mode, the ownership and the key to wherever it points — reproduced on
        // `debian:13`, where a directory owned by root came back owned by the
        // account that planted the link, with a file written inside it.
        //
        // This check alone is not the defence, and used to be treated as one: a
        // reply here is about the path as it was at this instant, and the
        // account can plant a link immediately afterwards. It stays because
        // refusing before anything is created gives the operator the honest
        // error, rather than one raised from inside the write. What actually
        // holds is `write_in_owned_dir`, which re-checks between its own steps.
        for candidate in [&ssh_dir, &path] {
            if files.is_symlink(executor, candidate)? {
                return Err(Error::UnsafeSymlink {
                    path: candidate.clone(),
                });
            }
        }

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

        // The directory, both modes, both owners and the contents in one
        // privileged invocation. It used to be up to eight of them, each
        // resolving `~/.ssh` and `authorized_keys` afresh, with the symlink
        // check having happened once at the top — so the account that owns this
        // home could plant a link between any two and have root apply a mode,
        // an ownership or a key somewhere it chose. `chown` and `chmod` follow
        // links; the window was small and the attacker is the one process
        // guaranteed to be watching for it.
        //
        // sshd silently ignores authorized_keys when the directory or file is
        // group- or world-accessible, which is why the modes travel with the
        // write rather than being applied after it: a file that is briefly
        // readable is a key somebody else may have read.
        files.write_in_owned_dir(
            executor,
            &OwnedDirWrite {
                dir: &ssh_dir,
                dir_mode: SSH_DIR_MODE,
                path: &path,
                file_mode: AUTHORIZED_KEYS_MODE,
                owner: &user,
                contents: &updated,
            },
        )?;

        report(progress, &Msg::TaskSshKeyAuthorised);

        // Authorising a key only ever grants access; undoing it is the
        // dangerous direction, so it is not offered here.
        //
        // Deliberately unrecorded for the same reason, and stated here because
        // this is where somebody will look for the missing call. Every other
        // file this tool edits leaves a copy under `/var/lib/initd` so the
        // change can be put back later; restoring this one *removes* an
        // authorised key, which is the operation that locks an administrator
        // out rather than the one that rescues them. A history offering it
        // beside the harmless reverts would make the two look alike.
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

    #[test]
    fn the_account_field_does_not_recommend_root() {
        // A pre-filled field is the recommendation, whatever the comment
        // beside it says. `root` there pointed at the configuration
        // `ssh.harden` disables, and once the hardening guard stopped counting
        // root it produced a loop: harden refuses saying to authorise a key,
        // this field offers root again, and accepting it repeats the refusal.
        //
        // Asserted of `params`, which is the task's own declaration and what
        // the CLI documents. `params_here` may fill it from `SUDO_USER`, which
        // is a fact about the session rather than about the task, and cannot
        // be asserted here without mutating the process's environment — global
        // to every test thread.
        let field = AuthorizeKey
            .params()
            .into_iter()
            .find(|param| param.name == AuthorizeKey::USER)
            .expect("the account field must be declared");

        assert!(
            field.initial.is_empty(),
            "the field must ask rather than recommend an account: {:?}",
            field.initial
        );
    }

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
    fn a_link_planted_after_the_check_is_still_refused() {
        // The window the two tests above cannot see. Both plant the link
        // *before* the task looks, which is the easy case; the account owning
        // this home can equally plant one immediately after the check answers,
        // while the write is under way. That used to work: the check ran once
        // and up to eight privileged commands followed, each resolving the path
        // again, and `chown` and `chmod` both follow links.
        //
        // Now the write is one invocation that re-checks between its steps and
        // exits 9 naming the path. Simulated by letting the up-front checks
        // pass and having the write answer as the script does.
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD),
            Reply::failure(1, ""), // test -L: ~/.ssh is not a link, yet
            Reply::failure(1, ""), // test -L: nor is authorized_keys, yet
            Reply::failure(1, ""), // test -e: absent
            // The script's own refusal. Built by hand rather than with
            // `Reply::failure`, which puts its text on stderr: the path travels
            // on stdout, so that a shell's own diagnostics cannot be mistaken
            // for one.
            Reply::Ran {
                code: 9,
                stdout: "/root/.ssh/authorized_keys".to_owned(),
                stderr: String::new(),
            },
        ]);
        let backend = for_family(Family::Debian);

        let err = AuthorizeKey
            .run(
                &mock,
                backend.as_ref(),
                &key_values("root", TEST_KEY),
                &mut |_| {},
            )
            .expect_err("a link planted mid-write must be refused");

        // Reported as the link it is, not as an anonymous command failure: the
        // operator needs to know somebody is racing them for this path.
        match err {
            Error::UnsafeSymlink { path } => {
                assert_eq!(path, "/root/.ssh/authorized_keys");
            }
            other => panic!("expected an unsafe-symlink refusal, got {other:?}"),
        }
    }

    #[test]
    fn authorising_a_key_sets_the_permissions_sshd_requires() {
        let mock = MockExecutor::with_replies([
            Reply::ok(ROOT_PASSWD), // getent passwd: where root's home is
            Reply::failure(1, ""),  // test -L: ~/.ssh is not a link
            Reply::failure(1, ""),  // test -L: nor is authorized_keys
            Reply::failure(1, ""),  // authorized_keys absent
            Reply::ok(""),          // the write, modes and owners in one
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

        // Asserted on the arguments of the one invocation rather than on two
        // separate commands: both modes now travel with the write, which is
        // the whole point of it being one command.
        let write = mock
            .recorded()
            .iter()
            .find(|c| c.program == "sh")
            .cloned()
            .expect("the write must happen");

        assert!(
            write.args.contains(&"700".to_owned()),
            "~/.ssh must be 700: {:?}",
            write.args
        );
        assert!(
            write.args.contains(&"600".to_owned()),
            "authorized_keys must be 600: {:?}",
            write.args
        );
        assert!(
            write
                .args
                .contains(&"/root/.ssh/authorized_keys".to_owned()),
            "the key must land where sshd reads it: {:?}",
            write.args
        );
    }

    #[test]
    fn a_new_authorized_keys_is_restricted_before_it_holds_a_key() {
        // The property, and the reason it is asserted on the order rather than
        // on the final mode: a file created with the shell's umask and
        // chmodded afterwards is world-readable in between. A local account can
        // read it in that window, or hold it open and influence which keys sshd
        // honours. A test that only checks the mode at the end passes against
        // both orders.
        //
        // Asserted against the script rather than against a sequence of mocked
        // commands, because the ordering is now inside one invocation: the
        // staging file is created by `install` with its final mode already on
        // it, and the contents arrive afterwards on stdin. There is no longer a
        // moment when the file exists and the mode does not, which is a
        // stronger guarantee than the ordering this test used to pin — and one
        // no arrangement of mock replies can observe.
        let script = crate::backend::unix_files::UnixFiles::owned_dir_script();

        let creates = script
            .find("install -m \"$file_mode\"")
            .expect("the staging file must be created by install, with its mode");
        let writes = script
            .find("cat > \"$staged\"")
            .expect("the contents must arrive after it");

        assert!(
            creates < writes,
            "the mode must be on the file before any content is: {script}"
        );

        // The other half: what `install` creates must be the file that is
        // published, so the mode cannot be lost by the move.
        assert!(
            script.contains("mv -f \"$staged\" \"$file\""),
            "the staged file must be the one published: {script}"
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
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(OTHER_KEY),   // holding somebody else's key
            Reply::ok(""),          // the write
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
            .find_map(|c| (c.program == "sh").then(|| c.stdin.clone()).flatten())
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
            Reply::failure(1, ""), // test -e: authorized_keys absent
            Reply::ok(""),         // the write
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
            !mock.recorded().iter().any(|c| c.program == "sh"),
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
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(existing),    // holding somebody else's key
            Reply::ok(""),          // the write
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
            .find(|cmd| cmd.program == "sh")
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
