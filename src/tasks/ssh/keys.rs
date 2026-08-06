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
                .with_hint("the account the key authorises"),
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
            report(progress, "The key is already authorised; nothing to do");
            return Ok(Outcome::Done);
        }

        report(progress, format!("Adding the key to {path}..."));

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

        report(progress, "Key authorised");

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
