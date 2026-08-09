//! A record of what this tool copied aside before changing it.
//!
//! **This is not a database, and the distinction is the whole design.** The
//! state still lives in the host: whether `PermitRootLogin` is `no` is answered
//! by reading `sshd_config`, never by consulting anything here. This answers
//! one question and refuses to grow a second — *is there a copy of how this
//! file looked before initd touched it, and where?*
//!
//! Without it, reverting a configuration change was possible only inside the
//! session that made it. `.initd.bak` sits beside its original and survives a
//! reboot, but nothing records which task wrote it, when, or over what — so a
//! second write silently replaced the copy a revert would have restored, and an
//! operator returning tomorrow had a file of unknown age and no way to tell.
//!
//! ## Append-only, and why that is the whole locking story
//!
//! One JSONL file, appended to and never rewritten. A partially written final
//! line is invalid JSON and is discarded on read, so an interrupted append
//! costs the last record rather than the file. Rewriting in place would need a
//! lock, and a lock needs a stale-lock story on a tool whose whole point is
//! running on a machine that may be rebooted underneath it.
//!
//! ## What may never go in
//!
//! No secrets, and that holds in two places rather than one.
//!
//! In the *record*, by construction: the writer takes a typed [`BackupRecord`]
//! with no free-form field, and `ParamValues` never reaches this module, so
//! `users.create`'s password cannot arrive however carelessly a caller is
//! written.
//!
//! In the *copies*, by which tasks record at all. A record naming a copy full
//! of private keys would keep the secret out of the line and put it in the file
//! the line points at, which is not a distinction worth making. So
//! `wireguard.add-peer` records nothing — `wg0.conf` holds the server's private
//! key and every peer's preshared key — and neither does `ssh.authorize-key`,
//! for a different reason worth reading where it is written: restoring that
//! file *removes* an authorised key.
//!
//! ## Best effort on write, authoritative on read
//!
//! A host with a read-only `/var/lib`, or one where this runs unprivileged,
//! cannot be written to. The task still runs and reports that no record was
//! kept — the same way form suggestions degrade rather than refusing to open a
//! form. What this must never do is claim a revert is available when nothing
//! was recorded.

#![allow(
    dead_code,
    reason = "the writers and the History area that reads them land in the commits after this one"
)]

use crate::domain::files::FileEditor;
use crate::exec::{Command, Executor};

/// Where records are kept.
///
/// Under `/var/lib` rather than `/etc`: this is state the tool maintains, not
/// configuration an administrator edits, and the Filesystem Hierarchy Standard
/// is explicit about the difference.
pub const INDEX_DIR: &str = "/var/lib/initd";

/// The record file itself.
pub const INDEX_PATH: &str = "/var/lib/initd/backups.jsonl";

/// Where the copies themselves are kept.
pub const BACKUP_DIR: &str = "/var/lib/initd/backups";

/// Mode for the whole tree.
///
/// `0700` because a copy inherits whatever the original was worth protecting.
/// `sshd_config` is `0600` on several distributions, and a copy of it under a
/// world-readable directory would undo that — the same mistake
/// `wireguard.install` made once by chmodding after writing rather than
/// before.
///
/// It is not what keeps key material safe, because none is kept here:
/// `wireguard.add-peer` writes the one file that holds private keys and
/// deliberately records nothing, so this directory never holds a copy of them.
/// A mode is a second line of defence; not having the secret is the first.
pub const TREE_MODE: u32 = 0o700;

/// Mode for the index file itself.
///
/// `0600` for the same reason the directories are `0700`, and it has to be set
/// explicitly: the append is a shell redirect, so the file is created under the
/// process umask and lands `0644` — measured on `debian:13` and `alpine:3.23`,
/// which agreed. What that publishes is not a secret but is not nothing: every
/// path this tool has changed, when, and the digests of their contents before
/// and after. A map of how the host is configured, readable by any account.
pub const INDEX_MODE: u32 = 0o600;

/// How many copies of one path are kept.
///
/// Bounded because an unbounded history of a file edited weekly is a directory
/// nobody prunes, on a machine whose disk an administrator is not watching. Ten
/// is enough to reach past a bad afternoon and few enough to stay reviewable by
/// hand.
pub const RETAINED_PER_PATH: usize = 10;

/// One backup, as it is recorded.
///
/// Every field is typed and there is no free-form map, which is what makes
/// "no secrets in the index" a property of the type rather than a rule someone
/// has to remember at each call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecord {
    /// Task that made the change.
    pub task: &'static str,
    /// The file that was changed.
    pub path: String,
    /// Where the copy of its previous contents lives.
    pub copy: String,
    /// When, as the host reported it.
    pub at: String,
    /// SHA-256 of the copy, proving it is intact.
    ///
    /// A backup silently truncated by a full disk must not be restored over a
    /// working configuration.
    pub sha256_before: String,
    /// SHA-256 of what this tool wrote.
    ///
    /// The load-bearing field. On revert the live file is hashed and compared
    /// against this: a mismatch means somebody edited it since, and restoring
    /// would discard their work without saying so.
    pub sha256_after: String,
    /// The unit to reload once the file is back, if any.
    pub service: &'static str,
}

impl BackupRecord {
    /// Renders the record as one JSON line.
    ///
    /// Hand-written rather than through `serde`, which this project does not
    /// depend on and would not add for seven fields of known shape. Every value
    /// is either a digest, a timestamp, a task id or a path — the first three
    /// cannot contain a quote or a backslash, and the fourth is escaped.
    pub fn to_line(&self) -> String {
        format!(
            r#"{{"v":1,"at":"{at}","task":"{task}","path":"{path}","copy":"{copy}","sha256_before":"{before}","sha256_after":"{after}","service":"{service}"}}"#,
            at = escape(&self.at),
            task = self.task,
            path = escape(&self.path),
            copy = escape(&self.copy),
            before = escape(&self.sha256_before),
            after = escape(&self.sha256_after),
            service = self.service,
        )
    }

    /// Reads a record back from one JSON line.
    ///
    /// Returns `None` for anything that does not parse, which is what makes an
    /// interrupted append cost its own line rather than the file: a half-written
    /// final record is unreadable by definition and is skipped.
    pub fn from_line(line: &str) -> Option<Self> {
        let path = field(line, "path")?;
        let copy = field(line, "copy")?;
        let at = field(line, "at")?;
        let sha256_before = field(line, "sha256_before")?;
        let sha256_after = field(line, "sha256_after")?;

        // The two `&'static str` fields cannot be recovered as such from a
        // file, so they are matched back against what the tree actually holds.
        // A record naming a task this build does not have is from a newer
        // version and is skipped rather than guessed at.
        let task = crate::tasks::find(&field(line, "task")?).map(|task| task.id())?;
        let service = field(line, "service")?;
        let service = known_service(&service)?;

        Some(Self {
            task,
            path,
            copy,
            at,
            sha256_before,
            sha256_after,
            service,
        })
    }
}

/// The service names a record may name, as `&'static str`.
///
/// A record's service is reloaded after a restore, which means it reaches a
/// command. Matched against a closed set rather than taken from the file, so a
/// tampered or corrupted index cannot name an arbitrary unit — the index is
/// written by root and read by root, and a value that crosses that boundary is
/// checked rather than trusted.
fn known_service(name: &str) -> Option<&'static str> {
    // Every unit any family names for a capability this tool configures.
    const KNOWN: [&str; 7] = [
        "",
        "ssh.service",
        "sshd.service",
        "sshd",
        "caddy.service",
        "fail2ban.service",
        "crowdsec.service",
    ];

    KNOWN.into_iter().find(|known| *known == name)
}

/// Escapes the two characters that would break a JSON string.
///
/// Paths are the only field that can contain either, and a path holding a quote
/// is legal on Linux however unlikely.
fn escape(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

/// Reads one string field out of a JSON line.
///
/// A parser for exactly the shape [`BackupRecord::to_line`] writes, rather than
/// a general one: the file is written by this module and read by this module,
/// and a dependency for that would be a dependency to audit for the sake of
/// seven flat fields.
fn field(line: &str, name: &str) -> Option<String> {
    let key = format!("\"{name}\":\"");
    let start = line.find(&key)? + key.len();
    let rest = &line[start..];

    // Walk rather than `find('"')`, so an escaped quote inside a path does not
    // end the value early.
    let mut value = String::new();
    let mut chars = rest.chars();

    while let Some(character) = chars.next() {
        match character {
            '"' => return Some(value),
            '\\' => value.push(chars.next()?),
            _ => value.push(character),
        }
    }

    None
}

/// Appends a record, reporting whether it could be kept.
///
/// Best effort by design: a host with a read-only `/var/lib`, or one where this
/// runs unprivileged, gets `Ok(false)` and a task that carries on. The caller
/// reports that no record was kept rather than failing a change that has
/// already been applied correctly.
pub fn append(executor: &dyn Executor, files: &dyn FileEditor, record: &BackupRecord) -> bool {
    if !make_tree(executor, files) {
        return false;
    }

    // `>>` through `sh` rather than `tee -a`, for one reason: `O_APPEND` is
    // what makes concurrent writes not interleave, and both give it, but `tee`
    // would also echo the line to stdout and into the output pane.
    //
    // The line reaches the shell through stdin rather than as an argument, the
    // same rule every other write here follows: an argument would need
    // escaping, and a flaw in that escaping is a root-level injection.
    let command = Command::new("sh")
        .args(["-c", &format!("cat >> {INDEX_PATH}")])
        .privileged()
        .stdin(format!("{}\n", record.to_line()));

    let Ok(output) = executor.run(&command) else {
        return false;
    };

    if !output.success() {
        return false;
    }

    // After the append, because the file may not have existed before it, and
    // `chmod` on a path that is not there fails. Every append re-applies it,
    // which costs one command and covers an index restored from a backup or
    // created by an older build that did not set it.
    //
    // Measured rather than assumed: without this the shell's redirect creates
    // the file under the process umask and it lands `0644` on `debian:13` and
    // `alpine:3.23` alike — world-readable, holding every path this tool has
    // touched and the digests of their contents.
    files.set_mode(executor, INDEX_PATH, INDEX_MODE).is_ok()
}

/// Creates the directories the index lives in, at the mode they must have.
///
/// Both of them, and that is the point. `create_dir` on the inner path makes
/// the parent too — `install -d` does — but it applies the requested mode only
/// to the leaf, so `/var/lib/initd` came out at the process umask's `0755`
/// while `/var/lib/initd/backups` underneath it was correctly `0700`. Measured
/// on `debian:13` and `alpine:3.23`, which agreed.
///
/// A world-readable parent does not disclose the copies inside a `0700` child,
/// but it does disclose that they exist and what they are named — and the names
/// are the paths this tool has changed, flattened. That is a map of what has
/// been configured on the host, readable by any account.
fn make_tree(executor: &dyn Executor, files: &dyn FileEditor) -> bool {
    files.create_dir(executor, INDEX_DIR, TREE_MODE).is_ok()
        && files.create_dir(executor, BACKUP_DIR, TREE_MODE).is_ok()
}

/// Every record this index holds, oldest first.
///
/// A missing or unreadable index is an empty list rather than an error: a host
/// where this tool has never run has no records, and that is an answer.
pub fn read_all(executor: &dyn Executor, files: &dyn FileEditor) -> Vec<BackupRecord> {
    let Ok(true) = files.exists(executor, INDEX_PATH) else {
        return Vec::new();
    };

    let Ok(contents) = files.read(executor, INDEX_PATH) else {
        return Vec::new();
    };

    contents
        .lines()
        .filter_map(BackupRecord::from_line)
        .collect()
}

/// SHA-256 of a file, as the host computes it.
///
/// `sha256sum` rather than a crate: it is in coreutils and in busybox, this
/// project already depends on it for release verification, and hashing a file
/// this tool is about to move is not worth a dependency.
///
/// `None` where the file cannot be read, which the caller must treat as "cannot
/// prove anything" rather than as a mismatch.
pub fn digest_of(executor: &dyn Executor, path: &str) -> Option<String> {
    let command = Command::new("sha256sum").arg(path).privileged();
    let output = executor.run(&command).ok()?;

    if !output.success() {
        return None;
    }

    output
        .stdout
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .filter(|digest| digest.len() == 64)
}

/// The host's own idea of now, as a filename-safe stamp.
///
/// Asked of the machine rather than computed, because this project carries no
/// time dependency and adding one for a string would be a crate to audit for
/// something `date` already answers. UTC so that records from a host whose
/// timezone changes still sort.
pub fn timestamp(executor: &dyn Executor) -> Option<String> {
    let command = Command::new("date").args(["-u", "+%Y%m%dT%H%M%SZ"]);
    let output = executor.run(&command).ok()?;

    if !output.success() {
        return None;
    }

    let stamp = output.stdout.trim().to_owned();

    // A stamp that is not the shape asked for means `date` is not the one this
    // expects; better no record than a filename built from something else.
    (stamp.len() == 16 && stamp.ends_with('Z')).then_some(stamp)
}

/// Records a copy that [`FileEditor::write`] has already taken.
///
/// The cheaper of the two ways in, and the one every configuration task uses.
/// `write` backs a file up before replacing it, so the copy exists by the time
/// a task can ask about it — taking a second one would double the I/O and, more
/// to the point, copy the file *after* the write rather than before.
///
/// What it costs is two commands: a timestamp and a digest of the new contents.
/// The digest of the previous contents comes free, because the copy is that
/// file and hashing it is the same work either way.
///
/// The copy is moved under [`BACKUP_DIR`] with a timestamp in its name, which is
/// what makes it survive the next write to the same path — `write` reuses one
/// fixed `.initd.bak` per file, so without this the second change to
/// `sshd_config` would overwrite the copy the first one left.
///
/// Answers where the copy ended up, or `None` if nothing was recorded.
///
/// The path rather than a yes/no, because the caller has to be able to *name*
/// it. `ssh.harden` tells the operator where the previous configuration was
/// saved, and that line is read by somebody who has just locked themselves out
/// — it named `<file>.initd.bak`, which this function has by then moved, so the
/// one message that mattered pointed at a path that no longer existed.
///
/// `None` is not a failure: the change has already been applied correctly, and
/// the caller says no cross-session revert will be available rather than
/// failing a task over bookkeeping.
pub fn record_existing(
    executor: &dyn Executor,
    files: &dyn FileEditor,
    task: &'static str,
    backup: &crate::domain::files::Backup,
    service: &'static str,
) -> Option<String> {
    let at = timestamp(executor)?;

    if !make_tree(executor, files) {
        return None;
    }

    // Before the move, and asked of the filesystem: two changes to one file
    // inside the same second would otherwise name the same copy and the second
    // would overwrite the first.
    let kept = free_copy_path(executor, files, &backup.original, &at)?;

    // Moved rather than copied: `write` put it beside the original under one
    // fixed name, and leaving it there means the next write to the same path
    // overwrites it. Moving is also what keeps a second copy of a file holding
    // a private key from existing at all.
    let command = Command::new("mv").args([&backup.copy, &kept]).privileged();

    if !executor.run(&command).ok().is_some_and(|out| out.success()) {
        return None;
    }

    let record = BackupRecord {
        task,
        path: backup.original.clone(),
        sha256_before: digest_of(executor, &kept)?,
        sha256_after: digest_of(executor, &backup.original)?,
        copy: kept,
        at,
        service,
    };

    if !append(executor, files, &record) {
        // The copy is on disk and the line is not, so nothing can find it
        // again. Reported as unrecorded rather than as a path the caller would
        // print: a message naming a copy no index knows about is a message
        // promising a revert that has no way to happen.
        return None;
    }

    prune(executor, files, &record.path);

    Some(record.copy)
}

/// Deletes the oldest copies of one path, keeping [`RETAINED_PER_PATH`].
///
/// Bounded because the material is sensitive rather than merely bulky: an
/// unbounded history of `wg0.conf` is an unbounded number of copies of the
/// server's private key, each one another file that has to stay `0600` forever.
///
/// The index keeps its lines. A record whose copy is gone is still the answer
/// to "what happened to this file and when", and a revert that finds the copy
/// missing refuses on the digest check rather than on a dangling path.
fn prune(executor: &dyn Executor, files: &dyn FileEditor, path: &str) {
    let copies: Vec<String> = read_all(executor, files)
        .into_iter()
        .filter(|record| record.path == path)
        .map(|record| record.copy)
        .collect();

    let Some(surplus) = copies.len().checked_sub(RETAINED_PER_PATH) else {
        return;
    };

    // Oldest first, because records are appended in order.
    for copy in copies.into_iter().take(surplus) {
        let command = Command::new("rm").args(["-f", &copy]).privileged();
        let _ = executor.run(&command);
    }
}

/// Where a copy of `path` taken at `stamp` is kept.
///
/// The original's path is flattened into the filename rather than recreated as
/// a directory tree: `/var/lib/initd/backups/etc-ssh-sshd_config.<stamp>` is
/// one directory to mode `0700` and one to audit, where a mirrored tree is a
/// new directory per depth, each of which could be created with the wrong mode.
pub fn copy_path(original: &str, stamp: &str) -> String {
    let flattened: String = original
        .trim_start_matches('/')
        .chars()
        .map(|character| if character == '/' { '-' } else { character })
        .collect();

    format!("{BACKUP_DIR}/{flattened}.{stamp}")
}

/// A path like [`copy_path`]'s that nothing is using yet.
///
/// The stamp has one-second resolution, so two changes to the same file inside
/// one second name the same copy and the second overwrites the first — which is
/// precisely the failure this whole index exists to prevent, reappearing one
/// layer down. Measured rather than reasoned about: two `ssh.change-port` runs
/// in a container produced two records and one copy.
///
/// Answered by asking the filesystem rather than by making the stamp finer.
/// `date` is the host's, `%N` is a GNU extension busybox does not have, and a
/// name that is unique because nothing is at it is unique for a reason that
/// does not depend on a clock.
///
/// Gives up after a small number of attempts rather than looping: past that,
/// something other than a same-second collision is going on, and no record is
/// better than a loop in a tool running as root.
fn free_copy_path(
    executor: &dyn Executor,
    files: &dyn FileEditor,
    original: &str,
    stamp: &str,
) -> Option<String> {
    /// How many same-second changes to one file are worth accommodating.
    const ATTEMPTS: u32 = 100;

    let base = copy_path(original, stamp);

    if !files.exists(executor, &base).ok()? {
        return Some(base);
    }

    (1..ATTEMPTS)
        .map(|nth| format!("{base}.{nth}"))
        .find(|candidate| files.exists(executor, candidate).is_ok_and(|taken| !taken))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    fn a_record() -> BackupRecord {
        BackupRecord {
            task: "ssh.harden",
            path: "/etc/ssh/sshd_config".to_owned(),
            copy: "/var/lib/initd/backups/etc-ssh-sshd_config.20260809T142203Z".to_owned(),
            at: "20260809T142203Z".to_owned(),
            sha256_before: "a".repeat(64),
            sha256_after: "b".repeat(64),
            service: "ssh.service",
        }
    }

    #[test]
    fn a_record_survives_being_written_and_read_back() {
        let record = a_record();

        assert_eq!(
            BackupRecord::from_line(&record.to_line()),
            Some(record),
            "a record must round-trip through its own format"
        );
    }

    #[test]
    fn a_half_written_line_costs_itself_and_nothing_else() {
        // What an interrupted append leaves. Discarded rather than parsed
        // partially, which is the whole reason the file is append-only: no
        // lock, and the damage is bounded to the last record.
        let good = a_record().to_line();
        let truncated = &good[..good.len() / 2];

        assert!(BackupRecord::from_line(truncated).is_none());
        assert!(BackupRecord::from_line("").is_none());
        assert!(BackupRecord::from_line("{not json at all").is_none());
    }

    #[test]
    fn a_path_holding_a_quote_does_not_break_the_line() {
        // Legal on Linux, however unlikely, and the one field that can contain
        // a character the format cares about.
        let mut record = a_record();
        record.path = "/etc/we\"ird/na\\me".to_owned();

        let read = BackupRecord::from_line(&record.to_line()).expect("it must round-trip");

        assert_eq!(read.path, "/etc/we\"ird/na\\me");
    }

    #[test]
    fn a_record_naming_something_this_build_does_not_have_is_skipped() {
        // An index written by a newer version, read by an older one. Skipped
        // rather than guessed at: the alternative is reloading a unit named by
        // a file, which is a value crossing a trust boundary.
        let mut line = a_record().to_line();
        line = line.replace("ssh.harden", "some.future.task");

        assert!(BackupRecord::from_line(&line).is_none());

        let mut line = a_record().to_line();
        line = line.replace("ssh.service", "attacker.service");

        assert!(
            BackupRecord::from_line(&line).is_none(),
            "a unit name from the file must be matched against what this build knows"
        );
    }

    #[test]
    fn records_are_read_back_in_the_order_they_were_written() {
        // The file is appended to, so it reads oldest first, and the history
        // reverses it to put the newest under the cursor. Both halves depend
        // on the order surviving the round trip: a reader that sorted or
        // reordered would make "the newest" a different record from the last
        // one written.
        let mut older = a_record();
        older.at = "20260101T000000Z".to_owned();
        older.sha256_after = "c".repeat(64);

        let newer = a_record();

        let index = format!("{}\n{}\n", older.to_line(), newer.to_line());
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok(index)]);
        let files = crate::backend::unix_files::UnixFiles::new();

        let read = read_all(&mock, &files);

        assert_eq!(read.len(), 2);
        assert_eq!(read[0].sha256_after, older.sha256_after);
        assert_eq!(read[1].sha256_after, newer.sha256_after);
    }

    #[test]
    fn a_host_this_tool_never_ran_on_has_no_records_rather_than_an_error() {
        // `test -e` fails: no index. An empty list is the answer, and what
        // makes "no record means no revert offered" work on a fresh machine.
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let files = crate::backend::unix_files::UnixFiles::new();

        assert!(read_all(&mock, &files).is_empty());
    }

    #[test]
    fn two_changes_in_one_second_do_not_share_a_copy() {
        // The stamp has one-second resolution, so a second change to the same
        // file inside the same second named the same copy and overwrote the
        // first — the very failure the index exists to prevent, one layer
        // down. Measured: two `ssh.change-port` runs in a container left two
        // records and one copy.
        let taken = MockExecutor::with_replies([
            Reply::ok(""),         // test -e on the plain name: taken
            Reply::failure(1, ""), // test -e on `.1`: free
        ]);
        let files = crate::backend::unix_files::UnixFiles::new();

        let chosen = free_copy_path(&taken, &files, "/etc/ssh/sshd_config", "20260809T142203Z")
            .expect("a free name must be found");

        assert_eq!(
            chosen,
            "/var/lib/initd/backups/etc-ssh-sshd_config.20260809T142203Z.1"
        );
    }

    #[test]
    fn a_free_name_is_used_as_it_is() {
        // The ordinary case, and the one that keeps the names readable: only a
        // collision gets a suffix.
        let free = MockExecutor::with_replies([Reply::failure(1, "")]);
        let files = crate::backend::unix_files::UnixFiles::new();

        assert_eq!(
            free_copy_path(&free, &files, "/etc/ssh/sshd_config", "20260809T142203Z"),
            Some("/var/lib/initd/backups/etc-ssh-sshd_config.20260809T142203Z".to_owned())
        );
    }

    #[test]
    fn a_copy_is_named_for_the_file_it_came_from_and_when() {
        // Flattened rather than mirrored: one directory to mode 0700, not a
        // new one per depth each of which could be created wrongly.
        assert_eq!(
            copy_path("/etc/ssh/sshd_config", "20260809T142203Z"),
            "/var/lib/initd/backups/etc-ssh-sshd_config.20260809T142203Z"
        );
    }

    #[test]
    fn a_digest_that_is_not_one_is_refused() {
        // `sha256sum` prints the digest then the filename. A truncated or
        // error-shaped answer must not be recorded as if it proved something.
        let good = MockExecutor::with_replies([Reply::ok(format!(
            "{}  /etc/ssh/sshd_config",
            "a".repeat(64)
        ))]);
        assert_eq!(
            digest_of(&good, "/etc/ssh/sshd_config"),
            Some("a".repeat(64))
        );

        let short = MockExecutor::with_replies([Reply::ok("abc  /etc/ssh/sshd_config")]);
        assert_eq!(digest_of(&short, "/etc/ssh/sshd_config"), None);

        let failed = MockExecutor::with_replies([Reply::failure(1, "No such file")]);
        assert_eq!(digest_of(&failed, "/etc/ssh/sshd_config"), None);
    }

    #[test]
    fn a_timestamp_that_is_not_the_shape_asked_for_is_refused() {
        let good = MockExecutor::with_replies([Reply::ok("20260809T142203Z\n")]);
        assert_eq!(timestamp(&good), Some("20260809T142203Z".to_owned()));

        // A `date` that answered something else entirely. Better no record
        // than a filename built from a string of unknown shape.
        let odd = MockExecutor::with_replies([Reply::ok("Sun Aug  9 14:22:03 UTC 2026")]);
        assert_eq!(timestamp(&odd), None);
    }

    #[test]
    fn an_index_that_cannot_be_written_is_reported_rather_than_raised() {
        // A read-only /var/lib, or running unprivileged. The task has already
        // applied its change correctly; failing it here would report a
        // successful change as a failure.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                  // install -d /var/lib/initd
            Reply::ok(""),                  // install -d …/backups
            Reply::failure(1, "Read-only"), // the append itself
        ]);
        let files = crate::backend::unix_files::UnixFiles::new();

        assert!(!append(&mock, &files, &a_record()));
    }

    #[test]
    fn neither_directory_is_left_readable_by_everyone() {
        // Both, and that is the point. `install -d` creates the parent on the
        // way to the leaf but applies the requested mode only to the leaf, so
        // asking for `…/backups` alone left `/var/lib/initd` at the umask's
        // 0755 — measured on debian:13 and alpine:3.23, which agreed.
        //
        // A readable parent does not disclose the copies inside a 0700 child,
        // but it discloses their names, and the names are the paths this tool
        // has changed. That is a map of the host's configuration.
        let mock = MockExecutor::new();
        let files = crate::backend::unix_files::UnixFiles::new();

        append(&mock, &files, &a_record());

        let created: Vec<String> = mock
            .recorded_lines()
            .into_iter()
            .filter(|line| line.starts_with("install -d"))
            .collect();

        assert_eq!(
            created.len(),
            2,
            "both directories must be made: {created:?}"
        );

        for line in &created {
            assert!(
                line.contains("700"),
                "a directory must not be readable: {line}"
            );
        }
    }

    #[test]
    fn the_index_is_not_left_readable_by_everyone_either() {
        // The append is a shell redirect, so the file is created under the
        // process umask and lands 0644 unless something says otherwise.
        // Nothing did, and no mock could have noticed: only a real filesystem
        // has a umask.
        let mock = MockExecutor::new();
        let files = crate::backend::unix_files::UnixFiles::new();

        append(&mock, &files, &a_record());

        assert!(
            mock.recorded_lines()
                .iter()
                .any(|line| line == "chmod 600 /var/lib/initd/backups.jsonl"),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_record_carries_no_field_a_secret_could_reach() {
        // Enforced by the type rather than by discipline: every field is a
        // path, a digest, a timestamp or an id, and there is no free-form map
        // for a caller to put a password in. This test exists so that adding
        // one is a deliberate act with a failing test attached.
        let line = a_record().to_line();

        for field in ["password", "secret", "key", "private"] {
            assert!(
                !line.contains(field),
                "the record format must have no field a secret could be put in: {line}"
            );
        }
    }
}
