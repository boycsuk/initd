//! POSIX implementation of [`FileEditor`].
//!
//! Shared by every family: `cat`, `tee`, `cp`, `chmod`, `install` and `chown`
//! behave the same everywhere `initd` runs, and all are resolved through
//! `PATH` rather than by absolute location.

use super::systemd::{run_capturing, run_checked};
use crate::domain::files::{Backup, FileEditor, OwnedDirWrite};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Suffix appended to backup copies.
///
/// Fixed rather than timestamped, so a file accumulates one backup instead of a
/// directory full of them. The copy that matters is the state before the
/// current change, and what bounds the cost of keeping only that one is the
/// verification window: the interface is modal while it is open — every key
/// goes to keeping or reverting — so a second task cannot touch the file until
/// the first one's copy has done its job.
///
/// The command line has no such window, so two invocations in a row do replace
/// the first copy with the state the first invocation produced. What that
/// costs is bounded in turn by each task validating and rolling back on its
/// own before it ever returns; what it leaves is an operator who ran two
/// commands having a way back to the second, not the first. The path is
/// printed for exactly that reason.
const BACKUP_SUFFIX: &str = ".initd.bak";

/// Suffix of the file a new version is written to before replacing the target.
///
/// Distinct from [`BACKUP_SUFFIX`] so a staging file left behind by an
/// interrupted write is never mistaken for the backup a revert would restore.
const STAGING_SUFFIX: &str = ".initd.new";

/// Mode the staging file is created at, before anything is written into it.
///
/// Deliberately the narrowest thing that works rather than the target's mode:
/// the staging file is written by root and read by nobody, so it needs no
/// wider access, and starting narrow means a secret is never briefly exposed
/// while the right mode is being determined. Whatever the target should end up
/// at is applied afterwards, which may widen it.
const STAGING_MODE: u32 = 0o600;

/// Mode a file this tool creates is given, when there is no existing one to
/// keep.
///
/// What `tee` produced on its own before the staging file was created
/// explicitly: measured at `644` on `debian:13` under root's default `0022`
/// umask. Stated rather than inherited now, because the staging file is
/// deliberately narrower than any target should be — inheriting it would give
/// a freshly created `sshd_config` mode `0600` and stop every non-root reader,
/// which is a change this was never meant to make.
const NEW_FILE_MODE: u32 = 0o644;

/// Exit code the owned-directory script uses for a link it would have followed.
///
/// Apart from the codes the utilities themselves produce, so "somebody planted
/// a link" is distinguishable from "the disk is full". 9 is outside the range
/// `install`, `chmod`, `chown` and `mv` use, and outside the 126-128 and 128+n
/// ranges a shell reserves for "not executable" and "killed by a signal".
const SYMLINK_REFUSED: i32 = 9;

/// Edits files using standard POSIX utilities.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnixFiles;

impl UnixFiles {
    pub const fn new() -> Self {
        Self
    }

    /// Path where the backup of a file is kept.
    fn backup_path(path: &str) -> String {
        format!("{path}{BACKUP_SUFFIX}")
    }

    /// Path a new version is written to before being moved into place.
    ///
    /// Beside the target rather than in `/tmp`, because a rename is only atomic
    /// within a filesystem: across two, `mv` copies, and the guarantee is lost
    /// precisely where `/etc` and `/tmp` are separate mounts. Sitting in the
    /// same directory also means the file is created under the same policy —
    /// SELinux labels a new file from its parent, so a staging file made in
    /// `/tmp` would arrive mislabelled.
    fn staging_path(path: &str) -> String {
        format!("{path}{STAGING_SUFFIX}")
    }
}

impl FileEditor for UnixFiles {
    fn read(&self, executor: &dyn Executor, path: &str) -> Result<String> {
        // Reading is privileged: sshd_config is mode 600 on some systems.
        let command = Command::new("cat").arg(path).privileged();
        let output = run_capturing(executor, &command)?;

        Ok(output.stdout)
    }

    fn exists(&self, executor: &dyn Executor, path: &str) -> Result<bool> {
        // `test -e` exits non-zero for "no", which is an answer rather than a
        // failure, so the exit code is read instead of checked.
        let command = Command::new("test").args(["-e", path]).privileged();

        Ok(executor.run(&command)?.success())
    }

    fn is_symlink(&self, executor: &dyn Executor, path: &str) -> Result<bool> {
        // `test -L` is POSIX and answers by exit code, like `test -e` above: a
        // path that is not a link is an answer rather than a failure.
        let command = Command::new("test").args(["-L", path]).privileged();

        Ok(executor.run(&command)?.success())
    }

    fn backup(&self, executor: &dyn Executor, path: &str) -> Result<Backup> {
        let copy = Self::backup_path(path);

        // `-p` preserves mode and ownership, so restoring cannot silently
        // loosen the permissions of a sensitive file.
        let command = Command::new("cp").args(["-p", path, &copy]).privileged();

        run_checked(executor, &command)?;

        Ok(Backup {
            original: path.to_owned(),
            copy,
        })
    }

    fn write(&self, executor: &dyn Executor, path: &str, contents: &str) -> Result<Option<Backup>> {
        let backup = if self.exists(executor, path)? {
            Some(self.backup(executor, path)?)
        } else {
            None
        };

        Self::install(executor, path, contents, backup.is_some())?;

        Ok(backup)
    }

    fn write_uncopied(&self, executor: &dyn Executor, path: &str, contents: &str) -> Result<()> {
        // Whether to preserve the mode is keyed on the file already existing,
        // where `write` keys it on a backup having been taken. The two are the
        // same question there and not here: this path never takes one.
        let keep_mode = self.exists(executor, path)?;

        Self::install(executor, path, contents, keep_mode)
    }

    fn restore(&self, executor: &dyn Executor, backup: &Backup) -> Result<()> {
        let command = Command::new("cp")
            .args(["-p", &backup.copy, &backup.original])
            .privileged();

        run_checked(executor, &command)
    }

    fn set_mode(&self, executor: &dyn Executor, path: &str, mode: u32) -> Result<()> {
        let command = Command::new("chmod")
            .args([&format!("{mode:o}"), path])
            .privileged();

        run_checked(executor, &command)
    }

    fn create_dir(&self, executor: &dyn Executor, path: &str, mode: u32) -> Result<()> {
        // `install -d` creates the directory with the mode applied atomically,
        // avoiding the window where a new ~/.ssh sits world-readable.
        let command = Command::new("install")
            .args(["-d", "-m", &format!("{mode:o}"), path])
            .privileged();

        run_checked(executor, &command)
    }

    fn write_in_owned_dir(&self, executor: &dyn Executor, spec: &OwnedDirWrite<'_>) -> Result<()> {
        let script = Self::owned_dir_script();

        // Every path is a positional parameter, never interpolated. A home
        // directory comes from the passwd database and a user name is
        // validated, but the guarantee here should not rest on either: `sh -c`
        // reading a value carrying a backtick as more of the script is a root
        // command injection, and `"$1"` cannot be.
        let command = Command::new("sh")
            .args([
                "-c",
                script,
                "sh",
                spec.dir,
                &format!("{:o}", spec.dir_mode),
                spec.path,
                &format!("{:o}", spec.file_mode),
                spec.owner,
            ])
            .privileged()
            .stdin(spec.contents.to_owned());

        let output = executor.run(&command)?;

        if !output.success() {
            // The script exits 9 on a link it refused to follow, apart from
            // any other failure, so the operator is told which of the two
            // happened. Any other code is an ordinary command failure.
            if output.code == SYMLINK_REFUSED {
                return Err(Error::UnsafeSymlink {
                    path: output.stdout.trim().to_owned(),
                });
            }

            return Err(Error::CommandFailed {
                command: command.to_string(),
                code: output.code,
                stderr: output.stderr,
            });
        }

        Ok(())
    }
}

impl UnixFiles {
    /// The one-invocation write into a directory its owner controls.
    ///
    /// Held here as a `&'static str` rather than built per call: nothing about
    /// it varies, and a script assembled from values is the thing this method
    /// exists to avoid. The paths arrive as `"$1"`..`"$5"`.
    ///
    /// What each step is for, since a shell script inside Rust is the least
    /// reviewable code in this tree:
    ///
    /// - `set -eu` so any failing step ends the sequence rather than carrying
    ///   on to write a key into a directory whose mode was never applied.
    /// - The directory is created with [`install -d`], which applies mode and
    ///   owner as it creates. A missing directory is therefore never briefly
    ///   world-readable, and never briefly owned by root.
    /// - Each link test happens immediately before the command it guards, and
    ///   the file is staged and moved rather than written in place. `mv` within
    ///   one directory does not follow a link at the destination — it replaces
    ///   it — so the contents cannot land somewhere else even if one appears
    ///   between the test and the move.
    /// - `chown -h` never dereferences, so the ownership of a link's target
    ///   cannot be changed through it.
    /// - The staging file is created by `install` with the final mode and owner
    ///   already on it, so it is never readable by the account whose directory
    ///   it sits in, not even for the moment before the move.
    ///
    /// [`install -d`]: https://www.gnu.org/software/coreutils/install
    pub(crate) const fn owned_dir_script() -> &'static str {
        // `$1` dir, `$2` dir mode, `$3` file, `$4` file mode, `$5` owner.
        r#"set -eu
dir=$1; dir_mode=$2; file=$3; file_mode=$4; owner=$5
if [ -L "$dir" ]; then printf '%s' "$dir"; exit 9; fi
install -d -m "$dir_mode" -o "$owner" -g "$owner" "$dir"
if [ -L "$dir" ]; then printf '%s' "$dir"; exit 9; fi
if [ -L "$file" ]; then printf '%s' "$file"; exit 9; fi
staged=$file.initd.new
rm -f "$staged"
install -m "$file_mode" -o "$owner" -g "$owner" /dev/null "$staged"
cat > "$staged"
if [ -L "$file" ]; then rm -f "$staged"; printf '%s' "$file"; exit 9; fi
mv -f "$staged" "$file"
chown -h "$owner:$owner" "$file"
"#
    }

    /// Writes `contents` over `path` atomically, keeping the target's mode.
    ///
    /// The half of a write that [`FileEditor::write`] and
    /// [`FileEditor::write_uncopied`] share: everything after the decision
    /// about whether a copy is taken first.
    ///
    /// `keep_mode` asks whether the target already has a mode worth carrying
    /// over. `write` answers it with "a backup was taken" and `write_uncopied`
    /// with "the file existed" — the same question wherever a copy is made,
    /// and only there.
    fn install(executor: &dyn Executor, path: &str, contents: &str, keep_mode: bool) -> Result<()> {
        // `tee` truncates and then writes, so a process that dies between the
        // two — a full disk, an OOM kill, the power going — leaves
        // `sshd_config` empty or half a file, which is a third state neither
        // the change nor the backup describes. A rename within one directory
        // is atomic: every reader sees the old file or the new one.
        //
        // The temporary sits in the target's own directory because a rename
        // across filesystems is not a rename — `mv` falls back to copying, and
        // the guarantee is lost exactly where /etc and /tmp are separate
        // mounts.
        let staged = Self::staging_path(path);

        // The staging file is created empty and restrictive before anything is
        // written into it. `tee` alone creates it under the process umask, so
        // the contents existed at `0644` until the chmod below — and that chmod
        // only runs when `keep_mode` is set, which is the case `wg0.conf` does
        // *not* take on a rewrite: the target already exists at `0600`, so the
        // key sat world-readable in `wg0.conf.initd.new` instead of in
        // `wg0.conf`. The same bug as the one this file's comment below records,
        // moved one filename along.
        //
        // `install -m` rather than `touch` and `chmod`: it creates at the mode
        // in one step, so there is no window at all, and it is what
        // `owned_dir_script` already uses for this.
        let stage = Command::new("install")
            .args(["-m", &format!("{STAGING_MODE:o}"), "/dev/null", &staged])
            .privileged();

        run_checked(executor, &stage)?;

        // Contents travel on stdin, never as an argument: an argument would
        // need shell escaping, and a flaw in that escaping is a root-level
        // command injection.
        let write = Command::new("tee")
            .arg(&staged)
            .privileged()
            .stdin(contents);

        run_checked(executor, &write)?;

        // The mode goes on before the move, not after: a file created with the
        // process umask is world-readable for as long as a later chmod takes,
        // and `wg0.conf` is where that was found. An existing file keeps its
        // own mode rather than being given a default — the tool is editing it,
        // not deciding what it should be.
        //
        // Read with `stat -c` and applied with `chmod`, rather than in one step
        // with `chmod --reference` or `cp --preserve=mode`: neither exists on
        // busybox. Measured on `alpine:3.23`, where both fail and `stat -c %a`
        // answers `644` — the same lesson `diff`, `cmp` and `pgrep` each taught
        // once, which is that a tool present on Debian is not thereby present
        // everywhere.
        // A new file is given the default outright rather than left at whatever
        // the staging file was created as. That used to be the umask's doing
        // and is now `STAGING_MODE`, which is far too narrow to inherit: a
        // `sshd_config` this tool created would arrive at `0600` and stop being
        // readable by anything that is not root. The narrow staging mode exists
        // to keep a secret off the disk while the real mode is worked out, not
        // to become the real mode.
        let target_mode = if keep_mode {
            let mode = Command::new("stat").args(["-c", "%a", path]).privileged();

            run_capturing(executor, &mode)?.stdout.trim().to_owned()
        } else {
            format!("{NEW_FILE_MODE:o}")
        };

        let apply = Command::new("chmod")
            .args([&target_mode, &staged])
            .privileged();

        run_checked(executor, &apply)?;

        let install = Command::new("mv")
            .args([&staged, &path.to_owned()])
            .privileged();

        run_checked(executor, &install)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    /// Runs the owned-directory script the way `LocalExecutor` invokes it.
    ///
    /// Against a real shell rather than a mock, because the mock records that a
    /// command was issued and never runs it — so every property this script
    /// exists for (the modes it applies, the links it refuses, the staging file
    /// it must not leave behind) is invisible to the tests above. Written as a
    /// helper rather than inline because five cases share the invocation, and
    /// the invocation is the part that has to match production exactly.
    ///
    /// Returns the exit code and stdout, which is where the script names an
    /// offending path.
    fn run_owned_dir_script(
        dir: &std::path::Path,
        file: &std::path::Path,
        contents: &str,
    ) -> (i32, String) {
        use std::io::Write as _;
        use std::process::{Command as StdCommand, Stdio};

        let owner = std::process::Command::new("id")
            .arg("-un")
            .output()
            .expect("id must run");
        let owner = String::from_utf8_lossy(&owner.stdout).trim().to_owned();

        let mut child = StdCommand::new("sh")
            .args([
                "-c",
                UnixFiles::owned_dir_script(),
                "sh",
                &dir.to_string_lossy(),
                "700",
                &file.to_string_lossy(),
                "600",
                &owner,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sh must spawn");

        // A broken pipe is an expected outcome here, not a failure: the script
        // refuses a planted symlink and exits *before* reading stdin, so the
        // write lands on a pipe the child has already closed. Two of the cases
        // below are that refusal. Panicking on it made those tests fail
        // whenever the child won the race, which on a loaded CI runner it did
        // and on this machine it did not.
        //
        // Any other write error is still fatal: it would mean the script did
        // not receive the contents it was meant to write, and a scenario
        // asserting on those contents would be asserting on nothing.
        let written = child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(contents.as_bytes());

        if let Err(error) = written
            && error.kind() != std::io::ErrorKind::BrokenPipe
        {
            panic!("the contents must be written: {error:?}");
        }

        let output = child.wait_with_output().expect("sh must finish");

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    }

    /// A directory unique to one test, removed when it is dropped.
    struct TempHome(std::path::PathBuf);

    impl TempHome {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("initd-owned-dir-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("the temp home must be created");
            Self(dir)
        }

        fn path(&self, relative: &str) -> std::path::PathBuf {
            self.0.join(relative)
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::metadata(path)
            .expect("the path must exist")
            .permissions()
            .mode()
            & 0o777
    }

    #[test]
    fn the_owned_dir_script_applies_both_modes_as_it_writes() {
        let home = TempHome::new("modes");
        let dir = home.path(".ssh");
        let file = home.path(".ssh/authorized_keys");

        let (code, _) = run_owned_dir_script(&dir, &file, "ssh-ed25519 AAAA test@host\n");

        assert_eq!(code, 0, "a fresh write must succeed");
        assert_eq!(mode_of(&dir), 0o700, "sshd ignores a group-readable ~/.ssh");
        assert_eq!(mode_of(&file), 0o600, "and a group-readable key file");
        assert_eq!(
            std::fs::read_to_string(&file).expect("the file must exist"),
            "ssh-ed25519 AAAA test@host\n"
        );
    }

    #[test]
    fn the_owned_dir_script_leaves_no_staging_file_behind() {
        // The staging file carries the key with its final mode, but it sits in
        // a directory the account owns: one left behind is a second copy of
        // authorized_keys under a name nothing manages.
        let home = TempHome::new("staging");
        let dir = home.path(".ssh");
        let file = home.path(".ssh/authorized_keys");

        run_owned_dir_script(&dir, &file, "ssh-ed25519 AAAA test@host\n");

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("the directory must exist")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("initd.new"))
            .collect();

        assert!(
            leftovers.is_empty(),
            "staging file left behind: {leftovers:?}"
        );
    }

    #[test]
    fn the_owned_dir_script_refuses_a_link_in_place_of_the_file() {
        // The TOCTOU case. The task checks for a link before it starts, and the
        // account owning this home can plant one immediately afterwards — so
        // the script checks again between its own steps, and `mv` replaces a
        // link rather than following it.
        let home = TempHome::new("file-link");
        let dir = home.path(".ssh");
        let file = home.path(".ssh/authorized_keys");
        let target = home.path("elsewhere");

        std::fs::create_dir_all(&dir).expect("the directory must exist");
        std::os::unix::fs::symlink(&target, &file).expect("the link must be planted");

        let (code, stdout) = run_owned_dir_script(&dir, &file, "ssh-ed25519 AAAA attacker\n");

        assert_eq!(code, SYMLINK_REFUSED, "a planted link must be refused");
        assert_eq!(
            stdout.trim(),
            file.to_string_lossy(),
            "the refusal must name the path"
        );
        assert!(!target.exists(), "nothing may be written through the link");
    }

    #[test]
    fn the_owned_dir_script_refuses_a_link_in_place_of_the_directory() {
        // The same trick one level up: `install -d` and `chown` both follow a
        // link, so a linked ~/.ssh has root apply a mode and an ownership
        // wherever the account pointed it.
        let home = TempHome::new("dir-link");
        let dir = home.path(".ssh");
        let file = home.path(".ssh/authorized_keys");
        let target = home.path("real");

        std::fs::create_dir_all(&target).expect("the target must exist");
        std::os::unix::fs::symlink(&target, &dir).expect("the link must be planted");

        let (code, stdout) = run_owned_dir_script(&dir, &file, "ssh-ed25519 AAAA attacker\n");

        assert_eq!(code, SYMLINK_REFUSED, "a linked directory must be refused");
        assert_eq!(stdout.trim(), dir.to_string_lossy());
        assert_eq!(
            std::fs::read_dir(&target)
                .expect("the target must exist")
                .count(),
            0,
            "nothing may be written through it"
        );
    }

    #[test]
    fn the_owned_dir_script_keeps_the_mode_when_rewriting() {
        // A file that already exists is replaced, not appended to — the caller
        // read it and appended before calling — and the replacement must carry
        // the mode rather than inherit the umask.
        let home = TempHome::new("rewrite");
        let dir = home.path(".ssh");
        let file = home.path(".ssh/authorized_keys");

        run_owned_dir_script(&dir, &file, "first\n");
        let (code, _) = run_owned_dir_script(&dir, &file, "first\nsecond\n");

        assert_eq!(code, 0, "a rewrite must succeed");
        assert_eq!(mode_of(&file), 0o600, "the mode must survive the rewrite");
        assert_eq!(
            std::fs::read_to_string(&file).expect("the file must exist"),
            "first\nsecond\n"
        );
    }

    const CONFIG: &str = "/etc/ssh/sshd_config";

    #[test]
    fn read_returns_the_file_contents() {
        let mock = MockExecutor::with_replies([Reply::ok("Port 22\n")]);

        let contents = UnixFiles::new()
            .read(&mock, CONFIG)
            .expect("read must work");

        assert_eq!(contents, "Port 22\n");
        assert_eq!(mock.recorded_lines(), [format!("cat {CONFIG}")]);
    }

    #[test]
    fn read_failure_surfaces_as_an_error() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "No such file")]);

        let err = UnixFiles::new()
            .read(&mock, "/nope")
            .expect_err("a failing cat must surface");

        assert!(
            matches!(err, Error::CommandFailed { code: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn exists_maps_the_exit_code_to_a_boolean() {
        let present = MockExecutor::with_replies([Reply::ok("")]);
        let absent = MockExecutor::with_replies([Reply::failure(1, "")]);

        assert!(UnixFiles::new().exists(&present, CONFIG).expect("runs"));
        assert!(!UnixFiles::new().exists(&absent, CONFIG).expect("runs"));
    }

    #[test]
    fn write_backs_up_an_existing_file_first() {
        // First reply answers `test -e` with success, so a backup is taken.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),    // test -e
            Reply::ok(""),    // cp -p
            Reply::ok(""),    // install (staging)
            Reply::ok(""),    // tee (staging)
            Reply::ok("600"), // stat -c %a
            Reply::ok(""),    // chmod
            Reply::ok(""),    // mv
        ]);

        let backup = UnixFiles::new()
            .write(&mock, CONFIG, "Port 2222\n")
            .expect("write must work")
            .expect("an existing file must be backed up");

        assert_eq!(backup.copy, format!("{CONFIG}{BACKUP_SUFFIX}"));
        assert_eq!(
            mock.recorded_lines(),
            [
                format!("test -e {CONFIG}"),
                format!("cp -p {CONFIG} {CONFIG}{BACKUP_SUFFIX}"),
                format!("install -m 600 /dev/null {CONFIG}{STAGING_SUFFIX}"),
                format!("tee {CONFIG}{STAGING_SUFFIX}"),
                format!("stat -c %a {CONFIG}"),
                format!("chmod 600 {CONFIG}{STAGING_SUFFIX}"),
                format!("mv {CONFIG}{STAGING_SUFFIX} {CONFIG}"),
            ]
        );
    }

    #[test]
    fn an_uncopied_write_leaves_nothing_beside_the_original() {
        // The whole reason the method exists. `wg0.conf` holds the server's
        // private key and every peer's preshared key, and the sidecar copy an
        // ordinary `write` leaves is a second copy of all of them that no
        // retention ever reaches — `prune` only deletes copies the index names,
        // and the one task using this path deliberately writes no index entry.
        let mock = MockExecutor::with_replies([
            Reply::ok("1"),   // test -e
            Reply::ok(""),    // install (staging)
            Reply::ok(""),    // tee (staging)
            Reply::ok("600"), // stat -c %a
            Reply::ok(""),    // chmod
            Reply::ok(""),    // mv
        ]);

        UnixFiles::new()
            .write_uncopied(&mock, CONFIG, "[Peer]\n")
            .expect("an uncopied write must work");

        // Asserted as the whole sequence rather than as an absence of `cp`,
        // because the failure this guards against is a copy taken under some
        // other name: an exact list catches a command nobody thought to forbid.
        assert_eq!(
            mock.recorded_lines(),
            [
                format!("test -e {CONFIG}"),
                // The staging file is created at 600 before the key is written
                // into it, so the key never exists at the umask's mode even for
                // the round-trip the chmod below takes.
                format!("install -m 600 /dev/null {CONFIG}{STAGING_SUFFIX}"),
                format!("tee {CONFIG}{STAGING_SUFFIX}"),
                format!("stat -c %a {CONFIG}"),
                format!("chmod 600 {CONFIG}{STAGING_SUFFIX}"),
                format!("mv {CONFIG}{STAGING_SUFFIX} {CONFIG}"),
            ]
        );
    }

    #[test]
    fn an_uncopied_write_to_a_new_file_asks_for_no_mode_to_preserve() {
        // The edge the `keep_mode` flag exists for. `write` keys the mode
        // branch on a backup having been taken, which this path never does, so
        // it keys it on the file existing instead — and a file that does not
        // exist has no mode to read. `stat` on a missing path fails, so asking
        // anyway would turn creating a file into an error.
        let mock = MockExecutor::with_replies([
            Reply::failure(1, "No such file or directory"), // test -e
            Reply::ok(""),                                  // install (staging)
            Reply::ok(""),                                  // tee (staging)
            Reply::ok(""),                                  // chmod (the default)
            Reply::ok(""),                                  // mv
        ]);

        UnixFiles::new()
            .write_uncopied(&mock, CONFIG, "[Interface]\n")
            .expect("creating a file must work");

        assert_eq!(
            mock.recorded_lines(),
            [
                format!("test -e {CONFIG}"),
                format!("install -m 600 /dev/null {CONFIG}{STAGING_SUFFIX}"),
                format!("tee {CONFIG}{STAGING_SUFFIX}"),
                // 644 outright, not `stat` on a path that is not there. The
                // staging file's own 600 is deliberately too narrow to keep.
                format!("chmod 644 {CONFIG}{STAGING_SUFFIX}"),
                format!("mv {CONFIG}{STAGING_SUFFIX} {CONFIG}"),
            ],
            "a file that does not exist yet has no mode to carry over"
        );
    }

    #[test]
    fn the_target_is_never_the_file_being_written_to() {
        // `tee` truncates and then writes, so a process that dies between the
        // two leaves the target empty or half a file — a third state neither
        // the change nor the backup describes, on a file that decides whether
        // anyone can log in. A rename within a directory is atomic: a reader
        // sees the old file or the new one.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("644"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        UnixFiles::new()
            .write(&mock, CONFIG, "Port 2222\n")
            .expect("write must work");

        let written_to = mock
            .recorded()
            .into_iter()
            .find(|command| command.program == "tee")
            .map(|command| command.args.join(" "))
            .expect("tee must have run");

        assert_ne!(
            written_to, CONFIG,
            "the live file must never be the one truncated"
        );

        assert!(
            written_to.starts_with(CONFIG),
            "and the staging file must sit beside it, or the rename crosses a \
             filesystem and stops being atomic: {written_to}"
        );
    }

    #[test]
    fn an_existing_files_mode_survives_being_rewritten() {
        // Moving a staging file over a 0600 file must not publish it at the
        // staging mode. Read with `stat -c` and applied with `chmod` rather
        // than in one step: `chmod --reference` and `cp --preserve=mode` are
        // GNU extensions, and both fail on busybox — measured on alpine:3.23.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("600\n"),
            Reply::ok(""),
            Reply::ok(""),
        ]);

        UnixFiles::new()
            .write(&mock, CONFIG, "secret\n")
            .expect("write must work");

        let lines = mock.recorded_lines();
        let chmod = lines
            .iter()
            .position(|line| line.starts_with("chmod"))
            .expect("the mode must be applied");
        let moved = lines
            .iter()
            .position(|line| line.starts_with("mv"))
            .expect("the file must be moved into place");

        assert_eq!(
            lines[chmod],
            format!("chmod 600 {CONFIG}{STAGING_SUFFIX}"),
            "the original's own mode, not a default"
        );

        assert!(
            chmod < moved,
            "the mode goes on before the file is visible, never after: {lines:?}"
        );
    }

    #[test]
    fn write_skips_the_backup_for_a_new_file() {
        let mock = MockExecutor::with_replies([Reply::failure(1, ""), Reply::ok("")]);

        let backup = UnixFiles::new()
            .write(&mock, "/etc/new.conf", "data")
            .expect("write must work");

        assert!(backup.is_none(), "a new file has nothing to back up");
    }

    #[test]
    fn write_passes_contents_on_stdin_never_as_an_argument() {
        // The security property: file contents must not be interpolated into
        // a command line where they would need escaping.
        let contents = "Port 22\n# a \"quoted\" $(injection) attempt\n";
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""), // test -e: a new file
            Reply::ok(""),         // tee (staging)
            Reply::ok(""),         // mv
        ]);

        UnixFiles::new()
            .write(&mock, CONFIG, contents)
            .expect("write must work");

        let tee = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .expect("tee must have run");

        assert_eq!(tee.stdin.as_deref(), Some(contents));
        assert_eq!(
            tee.args,
            [format!("{CONFIG}{STAGING_SUFFIX}")],
            "contents must not appear in arguments"
        );
    }

    #[test]
    fn restore_copies_the_backup_back() {
        let mock = MockExecutor::new();
        let backup = Backup {
            original: CONFIG.to_owned(),
            copy: format!("{CONFIG}{BACKUP_SUFFIX}"),
        };

        UnixFiles::new()
            .restore(&mock, &backup)
            .expect("restore must work");

        assert_eq!(
            mock.recorded_lines(),
            [format!("cp -p {CONFIG}{BACKUP_SUFFIX} {CONFIG}")]
        );
    }

    #[test]
    fn set_mode_renders_the_mode_in_octal() {
        let mock = MockExecutor::new();

        UnixFiles::new()
            .set_mode(&mock, "/root/.ssh/authorized_keys", 0o600)
            .expect("chmod must work");

        assert_eq!(
            mock.recorded_lines(),
            ["chmod 600 /root/.ssh/authorized_keys"]
        );
    }

    #[test]
    fn create_dir_applies_the_mode_atomically() {
        let mock = MockExecutor::new();

        UnixFiles::new()
            .create_dir(&mock, "/root/.ssh", 0o700)
            .expect("install must work");

        assert_eq!(mock.recorded_lines(), ["install -d -m 700 /root/.ssh"]);
    }

    #[test]
    fn every_file_operation_requests_privileges() {
        // Files under /etc are not writable by an ordinary user; forgetting
        // this flag would make every operation fail at runtime.
        let mock = MockExecutor::new();
        let files = UnixFiles::new();

        files.set_mode(&mock, CONFIG, 0o600).expect("runs");
        files.create_dir(&mock, "/etc/ssh", 0o755).expect("runs");

        assert!(mock.recorded().iter().all(|cmd| cmd.needs_root));
    }
}
