//! POSIX implementation of [`FileEditor`].
//!
//! Shared by every family: `cat`, `tee`, `cp`, `chmod`, `install` and `chown`
//! behave the same everywhere `initd` runs, and all are resolved through
//! `PATH` rather than by absolute location.

use super::systemd::run_checked;
use crate::domain::files::{Backup, FileEditor};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Suffix appended to backup copies.
///
/// Fixed rather than timestamped so a repeated operation overwrites its own
/// backup instead of littering `/etc` with copies. The value that matters is
/// the state before the current change.
const BACKUP_SUFFIX: &str = ".initd.bak";

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
}

impl FileEditor for UnixFiles {
    fn read(&self, executor: &dyn Executor, path: &str) -> Result<String> {
        // Reading is privileged: sshd_config is mode 600 on some systems.
        let command = Command::new("cat").arg(path).privileged();
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::CommandFailed {
                command: command.to_string(),
                code: output.code,
                stderr: output.stderr,
            });
        }

        Ok(output.stdout)
    }

    fn exists(&self, executor: &dyn Executor, path: &str) -> Result<bool> {
        // `test -e` exits non-zero for "no", which is an answer rather than a
        // failure, so the exit code is read instead of checked.
        let command = Command::new("test").args(["-e", path]).privileged();

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

        // Contents travel on stdin, never as an argument: an argument would
        // need shell escaping, and a flaw in that escaping is a root-level
        // command injection.
        let command = Command::new("tee").arg(path).privileged().stdin(contents);

        run_checked(executor, &command)?;

        Ok(backup)
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

    fn set_owner(&self, executor: &dyn Executor, path: &str, owner: &str) -> Result<()> {
        let command = Command::new("chown")
            .args([&format!("{owner}:{owner}"), path])
            .privileged();

        run_checked(executor, &command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

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
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok(""), Reply::ok("")]);

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
                format!("tee {CONFIG}"),
            ]
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
        let mock = MockExecutor::with_replies([Reply::failure(1, ""), Reply::ok("")]);

        UnixFiles::new()
            .write(&mock, CONFIG, contents)
            .expect("write must work");

        let tee = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .expect("tee must have run");

        assert_eq!(tee.stdin.as_deref(), Some(contents));
        assert_eq!(tee.args, [CONFIG], "contents must not appear in arguments");
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
        files.set_owner(&mock, CONFIG, "root").expect("runs");

        assert!(mock.recorded().iter().all(|cmd| cmd.needs_root));
    }
}
