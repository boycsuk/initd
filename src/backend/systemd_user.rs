//! systemd implementation of [`UserServiceManager`].
//!
//! Shared by every systemd family. Alpine's OpenRC has no per-user service
//! manager at all, which is why this is behind a trait: rootless Docker there
//! needs a different mechanism entirely rather than a different command.

use super::systemd::run_checked;
use crate::domain::user_services::UserServiceManager;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// The variable `systemctl --user` finds the account's bus through.
///
/// Set by `pam_systemd` when a session is registered — and *not* set when it is
/// not, which used to be read here as proof the account had no service manager.
/// It is not proof: see [`SystemdUserServices::as_user`], which now supplies
/// this rather than depending on PAM having exported it.
const RUNTIME_DIR: &str = "XDG_RUNTIME_DIR";

/// Manages a user's own services through `systemctl --user`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemdUserServices;

impl SystemdUserServices {
    pub const fn new() -> Self {
        Self
    }

    /// A command run as the given account, against its own service manager.
    ///
    /// `machinectl shell` is deliberately not used, and neither is a bare
    /// `su`: `systemctl --user` needs `XDG_RUNTIME_DIR` to point at the
    /// account's own runtime directory, and a shell that inherits root's
    /// environment addresses root's service manager while appearing to
    /// address the user's. `runuser -l` sets up the session properly.
    /// `XDG_RUNTIME_DIR` is supplied rather than relied on, which is the part
    /// that had to be learned from a live host. `runuser -l` exports it only if
    /// PAM registers a session, and Debian's `/etc/pam.d/runuser-l` declares
    /// that module as `-session optional pam_systemd.so` — the leading `-`
    /// meaning "ignore silently if it will not load" and `optional` meaning
    /// "carry on if it fails". So the variable may simply not appear, on a host
    /// where the account plainly *has* a service manager.
    ///
    /// Reported from a Debian 13 server where `/run/user/1000` existed and
    /// `systemd-logind` was active, yet `runuser -l deploy -c 'printenv
    /// XDG_RUNTIME_DIR'` printed nothing and exited 1. Reproduced by commenting
    /// that one PAM line out, and the setup then worked once the variable was
    /// given: `systemctl --user` answered `running`.
    ///
    /// Computed with `id -u` inside the command rather than resolved here,
    /// because the trait is handed a name and a uid lookup of its own would be
    /// a second way to get the same answer. `${XDG_RUNTIME_DIR:-...}` so a
    /// session that *did* register keeps whatever it was given — this fills a
    /// gap rather than overriding a working environment.
    fn as_user(user: &str, args: &[&str]) -> Command {
        let script = format!(
            "export {RUNTIME_DIR}=\"${{{RUNTIME_DIR}:-/run/user/$(id -u)}}\"; {}",
            args.join(" ")
        );

        Command::new("runuser")
            .args(["-l", user, "-c", &script])
            .privileged()
    }
}

impl UserServiceManager for SystemdUserServices {
    fn session_is_reachable(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // Asks the service manager whether it answers, rather than asking
        // whether a variable is set. That distinction cost a real host: this
        // used to run `printenv XDG_RUNTIME_DIR` and refuse on an empty answer,
        // and Debian's `runuser -l` may not export it even where the account
        // has a perfectly good user manager — see [`Self::as_user`] for the PAM
        // line that decides it. The environment was a proxy for the question,
        // and on that host the proxy was wrong.
        //
        // `is-system-running` because it needs the bus and reports through the
        // exit code. Its *value* is deliberately not read: `degraded` means
        // some unit failed, which says nothing about whether this tool can
        // reach the manager, and refusing on it would turn one failed user unit
        // into a refusal to install another.
        let command = Self::as_user(user, &["systemctl", "--user", "is-system-running"]);

        match executor.run(&command) {
            Ok(output) => Ok(output.success() || output.stdout.trim() == "degraded"),
            // An unreachable bus is the answer this exists to give, not a
            // failure to obtain one.
            Err(Error::CommandFailed { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    fn is_lingering(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        let command = Command::new("loginctl").args(["show-user", user, "--property=Linger"]);
        let output = executor.run(&command)?;

        if !output.success() {
            // An account that has never logged in has no entry, which means it
            // is not lingering rather than that the question failed.
            return Ok(false);
        }

        // Compared whole rather than by substring: `Linger=no` contains `no`
        // and `Linger=yes` contains neither more nor less usefully, but a
        // careless `contains("yes")` would also match a future property.
        Ok(output.stdout.trim() == "Linger=yes")
    }

    fn enable_linger(&self, executor: &dyn Executor, user: &str) -> Result<()> {
        let command = Command::new("loginctl")
            .args(["enable-linger", user])
            .privileged();

        run_checked(executor, &command)
    }

    fn enable_and_start(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<()> {
        let command = Self::as_user(user, &["systemctl", "--user", "enable", "--now", service]);

        run_checked(executor, &command)
    }

    fn disable_and_stop(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<()> {
        let command = Self::as_user(user, &["systemctl", "--user", "disable", "--now", service]);
        let output = executor.run(&command)?;

        if output.success() {
            return Ok(());
        }

        // Absent is the state being asked for, told apart from a refusal by
        // systemd's own wording because `disable` overloads exit code 1 for
        // both. The same rescue the system-wide manager makes, for the same
        // reason: an uninstall that removed the engine took its unit with it.
        if super::systemd::unit_is_absent(&output.stderr) {
            return Ok(());
        }

        Err(Error::CommandFailed {
            command: command.to_string(),
            code: output.code,
            stderr: output.stderr,
        })
    }

    fn disable_linger(&self, executor: &dyn Executor, user: &str) -> Result<()> {
        let command = Command::new("loginctl")
            .args(["disable-linger", user])
            .privileged();

        run_checked(executor, &command)
    }

    fn is_active(&self, executor: &dyn Executor, user: &str, service: &str) -> Result<bool> {
        let command = Self::as_user(user, &["systemctl", "--user", "is-active", service]);
        let output = executor.run(&command)?;

        // Compared whole, not by substring: `is-active` answers `inactive` for
        // a unit that does not exist, and `inactive` contains `active`. This
        // project has already been caught by exactly that.
        Ok(output.stdout.trim() == "active")
    }

    fn has_subordinate_ids(&self, executor: &dyn Executor, user: &str) -> Result<bool> {
        // Both files must name the account: a UID range without a matching GID
        // range gives a container engine that starts and cannot map groups.
        for file in ["/etc/subuid", "/etc/subgid"] {
            let command = Command::new("grep").args(["-q", &format!("^{user}:"), file]);

            if !executor.run(&command)?.success() {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    #[test]
    fn a_session_that_pam_did_not_register_is_still_reachable() {
        // Reported from a Debian 13 server, and the reason this check no longer
        // asks about an environment variable. `/run/user/1000` existed and
        // `systemd-logind` was active, yet `runuser -l deploy -c 'printenv
        // XDG_RUNTIME_DIR'` printed nothing: Debian declares the module that
        // would have set it as `-session optional pam_systemd.so` in
        // `/etc/pam.d/runuser-l`, which may do nothing and say nothing.
        //
        // So the account had a service manager and the task refused to use it.
        // Reproduced by commenting that line out in a container, where
        // `systemctl --user` then answered `running` once the variable was
        // supplied.
        let mock = MockExecutor::with_replies([Reply::ok("running\n")]);

        assert!(
            SystemdUserServices::new()
                .session_is_reachable(&mock, "deploy")
                .expect("a manager that answers must be reachable")
        );

        let asked = mock.single_command().to_string();

        assert!(
            asked.contains("systemctl --user is-system-running"),
            "the manager must be asked directly: {asked}"
        );
        assert!(
            asked.contains("XDG_RUNTIME_DIR"),
            "and must be given the runtime directory rather than hoping for it: {asked}"
        );
        assert!(
            !asked.contains("printenv"),
            "asking what PAM exported is the defect this replaced: {asked}"
        );
    }

    #[test]
    fn a_degraded_manager_is_still_a_manager() {
        // `is-system-running` exits non-zero for `degraded`, which means some
        // unit failed — a fact about that unit, not about whether this tool can
        // reach the bus. Refusing on it would turn one broken user service into
        // a refusal to install another.
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);

        // The mock returns the value on stdout the way the real command does.
        let degraded = MockExecutor::with_replies([Reply::ok("degraded\n")]);

        assert!(
            SystemdUserServices::new()
                .session_is_reachable(&degraded, "deploy")
                .expect("degraded must not raise")
        );

        // And a genuinely absent manager is still refused, so the allowance
        // above cannot be satisfied by accepting everything.
        assert!(
            !SystemdUserServices::new()
                .session_is_reachable(&mock, "deploy")
                .expect("an unreachable bus is an answer")
        );
    }

    #[test]
    fn an_account_that_never_logged_in_is_not_lingering() {
        // No entry is an answer, not a failure: the account exists and simply
        // has no session record yet.
        let mock = MockExecutor::with_replies([Reply::failure(1, "Failed to get user")]);

        let lingering = SystemdUserServices::new()
            .is_lingering(&mock, "deploy")
            .expect("a missing entry must not raise");

        assert!(!lingering);
    }

    #[test]
    fn an_engine_whose_unit_went_with_its_package_is_not_a_failure() {
        // The uninstall order removes the package, which takes the unit with
        // it. Stopping the service afterwards must not fail at the last step
        // having done everything it was asked.
        let mock = MockExecutor::with_replies([Reply::failure(
            1,
            "Failed to disable unit: Unit file docker.service does not exist.",
        )]);

        SystemdUserServices::new()
            .disable_and_stop(&mock, "deploy", "docker.service")
            .expect("an absent unit is the state that was wanted");
    }

    #[test]
    fn lingering_is_withdrawn_by_its_own_command() {
        // Left behind, linger is an account kept awake for a service that is
        // gone — harmless, and the kind of residue that makes an uninstall
        // untrustworthy.
        let mock = MockExecutor::new();

        SystemdUserServices::new()
            .disable_linger(&mock, "deploy")
            .expect("withdrawing linger must succeed");

        assert_eq!(mock.recorded_lines(), ["loginctl disable-linger deploy"]);
        assert!(mock.any_privileged());
    }

    #[test]
    fn lingering_is_read_from_the_whole_property() {
        let mock = MockExecutor::with_replies([Reply::ok("Linger=yes\n")]);

        assert!(
            SystemdUserServices::new()
                .is_lingering(&mock, "deploy")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn linger_no_is_not_lingering() {
        let mock = MockExecutor::with_replies([Reply::ok("Linger=no\n")]);

        assert!(
            !SystemdUserServices::new()
                .is_lingering(&mock, "deploy")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn an_inactive_service_is_not_active() {
        // `inactive` contains `active`. A substring check here passed against a
        // container where the package had failed to install, which is how this
        // rule got written down in the first place.
        let mock = MockExecutor::with_replies([Reply::ok("inactive\n")]);

        assert!(
            !SystemdUserServices::new()
                .is_active(&mock, "deploy", "docker.service")
                .expect("the query must succeed")
        );
    }

    #[test]
    fn a_users_service_is_addressed_through_a_login_session() {
        // `systemctl --user` needs XDG_RUNTIME_DIR pointing at the account's
        // own runtime directory. A command that inherits root's environment
        // addresses root's manager while appearing to address the user's.
        let mock = MockExecutor::with_replies([Reply::ok("")]);

        SystemdUserServices::new()
            .enable_and_start(&mock, "deploy", "docker.service")
            .expect("enabling must succeed");

        let line = mock.recorded_lines().remove(0);

        assert!(line.starts_with("runuser -l deploy"), "{line}");
        assert!(line.contains("systemctl --user"), "{line}");
    }

    #[test]
    fn both_subordinate_ranges_are_required() {
        // A UID range with no matching GID range gives an engine that starts
        // and cannot map groups.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),         // subuid names the account
            Reply::failure(1, ""), // subgid does not
        ]);

        let has = SystemdUserServices::new()
            .has_subordinate_ids(&mock, "deploy")
            .expect("the query must succeed");

        assert!(!has, "one range without the other is not enough");
    }

    #[test]
    fn a_subordinate_range_is_matched_at_the_start_of_the_line() {
        // `deploy` must not be satisfied by an entry for `deployer`.
        let mock = MockExecutor::with_replies([Reply::ok(""), Reply::ok("")]);

        SystemdUserServices::new()
            .has_subordinate_ids(&mock, "deploy")
            .expect("the query must succeed");

        assert!(
            mock.recorded_lines()[0].contains("^deploy:"),
            "{:?}",
            mock.recorded_lines()
        );
    }
}
