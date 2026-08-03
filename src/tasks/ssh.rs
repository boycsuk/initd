//! SSH administration tasks.
//!
//! Not one of these tasks knows which distribution it runs on. Package names,
//! unit names and command syntax all arrive through the backend — that is the
//! property this whole design exists to provide.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::error::{Error, Result};
use crate::exec::{Executor, OutputLine, Stream};
use crate::tasks::sshd_config::{self, SSHD_CONFIG};
use crate::tasks::{Category, Node, Progress, Task};

/// Families every SSH task supports.
const SUPPORTED: &[Family] = &[Family::Debian, Family::Arch];

/// Where a user's authorised keys live, relative to their home directory.
const AUTHORIZED_KEYS_RELATIVE: &str = ".ssh/authorized_keys";

/// Mode SSH requires on `~/.ssh`; anything looser makes sshd ignore the keys.
const SSH_DIR_MODE: u32 = 0o700;

/// Mode SSH requires on `authorized_keys`.
const AUTHORIZED_KEYS_MODE: u32 = 0o600;

/// Key types `initd` accepts in an `authorized_keys` entry.
const VALID_KEY_PREFIXES: [&str; 5] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

/// Default port offered when none is given.
const DEFAULT_SSH_PORT: u32 = 22;

/// Builds the SSH category, subdivided by what each task acts on.
///
/// The area owns its own subdivision so that `tasks::tree()` stays a flat list
/// of areas. Parameterised tasks appear with placeholder values so the tree can
/// list them; the CLI and the TUI construct them with real arguments before
/// running.
pub fn category() -> Category {
    Category::new(
        "SSH",
        vec![
            Node::Category(Category::new(
                "Service",
                vec![Node::Task(Box::new(InstallSsh))],
            )),
            Node::Category(Category::new(
                "Configuration",
                vec![
                    Node::Task(Box::new(HardenSsh)),
                    Node::Task(Box::new(ChangePort {
                        port: DEFAULT_SSH_PORT,
                    })),
                ],
            )),
            Node::Category(Category::new(
                "Keys",
                vec![Node::Task(Box::new(AuthorizeKey {
                    user: "root".to_owned(),
                    key: String::new(),
                }))],
            )),
        ],
    )
}

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Installs the OpenSSH server and enables it at boot.
pub struct InstallSsh;

impl Task for InstallSsh {
    fn id(&self) -> &'static str {
        "ssh.install"
    }

    fn title(&self) -> &'static str {
        "Install and enable the SSH server"
    }

    fn description(&self) -> &'static str {
        "Installs the OpenSSH server package and enables its service so it \
         starts at boot."
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        progress: Progress<'_>,
    ) -> Result<()> {
        // The task asks for a capability; the backend knows the names.
        let package = backend.package_for(Capability::Ssh);
        let service = backend.service_for(Capability::Ssh);

        if backend.packages().is_installed(executor, package)? {
            report(progress, format!("{package} is already installed"));
        } else {
            report(progress, format!("Installing {package}..."));
            backend.packages().install(executor, package)?;
        }

        report(progress, format!("Enabling {service}..."));
        backend.services().enable_and_start(executor, service)?;

        let state = backend.services().state(executor, service)?;
        report(
            progress,
            format!(
                "{service}: {}, {}",
                if state.active { "active" } else { "inactive" },
                if state.enabled { "enabled" } else { "disabled" }
            ),
        );

        Ok(())
    }
}

/// Disables root login and password authentication.
///
/// Destructive: applied to a server the administrator reaches over SSH without
/// a working key, it locks them out. The task refuses to disable password
/// authentication when no authorised key exists.
pub struct HardenSsh;

impl Task for HardenSsh {
    fn id(&self) -> &'static str {
        "ssh.harden"
    }

    fn title(&self) -> &'static str {
        "Harden the SSH configuration"
    }

    fn description(&self) -> &'static str {
        "Disables root login and password authentication, keeping a backup of \
         the previous configuration. Requires an authorised key to be in place."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        progress: Progress<'_>,
    ) -> Result<()> {
        let files = backend.files();
        let contents = files.read(executor, SSHD_CONFIG)?;

        // Disabling password authentication without a key in place is the
        // documented way administrators lock themselves out of a server.
        if !has_any_authorized_key(executor, backend)? {
            return Err(Error::InvalidSshdConfig {
                details: "no authorised key found for root; disabling password \
                          authentication now would lock you out. Add a key with \
                          `ssh.authorize-key` first."
                    .to_owned(),
            });
        }

        report(
            progress,
            "Disabling root login and password authentication...",
        );

        let hardened = [
            ("PermitRootLogin", "no"),
            ("PasswordAuthentication", "no"),
            ("ChallengeResponseAuthentication", "no"),
            ("PubkeyAuthentication", "yes"),
        ]
        .into_iter()
        .fold(contents, |acc, (directive, value)| {
            sshd_config::set_directive(&acc, directive, value)
        });

        let backup = sshd_config::write_validated(executor, backend, &hardened)?;

        if let Some(backup) = backup {
            report(
                progress,
                format!("Previous configuration saved to {}", backup.copy),
            );
        }

        reload_ssh(executor, backend, progress)
    }
}

/// Adds a public key to a user's `authorized_keys`.
pub struct AuthorizeKey {
    pub user: String,
    pub key: String,
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

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        progress: Progress<'_>,
    ) -> Result<()> {
        let key = self.key.trim();
        is_valid_public_key(key)?;

        let files = backend.files();
        let home = home_dir(&self.user);
        let ssh_dir = format!("{home}/.ssh");
        let path = format!("{home}/{AUTHORIZED_KEYS_RELATIVE}");

        // sshd silently ignores authorized_keys when the directory or file is
        // group- or world-accessible, so the modes are part of the operation
        // rather than an afterthought.
        files.create_dir(executor, &ssh_dir, SSH_DIR_MODE)?;
        files.set_owner(executor, &ssh_dir, &self.user)?;

        let existing = if files.exists(executor, &path)? {
            files.read(executor, &path)?
        } else {
            String::new()
        };

        if key_is_present(&existing, key) {
            report(progress, "The key is already authorised; nothing to do");
            return Ok(());
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

        files.write(executor, &path, &updated)?;
        files.set_mode(executor, &path, AUTHORIZED_KEYS_MODE)?;
        files.set_owner(executor, &path, &self.user)?;

        report(progress, "Key authorised");

        Ok(())
    }
}

/// Home directory of a user.
///
/// Root is the documented exception to `/home/<name>`.
fn home_dir(user: &str) -> String {
    if user == "root" {
        "/root".to_owned()
    } else {
        format!("/home/{user}")
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

/// Changes the port sshd listens on.
pub struct ChangePort {
    pub port: u32,
}

impl Task for ChangePort {
    fn id(&self) -> &'static str {
        "ssh.change-port"
    }

    fn title(&self) -> &'static str {
        "Change the SSH port"
    }

    fn description(&self) -> &'static str {
        "Changes the port sshd listens on, keeping a backup and validating \
         before reloading. The new port may also need firewall or SELinux \
         configuration."
    }

    fn is_destructive(&self) -> bool {
        true
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        progress: Progress<'_>,
    ) -> Result<()> {
        if self.port == 0 || self.port > 65535 {
            return Err(Error::InvalidPort { port: self.port });
        }

        let files = backend.files();
        let contents = files.read(executor, SSHD_CONFIG)?;

        // An unset Port directive means sshd is on its default of 22.
        let current = sshd_config::directive_value(&contents, "Port")
            .unwrap_or_else(|| DEFAULT_SSH_PORT.to_string());

        if current == self.port.to_string() {
            report(
                progress,
                format!("The port is already {current}; nothing to do"),
            );
            return Ok(());
        }

        let updated = sshd_config::set_directive(&contents, "Port", &self.port.to_string());

        report(
            progress,
            format!("Changing the port from {current} to {}...", self.port),
        );
        sshd_config::write_validated(executor, backend, &updated)?;

        // Debian ships ssh.socket alongside ssh.service. When it is active the
        // socket owns the listening port, so editing sshd_config alone changes
        // nothing. Detect and warn rather than silently reconfiguring units.
        warn_if_socket_activated(executor, backend, progress)?;

        report(
            progress,
            format!(
                "Port set to {}. If a firewall or SELinux is active, the new \
                 port may need to be opened before it can be reached.",
                self.port
            ),
        );

        reload_ssh(executor, backend, progress)
    }
}

/// Warns when socket activation would override the configured port.
fn warn_if_socket_activated(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    const SSH_SOCKET: &str = "ssh.socket";

    let state = backend.services().state(executor, SSH_SOCKET)?;

    if state.active || state.enabled {
        progress(OutputLine {
            stream: Stream::Stderr,
            text: format!(
                "warning: {SSH_SOCKET} is active and defines the listening port \
                 itself. The port in sshd_config will not take effect until the \
                 socket unit is reconfigured or disabled."
            ),
        });
    }

    Ok(())
}

/// Whether root has at least one authorised key.
///
/// Read through the file editor rather than `std::fs` so it works under
/// privilege escalation, and so a missing file is a plain `false`.
fn has_any_authorized_key(executor: &dyn Executor, backend: &dyn Backend) -> Result<bool> {
    let path = format!("/root/{AUTHORIZED_KEYS_RELATIVE}");

    if !backend.files().exists(executor, &path)? {
        return Ok(false);
    }

    let contents = backend.files().read(executor, &path)?;

    Ok(contents
        .lines()
        .any(|line| is_valid_public_key(line.trim()).is_ok()))
}

/// Reloads SSH so a new configuration takes effect.
///
/// Reload rather than restart: restarting drops the very session the
/// administrator is connected through.
fn reload_ssh(
    executor: &dyn Executor,
    backend: &dyn Backend,
    progress: Progress<'_>,
) -> Result<()> {
    let service = backend.service_for(Capability::Ssh);

    report(progress, format!("Reloading {service}..."));
    backend.services().reload(executor, service)
}

/// Validates the shape of an `authorized_keys` entry.
///
/// Only structural validation: type prefix plus a base64-looking body. Full
/// cryptographic verification is `ssh-keygen`'s job, and a malformed key would
/// make sshd ignore the whole file.
fn is_valid_public_key(line: &str) -> Result<()> {
    let invalid = |reason: &str| Error::InvalidPublicKey {
        reason: reason.to_owned(),
    };

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
    use crate::exec::mock::{MockExecutor, Reply};

    /// Runs the task against a mock, returning the commands it issued.
    fn run_install(family: Family, replies: Vec<Reply>) -> Vec<String> {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);

        InstallSsh
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect("install must succeed");

        mock.recorded_lines()
    }

    #[test]
    fn uses_debian_names_on_debian() {
        // First reply: package not installed, so an install follows.
        let commands = run_install(Family::Debian, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("apt-get install -y openssh-server")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now ssh.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn uses_arch_names_on_arch() {
        let commands = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert!(
            commands
                .iter()
                .any(|c| c.contains("pacman -S") && c.contains("openssh")),
            "got: {commands:?}"
        );
        assert!(
            commands
                .iter()
                .any(|c| c == "systemctl enable --now sshd.service"),
            "got: {commands:?}"
        );
    }

    #[test]
    fn the_same_task_produces_different_commands_per_family() {
        // The core claim of the design: identical task code, distro-correct
        // commands, with the package and the unit diverging independently.
        let debian = run_install(Family::Debian, vec![Reply::failure(1, "")]);
        let arch = run_install(Family::Arch, vec![Reply::failure(1, "")]);

        assert_ne!(debian, arch);
    }

    #[test]
    fn skips_installation_when_the_package_is_present() {
        // First reply reports the package as installed.
        let commands = run_install(Family::Debian, vec![Reply::ok("install ok installed")]);

        assert!(
            !commands.iter().any(|c| c.contains("apt-get install")),
            "an installed package must not be reinstalled: {commands:?}"
        );
        assert!(
            commands.iter().any(|c| c.contains("systemctl enable")),
            "the service must still be enabled: {commands:?}"
        );
    }

    #[test]
    fn a_failing_install_propagates() {
        let mock = MockExecutor::with_replies([
            Reply::failure(1, ""),
            Reply::failure(100, "E: Unable to locate package"),
        ]);
        let backend = for_family(Family::Debian);

        let err = InstallSsh
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect_err("a failing install must surface");

        assert!(
            matches!(err, crate::error::Error::CommandFailed { code: 100, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn reports_progress_to_the_caller() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        InstallSsh
            .run(&mock, backend.as_ref(), &mut |line| lines.push(line.text))
            .expect("install must succeed");

        assert!(!lines.is_empty(), "the task must report what it is doing");
    }

    #[test]
    fn supports_both_families() {
        assert!(InstallSsh.supports(Family::Debian));
        assert!(InstallSsh.supports(Family::Arch));
    }

    /// A valid ed25519 key body, long enough to pass structural validation.
    const TEST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKj8VQqPmVxOKGVkGYhAaKcHVDkPAeSlZLnQFDKmvXYZ user@host";

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
    fn hardening_refuses_without_an_authorised_key() {
        // The lockout guard: disabling passwords with no key stranded the
        // administrator outside the server.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::failure(1, ""),  // authorized_keys does not exist
        ]);
        let backend = for_family(Family::Debian);

        let err = HardenSsh
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect_err("hardening without a key must refuse");

        assert!(matches!(err, Error::InvalidSshdConfig { .. }), "{err:?}");
        assert!(
            !mock.recorded_lines().iter().any(|c| c.starts_with("tee")),
            "nothing may be written when the guard trips"
        );
    }

    #[test]
    fn hardening_disables_root_login_and_passwords() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read sshd_config
            Reply::ok(""),          // authorized_keys exists
            Reply::ok(TEST_KEY),    // it contains a valid key
            Reply::ok(""),          // test -e for the write
            Reply::ok(""),          // cp backup
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::ok(""),          // systemctl reload
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect("hardening must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("PermitRootLogin no"));
        assert!(written.contains("PasswordAuthentication no"));
    }

    #[test]
    fn hardening_reloads_rather_than_restarts() {
        // Restarting would drop the administrator's own session.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(""),
            Reply::ok(TEST_KEY),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        HardenSsh
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect("hardening must succeed");

        let commands = mock.recorded_lines();
        assert!(commands.iter().any(|c| c.contains("systemctl reload")));
        assert!(!commands.iter().any(|c| c.contains("systemctl restart")));
    }

    #[test]
    fn authorising_a_key_sets_the_permissions_sshd_requires() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),         // install -d
            Reply::ok(""),         // chown dir
            Reply::failure(1, ""), // authorized_keys absent
            Reply::ok(""),         // test -e inside write
            Reply::ok(""),         // tee
            Reply::ok(""),         // chmod
            Reply::ok(""),         // chown file
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey {
            user: "root".to_owned(),
            key: TEST_KEY.to_owned(),
        }
        .run(&mock, backend.as_ref(), &mut |_| {})
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
    fn authorising_the_same_key_twice_does_not_duplicate_it() {
        let mock = MockExecutor::with_replies([
            Reply::ok(""),       // install -d
            Reply::ok(""),       // chown
            Reply::ok(""),       // authorized_keys exists
            Reply::ok(TEST_KEY), // and already holds the key
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey {
            user: "root".to_owned(),
            key: TEST_KEY.to_owned(),
        }
        .run(&mock, backend.as_ref(), &mut |_| {})
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
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(existing),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);

        AuthorizeKey {
            user: "root".to_owned(),
            key: TEST_KEY.to_owned(),
        }
        .run(&mock, backend.as_ref(), &mut |_| {})
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

        let err = AuthorizeKey {
            user: "root".to_owned(),
            key: "definitely not a key".to_owned(),
        }
        .run(&mock, backend.as_ref(), &mut |_| {})
        .expect_err("an invalid key must be rejected");

        assert!(matches!(err, Error::InvalidPublicKey { .. }), "{err:?}");
        assert!(
            mock.recorded().is_empty(),
            "validation must happen before any command runs"
        );
    }

    #[test]
    fn changing_the_port_writes_and_validates() {
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"), // read
            Reply::ok(""),          // test -e
            Reply::ok(""),          // cp
            Reply::ok(""),          // tee
            Reply::ok(""),          // sshd -t
            Reply::failure(3, ""),  // ssh.socket is-active
            Reply::failure(1, ""),  // ssh.socket is-enabled
            Reply::ok(""),          // reload
        ]);
        let backend = for_family(Family::Debian);

        ChangePort { port: 2222 }
            .run(&mock, backend.as_ref(), &mut |_| {})
            .expect("changing the port must succeed");

        let written = mock
            .recorded()
            .into_iter()
            .find(|cmd| cmd.program == "tee")
            .and_then(|cmd| cmd.stdin)
            .expect("the config must be written");

        assert!(written.contains("Port 2222"));
    }

    #[test]
    fn changing_the_port_rejects_out_of_range_values() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        for port in [0, 70_000] {
            let err = ChangePort { port }
                .run(&mock, backend.as_ref(), &mut |_| {})
                .expect_err("an out-of-range port must be rejected");

            assert!(matches!(err, Error::InvalidPort { .. }), "{err:?}");
        }
    }

    #[test]
    fn changing_the_port_warns_when_socket_activation_is_in_play() {
        // Debian's ssh.socket owns the port; editing sshd_config alone would
        // silently do nothing.
        let mock = MockExecutor::with_replies([
            Reply::ok("Port 22\n"),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok(""),
            Reply::ok("active\n"), // ssh.socket is active
            Reply::ok("enabled\n"),
            Reply::ok(""),
        ]);
        let backend = for_family(Family::Debian);
        let mut warnings = Vec::new();

        ChangePort { port: 2222 }
            .run(&mock, backend.as_ref(), &mut |line| {
                if line.stream == Stream::Stderr {
                    warnings.push(line.text);
                }
            })
            .expect("changing the port must succeed");

        assert!(
            warnings.iter().any(|w| w.contains("ssh.socket")),
            "socket activation must be reported: {warnings:?}"
        );
    }

    #[test]
    fn destructive_tasks_are_marked_as_such() {
        // The TUI gates these behind a confirmation prompt.
        assert!(HardenSsh.is_destructive());
        assert!(ChangePort { port: 22 }.is_destructive());
        assert!(!InstallSsh.is_destructive());
    }
}
