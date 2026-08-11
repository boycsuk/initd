//! `wireguard-tools` implementation of [`WireguardTools`].
//!
//! Shared by every family shipping `wg`, which is both implemented today. The
//! commands are identical; only the package providing them and the unit that
//! brings an interface up differ, and both come from the backend.

use crate::domain::wireguard::{Keypair, WireguardTools};
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};

/// Length of a base64-encoded Curve25519 key.
///
/// Every WireGuard key is 32 bytes, which is 44 base64 characters including
/// the `=` padding. Checked because a key that arrives truncated produces a
/// configuration `wg` accepts at parse time and that no peer can authenticate
/// against — the failure appears as a tunnel that never completes a handshake.
const KEY_LENGTH: usize = 44;

/// Drives WireGuard through `wg`.
#[derive(Debug, Clone, Copy, Default)]
pub struct WgTools;

impl WgTools {
    pub const fn new() -> Self {
        Self
    }

    /// Runs a `wg` subcommand that prints a key, and checks what came back.
    ///
    /// `secret_output` because these two subcommands print the secret itself:
    /// `genkey` a private key, `genpsk` a preshared one. Without it the key
    /// travels to whatever is observing the executor, which under the interface
    /// is the output pane — a transcript that is scrolled, pasted into bug
    /// reports and copied to the clipboard. `public_key_of` below needs no such
    /// marking: its secret goes *in* on stdin, and what it prints is public.
    fn generate(executor: &dyn Executor, subcommand: &str) -> Result<String> {
        let command = Command::new("wg").arg(subcommand).secret_output();
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::CommandFailed {
                command: command.to_string(),
                code: output.code,
                stderr: output.stderr,
            });
        }

        // Only the newline is stripped. Trimming more would eat the `=`
        // padding, and a key short by one character is one no handshake
        // completes against.
        let key = output.stdout.trim_matches(['\n', '\r']).to_owned();

        validate_key(&key)?;

        Ok(key)
    }
}

impl WireguardTools for WgTools {
    fn generate_keypair(&self, executor: &dyn Executor) -> Result<Keypair> {
        let private = Self::generate(executor, "genkey")?;
        let preshared = Self::generate(executor, "genpsk")?;
        let public = self.public_key_of(executor, &private)?;

        Ok(Keypair {
            private,
            public,
            preshared,
        })
    }

    fn public_key_of(&self, executor: &dyn Executor, private: &str) -> Result<String> {
        // The private key goes in on stdin, never as an argument.
        // `/proc/<pid>/cmdline` is readable by every account on the host, so an
        // argument here would publish the key for as long as the process runs.
        let command = Command::new("wg").arg("pubkey").stdin(private.to_owned());
        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::CommandFailed {
                command: command.to_string(),
                code: output.code,
                // The private key was on stdin, so it cannot appear here — but
                // stderr from a key operation is not somewhere to be casual.
                stderr: output.stderr,
            });
        }

        let key = output.stdout.trim_matches(['\n', '\r']).to_owned();

        validate_key(&key)?;

        Ok(key)
    }

    fn is_up(&self, executor: &dyn Executor, interface: &str) -> Result<bool> {
        // `wg show <iface>` exits non-zero when the interface does not exist,
        // which is an answer rather than a failure.
        let command = Command::new("wg").args(["show", interface]).privileged();

        Ok(executor.run(&command)?.success())
    }
}

/// Rejects anything that is not a WireGuard key.
///
/// A truncated key parses and never completes a handshake, so the failure
/// surfaces as a tunnel that silently does not work rather than as an error at
/// the point it was introduced.
pub fn validate_key(key: &str) -> Result<()> {
    if key.len() != KEY_LENGTH {
        return Err(Error::InvalidWireguardKey {
            reason: format!(
                "a key is {KEY_LENGTH} characters, this one is {}",
                key.len()
            ),
        });
    }

    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        return Err(Error::InvalidWireguardKey {
            reason: "a key is base64: letters, digits, +, / and =".to_owned(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::mock::{MockExecutor, Reply};

    /// A syntactically valid key, for tests that do not care which one.
    const KEY: &str = "aGVsbG8gd29ybGQgdGhpcyBpcyA0NCBjaGFycyBrZXk=";

    #[test]
    fn a_private_key_never_becomes_an_argument() {
        // /proc/<pid>/cmdline is world-readable, so an argument would publish
        // the key to every account on the host for the life of the process.
        let mock = MockExecutor::with_replies([Reply::ok(KEY)]);

        WgTools::new()
            .public_key_of(&mock, "cHJpdmF0ZSBrZXkgdGhhdCBtdXN0IG5vdCBsZWFrIQ==")
            .expect("deriving must succeed");

        let command = mock.single_command();

        assert!(
            !command.args.iter().any(|arg| arg.contains("cHJpdmF0")),
            "the private key must not appear in the arguments: {command:?}"
        );
        assert!(command.stdin.is_some(), "it belongs on stdin");
    }

    #[test]
    fn a_truncated_key_is_rejected() {
        // Padding stripped by an over-eager trim produces a key that parses and
        // never completes a handshake — a tunnel that silently does not work.
        let truncated = &KEY[..KEY.len() - 1];

        let err = validate_key(truncated).expect_err("a short key must be refused");

        assert!(matches!(err, Error::InvalidWireguardKey { .. }), "{err:?}");
    }

    #[test]
    fn the_padding_is_not_trimmed_away() {
        // `trim()` would take the trailing `=` off a key that ends in one.
        let mock = MockExecutor::with_replies([Reply::ok(format!("{KEY}\n"))]);

        let key = WgTools::generate(&mock, "genkey").expect("generation must succeed");

        assert!(key.ends_with('='), "the padding must survive: {key}");
        assert_eq!(key.len(), KEY_LENGTH);
    }

    #[test]
    fn a_keypair_carries_a_preshared_key() {
        // Not optional: it costs a line and survives an attacker who records
        // traffic now and breaks the asymmetric exchange later.
        let mock = MockExecutor::with_replies([
            Reply::ok(KEY), // genkey
            Reply::ok(KEY), // genpsk
            Reply::ok(KEY), // pubkey
        ]);

        let keypair = WgTools::new()
            .generate_keypair(&mock)
            .expect("generation must succeed");

        assert_eq!(keypair.preshared.len(), KEY_LENGTH);
        assert!(
            mock.recorded_lines().iter().any(|c| c.contains("genpsk")),
            "{:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn a_key_with_characters_outside_base64_is_rejected() {
        let err = validate_key("aGVsbG8gd29ybGQgdGhpcyBpcyA0NCBjaGFycyBrZXk!")
            .expect_err("a non-base64 key must be refused");

        assert!(matches!(err, Error::InvalidWireguardKey { .. }), "{err:?}");
    }

    #[test]
    fn a_missing_interface_is_an_answer_not_a_failure() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "Unable to access interface")]);

        let up = WgTools::new()
            .is_up(&mock, "wg0")
            .expect("a missing interface must not raise");

        assert!(!up);
    }
}
