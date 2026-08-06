//! Parameters a task collects before it runs.
//!
//! A task that needs a port or a public key declares what it needs rather than
//! being constructed with it. The tree can then offer the task without knowing
//! any values, and whichever interface is driving — the TUI's form, the CLI's
//! arguments — supplies them at the moment the task is run.
//!
//! Validation lives here too, beside the declaration, so a value is checked
//! the same way whether it arrived from a keystroke or an argument.

use std::collections::HashMap;
use std::str::FromStr as _;

use crate::error::{Error, Result};

/// The kind of value a parameter holds.
///
/// The interface uses this to decide how to present a field; the validation is
/// what actually enforces it, since a CLI argument never passes through a
/// keystroke filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A TCP port: 1-65535.
    Port,
    /// A username that must exist on this host.
    Username,
    /// A space-separated list of usernames, as `AllowUsers` takes.
    UsernameList,
    /// An OpenSSH public key, in `authorized_keys` format.
    PublicKey,
    /// An absolute filesystem path, such as a login shell.
    Path,
    /// An IPv4 subnet in CIDR notation, as `10.89.0.0/24`.
    Cidr,
    /// A single IPv4 address.
    Ip,
    /// An `address:port` a peer dials.
    Endpoint,
    /// A release version, as `0.44.0`.
    Version,
    /// A transport protocol: `tcp` or `udp`.
    ///
    /// A closed choice rather than free text, because the two are not
    /// interchangeable and a typo would open the wrong one silently — a `tcp`
    /// rule admits nothing for WireGuard.
    Protocol,
}

/// Characters that would change the meaning of the line a value is written
/// into.
///
/// Rejected for every value that reaches `sshd_config` verbatim: directives
/// are written with `format!("{directive} {value}")` and nothing escapes them,
/// so a newline would append a directive of the operator's choosing to a file
/// this tool edits as root. `#` would comment out the remainder of the line.
const CONFIG_UNSAFE: [char; 3] = ['\n', '\r', '#'];

/// Where the values a field can be filled from come from.
///
/// Named here and resolved elsewhere, deliberately. `ParamKind` validates a
/// string against a rule and touches nothing; reading `/etc/passwd` or
/// `/etc/shells` needs an [`crate::exec::Executor`], which would put the whole
/// backend behind a type whose job is to compare text. So this says *which*
/// question to ask and the interface, which holds the executor, asks it when
/// it opens the form.
///
/// Declared per parameter rather than derived from its [`ParamKind`], which is
/// where this started and was wrong. A kind describes the *shape* of a value;
/// what the host can offer for it depends on the value's *relation to the
/// system*, and the two come apart in both directions:
///
/// - `users.create` collects a username that must **not** exist. Offering the
///   accounts on the host there suggests exactly the values guaranteed to
///   fail — the tool refuses each one with "account exists".
/// - `wireguard.add-peer` collects a peer *label* that is validated as a
///   username because the character rules suit it. It is not an account, and
///   the host has nothing to say about it.
///
/// Both are `ParamKind::Username`, and neither wants what the third one does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suggestions {
    /// The accounts defined on this host.
    Accounts,
    /// The login shells `/etc/shells` admits.
    Shells,
}

impl ParamKind {
    /// Whether a character can appear in a value of this kind.
    ///
    /// Used to reject keystrokes that could not lead anywhere — digits only in
    /// a port field. It is a convenience, never the validation: a value that
    /// passes this can still be wrong, and [`ParamKind::validate`] is what
    /// decides.
    pub fn accepts(self, character: char) -> bool {
        match self {
            Self::Port => character.is_ascii_digit(),
            // A key is pasted far more often than typed, and its base64 body
            // and comment between them admit almost anything printable. A list
            // of usernames needs the space that separates its entries.
            Self::Username | Self::UsernameList | Self::PublicKey | Self::Path => {
                !character.is_control()
            }
            Self::Protocol => character.is_ascii_alphabetic(),
            Self::Version => character.is_ascii_digit() || character == '.',
            // Hostnames are admitted in an endpoint, so letters and `-` too.
            Self::Cidr | Self::Ip | Self::Endpoint => {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '/' | ':' | '-')
            }
        }
    }

    /// Checks a complete value, describing the problem if there is one.
    ///
    /// The message is shown beneath the field as it is typed, so it states
    /// what is wrong rather than merely that something is.
    pub fn validate(self, value: &str) -> std::result::Result<(), String> {
        match self {
            Self::Port => validate_port(value),
            Self::Username => validate_username(value),
            Self::UsernameList => validate_username_list(value),
            Self::PublicKey => validate_public_key(value),
            Self::Path => validate_path(value),
            Self::Protocol => validate_protocol(value),
            Self::Version => validate_version(value),
            Self::Cidr => validate_cidr(value),
            Self::Ip => validate_ip(value),
            Self::Endpoint => validate_endpoint(value),
        }
    }
}

/// Rejects anything that is not a usable TCP port.
fn validate_port(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("a port is required".to_owned());
    }

    match value.parse::<u32>() {
        // Port 0 asks the kernel to choose, which is meaningless for a service
        // an administrator has to be able to reach again.
        Ok(0) => Err("port 0 is not a port sshd can listen on".to_owned()),
        Ok(port) if port > MAX_PORT => Err(format!("a port cannot be above {MAX_PORT}")),
        Ok(_) => Ok(()),
        Err(_) => Err("a port must be a number".to_owned()),
    }
}

/// Highest valid TCP port.
///
/// Shared with the tasks that act on a port, so the range is stated once
/// rather than re-derived beside every check.
pub const MAX_PORT: u32 = 65_535;

/// Rejects anything that is not a dotted-quad IPv4 address.
///
/// Parsed by the standard library rather than octet by octet. A hand-rolled
/// check that parses each part with `str::parse` admits what the integer parser
/// admits, which is more than an address: a leading `+`, and leading zeros
/// without limit. That is not pedantry — `010.0.0.1` passed, and this value is
/// written verbatim into `wg0.conf`, where a leading zero is read as octal by
/// some tooling. The address reviewed and the address in effect would differ.
fn validate_ip(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("an address is required".to_owned());
    }

    // The count is checked first so the message can name the actual mistake:
    // `Ipv4Addr` refuses "10.0.0" and "1.2.3.4.5" alike, and "four parts" is
    // the useful thing to say about both.
    if value.split('.').count() != 4 {
        return Err("an address has four parts, as 10.89.0.2".to_owned());
    }

    if std::net::Ipv4Addr::from_str(value).is_err() {
        return Err(format!("{value} is not an address, as 10.89.0.2"));
    }

    Ok(())
}

/// Rejects anything that is not an IPv4 subnet in CIDR notation.
fn validate_cidr(value: &str) -> std::result::Result<(), String> {
    let Some((network, mask)) = value.split_once('/') else {
        return Err("a subnet carries its mask, as 10.89.0.0/24".to_owned());
    };

    validate_ip(network)?;

    match mask.parse::<u16>() {
        // Below /8 is a subnet larger than any private range, and /31 and /32
        // leave no room for a peer beside the server.
        Ok(bits) if (8..=30).contains(&bits) => Ok(()),
        Ok(bits) => Err(format!("/{bits} leaves no usable range for peers")),
        Err(_) => Err("the mask is a number, as /24".to_owned()),
    }
}

/// Rejects anything that could not be dialled as `address:port`.
fn validate_endpoint(value: &str) -> std::result::Result<(), String> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err("an endpoint carries its port, as 203.0.113.7:51820".to_owned());
    };

    if host.is_empty() {
        return Err("the address is missing".to_owned());
    }

    validate_port(port)
}

/// Rejects anything that could not name a release.
fn validate_version(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("a version is required".to_owned());
    }

    // Shape only. Whether this build can verify the version is a question for
    // the release table, and the task answers it when it runs.
    if !value
        .split('.')
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
    {
        return Err("a version is digits separated by dots, as 0.44.0".to_owned());
    }

    Ok(())
}

/// Rejects anything that is not a transport protocol this tool can write.
fn validate_protocol(value: &str) -> std::result::Result<(), String> {
    match value {
        "tcp" | "udp" => Ok(()),
        "" => Err("a protocol is required".to_owned()),
        _ => Err("the protocol must be tcp or udp".to_owned()),
    }
}

/// Rejects anything that is not a usable absolute path.
///
/// A shape check, not an existence check: whether the path is a real shell is
/// a question for the host, and [`crate::tasks::users::SetShell`] answers it
/// against `/etc/shells` when it runs.
fn validate_path(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("a path is required".to_owned());
    }

    // Relative paths are refused rather than resolved: what they resolve
    // against depends on the working directory of whatever runs the command,
    // and a login shell is recorded verbatim in the passwd entry.
    if !value.starts_with('/') {
        return Err("the path must be absolute".to_owned());
    }

    if value.contains(char::is_whitespace) {
        return Err("a path cannot contain spaces".to_owned());
    }

    // Same reasoning as every other value written into a system file: nothing
    // escapes these, and the CLI never passes through the keystroke filter.
    if let Some(bad) = value.chars().find(|c| CONFIG_UNSAFE.contains(c)) {
        return Err(format!("the path cannot contain {bad:?}"));
    }

    // A `..` segment makes the written path differ from the one that was
    // reviewed. Nothing here resolves symlinks or canonicalises, so the value
    // recorded in a passwd entry would not be the one an administrator read
    // back — refusing is cheaper than reasoning about where it lands.
    if value.split('/').any(|segment| segment == "..") {
        return Err("the path cannot contain '..'".to_owned());
    }

    Ok(())
}

/// Rejects a username that could not name an account.
///
/// This is a shape check, not an existence check: whether the user exists is a
/// question for the host, and the task asks it when it runs.
fn validate_username(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("a username is required".to_owned());
    }

    // A leading `-` makes the name an option rather than an operand. `useradd
    // -m -s /bin/sh -o` reads `-o` as "allow a duplicate UID" and never
    // creates an account called `-o`; `--system` would create one of a
    // different kind entirely. Nothing downstream escapes arguments — they are
    // passed as a vector, which prevents a *shell* injection but not this — so
    // the barrier belongs here.
    if value.starts_with('-') {
        return Err("a username cannot begin with '-'".to_owned());
    }

    // The portable set from `useradd(8)`: a name outside it is one some tool in
    // the chain will refuse anyway, and restricting it here means every value
    // that reaches a command is one no argument parser can reinterpret.
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("a username may hold letters, digits, '_', '-' and '.'".to_owned());
    }

    // `.` and `..` pass every check above and are not names — they are path
    // segments. `ssh.authorize-key` derives `/home/{user}/.ssh` from this
    // value, so `..` there resolves to `/home/.ssh` and has root create a
    // directory nobody asked for. The `/` that would make a longer traversal
    // possible is already excluded by the character set; these two are what
    // remain.
    if value.chars().all(|c| c == '.') {
        return Err("a username cannot be '.' or '..'".to_owned());
    }

    Ok(())
}

/// Rejects a list of usernames that could not name a set of accounts.
///
/// Shape only, as with a single username: whether the accounts exist is a
/// question for the host, and the task asks it when it runs. What is enforced
/// here is that the value cannot change the meaning of the line it is written
/// into — the CLI never passes through the keystroke filter, so this is the
/// only barrier between an argument and `sshd_config`.
fn validate_username_list(value: &str) -> std::result::Result<(), String> {
    if value.trim().is_empty() {
        return Err("at least one username is required".to_owned());
    }

    if value.contains(CONFIG_UNSAFE) {
        return Err("a username cannot contain a newline or a '#'".to_owned());
    }

    for name in value.split_whitespace() {
        // A comma separates entries in AllowGroups but not in AllowUsers, so
        // `alice,bob` would be read as one account named "alice,bob" and match
        // nobody — a configuration sshd accepts and that refuses every login.
        if name.contains(',') {
            return Err("separate usernames with spaces, not commas".to_owned());
        }

        validate_username(name)?;
    }

    Ok(())
}

/// Rejects a public key that sshd would not honour.
///
/// A malformed entry makes sshd ignore the *whole* file, so this is checked
/// before the key is ever written.
fn validate_public_key(value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err("a public key is required".to_owned());
    }

    crate::tasks::ssh::is_valid_public_key(value).map_err(|error| match error {
        Error::InvalidPublicKey { reason } => reason,
        other => other.to_string(),
    })
}

/// One value a task needs before it can run.
#[derive(Debug, Clone)]
pub struct Param {
    /// Identifier the task reads the value back by.
    pub name: &'static str,
    /// What the field is called in the interface.
    pub label: &'static str,
    pub kind: ParamKind,
    /// What the value is now, where the task can discover it.
    ///
    /// Shown as the starting content of the field, so the common case of
    /// "change this slightly" needs no retyping.
    pub initial: String,
    /// A short note shown beside the field.
    pub hint: Option<String>,
    /// What the host can offer for this field, where anything can.
    ///
    /// Opt-in per parameter: a field says so or is left alone. The default of
    /// `None` is what keeps a new parameter from silently inheriting
    /// suggestions that do not fit it — which is the mistake this field exists
    /// to have made impossible.
    pub suggestions: Option<Suggestions>,
}

impl Param {
    /// Declares a parameter with no starting value.
    pub fn new(name: &'static str, label: &'static str, kind: ParamKind) -> Self {
        Self {
            name,
            label,
            kind,
            initial: String::new(),
            hint: None,
            suggestions: None,
        }
    }

    /// Sets what the field starts out containing.
    #[must_use]
    pub fn with_initial(mut self, initial: impl Into<String>) -> Self {
        self.initial = initial.into();
        self
    }

    /// Attaches a note shown beside the field.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Offers the accounts this host has.
    ///
    /// For a field naming an account that must already exist. A field that
    /// names one which must *not* — `users.create` — asks for nothing: every
    /// account on the host is a value that task refuses.
    #[must_use]
    pub const fn suggesting_accounts(mut self) -> Self {
        self.suggestions = Some(Suggestions::Accounts);
        self
    }

    /// Offers the login shells this host admits.
    #[must_use]
    pub const fn suggesting_shells(mut self) -> Self {
        self.suggestions = Some(Suggestions::Shells);
        self
    }
}

/// The values collected for a task's parameters.
///
/// Keyed by [`Param::name`], so a task reads back what it declared rather than
/// depending on the order the interface happened to collect them in.
#[derive(Debug, Clone, Default)]
pub struct ParamValues {
    values: HashMap<&'static str, String>,
}

impl ParamValues {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a value.
    pub fn set(&mut self, name: &'static str, value: impl Into<String>) {
        self.values.insert(name, value.into());
    }

    /// Reads a value back, failing if the interface never collected it.
    ///
    /// A missing parameter is a programming error rather than user input, but
    /// it is still returned as an error: this runs as root, and a task that
    /// silently substituted a default could change something the operator
    /// never asked it to.
    pub fn get(&self, name: &str) -> Result<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| Error::MissingParameter {
                name: name.to_owned(),
            })
    }

    /// Reads a value back as a port.
    pub fn port(&self, name: &str) -> Result<u32> {
        let raw = self.get(name)?;

        raw.parse().map_err(|_| Error::InvalidPort {
            // A non-numeric value cannot be reported as the number it is not,
            // so the sentinel stands for "not a port at all".
            port: u32::MAX,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_field_accepts_only_digits() {
        assert!(ParamKind::Port.accepts('2'));
        assert!(!ParamKind::Port.accepts('a'));
        assert!(!ParamKind::Port.accepts(' '));
    }

    #[test]
    fn a_key_field_accepts_the_characters_a_key_contains() {
        // Keys are pasted more often than typed; base64 and the comment
        // between them admit almost anything printable.
        for character in ['A', 'z', '9', '+', '/', '=', '@', '-', ' '] {
            assert!(
                ParamKind::PublicKey.accepts(character),
                "a key may contain {character:?}"
            );
        }

        assert!(!ParamKind::PublicKey.accepts('\n'), "a newline ends a key");
    }

    #[test]
    fn port_validation_states_what_is_wrong() {
        // "invalid" tells the operator nothing they did not already know.
        assert!(ParamKind::Port.validate("22").is_ok());
        assert!(ParamKind::Port.validate("65535").is_ok());

        let too_high = ParamKind::Port
            .validate("70000")
            .expect_err("70000 is not a port");
        assert!(too_high.contains("65535"), "got {too_high:?}");

        let empty = ParamKind::Port
            .validate("")
            .expect_err("a port is required");
        assert!(empty.contains("required"), "got {empty:?}");
    }

    #[test]
    fn port_zero_is_rejected() {
        // Port 0 asks the kernel to choose, which is meaningless for a service
        // the administrator has to reach again.
        assert!(ParamKind::Port.validate("0").is_err());
    }

    #[test]
    fn a_username_cannot_contain_spaces() {
        assert!(ParamKind::Username.validate("admin").is_ok());
        assert!(ParamKind::Username.validate("web admin").is_err());
        assert!(ParamKind::Username.validate("").is_err());
    }

    #[test]
    fn a_username_list_accepts_several_names() {
        assert!(ParamKind::UsernameList.validate("alice bob").is_ok());
        assert!(ParamKind::UsernameList.validate("alice").is_ok());
        assert!(ParamKind::UsernameList.validate("").is_err());
        assert!(ParamKind::UsernameList.validate("   ").is_err());
    }

    #[test]
    fn a_username_list_rejects_a_value_that_would_change_the_line() {
        // Directives are written without escaping, so these would append a
        // directive of the caller's choosing, or comment out the rest.
        assert!(
            ParamKind::UsernameList
                .validate("alice\nPermitRootLogin yes")
                .is_err()
        );
        assert!(ParamKind::UsernameList.validate("alice\rbob").is_err());
        assert!(ParamKind::UsernameList.validate("alice #bob").is_err());
    }

    #[test]
    fn a_username_list_rejects_commas() {
        // AllowUsers separates on whitespace: "alice,bob" would be read as a
        // single account of that name and match nobody.
        assert!(ParamKind::UsernameList.validate("alice,bob").is_err());
    }

    #[test]
    fn a_username_list_field_accepts_a_space_but_not_a_newline() {
        assert!(ParamKind::UsernameList.accepts(' '));
        assert!(!ParamKind::UsernameList.accepts('\n'));
    }

    #[test]
    fn a_malformed_key_is_rejected_with_its_reason() {
        // A malformed entry makes sshd ignore the whole file, so the check
        // happens before the key is ever written.
        let error = ParamKind::PublicKey
            .validate("not-a-key")
            .expect_err("a malformed key must be rejected");

        assert!(!error.is_empty(), "the reason must be stated");
    }

    #[test]
    fn a_username_cannot_be_read_as_an_option() {
        // Found by running the CLI, not by reading it: `initd run
        // users.create user=-o` reached `useradd -m -s /bin/bash -o`, where
        // `-o` is useradd's "allow a duplicate UID" flag and no account named
        // `-o` is created. Arguments are passed as a vector, so no shell is
        // involved — which stops an injection but not an argument being
        // reinterpreted by the program receiving it.
        assert!(ParamKind::Username.validate("-o").is_err());
        assert!(ParamKind::Username.validate("--system").is_err());
        assert!(ParamKind::Username.validate("-").is_err());
    }

    #[test]
    fn ordinary_usernames_are_still_accepted() {
        // The guard must not cost the names people actually use. A `-` inside
        // the name is fine; only a leading one is an option.
        for name in ["alice", "deploy-bot", "web_admin", "user.name", "node1"] {
            assert!(
                ParamKind::Username.validate(name).is_ok(),
                "{name} must be accepted"
            );
        }
    }

    #[test]
    fn a_username_holding_shell_metacharacters_is_rejected() {
        // Nothing here reaches a shell today, but `busybox_accounts` builds an
        // `sh -c` string from a username to read the shadow entry. Rejecting
        // the characters that would matter there keeps that true regardless of
        // which backend runs.
        for hostile in ["alice;rm", "a$(id)", "a`id`", "a|b", "a&b", "../root"] {
            assert!(
                ParamKind::Username.validate(hostile).is_err(),
                "{hostile} must be refused"
            );
        }
    }

    #[test]
    fn a_relative_path_is_rejected() {
        // What a relative path resolves against depends on the working
        // directory of whatever runs the command, and a login shell is
        // recorded verbatim in the passwd entry.
        assert!(ParamKind::Path.validate("/usr/bin/fish").is_ok());
        assert!(ParamKind::Path.validate("usr/bin/fish").is_err());
        assert!(ParamKind::Path.validate("./fish").is_err());
        assert!(ParamKind::Path.validate("").is_err());
    }

    #[test]
    fn a_path_rejects_a_value_that_would_change_the_line() {
        // Same barrier as every other value written into a system file:
        // nothing escapes these, and the CLI never passes through the
        // keystroke filter.
        assert!(
            ParamKind::Path
                .validate("/bin/sh\nPermitRootLogin yes")
                .is_err()
        );
        assert!(ParamKind::Path.validate("/bin/sh #comment").is_err());
        assert!(ParamKind::Path.validate("/usr/local/bin/my shell").is_err());
    }

    #[test]
    fn values_are_read_back_by_name() {
        let mut values = ParamValues::new();
        values.set("port", "2222");

        assert_eq!(values.get("port").expect("the value was set"), "2222");
        assert_eq!(values.port("port").expect("a valid port"), 2222);
    }

    #[test]
    fn a_parameter_the_interface_never_collected_is_an_error() {
        // Substituting a default would change something the operator never
        // asked for, on a tool that runs as root.
        let values = ParamValues::new();

        assert!(values.get("port").is_err());
    }

    /// Runs a table of `(value, should_pass)` through one kind.
    ///
    /// The failure names the kind, the value and the direction, because a
    /// table that only says "assertion failed" makes the reader find the row.
    fn check_table(kind: ParamKind, table: &[(&str, bool)]) {
        for &(value, should_pass) in table {
            let result = kind.validate(value);

            assert_eq!(
                result.is_ok(),
                should_pass,
                "{kind:?} {} accept {value:?}, got {result:?}",
                if should_pass { "must" } else { "must not" },
            );
        }
    }

    #[test]
    fn an_address_is_an_address_and_not_merely_four_numbers() {
        // The bug this pins: parsing each octet with `str::parse` admitted what
        // the integer parser admits — a leading `+`, and leading zeros without
        // limit. `010.0.0.1` reached `wg0.conf`, where a leading zero reads as
        // octal to some tooling, so the address reviewed and the address in
        // effect were not the same address.
        check_table(
            ParamKind::Ip,
            &[
                ("10.89.0.2", true),
                ("0.0.0.0", true),
                ("255.255.255.255", true),
                ("010.0.0.1", false),
                ("+1.0.0.1", false),
                ("0000000010.0.0.1", false),
                ("10.0.0.0001", false),
                ("256.0.0.1", false),
                ("-1.0.0.1", false),
                ("10.0.0", false),
                ("10.0.0.1.2", false),
                ("10.0.0.a", false),
                ("10.0.0. 1", false),
                ("", false),
            ],
        );
    }

    #[test]
    fn a_subnet_carries_a_mask_that_leaves_room_for_peers() {
        // The boundaries are the point: /8 and /30 are the edges of the range
        // the comment beside them names, and an off-by-one at either end is
        // invisible to a test that only tries /24.
        check_table(
            ParamKind::Cidr,
            &[
                ("10.89.0.0/24", true),
                ("10.0.0.0/8", true),
                ("10.89.0.0/30", true),
                ("10.89.0.0/7", false),
                ("10.89.0.0/31", false),
                ("10.89.0.0/32", false),
                // The address half is validated too, so the octal trap cannot
                // come back through the subnet field.
                ("010.89.0.0/24", false),
                ("10.89.0.0", false),
                ("10.89.0.0/", false),
                ("10.89.0.0/x", false),
                ("", false),
            ],
        );
    }

    #[test]
    fn an_endpoint_is_dialled_as_address_and_port() {
        check_table(
            ParamKind::Endpoint,
            &[
                ("203.0.113.7:51820", true),
                ("vpn.example.org:51820", true),
                ("203.0.113.7:0", false),
                ("203.0.113.7:65536", false),
                ("203.0.113.7:", false),
                (":51820", false),
                ("203.0.113.7", false),
                ("", false),
            ],
        );
    }

    #[test]
    fn a_version_is_digits_and_dots_with_nothing_missing() {
        check_table(
            ParamKind::Version,
            &[
                ("0.44.0", true),
                ("1", true),
                ("1..2", false),
                (".1", false),
                ("1.", false),
                ("v1.2.3", false),
                ("1.2.3-rc1", false),
                ("", false),
            ],
        );
    }

    #[test]
    fn a_protocol_is_one_of_the_two_this_tool_writes() {
        check_table(
            ParamKind::Protocol,
            &[
                ("tcp", true),
                ("udp", true),
                ("TCP", false),
                ("sctp", false),
                ("", false),
            ],
        );
    }
}
