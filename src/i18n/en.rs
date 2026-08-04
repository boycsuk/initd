//! English message catalogue — the default and fallback language.

use super::Msg;

pub(super) fn render(message: &Msg) -> String {
    match message {
        Msg::OsReleaseUnreadable { path, source } => {
            format!("could not read {path}: {source}")
        }
        Msg::OsReleaseMissingId { path } => {
            format!("{path} does not declare an ID field")
        }
        Msg::UnsupportedDistro { id, id_like } => {
            let like = id_like.as_deref().unwrap_or("(none)");
            format!(
                "unsupported distribution: ID={id}, ID_LIKE={like}. \
                 Supported families: debian, arch"
            )
        }
        Msg::ProgramNotFound { program } => {
            format!("executable {program} was not found in PATH")
        }
        Msg::CommandFailed {
            command,
            code,
            stderr,
        } => {
            format!("`{command}` failed with exit code {code}: {stderr}")
        }
        Msg::CommandTerminatedBySignal { command } => {
            format!("`{command}` was terminated by a signal, with no exit code")
        }
        Msg::CommandIo { command, source } => {
            format!("I/O error while running `{command}`: {source}")
        }
        Msg::NoPrivilegeEscalator => "this operation requires root privileges, but no escalation \
             mechanism (sudo, doas or run0) was found in PATH"
            .to_owned(),
        Msg::InvalidSshdConfig { details } => {
            format!("the sshd configuration is invalid: {details}")
        }
        Msg::InvalidPublicKey { reason } => {
            format!("invalid public key: {reason}")
        }
        Msg::InvalidPort { port } => {
            format!("invalid port: {port} (must be between 1 and 65535)")
        }
        Msg::InvalidAllowUsers { reason } => {
            format!("invalid list of allowed users: {reason}")
        }
        Msg::LockoutNoKeyForRoot => "no authorised key found for root; disabling password \
             authentication now would lock you out. Add a key with `ssh.authorize-key` first"
            .to_owned(),
        Msg::LockoutUnknownUser { user } => {
            format!(
                "no account named {user} exists on this host; restricting SSH to it would \
                 refuse every login. Check the spelling, or create the account first"
            )
        }
        Msg::LockoutNoKeyForAllowedUsers { users } => {
            format!(
                "none of these accounts has an authorised key: {users}. Password \
                 authentication may already be disabled, which would leave no way to log \
                 in. Authorise a key for one of them with `ssh.authorize-key` first"
            )
        }
        Msg::MissingParameter { name } => {
            format!("the task was run without a value for {name}")
        }
        Msg::TaskVanished { task } => {
            format!("{task} stopped without reporting what it did")
        }
        Msg::TaskUnsupported { task, family } => {
            format!("task {task} is not supported on {family}")
        }
        // Names the group, because the answer is almost always that this
        // distribution calls it something else: Debian grants sudo through
        // `sudo`, Arch and RHEL through `wheel`.
        Msg::MissingGroup { group } => {
            format!("the group {group} does not exist on this system")
        }
        Msg::AccountExists { user } => {
            format!("the account {user} already exists")
        }
        Msg::NoSuchAccount { user } => {
            format!("there is no account named {user}")
        }
        Msg::GroupMembershipFailed { user, group } => {
            format!("{user} was not added to {group}, though the command reported success")
        }
        // Names the group, since the usual cause is that this distribution
        // calls it something else.
        Msg::NotAnAdministrator { user, group } => {
            format!("{user} is not in {group}, so it cannot escalate once root is locked")
        }
        Msg::NoAuthorizedKey { user } => {
            format!(
                "{user} has no authorised key, so it cannot log in — it was created \
                 without a password"
            )
        }
        Msg::AdminCannotBeRoot => "root cannot be the account that stays usable: it is the \
             one being locked"
            .to_owned(),
        Msg::ShellNotListed { shell } => {
            format!("{shell} is not listed in /etc/shells, so the system will refuse it")
        }
        Msg::ConsequencePortChanged { task, from, to } => {
            format!("{task} still refers to port {from}, not {to}")
        }
        Msg::ConsequenceRequiresSetting { task, setting } => {
            format!("{task} requires {setting}, which is not set")
        }
        Msg::ConsequenceNeedsRestart { task, service } => {
            format!("{service} must be restarted before {task} observes this")
        }
        Msg::ConsequenceAccountNotListed { task, user } => {
            format!("{task} does not name the account {user}")
        }
        Msg::ConsequenceConflictsOverBanRules { task } => {
            format!(
                "{task} also writes ban rules through the firewall; running \
                 both bans twice and unbans unpredictably"
            )
        }
        // Says plainly that this one cannot be checked from here. An
        // administrator who opens a port locally and still cannot reach it has
        // usually hit exactly this, and the tool has no way to see it.
        Msg::ConsequenceProviderFirewall { port, protocol } => {
            format!(
                "check your hosting provider's firewall allows {port}/{protocol} \
                 — this tool cannot see it"
            )
        }
        Msg::ConsequenceDnsMustResolve => {
            "the name must resolve to this host before a certificate can be \
             issued — this tool cannot see it"
                .to_owned()
        }
        Msg::Terminal { source } => {
            format!("terminal error: {source}")
        }
    }
}
