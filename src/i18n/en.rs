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
        Msg::FileIo { path, source } => {
            format!("I/O error on {path}: {source}")
        }
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
        Msg::Terminal { source } => {
            format!("terminal error: {source}")
        }
    }
}
