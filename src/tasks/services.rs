//! Workloads the server runs: a container engine and a web server.
//!
//! Both stop short of describing an application. `docker-rootless.install`
//! provisions the engine and does not run containers; `caddy.*` installs,
//! validates and hardens and does not write site configuration. Generating a
//! `reverse_proxy` block describes an application topology, which is where the
//! self-hosting panels live and where this tool deliberately does not go.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor, OutputLine, Stream};
use crate::tasks::consequence::{Check, Consequence, External, Protocol, Reason};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{Category, Node, Progress, Task};

/// Families these tasks support.
const SUPPORTED: &[Family] = &[Family::Debian, Family::Arch];

/// The user unit a rootless engine installs.
const DOCKER_USER_SERVICE: &str = "docker.service";

/// The ports a web server needs, and the parameter that lets it bind them.
const HTTP_PORT: u32 = 80;
const HTTPS_PORT: u32 = 443;

/// Reports a step to the caller as a normal output line.
fn report(progress: Progress<'_>, text: impl Into<String>) {
    progress(OutputLine {
        stream: Stream::Stdout,
        text: text.into(),
    });
}

/// Builds the services category.
pub fn category() -> Category {
    Category::new(
        "Services",
        vec![
            Node::Category(Category::new(
                "Containers",
                vec![Node::Task(Box::new(InstallDockerRootless))],
            )),
            Node::Category(Category::new(
                "Web server",
                vec![
                    Node::Task(Box::new(InstallCaddy)),
                    Node::Task(Box::new(ValidateCaddy)),
                    Node::Task(Box::new(CaddySecurityHeaders)),
                ],
            )),
        ],
    )
}

/// Installs the rootless Docker engine for one account.
pub struct InstallDockerRootless;

impl InstallDockerRootless {
    /// Name of the parameter holding the account the engine runs as.
    pub const USER: &'static str = "user";
}

impl Task for InstallDockerRootless {
    fn id(&self) -> &'static str {
        "docker-rootless.install"
    }

    fn title(&self) -> &'static str {
        "Install rootless Docker for a user"
    }

    fn description(&self) -> &'static str {
        "Installs the Docker engine under one account rather than as root, so a \
         container escape lands in an ordinary user rather than on the machine. \
         The account keeps its services running after logout."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the engine runs as"),
        ]
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn consequences(&self, _values: &ParamValues) -> Vec<Consequence> {
        // Rootless containers cannot bind below 1024 without this, and the
        // failure reads as a container problem rather than a kernel setting.
        vec![Consequence::Invalidates {
            task: "sysctl.unprivileged-ports",
            reason: Reason::RequiresSetting {
                setting: "net.ipv4.ip_unprivileged_port_start",
            },
            check: Some(Check {
                command: Command::new("sysctl").args(["-n", "net.ipv4.ip_unprivileged_port_start"]),
                resolved_when_stdout_contains: "80".to_owned(),
            }),
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(Self::USER)?.to_owned();

        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        let user_services = backend.user_services();

        // Checked before anything is installed: an account with no subordinate
        // range cannot start a single container, and finding that out after
        // the engine is installed wastes the install.
        if !user_services.has_subordinate_ids(executor, &user)? {
            return Err(Error::NoSubordinateIds { user });
        }

        report(progress, format!("installing docker for {user}"));

        backend
            .packages()
            .install(executor, backend.package_for(Capability::DockerRootless))?;

        // Lingering first. Without it the engine stops when the account's last
        // session ends, and because a user unit is wanted by `default.target`
        // rather than by anything reached at boot, nothing brings it back after
        // a reboot either.
        if !user_services.is_lingering(executor, &user)? {
            user_services.enable_linger(executor, &user)?;
            report(progress, format!("{user} may now keep services running"));
        }

        // The upstream setup script, run as the account rather than as root:
        // it writes into the user's own systemd directory, and run as root it
        // would install the engine for root.
        let setup = Command::new("runuser")
            .args(["-l", &user, "-c", "dockerd-rootless-setuptool.sh install"])
            .privileged();

        crate::backend::systemd::run_checked(executor, &setup)?;

        user_services.enable_and_start(executor, &user, DOCKER_USER_SERVICE)?;

        // Read back rather than assumed. `enable --now` exiting zero says the
        // command ran; a rootless engine that cannot map its ids or reach its
        // runtime directory fails after that point, and reporting success here
        // would send the administrator looking at their containers.
        if !user_services.is_active(executor, &user, DOCKER_USER_SERVICE)? {
            return Err(Error::ServiceDidNotStart {
                service: DOCKER_USER_SERVICE.to_owned(),
                user,
            });
        }

        report(
            progress,
            format!("{DOCKER_USER_SERVICE} is running as {user}"),
        );
        report(
            progress,
            format!("connect with DOCKER_HOST=unix:///run/user/$(id -u {user})/docker.sock"),
        );

        Ok(Outcome::Done)
    }
}

/// Installs the Caddy web server.
pub struct InstallCaddy;

impl Task for InstallCaddy {
    fn id(&self) -> &'static str {
        "caddy.install"
    }

    fn title(&self) -> &'static str {
        "Install the Caddy web server"
    }

    fn description(&self) -> &'static str {
        "Installs Caddy and enables it. Site configuration stays yours: this \
         tool administers the server, it does not describe what you deploy on it."
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn consequences(&self, _values: &ParamValues) -> Vec<Consequence> {
        vec![
            Consequence::Invalidates {
                task: "firewall.allow-port",
                reason: Reason::RequiresSetting {
                    setting: "inbound rules for 80 and 443",
                },
                check: Some(Check {
                    command: Command::new("nft")
                        .args(["list", "table", "inet", "initd"])
                        .privileged(),
                    resolved_when_stdout_contains: format!("tcp dport {HTTPS_PORT} accept"),
                }),
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port: HTTPS_PORT,
                    protocol: Protocol::Tcp,
                },
            },
            // Caddy issues certificates automatically, and the issuance fails
            // if the name does not already point here. Nothing on this host can
            // check that, so it is reported rather than verified.
            Consequence::External {
                note: External::DnsMustResolve,
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        report(progress, "installing caddy".to_owned());

        backend
            .packages()
            .install(executor, backend.package_for(Capability::Caddy))?;

        backend
            .services()
            .enable_and_start(executor, backend.service_for(Capability::Caddy))?;

        report(progress, "caddy is enabled".to_owned());
        report(
            progress,
            format!("it will answer on {HTTP_PORT} and {HTTPS_PORT} once the firewall admits them"),
        );

        Ok(Outcome::Done)
    }
}

/// Checks the Caddyfile parses.
pub struct ValidateCaddy;

impl Task for ValidateCaddy {
    fn id(&self) -> &'static str {
        "caddy.validate"
    }

    fn title(&self) -> &'static str {
        "Validate the Caddyfile"
    }

    fn description(&self) -> &'static str {
        "Asks Caddy whether its configuration parses, before a reload acts on it. \
         Changes nothing."
    }

    fn supported_families(&self) -> &'static [Family] {
        SUPPORTED
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let path = backend.path_for(Capability::Caddy);

        // Asked of Caddy rather than grepped out of the file. The directive
        // order in a Caddyfile is not its source order, so reading the text
        // says less about the running configuration than it appears to.
        let command = Command::new("caddy")
            .args(["validate", "--config", path])
            .privileged();

        let output = executor.run(&command)?;

        if !output.success() {
            return Err(Error::InvalidCaddyfile {
                details: output.stderr.trim().to_owned(),
            });
        }

        report(progress, format!("{path} parses"));

        Ok(Outcome::Done)
    }
}

/// Adds response headers that harden every site Caddy serves.
pub struct CaddySecurityHeaders;

impl Task for CaddySecurityHeaders {
    fn id(&self) -> &'static str {
        "caddy.security-headers"
    }

    fn title(&self) -> &'static str {
        "Add security response headers"
    }

    fn description(&self) -> &'static str {
        "Writes a snippet setting HSTS, nosniff, frame-deny and a referrer \
         policy, which sites import with `import security_headers`."
    }

    /// It changes a file the running server reads, and a Caddyfile that no
    /// longer parses takes every site down at the next reload.
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
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let path = backend.path_for(Capability::Caddy);
        let files = backend.files();

        let existing = if files.exists(executor, path)? {
            files.read(executor, path)?
        } else {
            String::new()
        };

        if existing.contains(SNIPPET_NAME) {
            report(progress, "the snippet is already defined".to_owned());

            return Ok(Outcome::Done);
        }

        let backup = files.write(executor, path, &format!("{}{existing}", security_snippet()))?;

        // Validated after writing, because what matters is whether the file the
        // server will read parses — and restored rather than left broken, since
        // a Caddyfile that does not parse takes every site down on reload.
        let validate = Command::new("caddy")
            .args(["validate", "--config", path])
            .privileged();

        if !executor.run(&validate)?.success() {
            if let Some(ref backup) = backup {
                files.restore(executor, backup)?;
            }

            return Err(Error::InvalidCaddyfile {
                details: "the snippet did not parse; the file was restored".to_owned(),
            });
        }

        report(progress, format!("{SNIPPET_NAME} is defined in {path}"));
        report(
            progress,
            format!("add `import {SNIPPET_NAME}` to a site block to apply it"),
        );

        Ok(Outcome::Done)
    }
}

/// Name of the snippet the headers task defines.
const SNIPPET_NAME: &str = "security_headers";

/// The snippet itself.
fn security_snippet() -> String {
    // `X-Forwarded-*` is deliberately absent. Caddy populates those itself, and
    // setting them by hand breaks client-IP detection for everything behind it.
    //
    // A snippet rather than a global block: applying headers to every site
    // silently would change how an application already deployed here behaves,
    // and this tool does not edit site configuration.
    format!(
        "({SNIPPET_NAME}) {{\n\
         \theader {{\n\
         \t\tStrict-Transport-Security \"max-age=31536000; includeSubDomains\"\n\
         \t\tX-Content-Type-Options nosniff\n\
         \t\tX-Frame-Options DENY\n\
         \t\tReferrer-Policy strict-origin-when-cross-origin\n\
         \t\t-Server\n\
         \t}}\n\
         }}\n\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::exec::mock::{MockExecutor, Reply};

    fn user_values(user: &str) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(InstallDockerRootless::USER, user.to_owned());
        values
    }

    fn run(
        task: &dyn Task,
        family: Family,
        replies: Vec<Reply>,
        values: &ParamValues,
    ) -> (Result<Outcome>, Vec<String>) {
        let mock = MockExecutor::with_replies(replies);
        let backend = for_family(family);
        let outcome = task.run(&mock, backend.as_ref(), values, &mut |_| {});

        (outcome, mock.recorded_lines())
    }

    #[test]
    fn an_account_without_subordinate_ids_is_refused_before_installing() {
        // A rootless engine maps container users onto that range, so without
        // one no container starts at all. Finding out after the install wastes
        // it.
        let (outcome, commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok(""),         // subuid names it
                Reply::failure(1, ""), // subgid does not
            ],
            &user_values("deploy"),
        );

        let err = outcome.expect_err("a missing range must be refused");

        assert!(matches!(err, Error::NoSubordinateIds { .. }), "{err:?}");
        assert!(
            !commands.iter().any(|c| c.contains("install")),
            "nothing must be installed: {commands:?}"
        );
    }

    #[test]
    fn the_engine_package_differs_by_family() {
        // Debian's distribution package does not carry the rootless setup
        // script at all; Arch's `docker` does. A single name would leave one
        // family with an install that has nothing to run.
        let debian = for_family(Family::Debian);
        let arch = for_family(Family::Arch);

        assert_eq!(
            debian.package_for(Capability::DockerRootless),
            "docker-ce-rootless-extras"
        );
        assert_eq!(arch.package_for(Capability::DockerRootless), "docker");
    }

    #[test]
    fn lingering_is_enabled_before_the_engine_starts() {
        // Without it the engine stops at logout, and a user unit wanted by
        // default.target is not brought back by anything at boot.
        let (outcome, commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok(""),          // subuid
                Reply::ok(""),          // subgid
                Reply::ok(""),          // install
                Reply::ok("Linger=no"), // not lingering yet
                Reply::ok(""),          // enable-linger
                Reply::ok(""),          // setuptool
                Reply::ok(""),          // enable --now
                Reply::ok("active"),    // is-active
            ],
            &user_values("deploy"),
        );

        outcome.expect("the install must succeed");

        let linger = commands
            .iter()
            .position(|c| c.contains("enable-linger"))
            .expect("lingering must be enabled");
        let start = commands
            .iter()
            .position(|c| c.contains("enable --now"))
            .expect("the engine must be started");

        assert!(linger < start, "linger must come first: {commands:?}");
    }

    #[test]
    fn an_engine_that_did_not_come_up_is_an_error() {
        // `enable --now` exiting zero says the command ran. Reporting success
        // here would send the administrator to look at their containers.
        let (outcome, _) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok(""),
                Reply::ok(""),
                Reply::ok(""),
                Reply::ok("Linger=yes"),
                Reply::ok(""),
                Reply::ok(""),
                Reply::ok("inactive"), // enabled, not running
            ],
            &user_values("deploy"),
        );

        let err = outcome.expect_err("a service that did not start must fail");

        assert!(matches!(err, Error::ServiceDidNotStart { .. }), "{err:?}");
    }

    #[test]
    fn installing_the_engine_points_at_the_port_setting() {
        // Rootless containers cannot bind below 1024 without it, and the
        // failure reads as a container problem.
        let consequences = InstallDockerRootless.consequences(&user_values("deploy"));

        assert_eq!(consequences.len(), 1, "{consequences:?}");
        assert_eq!(
            consequences[0].task(),
            Some("sysctl.unprivileged-ports"),
            "{consequences:?}"
        );
        assert!(consequences[0].check().is_some(), "it is readable locally");
    }

    #[test]
    fn caddy_warns_about_dns_it_cannot_check() {
        // Certificates are issued automatically and issuance fails if the name
        // does not already point here. Nothing on this host can see that.
        let consequences = InstallCaddy.consequences(&ParamValues::new());

        let dns = consequences
            .iter()
            .find(|c| c.is_external() && c.check().is_none())
            .expect("an unverifiable warning must be present");

        assert!(dns.task().is_none(), "external warnings name no task");
    }

    #[test]
    fn the_caddyfile_is_asked_rather_than_grepped() {
        // Directive order in a Caddyfile is not its source order, so reading
        // the text says less about the running configuration than it appears.
        let (outcome, commands) = run(
            &ValidateCaddy,
            Family::Debian,
            vec![Reply::ok("Valid configuration")],
            &ParamValues::new(),
        );

        outcome.expect("a valid file must pass");

        assert!(
            commands.iter().any(|c| c.contains("caddy validate")),
            "{commands:?}"
        );
    }

    #[test]
    fn an_invalid_caddyfile_is_reported_with_its_reason() {
        let (outcome, _) = run(
            &ValidateCaddy,
            Family::Debian,
            vec![Reply::failure(1, "unrecognized directive: reverse_prox")],
            &ParamValues::new(),
        );

        let err = outcome.expect_err("an invalid file must fail");

        match err {
            Error::InvalidCaddyfile { details } => {
                assert!(details.contains("reverse_prox"), "{details}");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn the_security_snippet_does_not_touch_forwarded_headers() {
        // Caddy populates X-Forwarded-* itself; setting them by hand breaks
        // client-IP detection for everything behind it.
        let snippet = security_snippet();

        assert!(!snippet.contains("X-Forwarded"), "{snippet}");
        assert!(snippet.contains("Strict-Transport-Security"), "{snippet}");
        assert!(
            snippet.contains("X-Content-Type-Options nosniff"),
            "{snippet}"
        );
    }

    #[test]
    fn the_snippet_applies_to_nothing_on_its_own() {
        // A global header block would silently change how an application
        // already deployed here behaves. A snippet is opt-in per site.
        let snippet = security_snippet();

        assert!(
            snippet.starts_with(&format!("({SNIPPET_NAME})")),
            "it must be a snippet, not a global block: {snippet}"
        );
    }

    #[test]
    fn a_snippet_that_does_not_parse_is_rolled_back() {
        // A Caddyfile that does not parse takes every site down at the next
        // reload, so a broken file is never left in place.
        let (outcome, commands) = run(
            &CaddySecurityHeaders,
            Family::Debian,
            vec![
                Reply::ok(""),                    // the file exists
                Reply::ok("example.com {\n}\n"),  // read it
                Reply::ok(""),                    // backup
                Reply::ok(""),                    // write
                Reply::failure(1, "parse error"), // validate rejects it
                Reply::ok(""),                    // restore
            ],
            &ParamValues::new(),
        );

        assert!(outcome.is_err(), "a rejected snippet must fail");
        assert!(
            commands.iter().any(|c| c.contains("cp -p")),
            "the original must be restored: {commands:?}"
        );
    }

    #[test]
    fn defining_the_snippet_twice_does_nothing() {
        let existing = format!("({SNIPPET_NAME}) {{\n\theader {{\n\t}}\n}}\n");

        let (outcome, commands) = run(
            &CaddySecurityHeaders,
            Family::Debian,
            vec![Reply::ok(""), Reply::ok(existing)],
            &ParamValues::new(),
        );

        outcome.expect("an existing snippet is the desired state");

        assert!(
            !commands.iter().any(|c| c.contains("tee")),
            "nothing must be written: {commands:?}"
        );
    }
}
