//! Workloads the server runs: a container engine and a web server.
//!
//! Both stop short of describing an application. `docker-rootless.install`
//! provisions the engine and does not run containers; `caddy.*` installs,
//! validates and hardens and does not write site configuration. Generating a
//! `reverse_proxy` block describes an application topology, which is where the
//! self-hosting panels live and where this tool deliberately does not go.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::binaries::{Artefact, Release};
use crate::domain::firewall::Protocol as FirewallProtocol;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{Check, Consequence, External, Protocol, Reason, firewall_check};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{
    Category, Confirmation, Node, Progress, Support, Task, report, supported_everywhere,
};

/// The user unit a rootless engine installs.
const DOCKER_USER_SERVICE: &str = "docker.service";

/// The ports a web server needs, and the parameter that lets it bind them.
const HTTP_PORT: u32 = 80;
const HTTPS_PORT: u32 = 443;

/// Builds the services category.
pub fn category() -> Category {
    Category::new(
        "Services",
        vec![
            Node::Category(Category::new(
                "Containers",
                vec![Node::Reversible {
                    forward: Box::new(InstallDockerRootless),
                    inverse: Box::new(UninstallDockerRootless),
                }],
            )),
            Node::Category(Category::new(
                "Web server",
                vec![
                    Node::Reversible {
                        forward: Box::new(InstallCaddy),
                        inverse: Box::new(UninstallCaddy),
                    },
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

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerRootless)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker-rootless.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the engine runs as")
                .suggesting_accounts()
                .naming_an_existing_account(),
        ]
    }

    fn support(&self, family: Family) -> Support {
        match family {
            // RHEL reaches the engine differently — Red Hat ships Podman and
            // packages no Docker — but it gets there: the task registers
            // Docker's own repository after checking its signing key against a
            // fingerprint published independently of it.
            Family::Debian | Family::Arch | Family::Rhel => Support::Yes,
            Family::Alpine => Support::No(
                "no per-user service manager at all: the engine runs under the \
                 account's own systemd instance, and OpenRC has no equivalent",
            ),
        }
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
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

        report(progress, &Msg::TaskDockerInstalling { user: user.clone() });

        // Where the distribution packages no Docker, the engine comes from
        // Docker's own repository — registered only if its signing key matches
        // a fingerprint this build carries from three sources the serving host
        // does not control. Registered before the install rather than as part
        // of it, so a key that does not match stops here with nothing changed.
        if let (Some(repositories), Some(repository)) = (
            backend.repositories(),
            backend.repository_for(Capability::DockerRootless),
        ) && !repositories.is_registered(executor, &repository)?
        {
            report(
                progress,
                &Msg::TaskRepositoryRegistering {
                    repository: repository.name.to_owned(),
                },
            );

            repositories.register(executor, &repository)?;
        }

        backend
            .packages()
            .install(executor, backend.package_for(Capability::DockerRootless))?;

        // Lingering first. Without it the engine stops when the account's last
        // session ends, and because a user unit is wanted by `default.target`
        // rather than by anything reached at boot, nothing brings it back after
        // a reboot either.
        if !user_services.is_lingering(executor, &user)? {
            user_services.enable_linger(executor, &user)?;
            report(progress, &Msg::TaskLingerEnabled { user: user.clone() });
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
            &Msg::TaskServiceRunningAs {
                service: DOCKER_USER_SERVICE.to_owned(),
                user: user.clone(),
            },
        );
        report(progress, &Msg::TaskDockerConnectHint { user: user.clone() });

        Ok(Outcome::Done)
    }
}

/// Installs the Caddy web server.
pub struct InstallCaddy;

impl InstallCaddy {
    /// Releases this build carries a digest for.
    ///
    /// Computed from the archives at these URLs on 2026-08-05, by the rule the
    /// other tables follow: a digest served by the host serving the artefact
    /// proves only that the transfer completed.
    ///
    /// Caddy is Go, so the published binary depends on no system library and
    /// one artefact per architecture serves every family — the same property
    /// that makes Zellij's musl build reusable. Note the release publishes
    /// `.deb` packages but no `.rpm`: the RPMs upstream points RHEL users at
    /// come from a COPR whose signing key sits on the host serving the
    /// packages, is on no keyserver, and which `dnf` warns is held to no
    /// security level. The tarball is the route that can be verified.
    pub const RELEASES: &[Release] = &[Release {
        version: "2.11.4",
        archive_member: "caddy",
        artefacts: &[
            Artefact {
                arch: "x86_64",
                url: "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_amd64.tar.gz",
                sha256: "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9",
            },
            Artefact {
                arch: "aarch64",
                url: "https://github.com/caddyserver/caddy/releases/download/v2.11.4/caddy_2.11.4_linux_arm64.tar.gz",
                sha256: "52d42ae12b3462097e9868da6dfed3c9648ae12edd3b3638102312af84cb6904",
            },
        ],
    }];
}

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

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Caddy)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["caddy.install"]
    }

    fn consequences(&self, backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        vec![
            Consequence::Invalidates {
                task: "firewall.allow-port",
                reason: Reason::RequiresSetting {
                    setting: "inbound rules for 80 and 443",
                },
                // Asked of whichever front-end holds this host's ruleset. Only
                // 443 is checked, as before: a check carries one command, and
                // the port that matters is the one a browser reaches.
                check: firewall_check(backend, HTTPS_PORT, FirewallProtocol::Tcp),
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
        report(
            progress,
            &Msg::TaskInstalling {
                what: "caddy".to_owned(),
            },
        );

        // A package brings a unit with it; a release archive is a binary and
        // nothing else. Where the family has no package the binary is installed
        // and the difference is stated, rather than a unit being written here —
        // a unit file this tool invented would be one the distribution does not
        // know about and would not replace when Caddy is later packaged.
        if backend.has_package_for(Capability::Caddy) {
            backend
                .packages()
                .install(executor, backend.package_for(Capability::Caddy))?;

            backend
                .services()
                .enable_and_start(executor, backend.service_for(Capability::Caddy))?;

            report(
                progress,
                &Msg::TaskUnitEnabled {
                    unit: "caddy".to_owned(),
                },
            );
        } else {
            let release = crate::backend::release_installer::release_for(
                Self::RELEASES,
                Self::RELEASES
                    .first()
                    .map(|release| release.version)
                    .unwrap_or_default(),
            )?;

            backend.binaries().install(executor, "caddy", release)?;

            report(
                progress,
                &Msg::TaskCaddyInstalledAt {
                    version: release.version.to_owned(),
                },
            );
            report(progress, &Msg::TaskCaddyNoUnit);
        }
        report(
            progress,
            &Msg::TaskCaddyPorts {
                http: HTTP_PORT,
                https: HTTPS_PORT,
            },
        );

        Ok(Outcome::Done)
    }
}

/// Removes the Caddy web server.
pub struct UninstallCaddy;

impl Task for UninstallCaddy {
    fn id(&self) -> &'static str {
        "caddy.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the Caddy web server"
    }

    fn description(&self) -> &'static str {
        "Stops Caddy, disables it at boot, and removes it. Site configuration \
         is kept unless you ask for it to be purged — this tool did not write \
         it and does not assume you want it gone."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Caddy)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["caddy.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // The headers snippet is a file `caddy.security-headers` wrote into a
        // Caddyfile that is about to stop being read — or, if purged, to stop
        // existing. Stated rather than acted on, as every consequence is.
        vec![Consequence::Invalidates {
            task: "caddy.security-headers",
            reason: Reason::RequiresSetting {
                setting: "a Caddy installation to serve them",
            },
            // No command answers this usefully: whether the snippet still
            // matters depends on whether Caddy comes back, which is a question
            // about intent rather than about the host.
            check: None,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        crate::tasks::uninstall::undo(
            executor,
            backend,
            values,
            progress,
            Capability::Caddy,
            "caddy",
        )
    }
}

/// Checks the Caddyfile parses.
pub struct ValidateCaddy;

impl Task for ValidateCaddy {
    /// Asks Caddy to parse a file. Nothing is written and no
    /// service is touched — the point is to learn this *before* a reload acts.
    fn confirmation(&self) -> Confirmation {
        Confirmation::None
    }

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

    supported_everywhere!();

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

        report(
            progress,
            &Msg::TaskCaddyParses {
                path: path.to_owned(),
            },
        );

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
    fn confirmation(&self) -> Confirmation {
        Confirmation::Change
    }

    supported_everywhere!();

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
            report(progress, &Msg::TaskCaddySnippetDefined);

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

        // After the validation, for the same reason `sshd_config` records
        // after its own: a file that did not parse is restored, so a record of
        // it would offer to put back what is already there.
        if let Some(ref backup) = backup {
            let kept = crate::backend::backup_index::record_existing(
                executor,
                files,
                self.id(),
                backup,
                backend.service_for(Capability::Caddy),
            );

            report(
                progress,
                if kept.is_some() {
                    &Msg::TaskChangeRecorded
                } else {
                    &Msg::TaskChangeNotRecorded
                },
            );
        }

        report(
            progress,
            &Msg::TaskCaddySnippetWritten {
                name: SNIPPET_NAME.to_owned(),
                path: path.to_owned(),
            },
        );
        report(
            progress,
            &Msg::TaskCaddyImportHint {
                name: SNIPPET_NAME.to_owned(),
            },
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

/// Removes the rootless Docker engine from one account.
///
/// The one inverse that is not a package removal, mirroring a forward task
/// that is not a package install: the engine is set up per account by
/// upstream's own script, so undoing it means running that script's `uninstall`
/// as the same account. The package is left alone — another account may be
/// running its own engine from it.
pub struct UninstallDockerRootless;

impl Task for UninstallDockerRootless {
    fn id(&self) -> &'static str {
        "docker-rootless.uninstall"
    }

    fn title(&self) -> &'static str {
        // Kept within the tree pane's width rather than widening the pane for
        // every row: "…from a user" says the same thing as "…from an account"
        // in five fewer cells, and the description below has the room to be
        // precise.
        "Remove rootless Docker from a user"
    }

    fn description(&self) -> &'static str {
        "Stops the account's engine, runs upstream's own uninstall as that \
         account, and stops it lingering. Containers, images and volumes under \
         the account's own directory are left: they are its data, not this \
         tool's. The Docker package stays, since another account may be \
         running an engine from it."
    }

    fn support(&self, family: Family) -> Support {
        InstallDockerRootless.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerRootless)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker-rootless.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(InstallDockerRootless::USER, "Username", ParamKind::Username)
                .with_hint("the account whose engine is removed")
                .suggesting_accounts()
                .naming_an_existing_account(),
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let user = values.get(InstallDockerRootless::USER)?.to_owned();
        let user_services = backend.user_services();

        report(
            progress,
            &Msg::TaskDisabling {
                unit: DOCKER_USER_SERVICE.to_owned(),
            },
        );

        user_services.disable_and_stop(executor, &user, DOCKER_USER_SERVICE)?;

        // Upstream's own script, run as the account for the same reason the
        // install is: it works inside that account's systemd directory, and as
        // root it would act on root's engine instead.
        let teardown = Command::new("runuser")
            .args(["-l", &user, "-c", "dockerd-rootless-setuptool.sh uninstall"])
            .privileged();

        crate::backend::systemd::run_checked(executor, &teardown)?;

        // Last, mirroring the install's "lingering first". Withdrawn after the
        // engine is gone rather than before: linger is what keeps a user's
        // units alive without a session, and revoking it first would race the
        // teardown that still needs them.
        user_services.disable_linger(executor, &user)?;

        report(
            progress,
            &Msg::TaskRemoving {
                what: format!("the rootless engine for {user}"),
            },
        );

        Ok(Outcome::Done)
    }
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
        let consequences = InstallDockerRootless
            .consequences(for_family(Family::Debian).as_ref(), &user_values("deploy"));

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
        let consequences =
            InstallCaddy.consequences(for_family(Family::Debian).as_ref(), &ParamValues::new());

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
