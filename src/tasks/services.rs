//! Workloads the server runs: a container engine and a web server.
//!
//! Both stop short of describing an application. `docker.install` provisions
//! the engine and does not run containers; `caddy.*` installs,
//! validates and hardens and does not write site configuration. Generating a
//! `reverse_proxy` block describes an application topology, which is where the
//! self-hosting panels live and where this tool deliberately does not go.

use crate::backend::{Backend, Capability};
use crate::distro::Family;
use crate::domain::binaries::{Artefact, Payload, Release};
use crate::domain::firewall::Protocol as FirewallProtocol;
use crate::error::{Error, Result};
use crate::exec::{Command, Executor};
use crate::i18n::Msg;
use crate::tasks::consequence::{
    Check, Consequence, External, Protocol, Reason, Requirement, firewall_check, program_check,
};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{
    Category, Confirmation, Node, Progress, Support, Task, report, supported_everywhere,
};

/// The user unit a rootless engine installs.
const DOCKER_USER_SERVICE: &str = "docker.service";

/// The engine's own binary, which every family puts on the PATH under this
/// name whichever repository the packages came from.
const DOCKER_BINARY: &str = "docker";

/// The web server's own binary, as every family puts it on `PATH`.
const CADDY_BINARY: &str = "caddy";

/// Upstream's rootless installer, for the one family that packages no script.
///
/// `--proto '=https' --tlsv1.2` matching how the repository managers fetch a
/// key, and `-o` writing to a file the shell then runs rather than piping
/// straight into `sh`: a download cut halfway through a pipe executes the half
/// that arrived. What none of that provides is authenticity — upstream
/// publishes no digest for this script, which is what
/// [`External::UnverifiedRootlessInstaller`] tells the operator before it runs.
const ROOTLESS_INSTALLER_SCRIPT: &str = "set -eu; \
     script=$(mktemp); \
     trap 'rm -f \"$script\"' EXIT; \
     curl -fsSL --proto '=https' --tlsv1.2 https://get.docker.com/rootless -o \"$script\"; \
     sh \"$script\"";

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
                vec![
                    // The engine first, because the rootless row below needs it
                    // installed and refuses without it. Two rows rather than
                    // one: an engine is installed once for the machine, and a
                    // rootless setup is done per account, which is a difference
                    // the single row could not express.
                    Node::Reversible {
                        forward: Box::new(InstallDockerEngine),
                        inverse: Box::new(UninstallDockerEngine),
                    },
                    Node::Reversible {
                        forward: Box::new(InstallDockerRootless),
                        inverse: Box::new(UninstallDockerRootless),
                    },
                ],
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

/// Installs the Docker engine for the machine.
///
/// The system half, split from [`InstallDockerRootless`] because the two have
/// different scopes: an engine is installed once for the host, and a rootless
/// setup is done per account. Keeping them one task made a single capability
/// resolve one package name for two jobs, and on three families the name it
/// resolved was wrong — see [`Capability::DockerEngine`].
pub struct InstallDockerEngine;

impl Task for InstallDockerEngine {
    fn id(&self) -> &'static str {
        "docker.install"
    }

    fn title(&self) -> &'static str {
        "Install the Docker engine"
    }

    fn description(&self) -> &'static str {
        "Installs the container engine for the whole machine and starts it. \
         Containers run as root this way: to give one account an engine of its \
         own instead, run the rootless task afterwards."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerEngine)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker.install"]
    }

    supported_everywhere!();

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Membership in `docker` is equivalent to root — the daemon socket
        // takes commands that mount the host filesystem — and an operator who
        // adds themselves to it to avoid typing `sudo` has made that trade
        // without being told. Reported rather than done: this task installs an
        // engine and does not decide who may drive it.
        vec![Consequence::External {
            note: External::DockerGroupIsRoot,
        }]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        report(progress, &Msg::TaskDockerEngineInstalling);

        // Where the distribution packages no Docker, the engine comes from
        // Docker's own repository — registered only if its signing key matches
        // a fingerprint this build carries from sources the serving host does
        // not control. Registered before the install rather than as part of it,
        // so a key that does not match stops here with nothing changed.
        if let (Some(repositories), Some(repository)) = (
            backend.repositories(),
            backend.repository_for(Capability::DockerEngine),
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

        // Every name in one invocation, which is why `install` takes a slice:
        // upstream's page lists five packages on the families served from its
        // own repository, and installing them one at a time would leave a host
        // holding two of five if the third failed.
        let packages = engine_packages(backend);

        backend.packages().install(executor, &packages)?;

        let service = backend.service_for(Capability::DockerEngine);

        backend.services().enable_and_start(executor, service)?;

        // Read back rather than assumed, the way `ssh.install` does: `enable
        // --now` exiting zero says the command ran, and a daemon that failed
        // after that point would otherwise be reported as running. Both halves
        // are shown because they are independent — a daemon running but not
        // enabled is gone after the next reboot.
        let state = backend.services().state(executor, service)?;

        report(
            progress,
            &Msg::TaskUnitState {
                unit: service.to_owned(),
                active: state.active,
                enabled: state.enabled,
            },
        );

        Ok(Outcome::Done)
    }
}

/// Every package the engine needs on this family.
///
/// A free function rather than a method because the fallback belongs to the
/// caller: `packages_for` answers empty for the families whose engine is a
/// single package, and the single name is what `package_for` already resolved.
fn engine_packages(backend: &dyn Backend) -> Vec<&'static str> {
    let listed = backend.packages_for(Capability::DockerEngine);

    if listed.is_empty() {
        vec![backend.package_for(Capability::DockerEngine)]
    } else {
        listed.to_vec()
    }
}

/// Installs the rootless Docker engine for one account.
pub struct InstallDockerRootless;

impl InstallDockerRootless {
    /// Name of the parameter holding the account the engine runs as.
    pub const USER: &'static str = "user";
}

impl Task for InstallDockerRootless {
    fn id(&self) -> &'static str {
        "docker.rootless"
    }

    fn title(&self) -> &'static str {
        "Run Docker rootless for a user"
    }

    fn description(&self) -> &'static str {
        "Sets up the engine under one account rather than as root, so a \
         container escape lands in an ordinary user rather than on the machine. \
         Needs the engine installed first. The account keeps its services \
         running after logout."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerRootless)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker.rootless"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::USER, "Username", ParamKind::Username)
                .with_hint("the account the engine runs as")
                .suggesting_accounts()
                .naming_an_existing_account(),
        ]
    }

    /// The rootless setup configures an engine; the engine is installed once for the machine.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("docker", "docker.install")]
    }
    fn support(&self, family: Family) -> Support {
        match family {
            // Four families package the setup script, whether as part of the
            // engine or beside it, and give the account a systemd instance to
            // install it into.
            Family::Debian | Family::Rhel | Family::Suse => Support::Yes,
            // Arch has the per-user manager and not the script: measured on
            // `archlinux:latest`, `pacman -F dockerd-rootless-setuptool.sh`
            // finds nothing and no official package lists a rootless file.
            // Supported through upstream's installer, which the task asks about
            // before running because it is the one route here that fetches code
            // no digest covers.
            Family::Arch => Support::Yes,
            Family::Alpine => Support::No(
                "no per-user service manager at all: the engine runs under the \
                 account's own systemd instance, and OpenRC has no equivalent",
            ),
        }
    }

    fn consequences(&self, backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // Rootless containers cannot bind below 1024 without this, and the
        // failure reads as a container problem rather than a kernel setting.
        let mut consequences = vec![Consequence::Invalidates {
            task: "sysctl.unprivileged-ports",
            reason: Reason::RequiresSetting {
                setting: "net.ipv4.ip_unprivileged_port_start",
            },
            check: Some(Check {
                command: Command::new("sysctl").args(["-n", "net.ipv4.ip_unprivileged_port_start"]),
                resolved_when_stdout_contains: "80".to_owned(),
            }),
        }];

        // Only on the family where the script cannot come from a package.
        // Stating it everywhere would be a warning nobody can act on, which
        // teaches people to dismiss the ones that matter.
        if backend.family() == Family::Arch {
            consequences.push(Consequence::External {
                note: External::UnverifiedRootlessInstaller,
            });
        }

        consequences
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

        // The engine before anything else. This task used to install it as a
        // side effect, which is what made one task mean two scopes; now it
        // depends on the other having run, and says so rather than installing
        // a system-wide daemon from a task asked about one account.
        if !engine_is_present(executor, backend)? {
            return Err(Error::DockerEngineAbsent);
        }

        let user_services = backend.user_services();

        // Checked before anything is installed: an account with no subordinate
        // range cannot start a single container, and finding that out after
        // the engine is installed wastes the install.
        if !user_services.has_subordinate_ids(executor, &user)? {
            return Err(Error::NoSubordinateIds { user });
        }

        // And for the same reason: the engine runs under the account's own
        // service manager, so an account whose session cannot be established
        // has nothing to install it into. `runuser -l` is what opens that
        // session and `pam_systemd` is what furnishes it, listed on Debian as
        // `-session optional` — it fails without logging, leaving a shell with
        // an empty environment. Left to be discovered at `enable --now`, the
        // install has already happened and what surfaces is systemd's own
        // message about two unset variables, naming no cause.
        if !user_services.session_is_reachable(executor, &user)? {
            return Err(Error::NoUserSession { user });
        }

        report(progress, &Msg::TaskDockerInstalling { user: user.clone() });

        // What the account needs beyond the engine, where the family packages
        // it: `docker-ce-rootless-extras` on the two served by Docker's own
        // repository, `docker-rootless-extras` on openSUSE, `rootlesskit` on
        // Arch. The repository, where there is one, was registered by
        // `docker.install` — which this task has already checked ran.
        if backend.has_package_for(Capability::DockerRootless) {
            backend
                .packages()
                .install(executor, &[backend.package_for(Capability::DockerRootless)])?;
        }

        // Lingering first. Without it the engine stops when the account's last
        // session ends, and because a user unit is wanted by `default.target`
        // rather than by anything reached at boot, nothing brings it back after
        // a reboot either.
        if !user_services.is_lingering(executor, &user)? {
            user_services.enable_linger(executor, &user)?;
            report(progress, &Msg::TaskLingerEnabled { user: user.clone() });
        }

        run_rootless_setup(executor, backend, &user, progress)?;

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

/// Whether the system engine is installed.
///
/// Asked of the binary rather than of a package name, for the reason
/// `tui::probe` records about `sshd`: the engine may have arrived from the
/// distribution's repositories or from Docker's, under different names, and
/// `docker` is what both put on the PATH.
///
/// `is_installed` rather than `is_installed_here`, for the reason
/// [`caddy_is_present`] spells out below and `sshd_is_present` records having
/// been fixed for: the latter asks whether *this tool's* copy sits in
/// `/usr/local/bin`, and no route to Docker writes there. Both the
/// distribution's package and Docker's own repository install `/usr/bin/docker`,
/// so asking that way refused every host that had an engine — and
/// `docker.install` could not repair it, since installing the package lands in
/// the directory the check was not looking at.
fn engine_is_present(executor: &dyn Executor, backend: &dyn Backend) -> Result<bool> {
    backend.binaries().is_installed(executor, DOCKER_BINARY)
}

/// Whether this host has the web server.
///
/// Asked of the binary rather than of a package for the same reason as the
/// engine above, and with a sharper edge here: RHEL has no Caddy package at
/// all, so `caddy.install` there fetches a release binary that no package
/// manager knows about. A presence check reading the package database would
/// answer "absent" on a host serving traffic.
///
/// `is_installed` rather than `is_installed_here`: the latter asks about this
/// tool's own install directory, which would refuse a Caddy the distribution
/// packaged into `/usr/bin`.
fn caddy_is_present(executor: &dyn Executor, backend: &dyn Backend) -> Result<bool> {
    backend.binaries().is_installed(executor, CADDY_BINARY)
}

/// Runs upstream's rootless setup as the account.
///
/// Two routes, and which one a family takes is about whether the script can
/// come from a package. Where it can, it is already on the PATH and this runs
/// it. Arch is the exception the `Confirmation` above warns about: no official
/// package ships it, so the script is fetched from `get.docker.com/rootless`,
/// which publishes no per-artefact digest to check it against.
fn run_rootless_setup(
    executor: &dyn Executor,
    backend: &dyn Backend,
    user: &str,
    progress: Progress<'_>,
) -> Result<()> {
    // Run as the account rather than as root: the script writes into that
    // account's own systemd directory, and as root it would install an engine
    // for root.
    let script = if backend.family() == Family::Arch {
        report(progress, &Msg::TaskDockerFetchingInstaller);

        // `-o` on the pipeline so a failed download does not reach `sh`, and
        // `--proto '=https' --tlsv1.2` matching how the repository managers
        // fetch a key. What this cannot do is verify what arrives: upstream
        // publishes no digest for it, which is what the confirmation said.
        ROOTLESS_INSTALLER_SCRIPT
    } else {
        "dockerd-rootless-setuptool.sh install"
    };

    let setup = Command::new("runuser")
        .args(["-l", user, "-c", script])
        .privileged();

    crate::backend::systemd::run_checked(executor, &setup)
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
        payload: Payload::Member("caddy"),
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
                task: "firewall.manage-ports",
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
                .install(executor, &[backend.package_for(Capability::Caddy)])?;

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
            let release = crate::backend::release_installer::newest(Self::RELEASES)?;

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

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Caddy)
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

    /// Asking Caddy whether a file parses needs Caddy.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("caddy", "caddy.install")]
    }
    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // A missing server is a different answer from a broken configuration,
        // and without this it arrived as `ProgramNotFound` — a sentence about
        // `PATH` in front of an operator who asked whether their config parses.
        if !caddy_is_present(executor, backend)? {
            return Err(Error::CaddyAbsent);
        }

        let path = backend.path_for(Capability::Caddy);

        // A configuration that is not there is also not the same as one that
        // does not parse. Left to Caddy, an absent file comes back as
        // `InvalidCaddyfile` carrying `open …: no such file` — which reads as a
        // syntax error in a file the operator may never have created, and sends
        // them to edit something that does not exist.
        if !backend.files().exists(executor, path)? {
            return Err(Error::CaddyfileAbsent {
                path: path.to_owned(),
            });
        }

        // Asked of Caddy rather than grepped out of the file. The directive
        // order in a Caddyfile is not its source order, so reading the text
        // says less about the running configuration than it appears to.
        let command = Command::new(CADDY_BINARY)
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

    /// The snippet is validated by Caddy itself, so the server has to be here.
    ///
    /// The guard in `run` already refuses without it and names the same task;
    /// this is that fact where the tree can read it, so the row says so before
    /// a key is pressed rather than after.
    fn requires(&self, _backend: &dyn Backend) -> Vec<Requirement> {
        vec![program_check("caddy", "caddy.install")]
    }
    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // Before the file is touched, because the validation that would have
        // caught this runs *after* the write. `executor.run` on a missing
        // binary raises `ProgramNotFound`, and `?` carried it past the branch
        // that restores the backup — so a host with no Caddy got the snippet
        // written, no rollback, and an error naming `PATH` rather than the task
        // that installs the server. Asked of the binary rather than a package
        // name for the reason `engine_is_present` records: on RHEL this arrives
        // as a release binary that no package manager knows about.
        if !caddy_is_present(executor, backend)? {
            return Err(Error::CaddyAbsent);
        }

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
        crate::backend::backup_index::record_and_report(
            executor,
            files,
            self.id(),
            backup.as_ref(),
            backend.service_for(Capability::Caddy),
            progress,
        );

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

/// Removes the Docker engine from the machine.
///
/// The system half's inverse, and an ordinary package removal unlike the
/// rootless one below. What it deliberately does not touch is
/// `/var/lib/docker`: images, volumes and containers are the operator's data,
/// and a removal that discarded them would be doing something nobody asked for
/// and nothing could undo.
pub struct UninstallDockerEngine;

impl Task for UninstallDockerEngine {
    fn id(&self) -> &'static str {
        "docker.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall the Docker engine"
    }

    fn description(&self) -> &'static str {
        "Stops the engine, disables it at boot, and removes it. Images, \
         volumes and containers under /var/lib/docker are left alone: they are \
         your data, and nothing here could put them back. Accounts running a \
         rootless engine keep theirs."
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerEngine)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::DockerEngine)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        // The rootless engines are user units that run the same binaries this
        // removes. Stated rather than checked: which accounts have one is a
        // question no single command answers, since each lives in its own home.
        vec![Consequence::Invalidates {
            task: "docker.rootless",
            reason: Reason::RequiresSetting {
                setting: "the engine these accounts run from",
            },
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
            Capability::DockerEngine,
            "docker",
        )
    }
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
        "docker.rootless-off"
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
         tool's. The engine itself stays, since the machine and other accounts \
         may still be using it."
    }

    fn support(&self, family: Family) -> Support {
        InstallDockerRootless.support(family)
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::DockerRootless)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["docker.rootless"]
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

        // Before the session is asked about, because an account that does not
        // exist has no session either and the two are not the same finding.
        // Measured: `user=noexiste` reported the service manager unreachable,
        // which is true, useless, and sends the reader to `systemd-logind` over
        // a typo. The install has always checked this; the inverse had not.
        if !backend.accounts().exists(executor, &user)? {
            return Err(Error::NoSuchAccount { user });
        }

        let user_services = backend.user_services();

        // Asked here as well as in the install, because the two run at
        // different times and the second cannot assume what the first left. A
        // host rebooted since, or one whose `systemd-logind` has stopped, has
        // an account whose service manager is no longer reachable — and this is
        // the task that was reported failing: `runuser -l deploy -c 'systemctl
        // --user disable --now docker.service'` answered `Failed to connect to
        // user scope bus`, which named two unset variables and no cause.
        //
        // Refused rather than skipped. A teardown that ran on regardless would
        // remove the engine's files while leaving a unit nothing stopped, and
        // report success over a half-removed install.
        if !user_services.session_is_reachable(executor, &user)? {
            return Err(Error::NoUserSession { user });
        }

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
        //
        // Where the install fetched the script rather than finding it in a
        // package, it left it in the account's own `~/bin` — so that is where
        // the uninstall looks. Running the bare name there would find nothing
        // and fail a teardown whose unit was already stopped above.
        let teardown_script = if backend.family() == Family::Arch {
            "$HOME/bin/dockerd-rootless-setuptool.sh uninstall"
        } else {
            "dockerd-rootless-setuptool.sh uninstall"
        };

        let teardown = Command::new("runuser")
            .args(["-l", &user, "-c", teardown_script])
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
        let backend = backend_for(family);
        let outcome = task.run(&mock, backend.as_ref(), values, &mut |_| {});

        (outcome, mock.recorded_lines())
    }

    /// A backend built the way [`crate::backend::for_distro`] builds one.
    ///
    /// `for_family` cannot serve here: Debian's Docker repository is keyed by
    /// suite, and a backend built without one refuses to register rather than
    /// guessing a codename. That refusal is correct on a host declaring no
    /// `VERSION_CODENAME` and wrong in a test meaning to exercise the install,
    /// so the scenarios state a distribution as a real one would.
    fn backend_for(family: Family) -> Box<dyn Backend> {
        match family {
            Family::Debian => Box::new(crate::backend::debian::DebianBackend::for_distribution(
                "debian",
                Some("trixie"),
            )),
            other => for_family(other),
        }
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
                Reply::ok("/usr/bin/docker"), // the engine is installed
                Reply::ok(""),                // subuid names it
                Reply::failure(1, ""),        // subgid does not
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
        // Each name measured in that family's own container rather than read
        // off a page. This test asserted Arch's `docker` carried the rootless
        // setup script; `pacman -F` finds no package that does, which is why
        // the name here is `rootlesskit` and the task fetches the script.
        let debian = for_family(Family::Debian);
        let arch = for_family(Family::Arch);
        let suse = for_family(Family::Suse);

        assert_eq!(
            debian.package_for(Capability::DockerRootless),
            "docker-ce-rootless-extras"
        );
        assert_eq!(arch.package_for(Capability::DockerRootless), "rootlesskit");
        assert_eq!(
            suse.package_for(Capability::DockerRootless),
            "docker-rootless-extras"
        );
    }

    #[test]
    fn the_engine_is_every_package_upstream_lists_not_just_the_first() {
        // The defect the split exists to fix. `docker-ce-rootless-extras`
        // declares `Enhances: docker-ce`, which apt honours as a suggestion:
        // measured on `debian:13`, installing it alone brings in rootlesskit
        // and the two scripts and leaves the host with no daemon and no client.
        // So the engine must name all five, and asking for one would reproduce
        // exactly the bug that shipped.
        let debian = backend_for(Family::Debian);

        assert_eq!(
            engine_packages(debian.as_ref()),
            vec![
                "docker-ce",
                "docker-ce-cli",
                "containerd.io",
                "docker-buildx-plugin",
                "docker-compose-plugin",
            ]
        );

        // And the families whose engine genuinely is one package still answer
        // one, through the fallback rather than through a list repeated in
        // every backend.
        assert_eq!(
            engine_packages(backend_for(Family::Arch).as_ref()),
            vec!["docker"]
        );
    }

    #[test]
    fn the_five_engine_packages_reach_the_package_manager_together() {
        // One transaction rather than five. A loop installing them one at a
        // time leaves a host holding two of five when the third fails, and
        // `install` taking a slice is what makes that unrepresentable.
        let (outcome, commands) = run(
            &InstallDockerEngine,
            Family::Debian,
            vec![
                Reply::failure(1, ""), // repo absent
                // What `register` installs before it can read a key at all:
                // neither curl nor gpg is on a bare Debian image.
                Reply::ok(""), // apt-get update
                Reply::ok(""), // apt-get install curl gnupg
                Reply::ok("9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n"), // key checks out
                Reply::ok(""), // install -d keyring
                Reply::ok(""), // fetch key
                Reply::ok(""), // write source
                Reply::ok(""), // apt-get update (repo)
                Reply::ok(""), // apt-get update (install)
                Reply::ok(""), // install
                Reply::ok(""), // enable --now
                Reply::ok("active"), // is-active
                Reply::ok("enabled"), // is-enabled
            ],
            &ParamValues::default(),
        );

        outcome.expect("the install must succeed");

        // The *last* apt-get install, not the first: `register` runs one of its
        // own for `curl` and `gnupg` before the key can be read, and matching
        // that one would assert the five packages against a command that never
        // names them.
        let install = commands
            .iter()
            .rfind(|c| c.contains("apt-get") && c.contains("install"))
            .expect("the engine must be installed");

        for package in [
            "docker-ce",
            "docker-ce-cli",
            "containerd.io",
            "docker-buildx-plugin",
            "docker-compose-plugin",
        ] {
            assert!(
                install.contains(package),
                "{package} must be in the same transaction: {install}"
            );
        }
    }

    #[test]
    fn arch_fetches_the_setup_script_and_every_other_family_runs_the_packaged_one() {
        // The one family whose rootless route is not a package, and the branch
        // nothing was asserting: every other test here runs Debian, so the Arch
        // arm could have selected the wrong script in either direction and the
        // suite would have agreed. That is the gap this change's own note in
        // CLAUDE.md warns about — a test that only exercises the refusal proves
        // nothing about what the task does.
        //
        // Pinned in both directions, because a branch that always fetched would
        // be just as wrong as one that never did: Debian has the script in a
        // package and must not reach the network for it.
        let replies = || {
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok("/usr/bin/docker"), // the engine is installed
                Reply::ok(""),                // subuid
                Reply::ok(""),                // subgid
                Reply::ok("/run/user/1001"),  // the session is reachable
                Reply::ok(""),                // pacman -Sy / apt-get update
                Reply::ok(""),                // install
                Reply::ok("Linger=yes"),      // already lingering
                Reply::ok(""),                // the setup script
                Reply::ok(""),                // enable --now
                Reply::ok("active"),          // is-active
            ]
        };

        let (arch, arch_commands) = run(
            &InstallDockerRootless,
            Family::Arch,
            replies(),
            &user_values("deploy"),
        );

        arch.expect("the Arch install must succeed");

        assert!(
            arch_commands
                .iter()
                .any(|c| c.contains("get.docker.com/rootless")),
            "Arch must fetch the script no package provides: {arch_commands:?}"
        );

        let (debian, debian_commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            replies(),
            &user_values("deploy"),
        );

        debian.expect("the Debian install must succeed");

        assert!(
            debian_commands
                .iter()
                .any(|c| c.contains("dockerd-rootless-setuptool.sh install")),
            "Debian must run the packaged script: {debian_commands:?}"
        );
        assert!(
            !debian_commands.iter().any(|c| c.contains("get.docker.com")),
            "and must not reach the network for it: {debian_commands:?}"
        );
    }

    #[test]
    fn the_arch_teardown_looks_where_the_arch_install_put_the_script() {
        // The mirror of the branch above, and the half easier to forget: on
        // Arch the script was never in a package, so upstream's installer left
        // it under the account's own `~/bin`. A teardown running the bare name
        // there finds nothing and fails a removal whose unit was already
        // stopped — reported as the uninstall being broken rather than as the
        // script being somewhere else.
        let (outcome, commands) = run(
            &UninstallDockerRootless,
            Family::Arch,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok("/run/user/1001"), // the session is reachable
                Reply::ok(""),               // disable --now
                Reply::ok(""),               // the teardown script
                Reply::ok(""),               // disable-linger
            ],
            &user_values("deploy"),
        );

        outcome.expect("the Arch teardown must succeed");

        assert!(
            commands
                .iter()
                .any(|c| c.contains("$HOME/bin/dockerd-rootless-setuptool.sh uninstall")),
            "the teardown must look in ~/bin on Arch: {commands:?}"
        );
    }

    #[test]
    fn the_rootless_setup_is_refused_where_no_engine_is_installed() {
        // The dependency the split creates, and the reason it is named rather
        // than left to upstream's script: that script reports a missing daemon
        // in terms naming neither this tool nor the task that installs one.
        let (outcome, commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::failure(1, ""), // `command -v docker` finds nothing
            ],
            &user_values("deploy"),
        );

        let err = outcome.expect_err("a host with no engine must be refused");

        assert!(matches!(err, Error::DockerEngineAbsent), "{err:?}");
        assert!(
            !commands.iter().any(|c| c.contains("setuptool")),
            "the setup script must not run: {commands:?}"
        );
    }

    #[test]
    fn the_engine_is_looked_for_where_docker_actually_installs() {
        // The assertion the two tests around this one could not make. Both feed
        // a positional `MockExecutor`, which hands back the next reply whatever
        // was asked — so the reply labelled `command -v docker` satisfied
        // `test -f /usr/local/bin/docker` just as happily, and the comment was
        // the only thing claiming which question was asked.
        //
        // It was the wrong one. `/usr/local/bin` is this tool's own directory
        // for release binaries; no route to Docker writes there. The engine
        // arrives at `/usr/bin/docker` from the distribution's package and from
        // Docker's repository alike, so the check refused every host that had
        // one — and `docker.install` could not clear it, which made the task
        // permanently unrunnable rather than merely blocked.
        let (outcome, commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok("/usr/bin/docker"),
                Reply::ok(""),               // subuid
                Reply::ok(""),               // subgid
                Reply::ok("/run/user/1001"), // the session is reachable
                Reply::ok(""),               // apt-get update
                Reply::ok(""),               // install
                Reply::ok("Linger=yes"),     // already lingering
                Reply::ok(""),               // the setup script
                Reply::ok(""),               // enable --now
                Reply::ok("active"),         // is-active
            ],
            &user_values("deploy"),
        );

        outcome.expect("a host with /usr/bin/docker has an engine");

        assert!(
            commands.iter().any(|c| c.contains("command -v docker")),
            "the engine must be looked for on the PATH: {commands:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("/usr/local/bin/docker")),
            "and never in this tool's own install directory: {commands:?}"
        );
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
                Reply::ok("/usr/bin/docker"), // the engine is installed
                Reply::ok(""),                // subuid
                Reply::ok(""),                // subgid
                // `printenv XDG_RUNTIME_DIR` as the account: a populated value
                // is a session `systemctl --user` can address.
                Reply::ok("/run/user/1001"),
                // No repository registration here any more: `docker.install`
                // does that, and this task refuses when it has not run.
                Reply::ok(""),          // apt-get update, which every install runs
                Reply::ok(""),          // install the rootless extras
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
    fn an_unreachable_session_is_refused_before_anything_is_installed() {
        // Reported from a Debian 13 host, on the uninstall half:
        // `runuser -l deploy -c 'systemctl --user disable --now docker.service'`
        // answered `Failed to connect to user scope bus via local transport:
        // $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined`.
        //
        // `runuser -l` is relied on to establish the session that furnishes
        // those variables, and `pam_systemd` — listed on Debian as
        // `-session optional`, so silent when it fails — is what furnishes
        // them. Reproduced under systemd as PID 1 by preventing logind from
        // creating a session: the shell starts, the environment is empty.
        //
        // Refused here rather than discovered at `enable --now`, by which point
        // the engine is installed and what surfaces is systemd's message naming
        // two variables and no cause.
        let (outcome, commands) = run(
            &InstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::ok("/usr/bin/docker"), // the engine is installed
                Reply::ok(""),                // subuid
                Reply::ok(""),                // subgid
                // The session was never established, so `printenv` exits
                // non-zero with nothing on stdout.
                Reply::failure(1, ""),
            ],
            &user_values("deploy"),
        );

        let err = outcome.expect_err("an unreachable session must be refused");

        assert!(
            matches!(err, Error::NoUserSession { ref user } if user == "deploy"),
            "the error must name the account: {err:?}"
        );

        // What the refusal is *for*: nothing may have been installed by the
        // time it happens. An error raised after the install would be correct
        // and useless.
        assert!(
            !commands.iter().any(|command| command.contains("apt-get")),
            "nothing may be installed before the session is known good: {commands:?}"
        );
    }

    #[test]
    fn an_unreachable_session_stops_the_uninstall_rather_than_half_removing_it() {
        // The half that was actually reported. Asked again here rather than
        // trusted from the install, because the two run at different times: a
        // host rebooted since, or one whose `systemd-logind` has stopped, has
        // an account whose service manager is no longer reachable.
        //
        // Refused rather than skipped, because the teardown that follows
        // removes the engine's files. Running it over a unit nothing could stop
        // leaves a half-removed install reported as a success.
        let (outcome, commands) = run(
            &UninstallDockerRootless,
            Family::Debian,
            vec![
                Reply::ok("deploy:x:1001:1001::/home/deploy:/bin/bash"),
                Reply::failure(1, ""), // no session
            ],
            &user_values("deploy"),
        );

        let err = outcome.expect_err("an unreachable session must be refused");

        assert!(
            matches!(err, Error::NoUserSession { ref user } if user == "deploy"),
            "the error must name the account: {err:?}"
        );
        assert!(
            !commands
                .iter()
                .any(|command| command.contains("setuptool") || command.contains("disable")),
            "neither the teardown nor the disable may run: {commands:?}"
        );
    }

    #[test]
    fn removing_from_an_account_that_does_not_exist_says_so() {
        // Measured against the binary: `user=noexiste` reported the service
        // manager unreachable, which is true of an account that is not there
        // and sends the reader to `systemd-logind` over a typo. The install has
        // always made this check; its inverse had not.
        let (outcome, _) = run(
            &UninstallDockerRootless,
            Family::Debian,
            vec![Reply::failure(1, "")], // getent: no such account
            &user_values("noexiste"),
        );

        let err = outcome.expect_err("a missing account must be refused");

        assert!(
            matches!(err, Error::NoSuchAccount { ref user } if user == "noexiste"),
            "the error must name the account, not the session: {err:?}"
        );
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
                Reply::ok("/usr/bin/docker"), // the engine is installed
                Reply::ok(""),                // subuid
                Reply::ok(""),                // subgid
                Reply::ok("/run/user/1001"),  // the session is reachable
                Reply::ok(""),                // apt-get update, before the install
                Reply::ok(""),                // install
                Reply::ok("Linger=yes"),      // already lingering
                Reply::ok(""),                // setuptool
                Reply::ok(""),                // enable --now
                Reply::ok("inactive"),        // enabled, not running
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
            vec![
                Reply::ok(""), // caddy is installed
                Reply::ok(""), // the Caddyfile exists
                Reply::failure(1, "unrecognized directive: reverse_prox"),
            ],
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
    fn validating_without_caddy_names_the_task_that_installs_it() {
        // `ProgramNotFound` is what this used to be: a sentence about `PATH` in
        // front of an operator who asked whether their configuration parses.
        let (outcome, _) = run(
            &ValidateCaddy,
            Family::Debian,
            vec![Reply::failure(1, "")], // caddy is not installed
            &ParamValues::new(),
        );

        assert!(
            matches!(outcome, Err(Error::CaddyAbsent)),
            "the refusal must name the missing server: {outcome:?}"
        );
    }

    #[test]
    fn a_missing_caddyfile_is_not_reported_as_a_broken_one() {
        // Caddy reports an absent file through the same channel as a syntax
        // error, so left to it the operator is sent to edit something that does
        // not exist.
        let (outcome, _) = run(
            &ValidateCaddy,
            Family::Debian,
            vec![
                Reply::ok(""),         // caddy is installed
                Reply::failure(1, ""), // the Caddyfile does not exist
            ],
            &ParamValues::new(),
        );

        assert!(
            matches!(outcome, Err(Error::CaddyfileAbsent { .. })),
            "an absent file is not an invalid one: {outcome:?}"
        );
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
                Reply::ok(""),                    // caddy is installed
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
            vec![Reply::ok(""), Reply::ok(""), Reply::ok(existing)],
            &ParamValues::new(),
        );

        outcome.expect("an existing snippet is the desired state");

        assert!(
            !commands.iter().any(|c| c.contains("tee")),
            "nothing must be written: {commands:?}"
        );
    }

    #[test]
    fn the_snippet_is_not_written_on_a_host_with_no_caddy() {
        // The validation that would have caught this runs *after* the write,
        // and `ProgramNotFound` propagated past the branch that restores the
        // backup — so the snippet stayed on disk, unvalidated, under an error
        // naming `PATH`. Checked before the file is touched instead.
        let (outcome, commands) = run(
            &CaddySecurityHeaders,
            Family::Debian,
            vec![Reply::failure(1, "")], // caddy is not installed
            &ParamValues::new(),
        );

        assert!(
            matches!(outcome, Err(Error::CaddyAbsent)),
            "the refusal must name the missing server: {outcome:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("tee")),
            "and nothing may be written: {commands:?}"
        );
    }
}
