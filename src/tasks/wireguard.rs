//! WireGuard server and peers.
//!
//! Sourced from shell scripts that ran in production, with the bugs those
//! scripts had fixed rather than reproduced. The three that mattered:
//!
//! - `AllowedIPs = 0.0.0.0/0` on a client without `::/0` leaks IPv6. The host
//!   keeps its own IPv6 route, so traffic to a dual-stack destination leaves
//!   outside the tunnel while the tunnel reports itself up.
//! - Addresses were handed out by scanning `10.89.0.2` to `.254` inside a `/16`,
//!   which exhausts at 253 peers with 65,000 free.
//! - `PostUp` hard-coded `iptables`, which does nothing on an nftables-only
//!   host — a VPN that connects and routes nothing.

use std::fmt::Write as _;

use crate::backend::{Backend, Capability};
use crate::domain::firewall::Protocol as FirewallProtocol;
use crate::domain::sysctl::Setting;
use crate::error::{Error, Result};
use crate::exec::Executor;
use crate::i18n::Msg;
use crate::tasks::consequence::{
    Check, Consequence, External, Protocol as WarnProtocol, Reason, firewall_check,
};
use crate::tasks::params::{Param, ParamKind, ParamValues};
use crate::tasks::revert::Outcome;
use crate::tasks::{
    Category, Confirmation, Node, Progress, Task, report, report_secret, report_verbatim,
    supported_everywhere,
};

/// The interface this tool manages.
///
/// Fixed rather than asked for: a second interface is a different topology,
/// not a different value, and offering the name invites `wg0` to be typed into
/// a tool that already manages one.
const INTERFACE: &str = "wg0";

/// The port WireGuard listens on unless told otherwise.
const DEFAULT_PORT: u32 = 51_820;

/// Mode for `wg0.conf`, which holds the server's private key.
const CONFIG_MODE: u32 = 0o600;

/// Mode for `/etc/wireguard`, which holds every key.
const CONFIG_DIR_MODE: u32 = 0o700;

/// Forwarding, without which the server routes nothing for its peers.
const IP_FORWARD: Setting = Setting {
    key: "net.ipv4.ip_forward",
    value: "1",
};

/// Builds the WireGuard category.
pub fn category() -> Category {
    Category::new(
        "WireGuard",
        // Install first, then status, then peers — the order the operations
        // actually happen in. Status led the list by the same reasoning the
        // firewall category uses, that knowing the state precedes changing it;
        // that holds where the thing exists, and WireGuard is the category an
        // operator most often opens on a host that has none. A status row above
        // the install answers "no tunnel is configured" to somebody who has not
        // configured one yet.
        vec![
            Node::Reversible {
                forward: Box::new(InstallWireguard),
                inverse: Box::new(UninstallWireguard),
            },
            Node::Task(Box::new(WireguardStatus)),
            Node::Task(Box::new(AddPeer)),
        ],
    )
}

/// Reports whether the tunnel is up and who is on it.
///
/// Beside the firewall's own status task, and for the same reason: the state
/// worth knowing before changing anything is the state the system is actually
/// in, not the one the last run left behind.
pub struct WireguardStatus;

impl Task for WireguardStatus {
    /// Reads the interface's state; nothing is written.
    fn confirmation(&self) -> Confirmation {
        Confirmation::None
    }

    fn id(&self) -> &'static str {
        "wireguard.status"
    }

    fn title(&self) -> &'static str {
        "Show the WireGuard status"
    }

    fn description(&self) -> &'static str {
        "Reports whether the tunnel interface is up and how many peers are \
         configured. Changes nothing."
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        _values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let config = format!(
            "{}/{INTERFACE}.conf",
            backend.path_for(Capability::Wireguard)
        );

        if !backend.files().exists(executor, &config)? {
            report(progress, &Msg::TaskWireguardNotConfigured);

            return Ok(Outcome::Done);
        }

        // Both are asked, because either alone misleads: a configured
        // interface that is down carries nothing, and an interface that is up
        // with no peers admits nobody.
        if backend.wireguard().is_up(executor, INTERFACE)? {
            report(
                progress,
                &Msg::TaskWireguardUp {
                    interface: INTERFACE.to_owned(),
                },
            );
        } else {
            report(
                progress,
                &Msg::TaskWireguardDown {
                    interface: INTERFACE.to_owned(),
                },
            );
        }

        let peers = backend
            .files()
            .read(executor, &config)?
            .lines()
            .filter(|line| line.trim() == "[Peer]")
            .count();

        report(progress, &Msg::TaskWireguardPeerCount { count: peers });

        Ok(Outcome::Done)
    }
}

/// Installs WireGuard and writes the server configuration.
pub struct InstallWireguard;

impl InstallWireguard {
    /// Name of the parameter holding the tunnel subnet.
    pub const SUBNET: &'static str = "subnet";
    /// Name of the parameter holding the listening port.
    pub const PORT: &'static str = "port";
}

impl Task for InstallWireguard {
    fn id(&self) -> &'static str {
        "wireguard.install"
    }

    fn title(&self) -> &'static str {
        "Install the WireGuard server"
    }

    fn description(&self) -> &'static str {
        "Installs WireGuard, generates the server keys and writes wg0.conf. \
         The tunnel carries no traffic until forwarding is enabled and the \
         port is open."
    }

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Wireguard)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["wireguard.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::SUBNET, "Tunnel subnet", ParamKind::Cidr)
                .with_initial("10.89.0.0/24")
                .with_hint("private range for the tunnel"),
            Param::new(Self::PORT, "Listen port", ParamKind::Port)
                .with_initial(DEFAULT_PORT.to_string())
                .with_hint("UDP"),
        ]
    }

    supported_everywhere!();

    fn consequences(&self, backend: &dyn Backend, values: &ParamValues) -> Vec<Consequence> {
        let Ok(port) = values.port(Self::PORT) else {
            return Vec::new();
        };

        vec![
            // A tunnel without forwarding establishes, reports itself up, and
            // routes nothing — the failure looks like a client problem.
            Consequence::Invalidates {
                task: "sysctl.ip-forward",
                reason: Reason::RequiresSetting {
                    setting: IP_FORWARD.key,
                },
                check: Some(Check {
                    command: crate::exec::Command::new("sysctl").args(["-n", IP_FORWARD.key]),
                    resolved_when_stdout_contains: IP_FORWARD.value.to_owned(),
                }),
            },
            // UDP, and the distinction is the point: a TCP rule for this port
            // admits none of WireGuard's traffic.
            //
            // The query comes from whichever front-end holds this host's
            // ruleset. Spelling `nft` here would be right on four families and
            // wrong on the fifth: RHEL runs firewalld, so the rule lives in a
            // zone and `nft list table inet initd` names a table that does not
            // exist — an answer of "still to do" for a port already open.
            Consequence::Invalidates {
                task: "firewall.manage-ports",
                reason: Reason::RequiresSetting {
                    setting: "an inbound UDP rule for this port",
                },
                check: firewall_check(backend, port, FirewallProtocol::Udp),
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port,
                    protocol: WarnProtocol::Udp,
                },
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let subnet = values.get(Self::SUBNET)?.to_owned();
        let port = values.port(Self::PORT)?;

        let dir = backend.path_for(Capability::Wireguard);
        let config = format!("{dir}/{INTERFACE}.conf");
        let files = backend.files();

        if files.exists(executor, &config)? {
            // Overwriting would discard the server key every existing peer is
            // configured against, and every one of them would stop connecting
            // with no indication why.
            return Err(Error::WireguardAlreadyConfigured { path: config });
        }

        report(progress, &Msg::TaskWireguardInstallingTools);
        backend
            .packages()
            .install(executor, backend.package_for(Capability::Wireguard))?;

        // 0700 before anything is written into it: the directory holds private
        // keys, and creating it world-readable even briefly is a window.
        files.create_dir(executor, dir, CONFIG_DIR_MODE)?;

        report(progress, &Msg::TaskWireguardGeneratingKeys);
        let keys = backend.wireguard().generate_keypair(executor)?;

        let server_address = first_address(&subnet)?;
        let contents = server_config(&keys.private, &server_address, port);

        // The mode is set on the path *before* the private key is written into
        // it. Writing first and tightening afterwards leaves a window in which
        // the server's private key sits in a world-readable file — brief, but
        // long enough for any account on the box, and `wg` warns about exactly
        // this when it writes a key itself.
        //
        // Creating it empty is what makes the ordering possible: `set_mode`
        // needs a path that exists, and an empty file discloses nothing.
        //
        // Both writes are `write_uncopied`, and the rule is the path rather
        // than the moment: nothing may ever copy `wg0.conf`, because a copy of
        // it is a copy of the server's private key and of every peer's
        // preshared key, and no retention reaches it — `prune` only deletes
        // copies the index names, and this task deliberately writes no index
        // entry.
        //
        // The first one looks like it cannot matter, since the file it creates
        // is empty. It matters on the second run: `install` refuses a host
        // that is already configured, but a *failed* first run leaves the file
        // behind, and an ordinary `write` would then copy the key that first
        // run had written. Measured on `alpine:3.23`, where the task fails at
        // `rc-update` after writing the key — the copy was 0 bytes after the
        // install and 151 after the next task touched the path, which is the
        // whole configuration.
        files.write_uncopied(executor, &config, "")?;
        files.set_mode(executor, &config, CONFIG_MODE)?;
        files.write_uncopied(executor, &config, &contents)?;

        report(
            progress,
            &Msg::TaskWireguardWrote {
                path: config.clone(),
            },
        );
        report(
            progress,
            &Msg::TaskWireguardServerKey {
                key: keys.public.clone(),
            },
        );

        // Enabled but not started: starting it before forwarding and the
        // firewall are in place produces a tunnel that comes up and carries
        // nothing, which is harder to diagnose than one that is plainly off.
        let unit = format!("{}{INTERFACE}", backend.service_for(Capability::Wireguard));
        backend.services().enable_and_start(executor, &unit)?;

        report(progress, &Msg::TaskUnitEnabled { unit: unit.clone() });

        Ok(Outcome::Done)
    }
}

/// Adds a peer to the server and prints its configuration.
pub struct AddPeer;

impl AddPeer {
    /// Name of the parameter holding the peer's name.
    pub const NAME: &'static str = "name";
    /// Name of the parameter holding the address to assign.
    pub const ADDRESS: &'static str = "address";
    /// Name of the parameter holding the server's public endpoint.
    pub const ENDPOINT: &'static str = "endpoint";
}

impl Task for AddPeer {
    fn id(&self) -> &'static str {
        "wireguard.add-peer"
    }

    fn title(&self) -> &'static str {
        "Add a WireGuard peer"
    }

    fn description(&self) -> &'static str {
        "Generates a keypair for one peer, records it on the server, and prints \
         the client configuration. The private key is printed once and never \
         stored — this tool cannot show it again."
    }

    fn params(&self) -> Vec<Param> {
        vec![
            Param::new(Self::NAME, "Peer name", ParamKind::Username)
                .with_hint("a label, recorded as a comment"),
            Param::new(Self::ADDRESS, "Tunnel address", ParamKind::Ip)
                .with_hint("one address inside the tunnel subnet"),
            Param::new(Self::ENDPOINT, "Server endpoint", ParamKind::Endpoint)
                .with_hint("the address:port peers dial, as seen from outside"),
        ]
    }

    supported_everywhere!();

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        let name = values.get(Self::NAME)?.to_owned();
        let address = values.get(Self::ADDRESS)?.to_owned();
        let endpoint = values.get(Self::ENDPOINT)?.to_owned();

        let dir = backend.path_for(Capability::Wireguard);
        let config = format!("{dir}/{INTERFACE}.conf");
        let files = backend.files();

        let existing = files.read(executor, &config)?;

        // Two peers sharing an address is a tunnel where the second one to
        // connect takes the first one's traffic, and neither reports an error.
        if existing.contains(&format!("AllowedIPs = {address}/32")) {
            return Err(Error::WireguardAddressTaken { address });
        }

        let keys = backend.wireguard().generate_keypair(executor)?;
        let server_public = server_public_key(executor, backend, &existing)?;

        let peer = peer_block(&name, &keys.public, &keys.preshared, &address);

        // Written through the one path that leaves no copy behind, unlike every
        // other configuration this tool edits. `wg0.conf` holds the server's
        // private key *and* every peer's preshared key, so any copy of it is a
        // second copy of all of them, on a machine where the point of the
        // original's `0600` was that one copy was enough.
        //
        // Both copies are refused, and they are different files. The index
        // under `/var/lib/initd` is refused because a record naming a copy full
        // of keys keeps the secret out of the record and puts it in the file
        // the record points at. The sidecar `wg0.conf.initd.bak` that an
        // ordinary `write` leaves is refused because nothing would ever prune
        // it: `prune` only reaches copies the index names, so a task that skips
        // the index and keeps the sidecar gets the disclosure the index was
        // bounded to avoid, and keeps it for the life of the host.
        //
        // What is given up is a way back. Removing a peer is `wg0.conf` minus
        // one block, which an administrator can do with an editor; recovering a
        // leaked private key is not something anybody can do.
        files.write_uncopied(executor, &config, &format!("{existing}{peer}"))?;

        // `syncconf` rather than restarting: a restart drops every established
        // tunnel, including the one an administrator may be connected through.
        let unit = format!("{}{INTERFACE}", backend.service_for(Capability::Wireguard));
        backend.services().reload(executor, &unit)?;

        report(
            progress,
            &Msg::TaskWireguardPeerAdded {
                name: name.clone(),
                address: address.clone(),
            },
        );
        report_verbatim(progress, String::new());
        report_secret(
            progress,
            client_config(
                &keys.private,
                &keys.preshared,
                &address,
                &server_public,
                &endpoint,
            ),
        );

        Ok(Outcome::Done)
    }
}

/// The server's own configuration.
fn server_config(private_key: &str, address: &str, port: u32) -> String {
    // No PostUp or PostDown. The masquerade rule those usually carry is spelled
    // differently for nftables and iptables, and a configuration that guesses
    // wrong leaves a tunnel that connects and routes nothing. The firewall is
    // modelled as its own capability precisely so this does not have to guess.
    //
    // SaveConfig is off so that the file stays what this tool wrote: with it
    // on, wg-quick rewrites the file on shutdown and any comment naming a peer
    // is lost.
    format!(
        "# Managed by initd.\n\
         [Interface]\n\
         Address = {address}\n\
         ListenPort = {port}\n\
         PrivateKey = {private_key}\n\
         SaveConfig = false\n"
    )
}

/// One peer's entry in the server configuration.
fn peer_block(name: &str, public_key: &str, preshared: &str, address: &str) -> String {
    let mut block = String::new();

    // `/32` rather than the subnet: on the server, AllowedIPs is the list of
    // addresses this peer is authorised to send from, so a wider mask lets one
    // peer impersonate every other.
    let _ = write!(
        block,
        "\n# {name}\n\
         [Peer]\n\
         PublicKey = {public_key}\n\
         PresharedKey = {preshared}\n\
         AllowedIPs = {address}/32\n"
    );

    block
}

/// The configuration a peer needs, printed once.
fn client_config(
    private_key: &str,
    preshared: &str,
    address: &str,
    server_public: &str,
    endpoint: &str,
) -> String {
    // `0.0.0.0/0, ::/0` together, never `0.0.0.0/0` alone. With only the IPv4
    // route the host keeps its own IPv6 route, so traffic to a dual-stack
    // destination leaves outside the tunnel while the tunnel reports itself up
    // — the leak is invisible from the client's point of view.
    format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {address}/32\n\
         \n\
         [Peer]\n\
         PublicKey = {server_public}\n\
         PresharedKey = {preshared}\n\
         Endpoint = {endpoint}\n\
         AllowedIPs = 0.0.0.0/0, ::/0\n\
         PersistentKeepalive = 25\n"
    )
}

/// The server's public key, derived from the private key in its configuration.
///
/// Derived rather than stored: a public key kept in a second file can disagree
/// with the private key in the first, and the peer configured from the stale
/// one never completes a handshake.
fn server_public_key(
    executor: &dyn Executor,
    backend: &dyn Backend,
    config: &str,
) -> Result<String> {
    let private = config
        .lines()
        .find_map(|line| line.trim().strip_prefix("PrivateKey"))
        .and_then(|rest| rest.trim().strip_prefix('='))
        .map(str::trim)
        .ok_or(Error::WireguardNotConfigured)?;

    backend.wireguard().public_key_of(executor, private)
}

/// The first usable address of a subnet, as the server's own.
///
/// `10.89.0.0/24` yields `10.89.0.1/24`: the mask is kept because the interface
/// address carries it, and dropping it would make the server think it is alone
/// on the tunnel.
fn first_address(subnet: &str) -> Result<String> {
    let (network, mask) = subnet.split_once('/').ok_or_else(|| Error::InvalidSubnet {
        subnet: subnet.to_owned(),
    })?;

    let mut octets: Vec<&str> = network.split('.').collect();

    if octets.len() != 4 {
        return Err(Error::InvalidSubnet {
            subnet: subnet.to_owned(),
        });
    }

    octets[3] = "1";

    Ok(format!("{}/{mask}", octets.join(".")))
}

/// Removes WireGuard, taking the tunnel down with it.
///
/// Does not delegate to [`crate::tasks::uninstall::undo`], unlike the other
/// nine. The unit here is a template — `wg-quick@` is not a unit, `wg-quick@wg0`
/// is — so the shared helper's `service_for` would hand systemd a name it does
/// not have.
pub struct UninstallWireguard;

impl Task for UninstallWireguard {
    fn id(&self) -> &'static str {
        "wireguard.uninstall"
    }

    fn title(&self) -> &'static str {
        "Uninstall WireGuard"
    }

    fn description(&self) -> &'static str {
        "Brings wg0 down, disables it at boot and removes the WireGuard tools. \
         wg0.conf and the server's keys are always left on disk, whichever \
         removal is chosen: they cannot be regenerated to match peers that \
         already hold the public key, so deleting them is a decision for \
         whoever knows those peers are gone."
    }

    /// The one uninstall that can end the session running it.
    ///
    /// An administrator connected *over* the tunnel loses the connection the
    /// moment `wg0` goes down — the same shape of mistake `ssh.harden` makes,
    /// and the reason that task is Lockout too. Unlike SSH, this one is
    /// offered at all: reaching a host over WireGuard is a choice, and one an
    /// operator can undo from a console, whereas removing the SSH server
    /// leaves nothing to reconnect *to*.
    fn confirmation(&self) -> Confirmation {
        Confirmation::Lockout
    }

    supported_everywhere!();

    fn subject(&self) -> Option<Capability> {
        Some(Capability::Wireguard)
    }

    fn affects(&self) -> &'static [&'static str] {
        &["wireguard.install"]
    }

    fn params(&self) -> Vec<Param> {
        vec![crate::tasks::uninstall::removal_param()]
    }

    fn params_here(&self, backend: &dyn Backend) -> Vec<Param> {
        crate::tasks::uninstall::removal_param_here(backend, Capability::Wireguard)
    }

    fn consequences(&self, _backend: &dyn Backend, _values: &ParamValues) -> Vec<Consequence> {
        vec![
            // Every peer holds a public key for a server that is going away.
            // Stated because the peers are elsewhere: nothing on this host can
            // tell them, and their configurations go on looking correct.
            Consequence::Invalidates {
                task: "wireguard.add-peer",
                reason: Reason::RequiresSetting {
                    setting: "every configured peer now points at a tunnel that is down",
                },
                check: None,
            },
            // The firewall rule admitting the tunnel's port outlives the
            // tunnel, and an open port with nothing behind it is exactly the
            // residue an uninstall is supposed to avoid leaving.
            Consequence::Invalidates {
                task: "firewall.manage-ports",
                reason: Reason::RequiresSetting {
                    setting: "the rule admitting the WireGuard port now admits nothing",
                },
                check: None,
            },
        ]
    }

    fn run(
        &self,
        executor: &dyn Executor,
        backend: &dyn Backend,
        values: &ParamValues,
        progress: Progress<'_>,
    ) -> Result<Outcome> {
        // The instance name, not the template. `wg-quick@` alone is a prefix
        // systemd has no unit for.
        let unit = format!("{}{INTERFACE}", backend.service_for(Capability::Wireguard));

        report(progress, &Msg::TaskDisabling { unit: unit.clone() });

        backend.services().disable_and_stop(executor, &unit)?;

        let package = backend.package_for(Capability::Wireguard);

        if !backend.packages().is_installed(executor, package)? {
            report(
                progress,
                &Msg::TaskNotInstalled {
                    what: package.to_owned(),
                },
            );

            return Ok(Outcome::Done);
        }

        // The choice reaches the package manager and stops there. `purge`
        // removes what the *package* ships; `/etc/wireguard/wg0.conf` was
        // written by `wireguard.install` and is deliberately not deleted by
        // either answer.
        //
        // Not an oversight to be tidied up later. That file holds the server's
        // private key, and every peer already holds the matching public one —
        // regenerating it does not restore a tunnel, it invalidates every
        // client. A field whose two values sit one character apart is not
        // where that should be decided, so neither value decides it.
        let purging = values
            .get(crate::tasks::uninstall::REMOVAL)
            .unwrap_or(crate::tasks::uninstall::KEEP_CONFIGURATION)
            == crate::tasks::uninstall::WITH_CONFIGURATION;

        report(
            progress,
            &if purging {
                Msg::TaskPurging {
                    what: package.to_owned(),
                }
            } else {
                Msg::TaskRemoving {
                    what: package.to_owned(),
                }
            },
        );

        if purging {
            backend.packages().purge(executor, package)?;
        } else {
            backend.packages().remove(executor, package)?;
        }

        Ok(Outcome::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::for_family;
    use crate::distro::Family;
    use crate::exec::OutputLine;
    use crate::exec::mock::{MockExecutor, Reply};

    /// A syntactically valid key, for tests that do not care which one.
    const KEY: &str = "aGVsbG8gd29ybGQgdGhpcyBpcyA0NCBjaGFycyBrZXk=";

    fn install_values(subnet: &str, port: u32) -> ParamValues {
        let mut values = ParamValues::new();
        values.set(InstallWireguard::SUBNET, subnet.to_owned());
        values.set(InstallWireguard::PORT, port.to_string());
        values
    }

    #[test]
    fn the_status_distinguishes_configured_from_running() {
        // Either alone misleads: a configured interface that is down carries
        // nothing, and reporting only "configured" reads as working.
        let mock = MockExecutor::with_replies([
            Reply::ok(""),                         // the config exists
            Reply::failure(1, "Unable to access"), // the interface is down
            Reply::ok(format!("[Interface]\nPrivateKey = {KEY}\n\n[Peer]\n")),
        ]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        WireguardStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |line| {
                lines.push(line.text)
            })
            .expect("the status must succeed");

        let output = lines.join("\n");

        assert!(output.contains("configured but down"), "{output}");
        assert!(output.contains("1 peer"), "{output}");
    }

    #[test]
    fn the_status_of_an_unconfigured_host_says_so() {
        let mock = MockExecutor::with_replies([Reply::failure(1, "")]);
        let backend = for_family(Family::Debian);
        let mut lines = Vec::new();

        WireguardStatus
            .run(&mock, backend.as_ref(), &ParamValues::new(), &mut |line| {
                lines.push(line.text)
            })
            .expect("the status must succeed");

        assert!(lines.join("\n").contains("not configured"), "{lines:?}");
    }

    #[test]
    fn a_client_route_covers_both_address_families() {
        // The leak the source scripts had: `0.0.0.0/0` alone leaves the host's
        // own IPv6 route in place, so traffic to a dual-stack destination goes
        // outside the tunnel while the tunnel reports itself up.
        let config = client_config(KEY, KEY, "10.89.0.2", KEY, "203.0.113.7:51820");

        assert!(
            config.contains("AllowedIPs = 0.0.0.0/0, ::/0"),
            "an IPv4-only route leaks IPv6: {config}"
        );
    }

    #[test]
    fn a_peer_is_authorised_for_one_address_only() {
        // On the server, AllowedIPs is what a peer may send *from*. A wider
        // mask lets any peer impersonate every other.
        let block = peer_block("laptop", KEY, KEY, "10.89.0.2");

        assert!(block.contains("AllowedIPs = 10.89.0.2/32"), "{block}");
        assert!(
            !block.contains("/24") && !block.contains("/16"),
            "a subnet mask here authorises impersonation: {block}"
        );
    }

    #[test]
    fn the_server_configuration_hard_codes_no_firewall_syntax() {
        // The third bug: `PostUp = iptables ...` does nothing on an
        // nftables-only host, leaving a tunnel that connects and routes
        // nothing. The firewall is a capability precisely so this can be left
        // out.
        let config = server_config(KEY, "10.89.0.1/24", 51_820);

        assert!(!config.contains("iptables"), "{config}");
        assert!(!config.contains("PostUp"), "{config}");
    }

    #[test]
    fn the_server_does_not_rewrite_its_own_configuration() {
        // With SaveConfig on, wg-quick rewrites the file at shutdown and every
        // comment naming a peer is lost.
        let config = server_config(KEY, "10.89.0.1/24", 51_820);

        assert!(config.contains("SaveConfig = false"), "{config}");
    }

    #[test]
    fn the_server_takes_the_first_address_of_its_subnet() {
        assert_eq!(first_address("10.89.0.0/24").unwrap(), "10.89.0.1/24");
        assert_eq!(first_address("192.168.4.0/22").unwrap(), "192.168.4.1/22");
    }

    #[test]
    fn a_subnet_without_a_mask_is_refused() {
        // The address the interface carries includes its mask; without one the
        // server believes it is alone on the tunnel.
        assert!(first_address("10.89.0.0").is_err());
        assert!(first_address("not-a-subnet").is_err());
    }

    #[test]
    fn the_private_key_never_lands_in_a_world_readable_file() {
        // The window this closes: writing the key and tightening the mode
        // afterwards leaves the server's private key readable by every account
        // on the box for as long as the two calls take. `wg` warns about
        // exactly this when it writes a key itself, which is how it surfaced —
        // in a container, from the tool's own stderr, not from a mock.
        //
        // Strict, because the subject here is the sequence. Under the lenient
        // mock a command inserted between the chmod and the write would answer
        // success from nowhere and this test would go on passing, having
        // stopped describing what the task does.
        // Every command the task actually runs, in order. Writing it out is
        // the point of the strict mock: the previous script named eleven
        // commands and the task ran fourteen, because each `write` is itself a
        // `test -e`, a `cp -p` backup and a `tee`. Those three were absorbed
        // as fabricated successes, and the comments beside the replies had
        // drifted onto the wrong commands without anything noticing.
        let mock = MockExecutor::with_exact_replies([
            Reply::failure(1, ""), // test -e: no existing configuration
            Reply::ok(""),         // apt-get update, before the install
            Reply::ok(""),         // apt-get install
            Reply::ok(""),         // install -d: the directory
            Reply::ok(KEY),        // wg genkey
            Reply::ok(KEY),        // wg genpsk
            Reply::ok(KEY),        // wg pubkey
            Reply::failure(1, ""), // test -e, opening the empty write
            Reply::ok(""),         // tee: stage the empty file
            Reply::ok(""),         // mv: publish it
            Reply::ok(""),         // chmod 600, before any secret exists
            Reply::ok(""),         // test -e, opening the real write
            // No `cp -p` here, and its absence is the assertion: by this point
            // the path exists, so an ordinary `write` would copy it to
            // `wg0.conf.initd.bak` before writing the private key into it —
            // and nothing would ever remove that copy, since retention only
            // reaches copies the index names and this task writes none.
            Reply::ok(""),    // tee: stage the configuration, with the key
            Reply::ok("600"), // stat -c %a: the mode set a moment ago
            Reply::ok(""),    // chmod: carry it onto the staging file
            Reply::ok(""),    // mv: publish it, already restricted
            Reply::ok(""),    // systemctl enable
        ]);
        let backend = for_family(Family::Debian);

        InstallWireguard
            .run(
                &mock,
                backend.as_ref(),
                &install_values("10.89.0.0/24", 51_820),
                &mut |_| {},
            )
            .expect("the install must succeed");

        let recorded = mock.recorded();

        let tightened = recorded
            .iter()
            .position(|command| command.args.iter().any(|arg| arg == "600"))
            .expect("the file must be tightened");

        let key_written = recorded
            .iter()
            .position(|command| {
                command
                    .stdin
                    .as_ref()
                    .is_some_and(|stdin| stdin.contains("PrivateKey"))
            })
            .expect("the key must be written");

        assert!(
            tightened < key_written,
            "the mode must be set before the key is written: {:?}",
            mock.recorded_lines()
        );

        // The other direction: a leftover reply means the task stopped running
        // a command this test still claims it runs.
        assert_eq!(
            mock.unused_replies(),
            0,
            "the script must describe the task exactly: {:?}",
            mock.recorded_lines()
        );
    }

    #[test]
    fn installing_over_an_existing_configuration_is_refused() {
        // A new server key silently invalidates every peer configured against
        // the old one, and each stops connecting with no indication why.
        let mock = MockExecutor::with_replies([Reply::ok("")]);
        let backend = for_family(Family::Debian);

        let err = InstallWireguard
            .run(
                &mock,
                backend.as_ref(),
                &install_values("10.89.0.0/24", 51_820),
                &mut |_| {},
            )
            .expect_err("an existing configuration must be refused");

        assert!(
            matches!(err, Error::WireguardAlreadyConfigured { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn installing_warns_that_forwarding_and_the_port_are_needed() {
        // Both are what turn a tunnel that establishes into one that carries
        // traffic, and neither is this task's to change.
        let consequences = InstallWireguard.consequences(
            for_family(Family::Debian).as_ref(),
            &install_values("10.89.0.0/24", 51_820),
        );

        let named: Vec<_> = consequences.iter().filter_map(|c| c.task()).collect();

        assert!(named.contains(&"sysctl.ip-forward"), "{named:?}");
        assert!(named.contains(&"firewall.manage-ports"), "{named:?}");
    }

    #[test]
    fn the_firewall_warning_names_udp() {
        // A TCP rule for this port admits none of WireGuard's traffic while
        // looking, in a listing, very much like it should.
        let consequences = InstallWireguard.consequences(
            for_family(Family::Debian).as_ref(),
            &install_values("10.89.0.0/24", 51_820),
        );

        let firewall = consequences
            .iter()
            .find(|c| c.task() == Some("firewall.manage-ports"))
            .expect("the firewall must be named");

        let check = firewall.check().expect("a local rule is answerable");

        assert_eq!(
            check.resolved_when_stdout_contains,
            "udp dport 51820 accept"
        );
    }

    #[test]
    fn the_firewall_check_asks_whichever_front_end_holds_the_ruleset() {
        // The bug this closes: the query was `nft list table inet initd`,
        // written into the task. Right on four families and wrong on the
        // fifth — RHEL runs firewalld, so the rule the tool wrote lives in a
        // zone and that table was never created. The check would answer "not
        // done" forever for a port that is already open, and a warning nobody
        // can resolve is one an administrator learns to scroll past, which
        // costs every other warning beside it.
        let check_for = |family| {
            InstallWireguard
                .consequences(
                    for_family(family).as_ref(),
                    &install_values("10.89.0.0/24", 51_820),
                )
                .into_iter()
                .find(|c| c.task() == Some("firewall.manage-ports"))
                .and_then(|c| c.check().cloned())
                .expect("the firewall consequence must carry a check")
        };

        let debian = check_for(Family::Debian);
        let rhel = check_for(Family::Rhel);

        assert_eq!(debian.command.program, "nft", "{:?}", debian.command);
        assert_eq!(
            rhel.command.program, "firewall-cmd",
            "the front-end RHEL actually runs: {:?}",
            rhel.command
        );

        // Each needle has to match the listing its own command produces, so
        // asserting they differ is asserting the pairing rather than the name.
        assert_eq!(
            debian.resolved_when_stdout_contains,
            "udp dport 51820 accept"
        );
        assert_eq!(rhel.resolved_when_stdout_contains, "51820/udp");
    }

    #[test]
    fn the_provider_warning_cannot_be_verified() {
        let consequences = InstallWireguard.consequences(
            for_family(Family::Debian).as_ref(),
            &install_values("10.89.0.0/24", 51_820),
        );

        let external: Vec<_> = consequences.iter().filter(|c| c.is_external()).collect();

        assert_eq!(external.len(), 1, "{consequences:?}");
        assert!(external[0].check().is_none());
    }

    #[test]
    fn the_printed_peer_configuration_is_marked_as_a_secret() {
        // It holds a private key and a preshared key, and it is printed because
        // the operator has to read it. Marking is what keeps the transcript
        // copy from carrying it back across the SSH hop into a clipboard
        // history — the disclosure `write_uncopied` refuses on disk.
        let mock = MockExecutor::with_replies([
            Reply::ok(format!("[Interface]\nPrivateKey = {KEY}\n")), // existing config
            Reply::ok(format!("{KEY}\n")),                           // genkey
            Reply::ok(format!("{KEY}\n")),                           // pubkey
            Reply::ok(format!("{KEY}\n")),                           // genpsk
            Reply::ok(format!("{KEY}\n")),                           // server pubkey
            Reply::ok(""),                                           // write
            Reply::ok(""),                                           // reload
        ]);

        let mut values = ParamValues::new();
        values.set(AddPeer::NAME, "phone".to_owned());
        values.set(AddPeer::ADDRESS, "10.89.0.9".to_owned());
        values.set(AddPeer::ENDPOINT, "203.0.113.7:51820".to_owned());

        let mut lines: Vec<OutputLine> = Vec::new();
        let _ = AddPeer.run(
            &mock,
            for_family(Family::Debian).as_ref(),
            &values,
            &mut |line| lines.push(line),
        );

        let holding_key: Vec<_> = lines.iter().filter(|l| l.text.contains(KEY)).collect();

        assert!(
            !holding_key.is_empty(),
            "the configuration must be printed: {lines:?}"
        );
        assert!(
            holding_key.iter().all(|l| l.sensitive),
            "every line carrying the key must be marked: {holding_key:?}"
        );
    }

    #[test]
    fn a_peer_cannot_take_an_address_another_holds() {
        // Two peers on one address is a tunnel where the second to connect
        // takes the first one's traffic, and neither reports an error.
        let existing = format!(
            "[Interface]\nPrivateKey = {KEY}\n\n# laptop\n[Peer]\nAllowedIPs = 10.89.0.2/32\n"
        );

        let mock = MockExecutor::with_replies([Reply::ok(existing)]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(AddPeer::NAME, "phone".to_owned());
        values.set(AddPeer::ADDRESS, "10.89.0.2".to_owned());
        values.set(AddPeer::ENDPOINT, "203.0.113.7:51820".to_owned());

        let err = AddPeer
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect_err("a taken address must be refused");

        assert!(
            matches!(err, Error::WireguardAddressTaken { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn the_server_public_key_is_derived_rather_than_stored() {
        // A public key kept in a second file can disagree with the private key
        // in the first, and a peer configured from the stale one never
        // completes a handshake.
        let mock = MockExecutor::with_replies([Reply::ok(KEY)]);
        let backend = for_family(Family::Debian);
        let config = format!("[Interface]\nPrivateKey = {KEY}\n");

        let public =
            server_public_key(&mock, backend.as_ref(), &config).expect("the key must be derivable");

        assert_eq!(public, KEY);
        assert!(
            mock.single_command().stdin.is_some(),
            "the private key belongs on stdin"
        );
    }

    #[test]
    fn a_configuration_without_a_private_key_is_an_error() {
        let mock = MockExecutor::new();
        let backend = for_family(Family::Debian);

        let err = server_public_key(&mock, backend.as_ref(), "[Interface]\n")
            .expect_err("a configuration with no key must fail");

        assert!(matches!(err, Error::WireguardNotConfigured), "{err:?}");
    }

    #[test]
    fn no_copy_of_the_key_file_is_ever_kept() {
        // The one configuration this tool edits and deliberately does not
        // record. `wg0.conf` holds the server's private key and every peer's
        // preshared key, so a copy under /var/lib/initd would be a second copy
        // of all of them — on a machine where the point of the original's 0600
        // was that one copy was enough.
        //
        // Pinned rather than left to the absence of a call, because the absence
        // is what a later contributor would read as an oversight and "fix".
        let existing = format!("[Interface]\nPrivateKey = {KEY}\n");

        let mock = MockExecutor::with_replies([
            Reply::ok(existing), // read the config
            Reply::ok(KEY),      // genkey
            Reply::ok(KEY),      // genpsk
            Reply::ok(KEY),      // pubkey for the peer
            Reply::ok(KEY),      // pubkey for the server
            Reply::ok("1"),      // the config exists, so its mode is preserved
            Reply::ok(""),       // stage the new contents
            Reply::ok("600"),    // read the mode off the original
            Reply::ok(""),       // apply it to the staged file
            Reply::ok(""),       // move it into place
            Reply::ok(""),       // reload
        ]);

        let mut values = ParamValues::new();
        values.set(AddPeer::NAME, "laptop".to_owned());
        values.set(AddPeer::ADDRESS, "10.89.0.2".to_owned());
        values.set(AddPeer::ENDPOINT, "203.0.113.7:51820".to_owned());

        AddPeer
            .run(
                &mock,
                for_family(Family::Debian).as_ref(),
                &values,
                &mut |_| {},
            )
            .expect("adding a peer must succeed");

        for line in mock.recorded_lines() {
            assert!(
                !line.contains("/var/lib/initd"),
                "the key file must never be copied into the index: {line}"
            );

            // The half this test missed while it passed. Refusing the index is
            // only one of the two copies: an ordinary `write` also leaves
            // `wg0.conf.initd.bak` beside the original, which no retention ever
            // reaches because `prune` only deletes copies the index names. The
            // assertion above was true of that file too, since it lives in
            // `/etc/wireguard` rather than under `/var/lib/initd`.
            assert!(
                !line.contains(".initd.bak"),
                "the key file must never be copied beside itself either: {line}"
            );

            // Pinned by the command rather than by the path, so a future copy
            // taken under some third name is caught as well. `cp` appears in
            // this task for no other purpose.
            assert!(
                !line.starts_with("cp "),
                "no copy of the key file may be taken at all: {line}"
            );
        }
    }

    #[test]
    fn adding_a_peer_reloads_rather_than_restarts() {
        // A restart drops every established tunnel, including the one the
        // administrator may be connected through.
        let existing = format!("[Interface]\nPrivateKey = {KEY}\n");

        let mock = MockExecutor::with_replies([
            Reply::ok(existing), // read the config
            Reply::ok(KEY),      // genkey
            Reply::ok(KEY),      // genpsk
            Reply::ok(KEY),      // pubkey for the peer
            Reply::ok(KEY),      // pubkey for the server
            Reply::ok("1"),      // the config exists, so its mode is preserved
            Reply::ok(""),       // stage the new contents
            Reply::ok("600"),    // read the mode off the original
            Reply::ok(""),       // apply it to the staged file
            Reply::ok(""),       // move it into place
            Reply::ok(""),       // reload
        ]);
        let backend = for_family(Family::Debian);

        let mut values = ParamValues::new();
        values.set(AddPeer::NAME, "laptop".to_owned());
        values.set(AddPeer::ADDRESS, "10.89.0.2".to_owned());
        values.set(AddPeer::ENDPOINT, "203.0.113.7:51820".to_owned());

        AddPeer
            .run(&mock, backend.as_ref(), &values, &mut |_| {})
            .expect("adding a peer must succeed");

        let commands = mock.recorded_lines();

        assert!(
            commands.iter().any(|c| c.contains("reload")),
            "{commands:?}"
        );
        assert!(
            !commands.iter().any(|c| c.contains("restart")),
            "a restart drops every tunnel: {commands:?}"
        );
    }
}
