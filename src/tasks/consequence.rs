//! What a task invalidates elsewhere when it succeeds.
//!
//! `sshd -t` proves a configuration parses and a reload proves the daemon took
//! it, but neither says whether the firewall still names the port that was just
//! changed. [`super::revert`] already names that case as a reason the
//! verification window exists — the tool could tell the administrator to wait,
//! but not what it had just invalidated.
//!
//! So tasks declare their consequences and the interface states them. Nothing
//! here acts: a tool that chains system changes on the administrator's behalf
//! is one whose blast radius nobody can predict, and this tool exists to make
//! changes reviewable rather than automatic.
//!
//! The distinction that matters is between what the tool can check and what it
//! can only report. A firewall rule is readable from this machine; a hosting
//! provider's edge firewall is not, and neither is a DNS record that has to
//! resolve before a certificate can be issued. Presenting both the same way
//! would imply the second had been verified.

use crate::exec::Command;
use crate::i18n::Msg;

/// Why one task's result no longer matches the system.
///
/// Structured rather than pre-rendered, for the same reason [`crate::error`]
/// carries data instead of text: the catalogue renders it in the resolved
/// locale, and a missing translation fails at compile time.
///
/// Declared together because the set is what the interface must know how to
/// render, and finding a new shape of warning while wiring up a task is how one
/// ends up rendered as a bare string. Each is constructed and rendered in this
/// module's tests, so a variant the catalogue cannot word still fails the build.
///
/// Every variant has a producer now. They were declared ahead of the tasks that
/// raise them and carried an allow saying so, which stayed after the tasks
/// landed — an allow outliving its reason is how the next genuinely dead
/// variant would have gone unnoticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A port was changed, and something else still refers to the old one.
    PortChanged { from: String, to: String },

    /// A setting this task needs is not in place.
    RequiresSetting { setting: &'static str },

    /// A service must be restarted before it observes a change.
    NeedsRestart { service: &'static str },

    /// An account was created that an allow-list does not name.
    AccountNotListed { user: String },

    /// An account something else refers to no longer exists.
    ///
    /// The mirror of [`AccountNotListed`](Self::AccountNotListed), and the
    /// more silent of the two: a key authorised for a deleted account
    /// authorises nothing, and an allow-list naming it admits nobody under
    /// that name while going on looking correct.
    AccountRemoved { user: String },
}

/// What two tasks would contend for.
///
/// Raised by the two brute-force banners, which both ship: `hardening.rs`
/// constructs it for fail2ban and for CrowdSec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    /// Both write ban rules through the firewall. A host running two of them
    /// bans twice and unbans unpredictably, since neither observes the other's
    /// rules.
    BanRules,
}

/// Something outside this machine that the tool cannot inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum External {
    /// A hosting provider's own firewall, upstream of this host.
    ///
    /// The motivating case: an administrator who opens a port locally and
    /// cannot reach it has usually hit this, and no on-host check can see it.
    ///
    /// `u32` rather than `u16` to match how ports are carried elsewhere in the
    /// task layer, where the wider type lets an out-of-range value be reported
    /// as the number that was actually entered.
    ProviderFirewall { port: u32, protocol: Protocol },

    /// A name has to resolve to this host before a certificate can be issued.
    DnsMustResolve,

    /// Membership in the `docker` group is equivalent to root.
    ///
    /// The daemon's socket takes commands that mount the host filesystem into a
    /// container, so anyone who can reach it can read and write any file on the
    /// machine. Said out loud because the usual next step after installing the
    /// engine — adding an account to `docker` so it need not type `sudo` —
    /// grants exactly that, and nothing about the command announces it. This
    /// task does not do it; it says what doing it would mean.
    DockerGroupIsRoot,

    /// The rootless setup script arrives with no digest to check it against.
    ///
    /// Raised only where no official package ships
    /// `dockerd-rootless-setuptool.sh` — Arch, measured — so the script comes
    /// from `get.docker.com/rootless`. Every other route here verifies what it
    /// fetches: repository keys are checked against fingerprints this build
    /// carries, and release binaries against digests. This one cannot be,
    /// because upstream publishes no per-artefact digest for it. External
    /// rather than a check, since the whole point is that there is nothing to
    /// verify against.
    UnverifiedRootlessInstaller,
}

/// Transport protocol, for warnings that name a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A read-only query answering whether a consequence still holds.
///
/// Carries the command rather than running it: consequences are declared while
/// a task is being defined, and executing anything at that point would run
/// commands the administrator never asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The command to run.
    pub command: Command,
    /// Text whose presence in stdout means the consequence is resolved.
    ///
    /// Matched as a substring, which is why the needle must be specific: this
    /// project has already been bitten by `is-active` answering `inactive`,
    /// where the wrong answer contains the right one.
    pub resolved_when_stdout_contains: String,
}

/// Something a task invalidates elsewhere when it succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consequence {
    /// Another task's result no longer matches the system, and the tool can
    /// say so because it can inspect what changed.
    Invalidates {
        /// Task id whose result is now stale.
        task: &'static str,
        reason: Reason,
        /// How to ask whether this still holds. `None` where the answer needs
        /// judgement rather than a command.
        check: Option<Check>,
    },

    /// Another task occupies the same ground and should not also be applied.
    ///
    /// Distinct from `Invalidates`: nothing is broken yet. Running both is what
    /// would break it. Raised by the two brute-force banners, which both ship.
    Conflicts { task: &'static str, over: Conflict },

    /// Something beyond this machine needs attention.
    ///
    /// Never carries a check. The whole point of the variant is that the tool
    /// cannot see what it is warning about, and offering to verify it would be
    /// a claim the interface makes on the tool's behalf that the tool cannot
    /// support.
    External { note: External },
}

impl Consequence {
    /// How to verify this consequence, if it can be verified at all.
    ///
    /// `External` always answers `None`, structurally rather than by
    /// convention — there is no field for it to answer with.
    ///
    /// Consumed by on-demand verification in the interface, which lands with
    /// the first task that has something to query.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn check(&self) -> Option<&Check> {
        match self {
            Self::Invalidates { check, .. } => check.as_ref(),
            Self::Conflicts { .. } | Self::External { .. } => None,
        }
    }

    /// The task this consequence points at, where it points at one.
    ///
    /// Used by the interface to offer jumping straight to the task that needs
    /// attention, which lands with on-demand verification.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn task(&self) -> Option<&'static str> {
        match self {
            Self::Invalidates { task, .. } | Self::Conflicts { task, .. } => Some(task),
            Self::External { .. } => None,
        }
    }

    /// Whether this warning is about something the tool cannot inspect.
    ///
    /// The interface renders these differently: an administrator has to be
    /// able to tell at a glance which warnings the tool can settle and which
    /// are theirs to chase.
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External { .. })
    }
}

impl Protocol {
    /// Lowercase name, as it appears in a port specification.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl Consequence {
    /// Renders this consequence through the message catalogue.
    ///
    /// The mapping lives here rather than in the interface so that the CLI and
    /// the TUI cannot word the same warning differently.
    pub fn message(&self) -> Msg {
        match self {
            Self::Invalidates { task, reason, .. } => match reason {
                Reason::PortChanged { from, to } => Msg::ConsequencePortChanged {
                    task: (*task).to_owned(),
                    from: from.clone(),
                    to: to.clone(),
                },
                Reason::RequiresSetting { setting } => Msg::ConsequenceRequiresSetting {
                    task: (*task).to_owned(),
                    setting: (*setting).to_owned(),
                },
                Reason::NeedsRestart { service } => Msg::ConsequenceNeedsRestart {
                    task: (*task).to_owned(),
                    service: (*service).to_owned(),
                },
                Reason::AccountNotListed { user } => Msg::ConsequenceAccountNotListed {
                    task: (*task).to_owned(),
                    user: user.clone(),
                },
                Reason::AccountRemoved { user } => Msg::ConsequenceAccountRemoved {
                    task: (*task).to_owned(),
                    user: user.clone(),
                },
            },
            Self::Conflicts { task, over } => match over {
                Conflict::BanRules => Msg::ConsequenceConflictsOverBanRules {
                    task: (*task).to_owned(),
                },
            },
            Self::External { note } => match note {
                External::ProviderFirewall { port, protocol } => Msg::ConsequenceProviderFirewall {
                    port: port.to_string(),
                    protocol: protocol.as_str().to_owned(),
                },
                External::DnsMustResolve => Msg::ConsequenceDnsMustResolve,
                External::DockerGroupIsRoot => Msg::ConsequenceDockerGroupIsRoot,
                External::UnverifiedRootlessInstaller => {
                    Msg::ConsequenceUnverifiedRootlessInstaller
                }
            },
        }
    }
}

/// The check that asks whether a port is open, phrased by this host's firewall.
///
/// Here rather than in each task because the answer is not a task's to know.
/// Four of the five families are driven through `nft`, so a literal spelled
/// in a task looks correct right up until RHEL, where the tool writes the rule
/// through firewalld and the nftables listing shows a table that was never
/// created. A consequence checked that way answers "still to do" forever, for
/// a port that is already open — a warning that cannot be resolved is one an
/// administrator learns to scroll past, which costs the other warnings too.
///
/// `None` where no front-end is present: the consequence is still worth stating
/// and there is nothing on this host to ask.
pub fn firewall_check(
    backend: &dyn crate::backend::Backend,
    port: u32,
    protocol: crate::domain::firewall::Protocol,
) -> Option<Check> {
    let (command, needle) = backend.firewalls().first()?.open_port_check(port, protocol);

    Some(Check {
        command,
        resolved_when_stdout_contains: needle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    /// One consequence of every shape the catalogue must render.
    ///
    /// Listed exhaustively on purpose: a variant added without a message is a
    /// warning that reaches the administrator as nothing at all.
    fn one_of_each() -> Vec<Consequence> {
        vec![
            Consequence::Invalidates {
                task: "firewall.manage-ports",
                reason: Reason::PortChanged {
                    from: "22".to_owned(),
                    to: "2222".to_owned(),
                },
                check: None,
            },
            Consequence::Invalidates {
                task: "wireguard.install",
                reason: Reason::RequiresSetting {
                    setting: "net.ipv4.ip_forward",
                },
                check: None,
            },
            Consequence::Invalidates {
                task: "docker.rootless",
                reason: Reason::NeedsRestart {
                    service: "docker.service",
                },
                check: None,
            },
            Consequence::Invalidates {
                task: "ssh.allow-users",
                reason: Reason::AccountNotListed {
                    user: "alice".to_owned(),
                },
                check: None,
            },
            Consequence::Conflicts {
                task: "crowdsec.install",
                over: Conflict::BanRules,
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port: 51820,
                    protocol: Protocol::Udp,
                },
            },
            Consequence::External {
                note: External::ProviderFirewall {
                    port: 2222,
                    protocol: Protocol::Tcp,
                },
            },
            Consequence::External {
                note: External::DnsMustResolve,
            },
        ]
    }

    #[test]
    fn every_consequence_renders_to_something_an_administrator_can_read() {
        for consequence in one_of_each() {
            let text = Lang::En.render(&consequence.message());

            assert!(
                !text.trim().is_empty(),
                "{consequence:?} rendered to nothing"
            );
        }
    }

    #[test]
    fn a_warning_names_the_port_and_protocol_it_is_about() {
        // "check your firewall" without the port is advice the administrator
        // has to go and re-derive.
        let udp = Consequence::External {
            note: External::ProviderFirewall {
                port: 51820,
                protocol: Protocol::Udp,
            },
        };

        let text = Lang::En.render(&udp.message());

        assert!(text.contains("51820"), "{text}");
        assert!(text.contains("udp"), "{text}");
    }

    #[test]
    fn an_unverifiable_warning_says_so_in_its_text() {
        // The marker distinguishes them on screen, but the sentence has to
        // stand on its own: this is the one class of warning the tool is
        // reporting without having checked anything.
        for note in [
            External::DnsMustResolve,
            External::ProviderFirewall {
                port: 80,
                protocol: Protocol::Tcp,
            },
        ] {
            let text = Lang::En.render(&Consequence::External { note }.message());

            assert!(
                text.contains("cannot see it"),
                "an external warning must admit it was not checked: {text}"
            );
        }
    }

    fn invalidates_with_check() -> Consequence {
        Consequence::Invalidates {
            task: "firewall.manage-ports",
            reason: Reason::PortChanged {
                from: "22".to_owned(),
                to: "2222".to_owned(),
            },
            check: Some(Check {
                command: Command::new("true"),
                resolved_when_stdout_contains: "2222".to_owned(),
            }),
        }
    }

    #[test]
    fn an_external_warning_offers_no_verification() {
        // Structural, not conventional: the variant has nowhere to put a
        // check. An interface that offered to verify the provider's firewall
        // would be claiming a capability the tool does not have.
        let consequence = Consequence::External {
            note: External::ProviderFirewall {
                port: 2222,
                protocol: Protocol::Tcp,
            },
        };

        assert!(consequence.check().is_none());
        assert!(consequence.is_external());
    }

    #[test]
    fn a_conflict_offers_no_verification_either() {
        // Two banners contending for the same rules is a decision, not a
        // state to query: the tool cannot tell which one the administrator
        // meant to keep.
        let consequence = Consequence::Conflicts {
            task: "crowdsec.install",
            over: Conflict::BanRules,
        };

        assert!(consequence.check().is_none());
        assert!(!consequence.is_external());
    }

    #[test]
    fn an_invalidation_can_carry_a_check() {
        assert!(invalidates_with_check().check().is_some());
        assert!(!invalidates_with_check().is_external());
    }

    #[test]
    fn an_invalidation_without_a_check_is_still_reported() {
        // Not every stale thing is queryable with one command. Such a
        // consequence must still be stated rather than dropped for being
        // unverifiable.
        let consequence = Consequence::Invalidates {
            task: "ssh.allow-users",
            reason: Reason::AccountNotListed {
                user: "alice".to_owned(),
            },
            check: None,
        };

        assert!(consequence.check().is_none());
        assert_eq!(consequence.task(), Some("ssh.allow-users"));
    }

    #[test]
    fn only_external_warnings_point_at_no_task() {
        // An `Invalidates` or `Conflicts` naming no task would render as a
        // warning with nowhere to go.
        assert_eq!(
            invalidates_with_check().task(),
            Some("firewall.manage-ports")
        );

        let external = Consequence::External {
            note: External::DnsMustResolve,
        };

        assert_eq!(external.task(), None);
    }
}
