# SPEC — Server administration beyond SSH

> Status: **all five phases shipped**, 2026-08-04. Written from two research
> passes (tooling landscape + per-component settings) and a review of
> `boycsuk/naisudotfun`, whose shell scripts are the field evidence behind
> several decisions here.
>
> The behavioural contract now lives in `docs/user-stories.md` and the
> reasoning in `CHANGELOG.md`. What this file still carries that they do not:
> the research those decisions came from, the alternatives rejected, and the
> two things below that are known to be incomplete. Delete it once those are
> closed.
>
> **Known incomplete:**
> - `zellij.install` on Debian ships an empty release table, so it refuses to
>   install anything. Each entry is a promise that this project verified that
>   artefact, and a plausible-looking wrong digest is worse than none. Real
>   SHA-256 digests are needed before that path works.
> - The container tests (91, ignored by default) have not been run against the
>   tasks added here. Everything below is verified against mocks; nothing in
>   phases 1-5 has been observed on a real Debian or Arch host.

## Why this document exists

The tool administers SSH well and nothing else. This spec adds seven components
the operator asked for — WireGuard, Docker rootless, Caddy, mise, Rust, fish,
Zellij — plus user administration, plus four capabilities the research showed
are table stakes and were missing from the request (firewall, sysctl, fail2ban,
unattended upgrades).

It also introduces the one genuinely novel thing in this project: **tasks that
declare what they break elsewhere**.

---

## 1. The central mechanism: consequences

### The problem, stated from evidence

`src/tasks/revert.rs:6` already names it, in a comment written before this spec:

> *"a firewall that was never opened on the new port"*

The code identified the failure and could only mitigate it by waiting — the
verification window exists partly because the tool cannot tell the operator
what it just invalidated.

The operator's own `naisudotfun` repo shows the same failure from the other
side. `scripts/vpn/setup-wireguard.sh` opens port `13379/tcp` in the firewall
because that is where SSH was moved — a number decided in a different file, on
a different day. Change the SSH port and that literal is silently stale. Two
scripts in that repo also configure IP forwarding by different routes
(`/etc/sysctl.conf` vs `/etc/sysctl.d/`), which is drift produced by having no
model of shared state.

### The research verdict

Reviewed ~25 tools at source level (not README level). **Nothing models
task-to-task consequence.** Three weaker patterns exist:

| Pattern | Example | Why it is not this |
|---|---|---|
| Host-state preconditions | linutil `Entry::is_supported()` — env var, file exists, command exists | Describes the *host*, evaluated once at menu build to hide entries. Never "another task changed something". |
| Shared input variable | konstruktoid `sshd_ports` read by sshd + ufw task files | Coupling hardcoded by the role author in one declarative run. The tool has no concept a relationship exists. |
| Inline sequencing | `du_setup` (647★, 6347 lines of bash) | Genuinely correct for SSH-port→firewall: opens new port, verifies listening, forces human confirmation, then closes old. But it is one code path for one pair. Not queryable, not extensible. |

Closest architectural precedent is YunoHost's `diagnosis` + regen-conf, which is
reactive (finds an already-broken state), Debian-locked and scoped to its own
managed stack. Closest conceptual precedent is chezmoi's `run_onchange_`, which
is content-hash invalidation the user wires by hand.

Two independent authors (`du_setup`, `vps-harden`) hand-rolled this logic
because no framework offers it. That is demand, not novelty for its own sake.

### The honest limit

`du_setup` must warn the operator to check their **provider's edge firewall**
(Hetzner, DigitalOcean). No on-host tool can detect or fix that. The model must
therefore distinguish two kinds of consequence, and never blur them —
**claiming to catch the unverifiable would be worse than silence.**

### Design

```rust
/// Something a task invalidates elsewhere when it succeeds.
///
/// Declared, never acted on. The interface states it; the operator decides.
/// This is deliberate: a tool that chains system changes on the operator's
/// behalf is a tool whose blast radius nobody can predict.
pub enum Consequence {
    /// Another task in this tree is now inconsistent, and the tool can say so
    /// because it can inspect the state in question.
    Invalidates {
        /// Task id whose result no longer matches the system.
        task: &'static str,
        /// What changed, as structured data for the i18n catalogue.
        reason: ConsequenceReason,
    },

    /// Another task occupies the same ground and should not also be applied.
    ///
    /// Distinct from `Invalidates`: nothing has been broken, but running both
    /// would produce a system where two components fight over the same
    /// resource. fail2ban and CrowdSec both write ban rules through the
    /// firewall, and a host running both bans twice and unbans unpredictably.
    Conflicts {
        /// Task id that should not also be run.
        task: &'static str,
        /// What the two would contend for.
        over: ConflictReason,
    },

    /// Something outside this machine needs attention. The tool cannot verify
    /// it and must not imply otherwise.
    ///
    /// The provider edge firewall is the motivating case: `du_setup` warns
    /// about it in capitals precisely because no on-host check can see it.
    External { note: ExternalNote },
}
```

Added to the `Task` trait as a defaulted method, so no existing task changes:

```rust
/// What this task invalidates elsewhere, given the values it ran with.
///
/// Takes `values` because the consequence often depends on them: changing the
/// SSH port to 2222 invalidates a firewall rule naming 22, but re-running the
/// task with 22 invalidates nothing.
fn consequences(&self, values: &ParamValues) -> Vec<Consequence> {
    Vec::new()
}
```

**Why `Vec<Consequence>` and not a graph structure:** consequences are declared
per task and collected at render time. A stored graph would need invalidating
whenever the system changed underneath it, which is the drift problem this is
meant to solve. Walking `all_tasks()` is O(n) over a tree of tens of entries.

**Why it returns text through i18n:** consistent with the existing rule that
`Error` variants carry structured data and never display strings.

### Presentation

Shown in the output pane after a task succeeds, before the verification window
if there is one. Never blocks. `docs/ui.md` gains a style role for it.

```
✓ ssh.change-port → 2222

┌─ Consequences ─────────────────────────┐
│ ! firewall.allow-port still names 22   │
│ ! fail2ban jail still watches 22       │
│ ⚠ Check your provider's edge firewall  │
│   — this tool cannot see it.           │
│                      [v] verify now    │
└────────────────────────────────────────┘
```

The `⚠` glyph is reserved for `External`. The distinction must be visible, not
merely present in the data.

### Staleness: verified on request, never on render

A consequence is a historical fact — *this task invalidated that* — and stays
on screen until dismissed. It is **not** re-evaluated automatically.

Re-checking on every render was rejected: a TUI redraws on each keypress, so
that means running `nft list ruleset` or `systemctl is-active` continuously.
The fix would be a cache with a TTL, and a stale cache is the same problem with
more machinery.

Instead `v` re-checks the one consequence under the cursor, on demand:

```rust
/// How to ask the system whether this consequence still holds.
///
/// `None` for `External` — the whole point of that variant is that the tool
/// cannot see the thing it is warning about, and offering to verify it would
/// be a lie the interface tells on the tool's behalf.
fn check(&self) -> Option<ConsequenceCheck>;
```

`External` consequences render without the `[v]` affordance. That asymmetry is
the design working: the operator can tell at a glance which warnings the tool
can settle and which are theirs to chase.

Verification is a read-only query through the `Executor`, so it inherits the
existing escalation and mock-testing machinery.

---

## 2. Agnosticism: what changes

The operator asked for "as agnostic as possible", resolved as **agnostic of
init system and of network layer**. Three consequences.

### 2.1 Existing debt to pay first

`SSHD_CONFIG` is a hardcoded path in `src/tasks/sshd_config.rs:14` — the task
layer. Package names and unit names already live in the backend; paths do not,
only because Debian and Arch happen to agree. That is the shape of assumption
that breaks on the next family.

**Change:** `Backend::path_for(Capability) -> &'static str`. Mechanical, no
behaviour change, its own commit.

### 2.2 New capability traits

| Trait | Implementations | Needed by |
|---|---|---|
| `ServiceManager` *(exists)* | systemd, **OpenRC** *(new, for Alpine)* | everything |
| `FirewallManager` *(new)* | nftables, iptables, ufw | ssh, wireguard, caddy |
| `SysctlManager` *(new)* | procfs + `/etc/sysctl.d/` | wireguard, docker |
| `AccountWriter` *(new)* | shadow-utils, busybox | users |
| `BinaryInstaller` *(new)* | checksum-verified release | zellij, mise |

`FirewallManager` is what makes network agnosticism real. WireGuard's
`PostUp`/`PostDown` must emit `nft` or `iptables` depending on the host —
`naisudotfun` hardcodes `iptables` and breaks on nftables-only systems.

### 2.3 The Zellij problem

Arch has `pacman -S zellij`. **Debian and Ubuntu have no package at all** —
verified against both package databases; blog posts claiming otherwise are
wrong. Debian needs download → verify checksum → install to `/usr/local/bin`.

That is a *different installation mechanism* per family, not a different
package name, so `PackageManager` cannot express it. Hence `BinaryInstaller`,
which mise and any future package-less tool also use.

**Checksums are compiled in, for a set of known versions the operator picks
from.** Fetching the checksum alongside the download would verify nothing that
matters: an attacker who controls the download controls the checksum file too,
so it protects against corruption in transit and not against attack. A pinned
digest means compromising *this* project's release, not upstream's.

```rust
/// A release this build knows how to verify.
///
/// Compiled in rather than fetched: a checksum downloaded from the same host
/// as the artefact proves only that the transfer completed.
pub struct Release {
    pub version: &'static str,
    pub sha256: &'static str,
    pub url: &'static str,
}
```

Offering several versions rather than only the newest keeps this project's
release cadence from dictating which upstream version an operator may install.
The task exposes them as a parameter; an unknown version is not installable,
which is the intended limit.

This mirrors the reasoning already recorded for the `curl | sh` installer: the
tool runs as root, so unverified remote code is not acceptable.

---

## 3. Categorisation

Grouped by **what they administer**, not by what they are.

```
Identity & Access          ← irreversible, prerequisite to most things
  users.create             create an admin user with a key
  users.set-shell          change a user's login shell
  users.lock-root          disable the root account          [HARD PREREQ]

Remote Access
  ssh.*                    (exists)
  wireguard.*              install, peers, DNS

Network                    ← the hub most consequences point at
  firewall.*               enable, allow-port, status
  sysctl.*                 ip-forward, unprivileged-ports

Hardening
  fail2ban.*               install, protect-ssh
  updates.*                unattended security upgrades

Services
  docker-rootless.*        rootless engine per user
  caddy.*                  install, Caddyfile, validate

Developer Environment      ← per-user, not per-system
  mise.*  rust.*  fish.*  zellij.*
```

**Firewall was not in the request but is load-bearing.** It is the destination
of most consequences; without it the mechanism points at tasks that do not
exist.

**`sysctl` is its own capability on the strength of the operator's repo.**
`ip_forward` (WireGuard) and `ip_unprivileged_port_start` (Docker rootless) are
shared by unrelated components. `naisudotfun` manages them from two scripts by
two different mechanisms — the exact drift a single owner prevents.

**Installing a tool is a system operation; configuring it for someone is not.**
Putting `mise`, `rustup`, `fish` or `zellij` on the machine writes to
`/usr/local/bin` or the package database and involves no user at all. Only a
narrow set of tasks is per-user, and each declares a `Username` parameter like
any other — no session state, no change to the tree:

| Per-user task | Why it cannot be system-wide |
|---|---|
| `fish.set-shell` | `chsh -s` targets an account by definition |
| `docker-rootless.install` | the daemon runs *as* an account: linger, `~/.config/systemd/user/` |
| `mise.activate` | activation writes to a user's shell config |

Splitting install from configure also keeps the destructive flag honest:
installing a binary is not destructive, changing someone's login shell is.

---

## 4. Phases

### Phase 1 — Identity & Access, Network foundation

Ordered first because everything else depends on there being a safe way in, and
because `users.lock-root` is the most dangerous operation in the tool.

| Task | Notes |
|---|---|
| *(refactor)* `path_for` | pay the agnosticism debt first |
| *(mechanism)* `Consequence` | proven against existing SSH tasks before new ones exist |
| `users.create` | user + key + admin group + sudoers |
| `users.set-shell` | requires shell present in `/etc/shells` |
| `users.lock-root` | hard prerequisite, see §5 |
| `firewall.enable` | default deny incoming |
| `firewall.allow-port` | consequence target for ssh/wireguard/caddy |
| `sysctl.ip-forward` | |
| `sysctl.unprivileged-ports` | consequence: restart rootless Docker |

Proving the consequence mechanism against *existing* SSH tasks is deliberate:
`ssh.change-port` gains a real consequence the moment `firewall.allow-port`
exists, with no new component in play.

### Phase 2 — WireGuard
install, peer add/remove, internal DNS. Sourced from `naisudotfun`, with its
bugs fixed (§6).

### Phase 3 — Services

| Task | Notes |
|---|---|
| `docker-rootless.install` | per-user; linger, subuid/subgid |
| `caddy.install` | package + unit; units differ per family |
| `caddy.validate` | `caddy validate`, never a file grep |
| `caddy.reload` | fails if `admin off` was set |
| `caddy.security-headers` | HSTS, nosniff, frame-deny, referrer policy |

`caddy.*` installs, validates and hardens — it does **not** generate site
configuration. Writing `reverse_proxy` blocks describes an application
topology, which is where Coolify and Dokploy live and where this tool
deliberately stops. Security headers are the exception because hardening *is*
this tool's domain, even when the file it lands in belongs to an application.

`X-Forwarded-*` must never be set: Caddy already populates those, and
overwriting them breaks client-IP detection downstream.

### Phase 4 — Developer Environment
mise, Rust, fish, Zellij.

### Phase 5 — Hardening

| Task | Notes |
|---|---|
| `fail2ban.install` | log-parsing, local only |
| `fail2ban.protect-ssh` | jail must follow the SSH port |
| `crowdsec.install` | conflicts with fail2ban |
| `updates.unattended-security` | Debian only, see §8.3 |

**Both banners ship, and each declares the other as a `Conflicts`.** They are
not interchangeable and the choice is the operator's: fail2ban parses local
logs and bans through the firewall with nothing leaving the host; CrowdSec adds
a reputation network that blocks addresses which attacked *other* hosts first,
at the cost of outbound telemetry and an account for the community blocklist.

Neither is installed by default. `ssh.harden` already writes `MaxAuthTries 3`
and `LoginGraceTime 30`, and with key-only authentication password brute force
does not apply at all — so this phase is defence in depth, not a gap being
plugged. Saying that plainly matters: a tool that implies a host is unprotected
without fail2ban is selling something.

---

## 5. `users.lock-root` — the one hard prerequisite

The operator chose **advisory consequences everywhere**, with this task as the
deliberate exception. The justification is empirical, not stylistic.

### What the research overturned

**A `!`-locked password does not block SSH key authentication for root.**
Verified in `pam_unix/passverify.c`: the `!` check runs in the *auth* phase, and
public-key auth never calls `pam_authenticate`. Web sources contradict this and
are wrong.

There is a second gate on top: OpenSSH's `platform_locked_account()`
(`auth.c:108`) is compiled behind `!options.use_pam`. With `UsePAM yes` — the
default everywhere — key auth succeeds anyway.

**Therefore `passwd -l root` alone does not do what the operator intends.**
Only `usermod --expiredate 1` (shadow field 8) blocks both paths. Use `1`, not
`chage -E 0`, which `shadow(5)` documents as ambiguous. `passwd -d` must never
appear anywhere near this task: it makes root *passwordless*.

### Why an advisory warning is insufficient here

Every other change in this tool is recoverable. `ssh.harden` has a verification
window. A wrong firewall rule can be removed from the console. Locking root
without a working administrative path can require provider rescue media or
physical access.

A dismissible warning does not protect against the only irreversible error in
the tool. So this task **refuses to run** unless it can verify:

1. A non-root account exists,
2. holding a non-empty `authorized_keys` with correct ownership and modes,
3. in the family's admin group (`sudo` on Debian, `wheel` on Arch),
4. with a sudoers rule that is actually parsed, and
5. `Defaults rootpw` / `targetpw` absent from sudoers.

Check 5 is not defensive padding: with `Defaults rootpw`, sudo authenticates
against **root's** password, so locking root kills sudo and root together.

Check 4 exists because `/etc/sudoers.d/alice.conf` is **silently ignored** —
any `.` in the filename disqualifies the file. It exits 0 and hardens nothing.

### Known untestable gap

`sulogin` behaviour after locking root cannot be verified in a container; it
needs a VM with a real console. Documented as a gap rather than left silently
untested — consistent with how this project treats coverage it does not have.

---

## 6. Verified settings

Only findings that change what gets built. Corrections first: several
widely-repeated premises are false.

### Corrections

| Commonly assumed | Verified reality |
|---|---|
| `apt install zellij` | **No such package** in any Debian/Ubuntu suite |
| Docker rootless uses slirp4netns | v29.5.0 defaults to **gvisor-tap-vsock**; slirp4netns no longer packaged |
| WireGuard MTU default 1420 | wg-quick *computes* `endpoint_mtu - 80`, floor 1280 |
| Caddy `encode` supports brotli | **zstd and gzip only** |
| `passwd -d` locks an account | Makes it **passwordless** |
| Caddy's unit has `NoNewPrivileges` etc. | That is **Arch's** unit; upstream's is materially different |
| mise `legacy_version_file` setting | **Removed**, not renamed |

### Silent-success bugs to defend against

Same class as the `is-active`/`inactive` substring bug already documented in
CLAUDE.md. All exit 0 while hardening nothing:

1. `/etc/sudoers.d/*.conf` — a `.` in the filename voids the file
2. `usermod -aG sudo` on Arch — group absent, **no error**
3. `PasswordAuthentication no` alone — PAM keyboard-interactive still accepts
   passwords *(already handled correctly in `src/tasks/ssh.rs`)*
4. sshd drop-in without the `Include` line — written, never read

Transverse rule: **assert with `sshd -T`, never by grepping the file.**

### Per-component notes that drive consequences

- **WireGuard** — `AllowedIPs` is bidirectional (inbound authorisation, outbound
  routing); `/32` per peer server-side. wg-quick silently sets
  `net.ipv4.conf.all.src_valid_mark=1` globally and undocumented, which reads as
  drift to an auditor. **Killer footgun:** `AllowedIPs = 0.0.0.0/0` without
  `::/0` leaks IPv6.
- **Docker rootless** — `loginctl enable-linger` is non-negotiable: without it
  containers die at logout and `WantedBy=default.target` brings nothing back
  after reboot. Rootless does **not** touch host iptables, which is why `ufw`
  actually works — the strongest argument for preferring it. Source-IP
  propagation is fixed with `"userland-proxy": false`.
- **Caddy** — directive order is predefined, not source order. Do **not** set
  `header_up X-Forwarded-*`; Caddy sets them and manual values break client-IP
  detection. `admin off` disables `caddy reload`.
- **mise** — activation is a *prompt hook*, so it never fires in
  non-interactive shells. Servers need shims or `mise exec --`. Trust state is
  per-user: a root-provisioned config is not trusted by the service account.
- **Rust** — rustup does not install a C linker; this is the top first-build
  failure. Confirmed on the development machine: both musl targets are
  installed and `musl-gcc` is **absent**, so the release build documented in
  CLAUDE.md fails at link today. Needs `musl-tools`. No `rust-toolchain.toml`
  exists despite CLAUDE.md pinning a stable version and two targets.
- **fish** — Debian 12 and Ubuntu 24.04 ship fish **3.x** (pre-Rust).
  `config.fish` runs non-interactively, so unguarded output breaks `scp` and
  `rsync`. `~/.profile` is never read. Never root's login shell.
- **Zellij** — prefer `zellij-no-web-*` artifacts; 0.44+ ships an optional HTTP
  server that has no business on a hardened host.

---

## 7. Consequence map

The edges the mechanism must express. `⚠` marks `External` — unverifiable by
design.

| Source | Consequence | Kind |
|---|---|---|
| `ssh.change-port` | `firewall.allow-port` names the old port | Invalidates |
| `ssh.change-port` | `fail2ban` jail watches the old port | Invalidates |
| `ssh.change-port` | ⚠ provider edge firewall | External |
| `wireguard.install` | needs `sysctl.ip-forward` | Invalidates |
| `wireguard.install` | needs UDP port open | Invalidates |
| `wireguard.install` | ⚠ provider edge firewall (UDP) | External |
| `docker-rootless.install` | needs `sysctl.unprivileged-ports` for :80/:443 | Invalidates |
| `docker-rootless.install` | needs `loginctl enable-linger` | Invalidates |
| `sysctl.unprivileged-ports` | rootless Docker must restart to pick it up | Invalidates |
| `caddy.install` | needs 80/443 open | Invalidates |
| `caddy.install` | ⚠ DNS must resolve to this host for ACME | External |
| `users.create` | `ssh.allow-users` does not name the new account | Invalidates |
| `users.set-shell` | shell must be listed in `/etc/shells` | Invalidates |
| `fish.install` | `mise` activation differs under fish | Invalidates |
| `mise.install` | not active in non-interactive shells | Invalidates |

`caddy.install → DNS` is `External` for the same reason as the edge firewall:
the tool cannot verify a DNS record it does not control, and ACME will fail
without it. Saying so is useful; implying it was checked is not.

---

## 8. Resolved design questions

Settled 2026-08-04. Recorded with their reasoning so the next reader does not
reopen them.

1. **Per-user scope** — installing a tool is a system operation and takes no
   user; only `fish.set-shell`, `docker-rootless.install` and `mise.activate`
   are per-user, and they declare a `Username` parameter like any other task.
   No session state was added. See §3.

2. **Consequence staleness** — static, with on-demand verification under `v`.
   Re-evaluating on render means running commands on every keypress; the cache
   that would fix it can go stale in turn. `External` consequences expose no
   verify affordance, because the tool cannot see what they warn about. See §1.

3. **`updates.*` on Arch** — Debian only in `supported_families()`. Arch is a
   rolling release with no equivalent, and the TUI already greys out
   unsupported tasks with the reason. Inventing a different operation under the
   same id would make the two families silently disagree about what the task
   does.

4. **`BinaryInstaller` checksums** — compiled in, for a set of selectable
   versions. A checksum fetched from the host serving the artefact proves only
   that the transfer completed. See §2.3.

5. **`fail2ban` vs CrowdSec** — both ship, each declaring the other as a
   `Conflicts`. The choice is the operator's because the tradeoff is theirs:
   local-only versus a reputation network that sends telemetry outbound. This
   is what introduced the `Conflicts` variant. See Phase 5.

6. **`caddy.*` scope** — install, validate, reload and security headers; no
   site generation. Headers are in scope because hardening is this tool's
   domain even when the file belongs to an application; `reverse_proxy` blocks
   are not, because they describe an application topology. See Phase 3.
