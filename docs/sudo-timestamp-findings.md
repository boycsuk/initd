# Sudo timestamp behaviour, measured

> **What this file is.** The record of an experiment run against real Debian 13
> and Arch containers before building `initd`'s asynchronous execution. It
> exists because the design rests on a property of `sudo` that could not be
> confirmed from documentation, and because two of the intermediate results
> were misleading enough to be worth writing down.
>
> **Reproducing it.** The probes live in `tests/fixtures/validate-*.sh` and
> `validate-rust-spawn.rs`, run through Docker:
>
> ```
> docker run --rm -t -v "$PWD/tests/fixtures:/f:ro" debian:13 \
>     sh /f/validate-sudo-debian.sh validate-persistence.sh
> docker run --rm -t -v "$PWD/tests/fixtures:/f:ro" archlinux:latest \
>     sh /f/validate-sudo-arch.sh validate-persistence.sh
> ```

## The question

Can `initd` authenticate once at startup and then run privileged commands
without prompting again — so that a task's output streams into the TUI's own
pane instead of the terminal being handed to `sudo` for every command?

## The answer

**Yes, on both families.** After one `sudo -v`, later `sudo -n` invocations are
accepted, including from spawned child processes, grandchildren and background
processes.

Two conditions have to hold, and both are things `initd` already satisfies or
can arrange:

| Condition | Why |
|---|---|
| A terminal must be present | Both distributions key the timestamp by `tty` (`sudo -V`: *Type of authentication timestamp record: tty*). With no controlling terminal, nothing persists at all. |
| The spawned process must not have `/dev/null` on stdin | `Command::output()` sets this implicitly, and Debian refuses such a process. Inheriting stdin fixes it. |

## What each distribution reports

| | Debian 13 | Arch |
|---|---|---|
| sudo version | 1.9.16p2 | 1.9.17p2 |
| Timestamp type | `tty` | `tty` |
| Timestamp timeout | not reported | 5 minutes |
| `Defaults use_pty` | yes | no |

The timeout matters: Arch expires a timestamp after **five minutes**, not the
fifteen often assumed. A long-running task can therefore outlive it.

`sudo -n -v` refreshes without prompting while a timestamp is still valid, and
so does any ordinary `sudo -n` command — running work keeps the window open on
its own.

## Two misleading results, recorded so they are not rediscovered

Both cost real time and neither reflects how `initd` runs.

**Command substitution is not representative.** Every probe that ran sudo
inside `$(...)` reported a refusal on Arch, while the same command run directly,
redirected to a file, or piped into another program was accepted. `$()` is not
a shape `initd` uses.

**A binary compiled by root and run through `su` is not representative
either.** The Rust probe was refused on Arch in every configuration — piped
stdout, file-backed stdout, fully inherited streams — while a plain shell in
the same session was accepted before and after it. Running the identical
sequence with no compiled binary in the picture showed parent, child,
grandchild and background child all accepted. The harness was the variable,
not sudo.

The lesson is the one already recorded in `CLAUDE.md` about `sshd -t`: a mock,
or a probe that does not reproduce the real process shape, invents failures
that do not exist.

## What this means for the design

- Authenticate once at startup, before the alternate screen is entered, while
  the terminal is still ordinary and `sudo` can draw its own prompt. The
  password is never read by `initd`.
- Spawn later commands with stdin inherited, never `Stdio::null()`.
- Do not assume the window lasts fifteen minutes. Treat a refusal mid-session
  as ordinary and re-authenticate by handing the terminal over again, rather
  than as an error.
- `doas` has no `-v` equivalent and `run0` authenticates through polkit, which
  owns its own prompt and caching. Neither is covered by this experiment;
  `initd` should fall back to handing the terminal over per command for them.
