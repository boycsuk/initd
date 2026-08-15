#!/bin/sh
# Downloads a published initd release and verifies it before installing.
#
#   curl -fsSL https://raw.githubusercontent.com/boycsuk/initd/main/install.sh | sh
#
# This script is piped into a shell, which means it runs unverified remote code
# as whatever user runs it. The one thing it can do about that is refuse to
# install a binary whose digest does not match the one published beside it —
# so the checksum check here is the point of the file, not a nicety, and every
# path that would skip it exits instead.
#
# What that does *not* protect against: anyone able to publish a release can
# write both the binary and its digest. Signed releases would close that, and
# they are not implemented — this says so rather than implying more assurance
# than it offers.

set -eu

REPO="boycsuk/initd"

# Where the binary lands. There is one answer, and that is deliberate.
#
# `initd` administers the machine: 138 of the commands it runs are privileged,
# and every task that installs a package, writes to `/etc` or touches a unit is
# among them. An account that cannot become root cannot run those, so a copy of
# the binary in that account's home is a program that starts, draws its
# interface, and fails at the first thing anybody asks it to do.
#
# So this refuses rather than installing somewhere it would not work. A
# `~/.local/bin` fallback was written, measured and removed for that reason: it
# turned "you cannot install this" into "you have installed this and it does
# not work", which is the worse of the two by some distance.
#
# `INITD_INSTALL_DIR` is still honoured, and is now the whole of the escape
# hatch: packaging, inspecting the binary, a host whose root path is elsewhere.
#
# The same directory `initd` installs *its* release binaries into — zellij,
# mise, caddy on RHEL; see `release_installer::INSTALL_DIR`. Correct for both,
# and worth stating in both places: the tool and the things it installs live
# side by side, so the one name that must stay unclaimed is `initd` itself.
SYSTEM_DIR="/usr/local/bin"

fail() {
    echo "install: $*" >&2
    exit 1
}

# `uname -m` names the architecture the way the release artefacts do, which is
# why the mapping below is short: the two the project publishes are already
# spelled the same.
target_for_machine() {
    case "$(uname -m)" in
        x86_64) echo "x86_64-unknown-linux-musl" ;;
        aarch64 | arm64) echo "aarch64-unknown-linux-musl" ;;
        *) fail "no published build for $(uname -m)" ;;
    esac
}

# Every tool this script needs, checked before anything is downloaded. A
# missing `sha256sum` discovered halfway through is the one failure that could
# tempt someone into installing unverified.
require_tools() {
    for tool in curl sha256sum install uname mktemp; do
        command -v "$tool" >/dev/null 2>&1 || fail "$tool is required and was not found"
    done
}

main() {
    require_tools

    target="$(target_for_machine)"
    version="${INITD_VERSION:-latest}"

    if [ "$version" = "latest" ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$version"
    fi

    # A directory removed however this exits, so a failed verification leaves
    # nothing behind that a later run might mistake for a checked download.
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT

    echo "downloading initd for $target"

    curl -fsSL --proto '=https' --tlsv1.2 \
        -o "$workdir/initd-$target" \
        "$base/initd-$target" \
        || fail "could not download the binary"

    curl -fsSL --proto '=https' --tlsv1.2 \
        -o "$workdir/SHA256SUMS" \
        "$base/SHA256SUMS" \
        || fail "could not download the checksums"

    echo "verifying"

    # Compared as two strings rather than through `sha256sum --check`, and the
    # reason is Alpine: its `sha256sum` is a busybox applet, and busybox knows
    # neither `--ignore-missing` nor `--check`. Both were answered with
    # `unrecognized option`, so the verification failed on a *genuine* release
    # and the script refused to install — reporting tampering where there was
    # none. Measured on `alpine:3.23` against busybox 1.37.0, and against GNU
    # coreutils 8.32 and 9.7, which accept this form as readily.
    #
    # `--ignore-missing` was there because the published list names both
    # architectures and only one is downloaded. Selecting the line for the one
    # in hand does the same work without needing a flag.
    expected=$(awk -v file="initd-$target" '$2 == file || $2 == "*" file { print $1; exit }' \
        "$workdir/SHA256SUMS")

    [ -n "$expected" ] \
        || fail "the published checksums name no initd-$target — not installing"

    actual=$(sha256sum "$workdir/initd-$target" | awk '{ print $1 }')

    [ "$expected" = "$actual" ] \
        || fail "the download did not match its published checksum — not installing"

    # Only now, and never before the check above.
    #
    # Called plainly rather than as `$(choose_install_dir)`, because a command
    # substitution runs its function in a subshell and every variable set there
    # is discarded when it exits. This one sets two — where to install and how
    # — and the second would have been lost, leaving the script trying to write
    # to a root-owned directory unprivileged. Measured rather than reasoned
    # about: the assignment does not survive, in `sh` and in `bash` alike.
    # Refuses on its own terms rather than returning: the two ways this can be
    # impossible call for different advice, and it is the one that knows which.
    choose_install_dir

    # Said before the write rather than after, because afterwards there is
    # nothing left to compare against: `install` replaces the file in place.
    report_replacement "$install_dir/initd"

    # `escalate` is empty unless the directory needs root *and* this account can
    # reach it without being asked for a password. Unquoted on purpose: it is
    # either nothing or a command with its own arguments.
    #
    # `install` overwrites whatever is there, which is what makes re-running
    # this an upgrade rather than an error — verified including the awkward
    # case, a binary that is *running*: the file is replaced by inode, so a
    # session someone left open in another terminal goes on working against the
    # copy it started with.
    # `install`'s own stderr is kept and shown rather than discarded. It used to
    # go to /dev/null with every failure reported as "could not write", which
    # names one cause out of several — a full disk, a read-only mount, a missing
    # directory and a refused escalation all reached the same sentence, and it
    # steered the reader towards `INITD_INSTALL_DIR`, the one answer that can
    # leave a working binary somewhere nothing looks for it.
    if ! install_error=$($escalate install -m 0755 \
        "$workdir/initd-$target" "$install_dir/initd" 2>&1); then
        [ -n "$install_error" ] && echo "install: $install_error" >&2
        fail "could not install to $install_dir — see the error above, or set INITD_INSTALL_DIR to somewhere writable"
    fi

    echo "installed $install_dir/initd"

    warn_if_unreachable "$install_dir"

    echo
    echo "run 'initd' for the interactive interface, or 'initd list' to see the tasks"
}

# Says what is about to be replaced, where anything is.
#
# `install` overwrites in silence, which is right — re-running this is how an
# upgrade is done — but silence is also how a *downgrade* happens without
# anybody noticing, and the two are the same command. The one thing a person
# re-running an install wants to know is what it displaces.
#
# Both versions come from the binaries themselves rather than from the tag
# asked for, because `INITD_VERSION` is usually `latest` and `latest` is not a
# version anyone can compare against. The downloaded copy has already been
# checksum-verified by the time this runs, so asking it is not a new trust.
#
# Every failure here is silent by design. This is a courtesy line, and an
# installed copy too old to answer `--version`, or one built for another
# architecture, must not stop an install that would have replaced it anyway.
report_replacement() {
    target_path="$1"

    [ -x "$target_path" ] || return 0

    installed=$("$target_path" --version 2>/dev/null | tr -d '\r') || return 0
    [ -n "$installed" ] || return 0

    incoming=$("$workdir/initd-$target" --version 2>/dev/null | tr -d '\r') || return 0
    [ -n "$incoming" ] || return 0

    if [ "$installed" = "$incoming" ]; then
        echo "reinstalling $installed over the copy at $target_path"
        return 0
    fi

    # `sort -V` is not POSIX and busybox's is a stub, so the comparison is left
    # to the reader rather than guessed at with something that sorts `0.10.0`
    # below `0.9.0`. Naming both versions answers the question either way, and
    # is honest about which direction this is going.
    echo "replacing $installed at $target_path with $incoming"
}

# Where the binary goes, and the command that puts it there — the second being
# nothing at all unless root is both needed and reachable. Both are set by
# `choose_install_dir`, which is why it is not called in a subshell.
install_dir=""
escalate=""

# Whether this account can become root *without being asked for a password*.
#
# The distinction is the whole of it. A script piped into a shell has already
# spent stdin on the script itself, so a password prompt has nowhere to read
# from: it either hangs or silently fails, and both look like the installer
# being broken. `sudo -n` refuses instead of prompting, which turns "can I
# escalate" into a question with an answer.
#
# The same reasoning `initd` itself follows before running a privileged
# command, arrived at there for the same reason: ask before a helper asks.
#
# `doas` and `run0` are checked too, since a host carrying one and not sudo is
# ordinary on Alpine and on a systemd box respectively. Each has its own
# spelling of "answer without prompting".
escalator() {
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        printf 'sudo'
        return 0
    fi

    if command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then
        printf 'doas'
        return 0
    fi

    if command -v run0 >/dev/null 2>&1 && run0 --no-ask-password true >/dev/null 2>&1; then
        printf 'run0 --no-ask-password'
        return 0
    fi

    return 1
}

# Decides where the binary goes and how it gets there, or refuses.
#
# Sets `install_dir` and `escalate` rather than printing either, which is why
# it must not be called in a subshell.
#
# The refusal is the interesting path, and it distinguishes two cases that look
# alike and are not. An account with *no* route to root cannot use this tool at
# all. An account whose `sudo` would ask for a password can — just not from a
# script that has already spent stdin on itself. The first is told to find an
# administrator; the second is told to run one command.
choose_install_dir() {
    if [ -n "${INITD_INSTALL_DIR:-}" ]; then
        install_dir="$INITD_INSTALL_DIR"

        mkdir -p "$install_dir" 2>/dev/null || true
        [ -w "$install_dir" ] && return 0

        if escalate=$(escalator); then
            $escalate mkdir -p "$install_dir" 2>/dev/null || true
            return 0
        fi

        escalate=""
        fail "cannot write to $INITD_INSTALL_DIR, and cannot become root to try"
    fi

    if [ -w "$SYSTEM_DIR" ]; then
        install_dir="$SYSTEM_DIR"
        return 0
    fi

    if escalate=$(escalator); then
        install_dir="$SYSTEM_DIR"
        $escalate mkdir -p "$install_dir" 2>/dev/null || true
        return 0
    fi

    escalate=""
    refuse_without_root
}

# Explains why there is nothing useful to install, and how to get one.
#
# Two messages, because there are two situations. Telling somebody with sudo to
# "ask an administrator" would be telling them to ask themselves.
refuse_without_root() {
    if command -v sudo >/dev/null 2>&1 || command -v doas >/dev/null 2>&1; then
        echo "install: initd administers this machine, so it needs root — and" >&2
        echo "         your sudo would ask for a password, which a script piped" >&2
        echo "         into a shell cannot answer." >&2
        echo >&2
        echo "         run it with sudo instead:" >&2
        echo >&2
        echo "             curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sudo sh" >&2
        echo >&2
        echo "         or authenticate first, so the next command needs no password:" >&2
        echo >&2
        echo "             sudo -v" >&2
        exit 1
    fi

    echo "install: initd administers this machine — installing packages, editing" >&2
    echo "         /etc, enabling units — and this account has no route to root." >&2
    echo >&2
    echo "         Nothing useful would be installed, so nothing was. Ask an" >&2
    echo "         administrator to run this, or run it as root." >&2
    exit 1
}

# Says so when the shell will not find what was just installed.
#
# `/usr/local/bin` is on every PATH this project has measured, so in the
# ordinary case this prints nothing. It is here for `INITD_INSTALL_DIR`, which
# can name anywhere at all — and a report of success that leaves the operator
# unable to run the thing is worse than the refusal it replaced.
#
# It names the line to add rather than saying "adjust your PATH", because the
# reader is being told this precisely because their shell did not do it for
# them.
warn_if_unreachable() {
    case ":${PATH}:" in
        *":$1:"*) return 0 ;;
    esac

    echo
    echo "note: $1 is not on your PATH, so the shell will not find initd yet."
    echo "      add it for this session:"
    echo
    echo "          export PATH=\"$1:\$PATH\""
    echo
    echo "      or permanently, in your shell's profile:"
    echo
    echo "          echo 'export PATH=\"$1:\$PATH\"' >> ~/.profile"
}

main "$@"
