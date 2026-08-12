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

# Where the binary lands, when nobody says otherwise.
#
# `INITD_INSTALL_DIR` still overrides both, and setting it is no longer the
# price of not being root: an ordinary account falls back to the second path
# below. That fallback is what makes `curl … | sh` work as whoever happens to
# be logged in, which is how this script is actually run.
SYSTEM_DIR="/usr/local/bin"
USER_DIR="${HOME:-/root}/.local/bin"

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
    install_dir=$(choose_install_dir) \
        || fail "could not write to $SYSTEM_DIR or $USER_DIR — set INITD_INSTALL_DIR to somewhere writable"

    install -m 0755 "$workdir/initd-$target" "$install_dir/initd" 2>/dev/null \
        || fail "could not write to $install_dir — set INITD_INSTALL_DIR to somewhere writable"

    echo "installed $install_dir/initd"

    warn_if_unreachable "$install_dir"

    echo
    echo "run 'initd' for the interactive interface, or 'initd list' to see the tasks"
}

# Picks the first directory this account can actually write to.
#
# Tried in order, and the order is the point: a system-wide install is what an
# administrator wants when they can have one, and an account that cannot write
# there is not an error — it is the ordinary case for `curl … | sh` run as
# whoever is logged in. `~/.local/bin` is where a user-level binary belongs by
# the XDG Base Directory Specification, and it is created if missing, since
# Debian's own `.profile` adds it to PATH *only when it exists*.
#
# An explicit `INITD_INSTALL_DIR` skips the search: somebody who named a
# directory meant that one, and silently installing somewhere else would be
# worse than failing.
choose_install_dir() {
    if [ -n "${INITD_INSTALL_DIR:-}" ]; then
        mkdir -p "$INITD_INSTALL_DIR" 2>/dev/null || true
        [ -w "$INITD_INSTALL_DIR" ] || return 1

        printf '%s' "$INITD_INSTALL_DIR"
        return 0
    fi

    if [ -w "$SYSTEM_DIR" ]; then
        printf '%s' "$SYSTEM_DIR"
        return 0
    fi

    mkdir -p "$USER_DIR" 2>/dev/null || true
    if [ -w "$USER_DIR" ]; then
        printf '%s' "$USER_DIR"
        return 0
    fi

    return 1
}

# Says so when the shell will not find what was just installed.
#
# Measured rather than assumed, because it differs per distribution: Debian's
# `.profile` adds `~/.local/bin` and only if the directory already existed,
# Rocky adds it from `.bashrc` — which a `sh` login never reads — and Alpine
# adds it nowhere. So on two of those three an install into that directory
# succeeds and `initd` is still not found.
#
# A report of success that leaves the operator unable to run the thing is the
# failure this exists to prevent. It names the line to add rather than saying
# "adjust your PATH", because the reader is being told this precisely because
# their shell did not do it for them.
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
