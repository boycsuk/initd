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
INSTALL_DIR="${INITD_INSTALL_DIR:-/usr/local/bin}"

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

    # Checked from inside the directory, because the published digests name the
    # files without a path. `--ignore-missing` lets one file be verified
    # against a list naming both architectures.
    (
        cd "$workdir"
        sha256sum --ignore-missing --check SHA256SUMS >/dev/null 2>&1
    ) || fail "the download did not match its published checksum — not installing"

    # Only now, and never before the check above.
    install -m 0755 "$workdir/initd-$target" "$INSTALL_DIR/initd" 2>/dev/null \
        || fail "could not write to $INSTALL_DIR — run as root, or set INITD_INSTALL_DIR"

    echo "installed $INSTALL_DIR/initd"
    echo
    echo "run 'initd' for the interactive interface, or 'initd list' to see the tasks"
}

main "$@"
