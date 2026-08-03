#!/bin/sh
# Probes how the escalation helpers on this host behave, for the decisions in
# `initd`'s execution layer.
#
# Run inside a container as a non-root user with sudo access:
#
#   docker run --rm -v "$PWD/tests/fixtures:/f:ro" debian:13 /f/validate-sudo.sh
#
# It answers four questions the design depends on:
#
#   1. Does `sudo -v` refresh a timestamp that a later `sudo -n` can use?
#   2. How long does that timestamp last by default?
#   3. Does `doas` offer anything equivalent?
#   4. Does `run0` need any of this?
#
# Nothing here is destructive: it validates and reads, and never configures.

set -u

say() { printf '\n=== %s\n' "$1"; }
answer() { printf '  %-28s %s\n' "$1" "$2"; }

say "Escalation helpers present"
for helper in sudo doas run0; do
    if command -v "$helper" >/dev/null 2>&1; then
        answer "$helper" "$(command -v "$helper")"
    else
        answer "$helper" "absent"
    fi
done

say "Effective user"
answer "id -u" "$(id -u)"
answer "whoami" "$(whoami 2>/dev/null || echo unknown)"

# Running as root makes every question below moot: initd skips escalation
# entirely in that case.
if [ "$(id -u)" -eq 0 ]; then
    say "Running as root"
    answer "escalation needed" "no — every question below is moot"
    exit 0
fi

if command -v sudo >/dev/null 2>&1; then
    say "sudo -n -v (is a timestamp already valid?)"
    if sudo -n -v 2>/dev/null; then
        answer "result" "valid — no password would be asked"
    else
        answer "result" "not valid — a password would be asked"
    fi

    say "sudo -n true (does a real command run unprompted?)"
    if sudo -n true 2>/dev/null; then
        answer "result" "yes — NOPASSWD or a live timestamp"
    else
        answer "result" "no — this is the case the design has to handle"
    fi

    say "timestamp_timeout"
    timeout=$(sudo -n sudoers-policy-check 2>/dev/null || true)
    if grep -rhs "timestamp_timeout" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        :
    else
        answer "configured" "not set — the compiled-in default applies"
    fi

    say "sudo -V default timeout"
    sudo -V 2>/dev/null | grep -i "timestamp timeout" || \
        answer "reported" "not shown without root"
fi

if command -v doas >/dev/null 2>&1; then
    say "doas equivalents"
    # doas has no -v: it authenticates per invocation, and persistence is a
    # per-rule setting rather than a client-side refresh.
    doas -h 2>&1 | head -5
    answer "has -v" "$(doas -v 2>&1 | head -1)"
fi

if command -v run0 >/dev/null 2>&1; then
    say "run0"
    answer "is a symlink to" "$(readlink -f "$(command -v run0)")"
    # run0 authenticates through polkit, which owns its own prompt and its own
    # caching, so a client-side timestamp refresh does not apply.
    answer "auth mechanism" "polkit — prompt and caching are not ours to drive"
fi

say "Done"
