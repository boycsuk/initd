#!/bin/sh
# Establishes whether a sudo timestamp survives into spawned processes, which
# is the property `initd`'s asynchronous execution rests on.
#
# It uses nothing but the shell. Earlier attempts measured a compiled binary
# built by root and run through layers of `su`, and reported refusals that
# turned out to belong to the harness rather than to sudo — see
# `docs/sudo-timestamp-findings.md`.
#
# It asks the question in the order that matters:
#
#   1. authenticate
#   2. run a privileged command from a child process
#   3. ask again from the parent
#
# If (2) is refused while (1) and (3) succeed, the timestamp is being consumed
# or invalidated rather than merely scoped — which is a different problem from
# the one every earlier probe assumed.

set -u

say() { printf '\n=== %s\n' "$1"; }

printf 'probe\n' | sudo -S -v 2>/dev/null
printf '  authenticate                 exit %s\n' "$?"

say "Parent, immediately"
if sudo -n true 2>/dev/null; then
    printf '  parent: sudo -n true         accepted\n'
else
    printf '  parent: sudo -n true         REFUSED\n'
fi

say "Child process"
if sh -c 'sudo -n true' 2>/dev/null; then
    printf '  child: sudo -n true          accepted\n'
else
    printf '  child: sudo -n true          REFUSED\n'
fi

say "Grandchild, two levels down"
if sh -c "sh -c 'sudo -n true'" 2>/dev/null; then
    printf '  grandchild: sudo -n true     accepted\n'
else
    printf '  grandchild: sudo -n true     REFUSED\n'
fi

say "Parent again, afterwards"
if sudo -n true 2>/dev/null; then
    printf '  parent: sudo -n true         still accepted\n'
else
    printf '  parent: sudo -n true         REFUSED\n'
fi

say "A background child, which is closest to how a TUI spawns work"
sh -c 'sudo -n true' 2>/dev/null &
wait $!
if [ $? -eq 0 ]; then
    printf '  background child             accepted\n'
else
    printf '  background child             REFUSED\n'
fi

printf '\n=== Done\n'
