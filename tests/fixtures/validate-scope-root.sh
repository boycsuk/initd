#!/bin/sh
# Reads sudo's compiled-in timestamp settings, which need root to print.
#
# This is the variable that explains the Debian/Arch disagreement: `sudo -V`
# reports the timestamp *type*, and a `tty`-keyed timestamp behaves differently
# from a `ppid`-keyed or global one when a tool authenticates once and spawns
# children afterwards.

set -u

printf '=== sudo build settings\n'
sudo -V | grep -iE "timestamp|timeout|Authentication timestamp" || \
    printf '  nothing matched\n'

printf '\n=== sudoers overrides\n'
grep -rhsE "timestamp_(type|timeout)|Defaults" /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | grep -vE "^#" || printf '  none\n'

printf '\n=== version\n'
sudo --version | head -1
