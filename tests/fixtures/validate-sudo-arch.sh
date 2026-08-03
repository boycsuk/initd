#!/bin/sh
# Container entrypoint for Arch, the counterpart of `validate-sudo-debian.sh`.
#
# Arch is worth probing separately: it ships a different sudo build, and its
# base image carries neither sudo nor a non-root account.
#
#   docker run --rm -t -v "$PWD/tests/fixtures:/f:ro" archlinux:latest \
#       sh /f/validate-sudo-arch.sh validate-child.sh

set -eu

pacman -Sy --noconfirm --quiet sudo >/dev/null 2>&1

useradd -m -s /bin/sh admin

# A password-requiring rule: a NOPASSWD one would make every probe succeed and
# prove nothing about the timestamp.
echo 'admin ALL=(ALL) ALL' > /etc/sudoers.d/admin
chmod 0440 /etc/sudoers.d/admin

echo 'admin:probe' | chpasswd

su admin -c "sh /f/${1:-validate-sudo.sh}"
