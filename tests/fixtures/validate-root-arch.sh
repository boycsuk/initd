#!/bin/sh
# Installs sudo on Arch and reads its build settings as root.
#
#   docker run --rm -v "$PWD/tests/fixtures:/f:ro" archlinux:latest \
#       sh /f/validate-root-arch.sh

set -eu

pacman -Sy --noconfirm --quiet sudo >/dev/null 2>&1

sh /f/validate-scope-root.sh
