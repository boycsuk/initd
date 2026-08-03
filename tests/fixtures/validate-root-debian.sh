#!/bin/sh
# Installs sudo on Debian and reads its build settings as root.
#
#   docker run --rm -v "$PWD/tests/fixtures:/f:ro" debian:13 \
#       sh /f/validate-root-debian.sh

set -eu

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq sudo >/dev/null 2>&1

sh /f/validate-scope-root.sh
