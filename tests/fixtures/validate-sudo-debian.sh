#!/bin/sh
# Container entrypoint: prepares a Debian image with an ordinary sudo user and
# runs the escalation probe as that user.
#
# Split from `validate-sudo.sh` so the probe itself stays distro-agnostic and
# can be run against an already-configured host.
#
#   docker run --rm -v "$PWD/tests/fixtures:/f:ro" debian:13 /f/validate-sudo-debian.sh

set -eu

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq sudo >/dev/null 2>&1

useradd -m -s /bin/sh admin

# A password-requiring rule, which is the case the design has to handle. A
# NOPASSWD rule would make every probe below trivially succeed and prove
# nothing about the timestamp.
echo 'admin ALL=(ALL) ALL' > /etc/sudoers.d/admin
chmod 0440 /etc/sudoers.d/admin

# A known password, so the timestamp probe can actually authenticate once.
echo 'admin:probe' | chpasswd

# Invoked through `sh` rather than executed directly: a read-only bind mount
# from a Windows filesystem does not carry the execute bit.
#
# The probe to run is passed as an argument, so the same container preparation
# serves both the survey and the timestamp experiment.
su admin -c "sh /f/${1:-validate-sudo.sh}"
