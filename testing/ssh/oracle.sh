#!/bin/bash
# QA-PLAN-006 §3 (PRD-008 REQ-SHN-2): the SSH prober against real OpenSSH. Builds a Linux binary,
# then runs testing/ssh/in-container.sh in Debian 12 (OpenSSH 9.2) and Debian 13 (OpenSSH 10.x).
#   bash testing/ssh/oracle.sh            (needs podman or docker)
set -eu
cd "$(dirname "$0")/../.."
ENGINE=${ENGINE:-$(command -v podman || command -v docker)}
OUT=$(mktemp -d)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$OUT/cipherhorizon" ./cmd/cipherhorizon
# Git Bash on Windows: hand the engine Windows paths, and stop it rewriting /ch:ro.
HOSTOUT=$OUT HOSTPWD=$PWD
if command -v cygpath >/dev/null; then HOSTOUT=$(cygpath -w "$OUT"); HOSTPWD=$(cygpath -w "$PWD"); export MSYS_NO_PATHCONV=1; fi
rc=0
for image in ${IMAGES:-debian:12-slim debian:13-slim}; do
  echo "#### $image"
  "$ENGINE" run --rm -v "$HOSTOUT:/ch:ro" -v "$HOSTPWD/testing/ssh:/oracle:ro" "$image" bash /oracle/in-container.sh || rc=1
done
rm -rf "$OUT"
exit $rc
