#!/bin/sh
# Before the package is removed (not on upgrade): stop and disable the service.
# Debian passes "remove"/"purge" (or "upgrade"); RPM passes 0 on removal, 1 on upgrade.
set -e
case "$1" in
  remove|purge|0)
    if [ -d /run/systemd/system ]; then
      systemctl disable --now cipherhorizon.service >/dev/null 2>&1 || true
    fi
    ;;
esac
exit 0
