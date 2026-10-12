#!/bin/sh
# After the package is removed. The database is kept: it is the scan history.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
case "$1" in
  remove|purge|0)
    echo "CipherHorizon was removed. Its database is kept in /var/lib/private/cipherhorizon; delete that folder to remove the scan history."
    ;;
esac
exit 0
