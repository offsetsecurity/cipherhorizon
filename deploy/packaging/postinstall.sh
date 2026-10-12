#!/bin/sh
# After the .deb/.rpm installs or upgrades CipherHorizon. The service is not started on a first
# install: a scanner should run because someone chose to run it.
set -e
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || true
  # An upgrade restarts a running service onto the new binary (the database migrates forward,
  # with a backup made first); a stopped one stays stopped.
  systemctl try-restart cipherhorizon.service >/dev/null 2>&1 || true
  if ! systemctl is-enabled --quiet cipherhorizon.service 2>/dev/null; then
    cat <<'EOF'
CipherHorizon is installed. Start it now and at every boot with:
    sudo systemctl enable --now cipherhorizon
then open http://127.0.0.1:8080 . Settings: /etc/cipherhorizon/env   Logs: journalctl -u cipherhorizon
EOF
  fi
else
  echo "CipherHorizon is installed. This system does not run systemd: start it with  cipherhorizon serve"
fi
exit 0
