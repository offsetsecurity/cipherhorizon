#!/bin/bash
# Runs inside a Debian container (QA-PLAN-006 §3): real sshd in each configuration, scanned by
# cipherhorizon ssh scan, compared with what OpenSSH itself says. Prints AGREE or DISAGREE per check.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq openssh-server openssh-client jq >/dev/null || { echo "SETUP FAILED"; exit 2; }
mkdir -p /run/sshd && ssh-keygen -A >/dev/null
CH=/ch/cipherhorizon
VERSION=$(ssh -V 2>&1)
echo "== $VERSION"
fail=0
norm() { tr ',' '\n' | grep -v -e '^ext-info-' -e '^kex-strict-' | sort; }

for cfg in /oracle/configs/*.conf; do
  name=$(basename "$cfg" .conf)
  conf=/tmp/sshd-$name.conf
  { cat /etc/ssh/sshd_config; echo "Port 2222"; cat "$cfg"; } > "$conf"
  if ! /usr/sbin/sshd -t -f "$conf" 2>/tmp/err; then
    echo "-- $name: not supported by this OpenSSH ($(head -1 /tmp/err)); skipped"
    continue
  fi
  /usr/sbin/sshd -f "$conf" -D -E /tmp/sshd-$name.log &
  pid=$!
  sleep 1
  "$CH" ssh scan --json 127.0.0.1:2222 >/tmp/rep.json 2>/tmp/scan.err
  T=$(/usr/sbin/sshd -T -f "$conf")
  echo "-- $name"
  for pair in "kexalgorithms:kex" "ciphers:cipherC2S" "macs:macC2S"; do
    key=${pair%%:*}; field=${pair##*:}
    want=$(echo "$T" | awk -v k="$key" '$1==k{print $2}' | norm)
    got=$(jq -r ".[0].report.algorithms.$field | join(\",\")" /tmp/rep.json | norm)
    if [ "$want" = "$got" ]; then echo "   AGREE    $key"; else echo "   DISAGREE $key"; echo "     sshd -T: $(echo $want)"; echo "     scanner: $(echo $got)"; fail=1; fi
  done
  # Host key fingerprints: every key the server loaded, as ssh-keygen prints them.
  want=$(echo "$T" | awk '$1=="hostkey"{print $2".pub"}' | while read -r f; do [ -f "$f" ] && ssh-keygen -lf "$f" | awk '{print $2}'; done | sort)
  got=$(jq -r '.[0].report.hostKeys[].fingerprint' /tmp/rep.json | sort)
  # A config restricting HostKeyAlgorithms advertises only those keys.
  if grep -q '^HostKeyAlgorithms ssh-ed25519$' "$cfg"; then want=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}'); fi
  if [ "$want" = "$got" ]; then echo "   AGREE    host key fingerprints ($(echo "$got" | wc -l))"; else echo "   DISAGREE host keys"; echo "     ssh-keygen: $(echo $want)"; echo "     scanner:    $(echo $got)"; fail=1; fi
  verified=$(jq -r '[.[0].report.hostKeys[] | select(.verified|not)] | length' /tmp/rep.json)
  [ "$verified" = 0 ] && echo "   AGREE    every host key signature verified" || { echo "   DISAGREE $verified host key signature(s) not verified"; fail=1; }
  # The client's own choice, where the local ssh is 10.x (its default list leads like OpenSSH 10.6's).
  ours=$(jq -r '.[0].report.negotiated.kex' /tmp/rep.json)
  if ssh -V 2>&1 | grep -q 'OpenSSH_1[0-9]'; then
    theirs=$(ssh -vv -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 127.0.0.1 true 2>&1 | tr -d '\r' | awk '/kex: algorithm:/{print $NF; exit}')
    [ "$ours" = "$theirs" ] && echo "   AGREE    negotiated kex ($ours)" || { echo "   DISAGREE negotiated kex: scanner $ours, ssh $theirs"; fail=1; }
  else
    echo "   (negotiated kex $ours; the local ssh client is older than 10, so its choice is not compared)"
  fi
  echo "   level L$(jq -r '.[0].evaluation.readiness.level' /tmp/rep.json) $(jq -r '.[0].evaluation.readiness.label' /tmp/rep.json), findings: $(jq -r '[.[0].evaluation.findings[].id] | unique | join(" ")' /tmp/rep.json)"
  kill $pid; wait $pid 2>/dev/null
done
exit $fail
