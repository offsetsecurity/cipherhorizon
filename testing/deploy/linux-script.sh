#!/usr/bin/env bash
# The Linux inventory script on three families (PRD-007 REQ-DP-5): Debian (dpkg), RHEL via UBI
# (rpm) and Alpine (apk, busybox). For each, it runs the script exactly as served, as root inside a
# throwaway container, checks the facts file (owner-only, a known header, packages found), uploads
# it to a local CipherHorizon server and checks the server turned it into a machine inventory.
#
# Usage: BIN=/path/to/linux/cipherhorizon testing/deploy/linux-script.sh
# Needs: podman (or ENGINE=docker), curl, a Linux cipherhorizon binary. Uses port 18090.
# With Podman on Windows or macOS, run it inside the machine (`podman machine ssh`).
set -euo pipefail

ENGINE=${ENGINE:-podman}
BIN=${BIN:?set BIN to a Linux cipherhorizon binary}
PORT=${PORT:-18090}
IMAGES=${IMAGES:-"docker.io/library/debian:12-slim registry.access.redhat.com/ubi9/ubi:9.6 docker.io/library/alpine:3.20"}
WORK=$(mktemp -d)
chmod 0755 "$WORK"
pass=0 fail=0
ok()  { echo "  ok    $*"; pass=$((pass + 1)); }
bad() { echo "  FAIL  $*"; fail=$((fail + 1)); }
cleanup() { [ -n "${srv:-}" ] && kill "$srv" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

"$BIN" scripts export "$WORK/scripts" 2>/dev/null
(cd "$WORK/scripts" && sha256sum --check --quiet inventory-scripts.sha256) && ok "the exported scripts match their checksums" || bad "checksum mismatch"

"$BIN" serve --no-login --db "$WORK/s.db" --addr "127.0.0.1:$PORT" >"$WORK/serve.log" 2>&1 &
srv=$!
for i in $(seq 1 50); do curl -fsS "http://127.0.0.1:$PORT/api/v1/health" >/dev/null 2>&1 && break; sleep 0.2; done

for img in $IMAGES; do
  name=$(basename "${img%%:*}")
  echo "== $img"
  out="$WORK/out-$name"
  mkdir -p "$out" && chmod 0777 "$out"
  if ! $ENGINE run --rm --pull=missing -v "$WORK/scripts:/s:ro" -v "$out:/out" -w /out "$img" \
      sh /s/cipherhorizon-inventory.sh /out/facts.txt >"$out/run.log" 2>&1; then
    bad "$name: the script failed: $(tail -3 "$out/run.log")"
    continue
  fi
  f="$out/facts.txt"
  head -1 "$f" | grep -q '^cipherhorizon-machine-facts' && ok "$name: a facts file was written" || { bad "$name: no facts file"; continue; }
  mode=$($ENGINE run --rm -v "$out:/out" "$img" stat -c %a /out/facts.txt 2>/dev/null || echo '?')
  [ "$mode" = 600 ] && ok "$name: it is readable by its owner only (0600)" || bad "$name: mode $mode"
  grep -q $'^host\tprivilege\tadmin' "$f" && ok "$name: ran as root" || bad "$name: privilege not admin"
  pk=$(grep -c $'\tpackage\t' "$f" || true)
  [ "$pk" -gt 0 ] && ok "$name: $pk cryptographic packages found" || bad "$name: no package facts"
  grep -q $'^ran\t' "$f" && ok "$name: every signature reports that it ran" || bad "$name: no 'ran' lines"
  grep -qi 'PRIVATE KEY' "$f" && bad "$name: private key text in the facts" || ok "$name: no private key text"
  resp=$(curl -s -w '\n%{http_code}' -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: text/plain; charset=utf-8' \
    --data-binary @"$f" "http://127.0.0.1:$PORT/api/v1/hosts/ingest")
  status=${resp##*$'\n'}
  body=${resp%$'\n'*}
  if [ "$status" = 200 ] || [ "$status" = 201 ]; then
    ok "$name: the server accepted the upload"
    comps=$(echo "$body" | grep -o '"components":[0-9]*' | head -1 | cut -d: -f2)
    pkgs=$(echo "$body" | grep -o '"packages":[0-9]*' | head -1 | cut -d: -f2)
    [ "${pkgs:-0}" -gt 0 ] && [ "${comps:-0}" -gt 0 ] && ok "$name: the server built a CBOM ($pkgs packages, $comps components)"       || bad "$name: summary: ${body:0:300}"
  else
    bad "$name: upload answered $status: ${body:0:200}"
  fi
done

hosts=$(curl -fsS "http://127.0.0.1:$PORT/api/v1/hosts" | grep -o '"id":' | wc -l)
n=$(echo $IMAGES | wc -w)
[ "$hosts" -ge "$n" ] && ok "the server lists $hosts machines" || bad "the server lists $hosts machines, want $n"

echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
