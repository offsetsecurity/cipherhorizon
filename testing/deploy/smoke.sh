#!/usr/bin/env bash
# Container smoke test (PRD-007 REQ-DP-1, REQ-DP-2): builds the image and runs it the way
# docker-compose.yml does (read-only, no capabilities, no new privileges), then walks a first install:
#
#   1. the container becomes healthy and, with sign-in off by default, answers without an account;
#   2. sign-in is turned on in Settings, which creates the administrator; then anonymous requests fail;
#   3. `db backup` writes a copy that opens;
#   4. a second container serves HTTPS with a mounted certificate and --sign-in on: its log prints the
#      one-time setup code, and the image's own CLI scans it (the product passes its own scan:
#      readiness L3, nothing worse than its test certificate).
#
# Usage: testing/deploy/smoke.sh            (ENGINE=docker to use Docker instead of Podman;
#        SKIP_BUILD=1 IMAGE=ghcr.io/... WANT_VERSION=1.0.0 to test a published image)
# Needs: podman or docker, curl, and openssl (or CERT= and KEY= naming a test certificate and key
# for 127.0.0.1). Uses host ports 18080, 18443 and 19000. With Podman on Windows or macOS the ports are
# not forwarded to the host: run it inside the machine (`podman machine ssh`), as on Linux.
set -euo pipefail

ENGINE=${ENGINE:-podman}
IMAGE=${IMAGE:-cipherhorizon:smoke}
NAME=chsmoke
HTTP_PORT=${HTTP_PORT:-18080}
TLS_PORT=${TLS_PORT:-18443}
ALT_PORT=${ALT_PORT:-19000}
WORK=$(mktemp -d)
pass=0 fail=0

ok()   { echo "  ok    $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
cleanup() {
  $ENGINE rm -f "$NAME" "$NAME-tls" "$NAME-port" >/dev/null 2>&1 || true
  $ENGINE volume rm -f "$NAME-data" "$NAME-tls-data" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
cleanup_quiet() { $ENGINE rm -f "$NAME" "$NAME-tls" "$NAME-port" >/dev/null 2>&1 || true; $ENGINE volume rm -f "$NAME-data" "$NAME-tls-data" >/dev/null 2>&1 || true; }
cleanup_quiet

# The hardening docker-compose.yml applies (audit L-13).
HARDEN=(--read-only --tmpfs /tmp:size=16m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g)
# The health check docker-compose.yml and the Quadlet unit declare. Podman ignores a Dockerfile HEALTHCHECK in
# an OCI-format image, which is what the release publishes, so a deployment declares it, and so does this test.
# Exec form (a JSON list), as the Quadlet unit has it: the image has no shell. Docker honours the image's own
# HEALTHCHECK, so only Podman is given one.
HEALTH=()
[ "$ENGINE" = podman ] && HEALTH=(--health-cmd '["/cipherhorizon","healthcheck"]' --health-interval 5s --health-timeout 3s --health-start-period 10s --health-retries 5)

echo "== build"
if [ -z "${SKIP_BUILD:-}" ]; then
  fmt=(); [ "$ENGINE" = podman ] && fmt=(--format docker) # OCI images drop HEALTHCHECK
  $ENGINE build "${fmt[@]}" -t "$IMAGE" --build-arg VERSION=0.0.0-smoke --build-arg MODULE="$(go list -m 2>/dev/null || echo github.com/offsetsecurity/cipherhorizon)" . >"$WORK/build.log" 2>&1 \
    && ok "the image builds" || { bad "the image does not build (see below)"; tail -30 "$WORK/build.log"; exit 1; }
fi
v=$($ENGINE run --rm "$IMAGE" version | sed -n 1p) # not head: under pipefail, SIGPIPE would end the script
[[ "$v" == "cipherhorizon ${WANT_VERSION:-0.0.0-smoke}"* ]] && ok "version: $v" || bad "version printed '$v'"

echo "== first run (hardened, as docker-compose.yml)"
$ENGINE volume create "$NAME-data" >/dev/null
$ENGINE run -d --name "$NAME" "${HARDEN[@]}" "${HEALTH[@]}" -p "127.0.0.1:$HTTP_PORT:8080" -v "$NAME-data:/data" "$IMAGE" >/dev/null
base="http://127.0.0.1:$HTTP_PORT"
for i in $(seq 1 60); do curl -fsS "$base/api/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$base/api/v1/health" | grep -q '"ok"' && ok "health answers" || bad "health does not answer"
for i in $(seq 1 30); do
  # Podman runs health checks from systemd timers, absent in some rootless setups (WSL): run it here.
  [ "$ENGINE" = podman ] && { $ENGINE healthcheck run "$NAME" >/dev/null 2>&1 || true; }
  st=$($ENGINE inspect -f '{{.State.Health.Status}}' "$NAME" 2>/dev/null || echo none)
  [ "$st" = healthy ] && break; sleep 1
done
[ "$st" = healthy ] && ok "the container's health check reports healthy" || bad "health status is '$st'"

s=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/assets")
[ "$s" = 200 ] && ok "sign-in is off by default: the API answers without an account" || bad "a default container asked for credentials: $s"
jar="$WORK/cookies"
s=$(curl -s -o "$WORK/setup.json" -w '%{http_code}' -c "$jar" -X PUT -H 'Content-Type: application/json' -H 'X-Requested-With: cipherhorizon' \
  -d '{"enabled":true,"username":"admin","password":"smoke test pass phrase"}' "$base/api/v1/settings/sign-in")
[ "$s" = 200 ] && ok "Settings turns sign-in on and creates the administrator" || bad "turning sign-in on answered $s: $(cat "$WORK/setup.json")"
s=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" "$base/api/v1/about")
[ "$s" = 200 ] && ok "the new session works" || bad "a signed-in request answered $s"
s=$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/about")
[ "$s" = 401 ] && ok "without a session the API now refuses (401)" || bad "unauthenticated about answered $s"
$ENGINE exec "$NAME" /cipherhorizon healthcheck >/dev/null 2>&1 && ok "healthcheck inside the read-only container" || bad "healthcheck failed inside"

echo "== backup while it runs"
if $ENGINE exec "$NAME" /cipherhorizon db backup --db /data/cipherhorizon.db /data/backup.db >"$WORK/backup.log" 2>&1; then
  ok "db backup wrote a copy"
  if $ENGINE run --rm -v "$NAME-data:/data" "$IMAGE" user list --db /data/backup.db 2>&1 | grep -q admin; then
    ok "the copy opens and holds the administrator"
  else bad "the copy does not hold the administrator"; fi
else bad "db backup failed: $(cat "$WORK/backup.log")"; fi

echo "== another port: CIPHERHORIZON_PORT (PRD-009 REQ-PORT-4, QA-PLAN-007 PORT)"
$ENGINE run -d --name "$NAME-port" "${HARDEN[@]}" -e CIPHERHORIZON_PORT="$ALT_PORT" -p "127.0.0.1:$ALT_PORT:$ALT_PORT" "$IMAGE" >/dev/null
for i in $(seq 1 60); do curl -fsS "http://127.0.0.1:$ALT_PORT/api/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$ALT_PORT/api/v1/health" | grep -q '"ok"' && ok "serves on port $ALT_PORT from CIPHERHORIZON_PORT" || bad "nothing answers on $ALT_PORT"
$ENGINE exec "$NAME-port" /cipherhorizon healthcheck >/dev/null 2>&1 && ok "the health check follows CIPHERHORIZON_PORT" || bad "the health check does not find port $ALT_PORT"
$ENGINE rm -f "$NAME-port" >/dev/null 2>&1 || true

echo "== HTTPS with a mounted certificate, scanned by the image's own CLI"
if [ -n "${CERT:-}" ]; then cp "$CERT" "$WORK/cert.pem"; cp "$KEY" "$WORK/key.pem"; else
command -v openssl >/dev/null || { bad "openssl is not installed here: set CERT= and KEY= to a test certificate for 127.0.0.1"; echo "== result: $pass passed, $fail failed"; exit 1; }
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1; fi
chmod 0644 "$WORK/key.pem" "$WORK/cert.pem" # the container's non-root user must read them
$ENGINE volume create "$NAME-tls-data" >/dev/null
$ENGINE run -d --name "$NAME-tls" "${HARDEN[@]}" -p "127.0.0.1:$TLS_PORT:8443" -v "$NAME-tls-data:/data" \
  -v "$WORK/cert.pem:/certs/cert.pem:ro" -v "$WORK/key.pem:/certs/key.pem:ro" \
  "$IMAGE" serve --addr 0.0.0.0:8443 --tls-cert /certs/cert.pem --tls-key /certs/key.pem --sign-in on --db /data/cipherhorizon.db >/dev/null
for i in $(seq 1 60); do curl -kfsS "https://127.0.0.1:$TLS_PORT/api/v1/health" >/dev/null 2>&1 && break; sleep 0.5; done
code=$($ENGINE logs "$NAME-tls" 2>&1 | grep -A3 'one-time setup code' | grep -Eo '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' | head -1 || true)
[ -n "$code" ] && ok "with --sign-in on the log prints the setup code" || bad "no setup code in the log"
s=$(curl -ks -o "$WORK/setup.json" -w '%{http_code}' -H 'Content-Type: application/json' -H 'X-Requested-With: cipherhorizon' \
  -d "{\"code\":\"$code\",\"username\":\"admin\",\"password\":\"smoke test pass phrase\"}" "https://127.0.0.1:$TLS_PORT/api/v1/auth/setup")
[ "$s" = 201 ] && ok "the administrator is created with the code" || bad "setup answered $s: $(cat "$WORK/setup.json")"
hsts=$(curl -ksI "https://127.0.0.1:$TLS_PORT/api/v1/health" | tr -d '\r' | grep -i '^strict-transport-security:' || true)
[ -n "$hsts" ] && ok "HTTPS answers with HSTS ($hsts)" || bad "no HSTS over HTTPS"
set +e
$ENGINE run --rm --network "container:$NAME-tls" "$IMAGE" tls scan --concurrency 8 --fail-on 'level<L3,severity>=critical' 127.0.0.1:8443 >"$WORK/scan.txt" 2>"$WORK/scan.err"
rc=$?
set -e
[ $rc = 0 ] && ok "the server passes its own scan (level L3 or better, nothing critical)" || { bad "self-scan exit $rc"; cat "$WORK/scan.err" | tail -5; }
grep -q "Post-quantum readiness   L3" "$WORK/scan.txt" && ok "readiness L3 (hybrid post-quantum key exchange)" || bad "readiness: $(grep 'readiness' "$WORK/scan.txt")"
sed -n '1,30p' "$WORK/scan.txt" | sed 's/^/        /'

echo "== result: $pass passed, $fail failed"
[ "$fail" = 0 ]
