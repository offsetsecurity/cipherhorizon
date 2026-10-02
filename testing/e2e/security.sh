#!/usr/bin/env bash
# Live security checks against the built binary (QA-PLAN-001, "Security"). Needs a
# server WITHOUT a token already running on 127.0.0.1:8080 for the DNS-rebinding checks
# (override with OPEN=http://host:port); run from the repository root after building dist/.
BIN=${BIN:-dist/cipherhorizon.exe}
WORK=$(mktemp -d)
TOKEN=qa-secret-token-0123456789
B=http://127.0.0.1:8081
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1  (got $3)"; pass=$((pass+1)); else echo "FAIL  $1  (want $2, got $3)"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== refusing to expose the server without a token =="
"$BIN" serve --addr 0.0.0.0:8082 --db "$WORK/sec-refuse.db" > "$WORK/refuse.out" 2>&1; rc=$?
check "serve --addr 0.0.0.0:8082 without token exits non-zero" 1 "$rc"
grep -q "without an access token" "$WORK/refuse.out" && echo "PASS  message explains why" && pass=$((pass+1)) || { echo "FAIL  message"; fail=$((fail+1)); }

"$BIN" serve --addr 127.0.0.1:8083 --token a --db "$WORK/sec-short.db" > "$WORK/short.out" 2>&1; rc=$?
check "a one-character token is refused (SEC-03)" 1 "$rc"
grep -q "too short" "$WORK/short.out" && echo "PASS  message says the token is too short" && pass=$((pass+1)) || { echo "FAIL  short-token message"; fail=$((fail+1)); }

rm -f "$WORK/sec.db"*
CIPHERHORIZON_TOKEN=$TOKEN "$BIN" serve --addr 127.0.0.1:8081 --db "$WORK/sec.db" > "$WORK/sec-serve.log" 2>&1 &
SRV=$!
sleep 2

echo "== authentication =="
check "no token -> 401"                    401 "$(code $B/api/v1/assets)"
check "wrong token -> 401"                 401 "$(code -H 'Authorization: Bearer nope' $B/api/v1/assets)"
check "bare token without scheme -> 401"   401 "$(code -H "Authorization: $TOKEN" $B/api/v1/assets)"
check "Bearer token -> 200"                200 "$(code -H "Authorization: Bearer $TOKEN" $B/api/v1/assets)"
check "UI shell loads without token"       200 "$(code $B/)"

AUTH=(-H "Authorization: Bearer $TOKEN")
echo "== the estate routes are guarded like the rest (SR-08, SR-12) =="
for r in /api/v1/estate /api/v1/systems /api/v1/systems/1/m2302.json /api/v1/systems/1/m2302.csv /api/v1/certificates /api/v1/links /api/v1/imports /api/v1/openapi.json /api/v1/graph/stats; do
  check "GET $r without a token -> 401"  401 "$(code $B$r)"
  check "GET $r with the token is not 401" 1 "$([ "$(code "${AUTH[@]}" $B$r)" != 401 ] && echo 1 || echo 0)"
done
check "POST /imports without X-Requested-With -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{}' "$B/api/v1/imports?newSystem=x")"
check "POST /imports from a foreign origin -> 403"    403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{}' "$B/api/v1/imports?newSystem=x")"
check "POST /imports naming no system -> 400"         400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{}' "$B/api/v1/imports")"
check "POST /imports of a non-CBOM -> 400"            400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"hello":1}' "$B/api/v1/imports?newSystem=x")"
check "PATCH a system without X-Requested-With -> 403" 403 "$(code -X PATCH "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"owner":"x"}' $B/api/v1/systems/1)"
echo "== cross-site request forgery =="
check "POST without X-Requested-With -> 403"  403 "$(code -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with foreign Origin -> 403"       403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with Sec-Fetch-Site: cross-site -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Sec-Fetch-Site: cross-site' -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with text/plain body -> 415"      415 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: text/plain' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST from same origin -> 201"          201 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H "Origin: $B" -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "PUT is not routed -> 405"              405 "$(code -X PUT "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' $B/api/v1/assets)"

echo "== TLS T1 routes: trust anchors, reference data, re-evaluation (SR-12, SR-20) =="
for r in /api/v1/trust-anchors /api/v1/reference-data /api/v1/systems/1/trust-anchors; do
  check "GET $r without a token -> 401"  401 "$(code $B$r)"
done
SYS=$(curl -s "${AUTH[@]}" $B/api/v1/systems | python -c 'import sys,json; print(json.load(sys.stdin)["systems"][0]["id"])')
check "GET reference data with the token -> 200" 200 "$(code "${AUTH[@]}" $B/api/v1/reference-data)"
check "POST trust anchors without X-Requested-With -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"pem":"x"}' $B/api/v1/systems/$SYS/trust-anchors)"
check "POST trust anchors from a foreign origin -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{"pem":"x"}' $B/api/v1/systems/$SYS/trust-anchors)"
KEYBODY='{"pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nQUFBQQ==\n-----END PRIVATE KEY-----\n"}'
check "an upload with a private key block is refused -> 400 (SR-20)" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d "$KEYBODY" $B/api/v1/systems/$SYS/trust-anchors)"
KEYMSG=$(curl -s -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d "$KEYBODY" $B/api/v1/systems/$SYS/trust-anchors)
echo "$KEYMSG" | grep -q "private key block" && { echo "PASS  the refusal says why"; pass=$((pass+1)); } || { echo "FAIL  refusal message: $KEYMSG"; fail=$((fail+1)); }
python -c 'import json; print(json.dumps({"pem": "<script>alert(1)</script>" + "A"*70000}))' > "$WORK/big.json"
check "an upload over 64 KiB -> 413" 413 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' --data-binary @"$WORK/big.json" $B/api/v1/systems/$SYS/trust-anchors)"
check "a hostile fingerprint in the path -> 400" 400 "$(code -X DELETE "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' "$B/api/v1/systems/$SYS/trust-anchors/%3Cscript%3E")"
check "POST reevaluate without X-Requested-With -> 403" 403 "$(code -X POST "${AUTH[@]}" $B/api/v1/scans/1/reevaluate)"
printf -- '-----BEGIN EC PRIVATE KEY-----\nQUFBQQ==\n-----END EC PRIVATE KEY-----\n' > "$WORK/bundle-with-key.pem"
"$BIN" serve --addr 127.0.0.1:8084 --db "$WORK/sec-bundle.db" --ca-bundle "$WORK/bundle-with-key.pem" > "$WORK/bundle.out" 2>&1; rc=$?
check "serve --ca-bundle with a key block exits non-zero" 1 "$rc"
grep -q "private key block" "$WORK/bundle.out" && { echo "PASS  and says why"; pass=$((pass+1)); } || { echo "FAIL  ca-bundle message"; fail=$((fail+1)); }

echo "== SSRF guard =="
check "cloud metadata address refused -> 400" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"169.254.169.254"}' $B/api/v1/assets)"
check "0.0.0.0 refused -> 400"                400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"0.0.0.0:443"}' $B/api/v1/assets)"
check "0.0.0.0/8 refused -> 400 (SEC-04)"     400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"0.1.2.3:443"}' $B/api/v1/assets)"
check "NAT64 form of the metadata address refused -> 400 (SEC-04)" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"[64:ff9b::a9fe:a9fe]:443"}' $B/api/v1/assets)"
check "host name with a control character refused on upload -> 400 (SEC-05)" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}' "$B/api/v1/hosts/ingest?name=a%01b")"
check "loopback literal refused at add time -> 400" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"127.0.0.1:9440"}' $B/api/v1/assets)"
# A host NAME that resolves to loopback passes add-time checks; the dialer's Control hook must still refuse it.
LB=$(curl -s -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d '{"target":"localhost:9440","name":"loopback-by-name"}' $B/api/v1/assets)
LBID=$(echo "$LB" | python -c 'import sys,json; print(json.load(sys.stdin)["id"])')
curl -s -o /dev/null -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' $B/api/v1/assets/$LBID/scan
sleep 3
ST=$(curl -s "${AUTH[@]}" $B/api/v1/assets/$LBID | python -c 'import sys,json; d=json.load(sys.stdin); print(d["latest"]["status"], "|", d["latest"]["error"])')
echo "      scan of a name resolving to loopback, without --allow-loopback: $ST"
case "$ST" in failed*"not allowed"*) echo "PASS  loopback refused at connect time"; pass=$((pass+1));; *) echo "FAIL  loopback target was scanned"; fail=$((fail+1));; esac

echo "== response headers =="
H=$(curl -s -D - -o /dev/null "${AUTH[@]}" $B/api/v1/about)
for want in "content-security-policy: default-src 'none'" "x-content-type-options: nosniff" "x-frame-options" "referrer-policy" "cache-control: no-store" "permissions-policy: camera=()"; do
  echo "$H" | tr 'A-Z' 'a-z' | grep -q "$want" && { echo "PASS  header $want"; pass=$((pass+1)); } || { echo "FAIL  header $want"; fail=$((fail+1)); }
done
echo "$H" | tr 'A-Z' 'a-z' | grep -q "content-security-policy" && echo "      $(echo "$H" | grep -i content-security-policy | tr -d '\r')"

echo "== failed logins are recorded, without the secret (SEC-03) =="
grep -q "authentication failed" "$WORK/sec-serve.log" && { echo "PASS  failed authentication is logged"; pass=$((pass+1)); } || { echo "FAIL  no log line for failed authentication"; fail=$((fail+1)); }
grep -q "nope" "$WORK/sec-serve.log" && { echo "FAIL  the log contains the submitted token"; fail=$((fail+1)); } || { echo "PASS  the submitted token is not logged"; pass=$((pass+1)); }

case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) echo "      (database file mode is not checked on Windows: the profile ACL applies)";;
  *) check "database file is owner-only (SEC-01)" 600 "$(stat -c %a "$WORK/sec.db" 2>/dev/null || stat -f %Lp "$WORK/sec.db")";;
esac

kill $SRV 2>/dev/null; taskkill //F //PID $SRV >/dev/null 2>&1

echo "== DNS rebinding (server without a token) =="
check "Host: evil.example -> 421"  421 "$(code -H 'Host: evil.example' ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"
check "Host: 127.0.0.1:8080 -> 200" 200 "$(code ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"
check "Host: localhost:8080 -> 200" 200 "$(code -H 'Host: localhost:8080' ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"

echo
echo "SUMMARY: $pass passed, $fail failed"
[ "$fail" = 0 ]
