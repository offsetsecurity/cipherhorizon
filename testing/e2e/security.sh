#!/usr/bin/env bash
# Live security checks against the built binary (QA-PLAN-001, "Security"). Needs a
# server WITHOUT a token already running on 127.0.0.1:8080 for the DNS-rebinding checks
# (override with OPEN=http://host:port); run from the repository root after building dist/.
BIN=${BIN:-dist/cbom-scan.exe}
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

rm -f "$WORK/sec.db"*
CBOM_SCAN_TOKEN=$TOKEN "$BIN" serve --addr 127.0.0.1:8081 --db "$WORK/sec.db" > "$WORK/sec-serve.log" 2>&1 &
SRV=$!
sleep 2

echo "== authentication =="
check "no token -> 401"                    401 "$(code $B/api/v1/assets)"
check "wrong token -> 401"                 401 "$(code -H 'Authorization: Bearer nope' $B/api/v1/assets)"
check "bare token without scheme -> 401"   401 "$(code -H "Authorization: $TOKEN" $B/api/v1/assets)"
check "Bearer token -> 200"                200 "$(code -H "Authorization: Bearer $TOKEN" $B/api/v1/assets)"
check "UI shell loads without token"       200 "$(code $B/)"

AUTH=(-H "Authorization: Bearer $TOKEN")
echo "== cross-site request forgery =="
check "POST without X-Requested-With -> 403"  403 "$(code -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with foreign Origin -> 403"       403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with Sec-Fetch-Site: cross-site -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Sec-Fetch-Site: cross-site' -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST with text/plain body -> 415"      415 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Content-Type: text/plain' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "POST from same origin -> 201"          201 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H "Origin: $B" -H 'Content-Type: application/json' -d '{"target":"example.com"}' $B/api/v1/assets)"
check "PUT is not routed -> 405"              405 "$(code -X PUT "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' $B/api/v1/assets)"

echo "== SSRF guard =="
check "cloud metadata address refused -> 400" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Content-Type: application/json' -d '{"target":"169.254.169.254"}' $B/api/v1/assets)"
check "0.0.0.0 refused -> 400"                400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Content-Type: application/json' -d '{"target":"0.0.0.0:443"}' $B/api/v1/assets)"
check "loopback literal refused at add time -> 400" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Content-Type: application/json' -d '{"target":"127.0.0.1:9440"}' $B/api/v1/assets)"
# A host NAME that resolves to loopback passes add-time checks; the dialer's Control hook must still refuse it.
LB=$(curl -s -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' -H 'Content-Type: application/json' -d '{"target":"localhost:9440","name":"loopback-by-name"}' $B/api/v1/assets)
LBID=$(echo "$LB" | python -c 'import sys,json; print(json.load(sys.stdin)["id"])')
curl -s -o /dev/null -X POST "${AUTH[@]}" -H 'X-Requested-With: cbom-scan' $B/api/v1/assets/$LBID/scan
sleep 3
ST=$(curl -s "${AUTH[@]}" $B/api/v1/assets/$LBID | python -c 'import sys,json; d=json.load(sys.stdin); print(d["latest"]["status"], "|", d["latest"]["error"])')
echo "      scan of a name resolving to loopback, without --allow-loopback: $ST"
case "$ST" in failed*"not allowed"*) echo "PASS  loopback refused at connect time"; pass=$((pass+1));; *) echo "FAIL  loopback target was scanned"; fail=$((fail+1));; esac

echo "== response headers =="
H=$(curl -s -D - -o /dev/null "${AUTH[@]}" $B/api/v1/about)
for want in "content-security-policy: default-src 'none'" "x-content-type-options: nosniff" "x-frame-options" "referrer-policy" "cache-control: no-store"; do
  echo "$H" | tr 'A-Z' 'a-z' | grep -q "$want" && { echo "PASS  header $want"; pass=$((pass+1)); } || { echo "FAIL  header $want"; fail=$((fail+1)); }
done
echo "$H" | tr 'A-Z' 'a-z' | grep -q "content-security-policy" && echo "      $(echo "$H" | grep -i content-security-policy | tr -d '\r')"

kill $SRV 2>/dev/null; taskkill //F //PID $SRV >/dev/null 2>&1

echo "== DNS rebinding (server without a token) =="
check "Host: evil.example -> 421"  421 "$(code -H 'Host: evil.example' ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"
check "Host: 127.0.0.1:8080 -> 200" 200 "$(code ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"
check "Host: localhost:8080 -> 200" 200 "$(code -H 'Host: localhost:8080' ${OPEN:-http://127.0.0.1:8080}/api/v1/assets)"

echo
echo "SUMMARY: $pass passed, $fail failed"
[ "$fail" = 0 ]
