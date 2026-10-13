#!/usr/bin/env bash
# Live security checks against the built binary (QA-PLAN-001, "Security"; ADR-0018 for sign-in).
# Starts its own servers on 127.0.0.1:8081-8088 (8086: scan scope); run from the repository root after building dist/.
BIN=${BIN:-dist/cipherhorizon.exe}
WORK=$(mktemp -d)
TOKEN=qa-secret-token-0123456789
B=http://127.0.0.1:8081
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then echo "PASS  $1  (got $3)"; pass=$((pass+1)); else echo "FAIL  $1  (want $2, got $3)"; fail=$((fail+1)); fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== refusing to expose sign-in over plain HTTP, or the server without sign-in (ADR-0018) =="
"$BIN" serve --addr 0.0.0.0:8082 --db "$WORK/sec-refuse.db" > "$WORK/refuse.out" 2>&1; rc=$?
check "serve --addr 0.0.0.0:8082 over plain HTTP exits non-zero" 1 "$rc"
grep -q "over plain HTTP" "$WORK/refuse.out" && echo "PASS  message explains why" && pass=$((pass+1)) || { echo "FAIL  message"; fail=$((fail+1)); }
"$BIN" serve --addr 0.0.0.0:8082 --no-login --db "$WORK/sec-refuse2.db" > "$WORK/refuse2.out" 2>&1; rc=$?
check "serve --no-login on a network address exits non-zero" 1 "$rc"
"$BIN" serve --addr 0.0.0.0:8082 --plain-http --db "$WORK/sec-refuse3.db" > "$WORK/refuse3.out" 2>&1; rc=$?
check "a network address without sign-in and without --open-network exits non-zero (UX-REVIEW-008 S3)" 1 "$rc"
grep -q -- "--open-network" "$WORK/refuse3.out" && echo "PASS  message names --sign-in on and --open-network" && pass=$((pass+1)) || { echo "FAIL  open-network message"; fail=$((fail+1)); }

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
for r in /api/v1/estate /api/v1/systems /api/v1/systems/1/m2302.json /api/v1/systems/1/m2302.csv /api/v1/certificates /api/v1/links /api/v1/imports /api/v1/openapi.json /api/v1/graph/stats /api/v1/inventory /api/v1/inventory/summary /api/v1/inventory/cbom /api/v1/inventory/dashboard /api/v1/inventory/report.pdf /api/v1/scans/1/report.pdf /api/v1/collector/scripts /api/v1/collector/scripts/cipherhorizon-inventory.sh /api/v1/collector/signatures; do
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

# Reads JSON on stdin and prints a JavaScript expression over it (d), e.g. json '.id'. node, not python:
# node is already required by the browser suites, and python is not installed everywhere.
json() { node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>{const d=JSON.parse(s);console.log(eval("d"+process.argv[1]))})' "$1"; }

echo "== TLS T1 routes: trust anchors, reference data, re-evaluation (SR-12, SR-20) =="
for r in /api/v1/trust-anchors /api/v1/reference-data /api/v1/systems/1/trust-anchors; do
  check "GET $r without a token -> 401"  401 "$(code $B$r)"
done
SYS=$(curl -s "${AUTH[@]}" $B/api/v1/systems | json '.systems[0].id')
check "GET reference data with the token -> 200" 200 "$(code "${AUTH[@]}" $B/api/v1/reference-data)"
check "POST trust anchors without X-Requested-With -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"pem":"x"}' $B/api/v1/systems/$SYS/trust-anchors)"
check "POST trust anchors from a foreign origin -> 403" 403 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{"pem":"x"}' $B/api/v1/systems/$SYS/trust-anchors)"
KEYBODY='{"pem":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nQUFBQQ==\n-----END PRIVATE KEY-----\n"}'
check "an upload with a private key block is refused -> 400 (SR-20)" 400 "$(code -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d "$KEYBODY" $B/api/v1/systems/$SYS/trust-anchors)"
KEYMSG=$(curl -s -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json' -d "$KEYBODY" $B/api/v1/systems/$SYS/trust-anchors)
echo "$KEYMSG" | grep -q "private key block" && { echo "PASS  the refusal says why"; pass=$((pass+1)); } || { echo "FAIL  refusal message: $KEYMSG"; fail=$((fail+1)); }
node -e 'process.stdout.write(JSON.stringify({pem: "<script>alert(1)</script>" + "A".repeat(70000)}))' > "$WORK/big.json"
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
LBID=$(echo "$LB" | json '.id')
curl -s -o /dev/null -X POST "${AUTH[@]}" -H 'X-Requested-With: cipherhorizon' $B/api/v1/assets/$LBID/scan
sleep 3
ST=$(curl -s "${AUTH[@]}" $B/api/v1/assets/$LBID | json '.latest.status + " | " + d.latest.error')
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

echo "== sign-in (ADR-0018) =="
L=http://127.0.0.1:8085
"$BIN" serve --addr 127.0.0.1:8085 --sign-in on --db "$WORK/login.db" > "$WORK/login.log" 2>&1 &
LSRV=$!
sleep 2
CODE=$(grep -oE '[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}' "$WORK/login.log" | head -1)
check "the setup code is printed in the server log" 1 "$([ -n "$CODE" ] && echo 1 || echo 0)"
check "no session -> 401"                     401 "$(code $L/api/v1/assets)"
check "the UI shell loads without a session"  200 "$(code $L/)"
check "auth state is public"                  200 "$(code $L/api/v1/auth/state)"
J=(-H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json')
check "setup with a wrong code -> 403"        403 "$(code -X POST "${J[@]}" -d '{"code":"AAAA-AAAA-AAAA","username":"ana","password":"violet amber harbour"}' $L/api/v1/auth/setup)"
check "setup without X-Requested-With -> 403" 403 "$(code -X POST -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\",\"username\":\"ana\",\"password\":\"violet amber harbour\"}" $L/api/v1/auth/setup)"
SH=$(curl -s -D - -o /dev/null -c "$WORK/jar" -X POST "${J[@]}" -d "{\"code\":\"$CODE\",\"username\":\"ana\",\"password\":\"violet amber harbour\"}" $L/api/v1/auth/setup)
echo "$SH" | grep -qi '^HTTP/1.1 201' && { echo "PASS  setup with the code -> 201"; pass=$((pass+1)); } || { echo "FAIL  setup: $(echo "$SH" | head -1)"; fail=$((fail+1)); }
CK=$(echo "$SH" | grep -i '^set-cookie: ch_session=' | tr 'A-Z' 'a-z')
for want in httponly "samesite=strict" "path=/"; do
  echo "$CK" | grep -q "$want" && { echo "PASS  session cookie: $want"; pass=$((pass+1)); } || { echo "FAIL  session cookie lacks $want: $CK"; fail=$((fail+1)); }
done
check "a second setup -> 409"                 409 "$(code -X POST "${J[@]}" -d "{\"code\":\"$CODE\",\"username\":\"eve\",\"password\":\"violet amber harbour\"}" $L/api/v1/auth/setup)"
check "with the session -> 200"               200 "$(code -b "$WORK/jar" $L/api/v1/assets)"
check "login without X-Requested-With -> 403 (login forgery)" 403 "$(code -X POST -H 'Content-Type: application/json' -d '{"username":"ana","password":"violet amber harbour"}' $L/api/v1/auth/login)"
check "login as a form post -> 403"           403 "$(code -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'username=ana&password=x' $L/api/v1/auth/login)"
M1=$(curl -s -X POST "${J[@]}" -d '{"username":"ana","password":"wrong password here"}' $L/api/v1/auth/login)
M2=$(curl -s -X POST "${J[@]}" -d '{"username":"nobody-here","password":"wrong password here"}' $L/api/v1/auth/login)
check "a wrong password and an unknown account answer alike" 1 "$([ "$M1" = "$M2" ] && echo 1 || echo 0)"
check "a password is never in the log"        0 "$(grep -c 'violet\|wrong password here' "$WORK/login.log")"
curl -s -o /dev/null -b "$WORK/jar" -X POST -H 'X-Requested-With: cipherhorizon' $L/api/v1/auth/logout
check "after sign-out the old cookie -> 401"  401 "$(code -b "$WORK/jar" $L/api/v1/assets)"
for i in $(seq 1 50); do curl -s -o /dev/null -X POST "${J[@]}" -d "{\"username\":\"guess$i\",\"password\":\"guessing password\"}" $L/api/v1/auth/login; done
check "one address guessing is rate-limited -> 429" 429 "$(code -X POST "${J[@]}" -d '{"username":"ana","password":"violet amber harbour"}' $L/api/v1/auth/login)"
kill $LSRV 2>/dev/null; taskkill //F //PID $LSRV >/dev/null 2>&1

if command -v openssl >/dev/null 2>&1; then
  echo "== HTTPS (--tls-cert/--tls-key) =="
  MSYS2_ARG_CONV_EXCL="/CN" openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=127.0.0.1" \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" >/dev/null 2>&1
  "$BIN" serve --addr 127.0.0.1:8087 --tls-cert "$WORK/cert.pem" --tls-key "$WORK/key.pem" --sign-in on --db "$WORK/tls.db" > "$WORK/tls.log" 2>&1 &
  TSRV=$!
  sleep 2
  check "HTTPS health -> 200" 200 "$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8087/api/v1/health)"
  check "plain HTTP to the TLS port is refused" 1 "$([ "$(code http://127.0.0.1:8087/api/v1/health)" != 200 ] && echo 1 || echo 0)"
  check "TLS 1.1 is refused" 1 "$(curl -sk --tlsv1.1 --tls-max 1.1 -o /dev/null https://127.0.0.1:8087/api/v1/health && echo 0 || echo 1)"
  TC=$(grep -oE '[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}' "$WORK/tls.log" | head -1)
  THDR=$(curl -sk -D - -o /dev/null -X POST "${J[@]}" -d "{\"code\":\"$TC\",\"username\":\"ana\",\"password\":\"violet amber harbour\"}" https://127.0.0.1:8087/api/v1/auth/setup)
  TCK=$(echo "$THDR" | grep -i '^set-cookie: __host-ch_session=' | tr 'A-Z' 'a-z')
  echo "$TCK" | grep -q "secure" && echo "$TCK" | grep -q "path=/" && ! echo "$TCK" | grep -q "domain=" \
    && { echo "PASS  over HTTPS the session cookie is __Host-ch_session: Secure, Path=/, no Domain (PRD-007 REQ-TR-2)"; pass=$((pass+1)); } \
    || { echo "FAIL  cookie over HTTPS: $TCK"; fail=$((fail+1)); }
  echo "$THDR" | tr -d '\r' | grep -qi '^strict-transport-security: max-age=31536000' \
    && { echo "PASS  HTTPS responses carry HSTS (REQ-SS-2)"; pass=$((pass+1)); } || { echo "FAIL  no HSTS over HTTPS"; fail=$((fail+1)); }
  # openssl s_client, not curl: curl on Windows (Schannel) ignores OpenSSL cipher names.
  ossl() { echo | MSYS_NO_PATHCONV=1 openssl s_client -connect 127.0.0.1:8087 -tls1_2 -cipher "$1" >/dev/null 2>&1 && echo 1 || echo 0; }
  check "TLS 1.2 with a CBC suite is refused (REQ-SS-1)" 0 "$(ossl ECDHE-ECDSA-AES128-SHA)"
  check "TLS 1.2 with RSA key transport is refused (REQ-SS-1)" 0 "$(ossl AES128-GCM-SHA256)"
  check "TLS 1.2 with an ECDHE AEAD suite is accepted" 1 "$(ossl ECDHE-ECDSA-AES128-GCM-SHA256)"
  kill $TSRV 2>/dev/null; taskkill //F //PID $TSRV >/dev/null 2>&1
else
  echo "      (openssl not found: the HTTPS checks were skipped)"
fi

echo "== scan scope (--scan-allow, PRD-007 REQ-AC-1) =="
S=http://127.0.0.1:8086
"$BIN" serve --addr 127.0.0.1:8086 --no-login --allow-loopback --scan-allow 10.0.0.0/8 --scan-allow lab.test --db "$WORK/scope.db" > "$WORK/scope.log" 2>&1 &
SSRV=$!
sleep 2
grep -q "scan scope: only 10.0.0.0/8, lab.test" "$WORK/scope.log" && { echo "PASS  the log states the scan scope"; pass=$((pass+1)); } || { echo "FAIL  scope log: $(head -5 "$WORK/scope.log")"; fail=$((fail+1)); }
SJ=(-H 'X-Requested-With: cipherhorizon' -H 'Content-Type: application/json')
check "a loopback target outside the scope is refused -> 400" 400 "$(code -X POST "${SJ[@]}" -d '{"target":"127.0.0.1:9440"}' $S/api/v1/assets)"
check "a public name outside the scope is refused -> 400" 400 "$(code -X POST "${SJ[@]}" -d '{"target":"example.org:443"}' $S/api/v1/assets)"
check "an address inside the scope is accepted -> 201" 201 "$(code -X POST "${SJ[@]}" -d '{"target":"10.2.3.4:443"}' $S/api/v1/assets)"
check "a name under a scope domain is accepted -> 201" 201 "$(code -X POST "${SJ[@]}" -d '{"target":"web.lab.test:443"}' $S/api/v1/assets)"
check "plain HTTP responses carry no HSTS (REQ-SS-2)" 0 "$(curl -sI $S/api/v1/health | grep -ci strict-transport || true)"
check "About reports the scope" 1 "$(curl -s $S/api/v1/about | grep -c '"scanScope":\["10.0.0.0/8","lab.test"\]')"
check "every change is in the activity log (2 endpoints added)" 2 "$(curl -s "$S/api/v1/audit?source=change" | grep -o '"action":"added"' | wc -l | tr -d ' ')"
kill $SSRV 2>/dev/null; taskkill //F //PID $SSRV >/dev/null 2>&1

echo "== DNS rebinding (server without sign-in, --no-login) =="
O=http://127.0.0.1:8088
"$BIN" serve --addr 127.0.0.1:8088 --no-login --db "$WORK/open.db" > "$WORK/open.log" 2>&1 &
OSRV=$!
sleep 2
check "Host: evil.example -> 421"  421 "$(code -H 'Host: evil.example' $O/api/v1/assets)"
check "Host: 127.0.0.1:8088 -> 200" 200 "$(code $O/api/v1/assets)"
check "Host: localhost:8088 -> 200" 200 "$(code -H 'Host: localhost:8088' $O/api/v1/assets)"
kill $OSRV 2>/dev/null; taskkill //F //PID $OSRV >/dev/null 2>&1

echo
echo "SUMMARY: $pass passed, $fail failed"
[ "$fail" = 0 ]
