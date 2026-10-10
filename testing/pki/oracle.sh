#!/usr/bin/env bash
# oracle.sh checks the served-chain trust verdicts of internal/pki against OpenSSL
# (QA-PLAN-004 §1, PRD-004 T1-M2): the same leaf, the same served intermediates, the
# same anchor, the same time. It also compares the OCSP fixtures' decoded fields, which
# TestOCSPAgainstOpenSSL does on every `go test` run.
#
#   testing/pki/oracle.sh          # needs Go and OpenSSL 3.x on PATH
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 2
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Paths handed to a native Windows openssl must be relative; work inside the fixture dir.
PKI_ORACLE_DIR="$(cygpath -w "$work" 2>/dev/null || echo "$work")" go test ./internal/pki -run '^TestWriteOracleFixtures$' -count=1 >/dev/null || { echo "fixture generation failed"; exit 2; }

pass=0; fail=0
for d in "$work"/*/; do
  name=$(basename "$d")
  read -r want at < "$d/expect"
  args=(verify -x509_strict -purpose sslserver -attime "$at" -CAfile anchors.pem)
  [ -s "$d/untrusted.pem" ] && args+=(-untrusted untrusted.pem)
  out=$(cd "$d" && openssl "${args[@]}" leaf.pem 2>&1)
  if echo "$out" | grep -q ': OK$'; then got=trusted; else got=untrusted; fi
  if [ "$got" = "$want" ]; then
    echo "AGREE     $name: $got"; pass=$((pass+1))
  else
    echo "DISAGREE  $name: ours=$want openssl=$got"; echo "          $(echo "$out" | tr '\n' ' ' | cut -c1-200)"; fail=$((fail+1))
  fi
done
echo
echo "SUMMARY: $pass agree, $fail disagree"
[ "$fail" = 0 ]
