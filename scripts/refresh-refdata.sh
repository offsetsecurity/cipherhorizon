#!/usr/bin/env bash
# Refreshes the bundled reference data (CRYPTO-REVIEW-004 P3, PRD-016 U-18): downloads the CCADB root
# stores, Chrome's CT log list, Mozilla OneCRL and the four RFCs with DH groups, regenerates
# internal/refdata/*_gen.go, and checks that every key the Go toolchain distrusts is on our lists.
#
#   scripts/refresh-refdata.sh [summary-file]
#
# Exit codes: 0 refreshed (or nothing changed), 1 a download or the generator failed, 3 Go distrusts a
# key that distrust.json and OneCRL do not list (add an incident to distrust.json by hand).
# With a summary file, writes a Markdown summary of what changed (for the weekly PR) and prints
# "changed=true|false": false when only retrieval dates and source checksums moved.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
summary="${1:-}"
today="$(date -u +%Y-%m-%d)"
src="$(mktemp -d)"
trap 'rm -rf "$src"' EXIT

fetch() { curl -sSfL --retry 3 --max-time 120 -o "$src/$1" "$2"; }
fetch mozilla.csv 'https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MozillaTLSServerAuthenticationCSV'
fetch chrome.csv 'https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=ChromeTLSServerAuthenticationCSV'
fetch ct.json 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
fetch onecrl.json 'https://firefox.settings.services.mozilla.com/v1/buckets/security-state/collections/onecrl/changeset?_expected=0'
for n in 2409 3526 5114 7919; do fetch "rfc$n.txt" "https://www.rfc-editor.org/rfc/rfc$n.txt"; done

cd "$root"
set +e
go run ./internal/refdata/gen -mozilla "$src/mozilla.csv" -chrome "$src/chrome.csv" -ctlogs "$src/ct.json" \
  -rfcs "$src" -onecrl "$src/onecrl.json" -go-verify "$(go env GOROOT)/src/crypto/x509/verify.go" \
  -retrieved "$today" -out internal/refdata
rc=$?
set -e
[ "$rc" -eq 0 ] || exit "$rc"

[ -n "$summary" ] || exit 0

# What changed, beyond the dates and checksums that move on every run.
gen=(internal/refdata/roots_gen.go internal/refdata/ctlogs_gen.go internal/refdata/dhprimes_gen.go internal/refdata/onecrl_gen.go)
meaningful="$(git diff -U0 -- "${gen[@]}" | grep -E '^[-+][^-+]' | grep -vE 'Retrieved: |SHA256: "|^[-+]// Code generated' || true)"
names() { git diff -U0 -- "$1" | grep -E "^$2" | grep -oE "$3" | sed -E "s/$3/\\1/" | sort -u || true; }
{
  echo "Weekly reference-data refresh, retrieved $today by \`scripts/refresh-refdata.sh\`."
  echo
  for f in roots_gen.go ctlogs_gen.go onecrl_gen.go dhprimes_gen.go; do
    a="$(git diff -U0 -- "internal/refdata/$f" | grep -cE '^\+[^+]' || true)"
    d="$(git diff -U0 -- "internal/refdata/$f" | grep -cE '^-[^-]' || true)"
    echo "- \`$f\`: +$a / -$d lines"
  done
  added="$(names internal/refdata/roots_gen.go '\+' 'Name: "([^"]+)"')"
  removed="$(names internal/refdata/roots_gen.go '-' 'Name: "([^"]+)"')"
  if [ -n "$added$removed" ]; then
    echo
    echo "Root-store entries that changed (a name on both sides changed status or constraints):"
    echo
    comm -13 <(echo "$removed") <(echo "$added") | sed '/^$/d; s/^/- added: /'
    comm -23 <(echo "$removed") <(echo "$added") | sed '/^$/d; s/^/- removed: /'
    comm -12 <(echo "$removed") <(echo "$added") | sed '/^$/d; s/^/- changed: /'
  fi
  k="$(git diff -U0 -- internal/refdata/onecrl_gen.go | grep -cE '^\+\s*\{SPKI' || true)"
  c="$(git diff -U0 -- internal/refdata/onecrl_gen.go | grep -cE '^\+\s*\{Issuer' || true)"
  if [ "$k$c" != "00" ]; then
    echo
    echo "OneCRL: $k key entries and $c CA-certificate entries added or changed. They are reported as"
    echo "\`CERT.DISTRUSTED-KEY\` (high). A key that is also a compromise belongs in \`distrust.json\` with its incident."
  fi
  echo
  echo "Checked by the job: the generator's own checks, Go's distrusted keys all listed, and"
  echo "\`go test ./internal/refdata/... ./internal/pki/... ./internal/eval/...\`."
} > "$summary"
if [ -n "$meaningful" ]; then echo "changed=true"; else echo "changed=false"; fi
