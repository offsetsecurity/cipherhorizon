#!/usr/bin/env bash
# Rename the product (PRD-003 REQ-REL-3, ADR-0014). The name appears in five places, all reached here:
#
#   1. the Go module path and every import           github.com/<owner>/cipherhorizon
#   2. the binary and command directories             cmd/cipherhorizon, cmd/cipherhorizon-collector
#   3. the property namespace in CBOMs                 cipherhorizon:classical-status ...
#   4. the environment variables                       CIPHERHORIZON_TOKEN ...
#   5. documentation, UI text and release config      CipherHorizon (display name), cipherhorizon (identifier)
#
#   scripts/rename.sh <new-identifier> <New Display Name>            # dry run: counts per category, changes nothing
#   scripts/rename.sh <new-identifier> <New Display Name> --apply    # rewrite files and move the cmd directories
#
# Then: gofmt -l . ; go build ./... && go test ./... , regenerate the golden CBOMs
# (go test ./internal/app -update), and read docs/engineering/RENAME.md for what a script cannot decide:
# the property-namespace registration and whether old CBOMs that carry the old prefix must still be read.
# Text about the history of the old name (CHANGELOG entries before this rename, ADR-0014) is left alone.
set -euo pipefail
id="${1:-}"; display="${2:-}"; mode="${3:-}"
[[ "$id" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ ]] && [ -n "$display" ] || { echo "usage: $0 <new-identifier> <New Display Name> [--apply]" >&2; exit 2; }
[ "$id" = cipherhorizon ] && { echo "the new identifier is the current one" >&2; exit 2; }
upper="$(echo "$id" | tr 'a-z-' 'A-Z_')"
cd "$(dirname "$0")/.."

# Text files that are not build output and not history.
files="$(grep -rIl --exclude-dir=.git --exclude-dir=dist --exclude-dir=node_modules --exclude-dir=artifacts \
  --exclude=CHANGELOG.md --exclude=ADR-0014-product-name.md --exclude=rename.sh -i -e cipherhorizon . || true)"

count() { local n=0 c; for f in $files; do c=$(grep -o -- "$1" "$f" 2>/dev/null | wc -l); n=$((n + c)); done; echo "$n"; }
echo "files that mention the name: $(echo "$files" | wc -l)"
echo "  module path and imports      github.com/*/cipherhorizon : $(count 'github\.com/[A-Za-z0-9_-]*/cipherhorizon')"
echo "  property namespace           cipherhorizon:             : $(count 'cipherhorizon:')"
echo "  environment variables        CIPHERHORIZON_             : $(count 'CIPHERHORIZON_')"
echo "  display name                 CipherHorizon              : $(count 'CipherHorizon')"
echo "  other identifier uses        cipherhorizon              : $(count 'cipherhorizon')"
echo "  directories to move          $(ls -d cmd/cipherhorizon* 2>/dev/null | tr '\n' ' ')"
[ "$mode" = "--apply" ] || { echo "dry run: nothing changed. Add --apply to rewrite."; exit 0; }

for f in $files; do
  sed -i.bak -e "s#CIPHERHORIZON#${upper}#g" -e "s#CipherHorizon#${display}#g" -e "s#cipherhorizon#${id}#g" "$f"
  rm -f "$f.bak"
done
for d in cmd/cipherhorizon*; do [ -d "$d" ] && mv "$d" "cmd/${id}${d#cmd/cipherhorizon}"; done
echo "renamed. next: gofmt -l . ; go build ./... && go test ./... ; go test ./internal/app -update"
