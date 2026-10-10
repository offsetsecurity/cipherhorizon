#!/usr/bin/env bash
# Remove build leftovers that no current target produces, so a stale binary (an old program name, a
# database from a past test run) can never be mistaken for current output. "make build" runs this first.
# It only touches dist/, which is git-ignored, regenerable build output, and never anything else.
set -euo pipefail

cd "$(dirname "$0")/.."
[ -d dist ] || exit 0

# What the current build produces. Everything else at the top of dist/ is stale.
keep_re='^(cipherhorizon|cipherhorizon-collector|demo-targets)(\.exe)?$'
# A GoReleaser run owns dist/ wholesale (it starts with --clean); leave its output alone.
[ -f dist/artifacts.json ] && exit 0

removed=0
for f in dist/* dist/.[!.]*; do
  [ -f "$f" ] || continue
  name="$(basename "$f")"
  if [[ ! "$name" =~ $keep_re ]]; then
    if rm -f -- "$f" 2>/dev/null; then
      echo "removed stale $f"
      removed=$((removed + 1))
    else
      echo "clean-stale: could not remove $f (in use by another process?); left in place" >&2
    fi
  fi
done
[ "$removed" -eq 0 ] || echo "clean-stale: removed $removed stale file(s) from dist/"
