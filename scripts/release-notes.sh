#!/usr/bin/env bash
# Print the CHANGELOG.md section for one version (used as the GitHub release notes).
#   scripts/release-notes.sh 0.1.0
# Fails if the section is missing or empty, so a release cannot go out without notes.
set -euo pipefail

version="${1:-}"
version="${version#v}"
[ -n "$version" ] || { echo "usage: $0 <version>" >&2; exit 2; }

changelog="$(dirname "$0")/../CHANGELOG.md"
notes="$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { on = 1; next }
  index($0, "## [") == 1       { on = 0 }
  /^\[[^]]+\]: /               { on = 0 }
  on                           { print }
' "$changelog")"

# trim leading/trailing blank lines
notes="$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')"
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no notes for version $version" >&2
  exit 1
fi
printf '%s\n' "$notes"
