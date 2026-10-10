#!/usr/bin/env bash
# Cut the changelog for a release: turns "## [Unreleased]" into "## [X.Y.Z] - DATE", opens a fresh
# Unreleased section and updates the compare links. It changes CHANGELOG.md only; you review the diff,
# commit it on a release-prep branch, open a PR, and tag after it merges (docs/engineering/RELEASING.md).
#   scripts/prepare-release.sh 0.1.0
set -euo pipefail

version="${1:-}"
version="${version#v}"
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
[[ "$version" =~ $semver ]] || { echo "usage: $0 <MAJOR.MINOR.PATCH[-prerelease]>" >&2; exit 2; }

cd "$(dirname "$0")/.."
f=CHANGELOG.md
grep -q '^## \[Unreleased\]' "$f" || { echo "$f has no [Unreleased] section" >&2; exit 1; }
if grep -q "^## \[$version\]" "$f"; then echo "$f already has a section for $version" >&2; exit 1; fi

# The Unreleased section must have content.
body="$(awk 'index($0,"## [Unreleased]")==1{on=1;next} index($0,"## [")==1{on=0} /^\[[^]]+\]: /{on=0} on' "$f")"
[ -n "$(printf '%s' "$body" | tr -d '[:space:]')" ] || { echo "[Unreleased] is empty: nothing to release" >&2; exit 1; }

date="$(date -u +%Y-%m-%d)"
tmp="$(mktemp)"
awk -v v="$version" -v d="$date" '
  index($0, "## [Unreleased]") == 1 { print; print ""; print "## [" v "] - " d; next }
  { print }
' "$f" > "$tmp"

# Compare links: [Unreleased] compares from the new tag; the new tag compares from the previous one
# (or points at the tag itself for the first release).
url="$(sed -n 's#^\[Unreleased\]: \(.*\)/compare/.*#\1#p' "$tmp" | head -1)"
if [ -n "$url" ]; then
  prev="$(grep -oE '^\[[0-9][^]]*\]' "$tmp" | head -1 | tr -d '[]' || true)"
  sed -i.bak "s#^\[Unreleased\]: .*#[Unreleased]: $url/compare/v$version...HEAD#" "$tmp"
  if [ -n "$prev" ]; then
    printf '[%s]: %s/compare/v%s...v%s\n' "$version" "$url" "$prev" "$version" >> "$tmp"
  else
    printf '[%s]: %s/releases/tag/v%s\n' "$version" "$url" "$version" >> "$tmp"
  fi
  rm -f "$tmp.bak"
fi
mv "$tmp" "$f"
echo "CHANGELOG.md: Unreleased is now $version ($date). Review it, then commit."
