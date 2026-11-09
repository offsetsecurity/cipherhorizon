#!/usr/bin/env bash
# Cut the changelog for a release: turns "## [Unreleased]" into "## [X.Y.Z] - DATE", opens a fresh
# Unreleased section and updates the compare links. It also locks the database migrations the release
# ships (internal/store/migrations.lock). It changes those two files only; you review the diff, commit
# it on a release-prep branch, open a PR, and tag after it merges (docs/engineering/RELEASING.md).
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
  # The release before this one is the next version heading down the file (headings are newest first).
  prev="$(grep -oE '^## \[[0-9][^]]*\]' "$tmp" | sed -n '2p' | sed 's/^## \[//; s/\]$//' || true)"
  if [ -n "$prev" ]; then
    newlink="[$version]: $url/compare/v$prev...v$version"
  else
    newlink="[$version]: $url/releases/tag/v$version"
  fi
  # The new link goes right under [Unreleased], so the list stays newest first.
  awk -v u="[Unreleased]: $url/compare/v$version...HEAD" -v n="$newlink" '
    index($0, "[Unreleased]: ") == 1 { print u; print n; next }
    { print }
  ' "$tmp" > "$tmp.bak" && mv "$tmp.bak" "$tmp"
  rm -f "$tmp.bak"
fi
mv "$tmp" "$f"
# The container image the README and the install guide tell people to run is this release's.
for doc in README.md docs/engineering/INSTALL.md; do
  sed -i -E "s#(ghcr\.io/offsetsecurity/cipherhorizon:)[0-9]+\.[0-9]+\.[0-9]+#\\1$version#g" "$doc"
done

echo "CHANGELOG.md: Unreleased is now $version ($date). Review it, then commit."

# Database migrations this release ships become history: lock them, so no later change can edit what
# installs of this version have already run (PRD-016 U-01).
lock=internal/store/migrations.lock
before="$(grep -c '^[0-9]' "$lock" || true)"
go test ./internal/store -run '^TestMigrationsLock$' -count=1 -args -lock-release="$version" >/dev/null
after="$(grep -c '^[0-9]' "$lock" || true)"
if [ "$after" -gt "$before" ]; then
  echo "$lock: locked migrations $((before + 1))-$after as shipped in v$version. Commit it with the changelog."
  echo "This release changes the database, so it needs its upgrade fixture before the tag (CI checks):"
  echo "  testing/upgrade/make-fixture.sh v$version HEAD"
  echo "and commit internal/store/testdata/upgrade/v$version.db with the release."
else
  echo "$lock: this release ships no new migration."
fi
