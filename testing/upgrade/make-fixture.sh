#!/usr/bin/env bash
# Makes the upgrade-test database for a released version (PRD-016 U-02): builds that release from its
# tag, runs it against the demo targets, seeds it through its own API (seed.mjs), adds an account
# with its own CLI, and writes a compact copy to internal/store/testdata/upgrade/<tag>.db.
#
#   testing/upgrade/make-fixture.sh v0.4.0          # a released version, built from its tag
#   testing/upgrade/make-fixture.sh v0.4.1 HEAD     # the release being prepared, before it is tagged
#
# The database is written by the release itself, so TestUpgradeFromEveryRelease upgrades what real
# installs of that version hold. Run it once per release, on the release branch before the tag
# (RELEASING.md step 2): the release commit only adds the changelog, the lock and this file, so HEAD
# builds the same program the tag will, stamped with the same version. Commit the file with the
# release. Needs Go, Node 22+ and git.
set -euo pipefail

tag="${1:-}"
ref="${2:-}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 vX.Y.Z [REF]" >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/internal/store/testdata/upgrade/$tag.db"
[ -e "$out" ] && { echo "$out already exists; a fixture is made once, from the release" >&2; exit 1; }
if [ -z "$ref" ]; then
  git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "no tag $tag (git fetch --tags), or give the release commit: $0 $tag HEAD" >&2; exit 1; }
  ref="$tag"
elif git -C "$root" rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  # Once the tag exists it is the release; a different commit would not be what installs hold.
  [ "$(git -C "$root" rev-parse "$tag^{commit}")" = "$(git -C "$root" rev-parse "$ref^{commit}")" ] ||
    { echo "$tag exists and is not $ref: build the fixture from the tag ($0 $tag)" >&2; exit 1; }
fi
grep -q "^## \[${tag#v}\]" "$root/CHANGELOG.md" || { echo "CHANGELOG.md has no section for ${tag#v}: run scripts/prepare-release.sh first" >&2; exit 1; }

work="$(mktemp -d)"
src="$work/src"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  git -C "$root" worktree remove --force "$src" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

exe=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) exe=".exe" ;; esac

git -C "$root" worktree add -q --detach "$src" "$ref"
module="$(cd "$src" && go list -m)"
version="${tag#v}"
(
  cd "$src"
  CGO_ENABLED=0 go build -trimpath -ldflags "-X $module/internal/version.Version=$version" -o "$work/cipherhorizon$exe" ./cmd/cipherhorizon
  go build -o "$work/demo-targets$exe" ./cmd/demo-targets
)

# Ports away from the defaults, so a server or demo already running on this machine is not disturbed.
demo_base=19440
port=18090
token="fixture-token-$(date +%s)-0123456789abcdef"
db="$work/fixture.db"

"$work/demo-targets$exe" -base-port "$demo_base" > "$work/demo.log" 2>&1 &
pids+=($!)
"$work/cipherhorizon$exe" serve --allow-loopback --token "$token" --db "$db" --addr "127.0.0.1:$port" > "$work/serve.log" 2>&1 &
serve_pid=$!
pids+=($serve_pid)
for _ in $(seq 1 100); do
  curl -sf "http://127.0.0.1:$port/api/v1/health" >/dev/null && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$port/api/v1/health" >/dev/null || { cat "$work/serve.log" >&2; exit 1; }

node "$root/testing/upgrade/seed.mjs" --base "http://127.0.0.1:$port" --token "$token" --demo-base "$demo_base"

# A host inventory, uploaded as the collector would: the release's own sample (testing/golden), to this
# local server only.
curl -sf -o /dev/null -X POST "http://127.0.0.1:$port/api/v1/hosts/ingest" \
  -H "Authorization: Bearer $token" -H "X-Requested-With: cipherhorizon" -H "Content-Type: application/json" \
  --data-binary "@$src/testing/golden/debian-13.cbom.json" || { echo "uploading the host inventory failed" >&2; exit 1; }

kill "$serve_pid"
wait "$serve_pid" 2>/dev/null || true

# An account, made the way an administrator makes one at the console (the password is a test value).
printf 'fixture-password-0123456789\n' | "$work/cipherhorizon$exe" user add --db "$db" --role admin fixture-admin

mkdir -p "$(dirname "$out")"
"$work/cipherhorizon$exe" db backup --db "$db" "$out"
echo "wrote $out ($(wc -c < "$out") bytes) with $("$work/cipherhorizon$exe" version | head -1)"
