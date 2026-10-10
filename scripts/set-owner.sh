#!/usr/bin/env bash
# Point the repository at its real GitHub home. The code base ships with a placeholder owner
# ("example") so it builds before a repository exists; run this once, before the first push:
#
#   scripts/set-owner.sh <github-user-or-org> [repo-name]      # repo-name defaults to cipherhorizon
#
# It rewrites the Go module path (go.mod and every import), the linker-flag paths in the release
# config, links in the docs, and the CODEOWNERS / changelog placeholders. Nothing else changes.
# It is idempotent. Review with "git diff --stat", then "go build ./... && go test ./...".
set -euo pipefail

owner="${1:-}"
repo="${2:-cipherhorizon}"
re='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$'
[[ "$owner" =~ $re ]] || { echo "usage: $0 <github-user-or-org> [repo-name]" >&2; exit 2; }
[[ "$repo" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid repo name: $repo" >&2; exit 2; }

cd "$(dirname "$0")/.."
old="$(go list -m 2>/dev/null || sed -n 's/^module //p' go.mod)"
new="github.com/$owner/$repo"

# Every tracked-or-untracked text file that is not build output.
files="$(grep -rIl --exclude-dir=.git --exclude-dir=dist --exclude-dir=node_modules --exclude-dir=artifacts \
  -e "$old" -e 'OWNER-PLACEHOLDER' -e 'github.com/example/' -e 'ghcr.io/example/' . || true)"

for f in $files; do
  [ "$f" = "./scripts/set-owner.sh" ] && continue
  sed -i.bak \
    -e "s#${old}#${new}#g" \
    -e "s#github\.com/example/cipherhorizon#${new}#g" \
    -e "s#ghcr\.io/example/cipherhorizon#ghcr.io/${owner}/${repo}#g" \
    -e "s#github\.com/OWNER-PLACEHOLDER/cipherhorizon#${new}#g" \
    -e "s#@OWNER-PLACEHOLDER#@${owner}#g" \
    -e "s#OWNER-PLACEHOLDER#${owner}#g" \
    "$f"
  rm -f "$f.bak"
done

# The install instructions use "<owner>" as a stand-in; make them copy-pasteable. And the README's
# "set the owner first" notice has done its job.
for f in README.md docs/engineering/DISTRIBUTION.md; do
  [ -f "$f" ] && sed -i.bak -e "s#<owner>#${owner}#g" "$f" && rm -f "$f.bak"
done
if [ -f README.md ]; then
  sed -i.bak -e '/<!-- placeholder-owner -->/,/<!-- \/placeholder-owner -->/d' README.md && rm -f README.md.bak
fi

echo "module path is now: $(sed -n 's/^module //p' go.mod)"
echo "next: gofmt -l . ; go build ./... && go test ./... ; git diff --stat"
