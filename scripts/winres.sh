#!/usr/bin/env bash
# Give the Windows programs their version information and icon (what Explorer shows under
# Properties > Details), from the release version. Without it Windows shows a blank version, or
# 0.0.0.0. The release build runs this before compiling (.goreleaser.yaml); for a local build:
#
#   scripts/winres.sh 0.1.0-rc.1        # or no argument: the version git describe gives
#   GOOS=windows go build ./cmd/cipherhorizon
#
# It writes cmd/<program>/rsrc_windows_{amd64,arm64}.syso, which "go build" links into Windows
# builds only (and which .gitignore keeps out of the repository). The text and the icon live in
# scripts/winres/. The full version (with any -rc.1 suffix) is the product version; Windows' own
# file version must be four numbers, so it is MAJOR.MINOR.PATCH.0.
set -euo pipefail

cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')}"
version="${version#v}"
core="${version%%[-+]*}"
if [[ "$core" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  file_version="$core.0"
else
  file_version="0.0.0.0" # an untagged build: say so rather than invent a number
fi

for prog in cipherhorizon cipherhorizon-collector; do
  go run github.com/tc-hib/go-winres@v0.3.3 make \
    --in "scripts/winres/$prog.json" --arch amd64,arm64 --out "cmd/$prog/rsrc" \
    --product-version "$version" --file-version "$file_version"
done
echo "windows version resources: product $version, file $file_version"
