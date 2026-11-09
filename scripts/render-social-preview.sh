#!/usr/bin/env bash
# Renders docs/img/social-preview.html to docs/img/social-preview.png (1280x640),
# the image GitHub shows when the repo link is shared. Needs Chrome, Chromium or Edge.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
browser="${BROWSER_BIN:-}"
if [ -z "$browser" ]; then
  for b in google-chrome chromium chromium-browser msedge \
           "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
           "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if command -v "$b" >/dev/null 2>&1 || [ -x "$b" ]; then browser="$b"; break; fi
  done
fi
[ -n "$browser" ] || { echo "no Chrome/Chromium/Edge found; set BROWSER_BIN" >&2; exit 1; }
src="$root/docs/img/social-preview.html"
out="$root/docs/img/social-preview.png"
if command -v cygpath >/dev/null 2>&1; then src="$(cygpath -m "$src")"; out="$(cygpath -m "$out")"; fi
"$browser" --headless=new --disable-gpu --user-data-dir="${TMPDIR:-/tmp}/ch-social-preview" --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1280,640 --virtual-time-budget=3000 \
  --screenshot="$out" "file:///${src#/}" >/dev/null 2>&1
echo "wrote $out"
