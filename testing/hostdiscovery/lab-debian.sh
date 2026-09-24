#!/usr/bin/env bash
# Ground-truth check of `cipherhorizon run` on a Debian-family Linux host (Debian, Ubuntu, Kali),
# for a WSL distro, a VM or a CI container.
#
#   1. Build the Linux binary on the development machine:
#        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/cipherhorizon-collector-linux ./cmd/cipherhorizon-collector
#   2. From inside the distro (in WSL the repo is under /mnt/<drive>/...):
#        bash testing/hostdiscovery/lab-debian.sh /mnt/d/code/pqc/dist/cipherhorizon-collector-linux
#        sudo bash testing/hostdiscovery/lab-debian.sh ...      # run again as root to compare tiers
#
# The ORACLE is dpkg-query and `openssl version`, run by this harness (never by the collector):
#   EXPECTED = installed packages whose name suggests crypto (a broader net than the collector's patterns)
#   DETECTED = what the CBOM inventoried
# It fails on any false positive, any version mismatch, and any OpenSSL capability the version does not justify.
#
# STATUS: written and reviewed, NOT YET RUN on a Linux host (no Linux environment was available when
# the pipeline was built). Until it has run, Linux is "fixtures only" (docs/host-discovery-program.md).
set -euo pipefail

BIN="${1:?usage: $0 /path/to/cipherhorizon-collector-linux}"
command -v python3 >/dev/null || { echo "python3 is needed by this harness" >&2; exit 2; }
command -v dpkg-query >/dev/null || { echo "not a dpkg host" >&2; exit 2; }

OUT="$(mktemp)"; ERR="$(mktemp)"
set +e; "$BIN" run -o "$OUT" 2>"$ERR"; CODE=$?; set -e
echo "collector exit code: $CODE (0 = complete, 2 = incomplete)"; sed 's/^/  collector: /' "$ERR"
# 0 = complete, 2 = a result was written but is incomplete; anything else (1) is a fatal failure
if [ "$CODE" != 0 ] && [ "$CODE" != 2 ]; then echo "collector failed (exit $CODE)" >&2; exit 1; fi
echo "harness privilege: $([ "$(id -u)" = 0 ] && echo ROOT || echo 'standard user')"

OPENSSL_VERSION="$(openssl version 2>/dev/null | awk '{print $2}' || true)"
echo "oracle: openssl version -> ${OPENSSL_VERSION:-<not installed>}"

# (Git Bash / MSYS test setups hand a Windows Python a POSIX path: translate it. A no-op on Linux.)
PYOUT="$OUT"; command -v cygpath >/dev/null 2>&1 && PYOUT="$(cygpath -w "$OUT")"
python3 - "$PYOUT" "${OPENSSL_VERSION:-}" <<'PY'
import json, re, subprocess, sys

cbom_path, openssl_version = sys.argv[1], sys.argv[2]
doc = json.load(open(cbom_path))
ours = {}
for c in doc["components"]:
    if c["type"] == "cryptographic-asset":
        continue
    ours[c["name"] + "|" + c.get("version", "")] = c

out = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"], capture_output=True, text=True, check=True).stdout
broad = re.compile(r"ssl|crypt|gnutls|nettle|hogweed|gpg|gnupg|sodium|nss|ssh|krb5|mbed|wolfssl|botan|gcrypt")
expected = {}
for line in out.splitlines():
    pkg, ver, status = (line.split("\t") + ["", "", ""])[:3]
    if status.endswith("installed") and broad.search(pkg):
        expected[pkg + "|" + ver] = pkg

agreed = [k for k in expected if k in ours]
missing = sorted(k for k in expected if k not in ours)
false_pos = sorted(k for k in ours if k not in expected)
print(f"EXPECTED (oracle, broad): {len(expected)}   DETECTED (collector): {len(ours)}   AGREED: {len(agreed)}")
print(f"FALSE POSITIVES (collector-only): {len(false_pos)}", *false_pos, sep="\n  ")
print(f"MISSING (oracle-only, to adjudicate): {len(missing)}")
for m in missing:
    print("  ", m)
print("Adjudicate MISSING by hand: dev/doc/helper packages and non-crypto names are correct exclusions.")

problems = 0
if false_pos:
    problems += 1

# Capability check: OpenSSL >= 3.5 must be credited with ML-KEM, older must not.
def num(v):
    m = re.match(r"(\d+)\.(\d+)", v or "")
    return (int(m[1]), int(m[2])) if m else None

refs = {c["bom-ref"]: c for c in doc["components"]}
provides = {}
for d in doc.get("dependencies", []):
    provides[d["ref"]] = d.get("provides", [])
v = num(openssl_version)
if v:
    for key, c in ours.items():
        if c["name"] in ("libssl3", "libssl3t64", "openssl") and c["type"] in ("library", "application"):
            names = {refs[r]["name"] for r in provides.get(c["bom-ref"], []) if r in refs}
            has_pqc = "ML-KEM-768" in names
            if has_pqc != (v >= (3, 5)):
                print(f"CAPABILITY MISMATCH: {key}: ML-KEM credited={has_pqc}, but OpenSSL {openssl_version} says {'yes' if v >= (3, 5) else 'no'}")
                problems += 1

meta = {p["name"]: p["value"] for p in doc["metadata"].get("properties", []) if p["name"].endswith(("privilege-tier", "host-os"))}
print("document says:", meta)
sys.exit(1 if problems else 0)
PY
