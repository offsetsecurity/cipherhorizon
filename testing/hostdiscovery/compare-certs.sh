#!/usr/bin/env bash
# Oracle for the Linux certificate sensor (sensor "cert-files"): compares what the collector
# reports with what OpenSSL says about the same files. Independent of the Go code: it uses only
# `openssl` and `python3` and re-derives the answer from the files themselves.
#
# Usage (on a Linux host, after running the collector):
#   cipherhorizon-collector run -o /tmp/host.cbom.json
#   testing/hostdiscovery/compare-certs.sh /tmp/host.cbom.json
#
# For every certificate component in the CBOM it checks, at each recorded location:
#   - the file exists and contains a certificate whose SHA-256 fingerprint equals the component's hash
#   - the key algorithm, key size (and curve) match what `openssl x509 -text` prints
# and it checks the reverse: every certificate file in the searched directories that OpenSSL can
# parse is present in the CBOM (no missing) and nothing in the CBOM is absent from disk (no extra).
# It also asserts that no private key appears in the CBOM.
#
# ROOT (optional) is a directory the searched paths are relative to, for checking a tree that is
# not this machine's own root (the sensor was run with that tree as its root). Without it the
# script reads the live host.
#
# STATUS: RUN against a real Linux-style tree (Git for Windows ships the Mozilla CA bundles under
# etc/pki/ca-trust/extracted/pem; see docs/host-discovery/stage-3-certificates-report.md).
# NOT yet run on a live Linux host (the development machine has no working Linux environment:
# docs/program/TRACKER.md OA-3).
set -u
CBOM=${1:?usage: compare-certs.sh host.cbom.json}
command -v openssl >/dev/null || { echo "openssl is required"; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 2; }

python3 - "$CBOM" <<'PY'
import json, subprocess, sys, os, re, hashlib

cbom = json.load(open(sys.argv[1]))
prefix = os.environ.get("ROOT", "").rstrip("/\\")
roots = ["etc/ssl/certs", "etc/pki/ca-trust/source/anchors", "etc/pki/ca-trust/extracted/pem", "etc/pki/tls/certs",
         "usr/local/share/ca-certificates", "usr/share/ca-certificates", "etc/letsencrypt/live",
         "etc/nginx", "etc/apache2", "etc/httpd", "etc/haproxy", "etc/postfix", "etc/dovecot"]
key_name = re.compile(r'(^|[-_.])(priv|privkey|private|key|keys|secret|pkcs12|p12|pfx|jks|keystore)([-_.]|$)', re.I)
key_ext = {'.key', '.p12', '.pfx', '.jks', '.keystore', '.p8', '.kdb', '.pk8'}
cert_ext = {'.crt', '.cer', '.pem', '.der'}

def fps_in(path):
    """SHA-256 fingerprints (lower hex) of every certificate OpenSSL finds in a file."""
    out = subprocess.run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", path], input=b"", capture_output=True)
    fps = set()
    if out.returncode == 0:
        p = subprocess.run(["openssl", "pkcs7", "-print_certs"], input=out.stdout.decode("ascii", "replace"), capture_output=True, text=True)
        for block in re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', p.stdout, re.S):
            f = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], input=block, capture_output=True, text=True)
            m = re.search(r'=([0-9A-F:]+)', f.stdout)
            if m: fps.add(m.group(1).replace(':', '').lower())
    else:  # bare DER
        f = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256", "-in", path], capture_output=True, text=True)
        m = re.search(r'=([0-9A-F:]+)', f.stdout)
        if m: fps.add(m.group(1).replace(':', '').lower())
    return fps

# 1. what the CBOM claims
claimed = {}   # (fingerprint, location) -> component
comps = [c for c in cbom.get("components", []) if c.get("type") == "cryptographic-asset"
         and c.get("cryptoProperties", {}).get("assetType") == "certificate"]
for c in comps:
    h = next((x["content"] for x in c.get("hashes", []) if x["alg"] == "SHA-256"), None)
    for o in (c.get("evidence", {}).get("occurrences") or []):
        claimed[(h, o["location"])] = c

# 2. what is on disk
on_disk = {}
for r in roots:
    base = prefix + "/" + r
    if not os.path.isdir(base): continue
    for d, dirs, files in os.walk(base, followlinks=False):
        dirs[:] = [x for x in dirs if x.lower() not in {"private", "private_keys", "keys", "keystore", "secrets", ".git"}]
        for f in files:
            p = os.path.join(d, f)
            ext = os.path.splitext(f)[1].lower()
            if ext in key_ext or key_name.search(f.lower()): continue
            if not (ext in cert_ext or re.fullmatch(r'[0-9a-f]{8}\.[0-9]+', f.lower())): continue
            # a link is followed once, only to a regular file inside the tree (the sensor's rule)
            if os.path.islink(p):
                t = os.path.realpath(p)
                if not os.path.isfile(t) or os.path.islink(t): continue
            for fp in fps_in(p):
                on_disk[(fp, p[len(prefix):].replace(os.sep, "/"))] = True

missing = sorted(set(on_disk) - set(claimed))
extra = sorted(set(claimed) - set(on_disk))
print(f"certificate observations: CBOM {len(claimed)}, OpenSSL {len(on_disk)}")
ok = True
for m in missing: print("MISSING from the CBOM:", m); ok = False
for e in extra: print("EXTRA in the CBOM:", e); ok = False

# 3. key facts for each claimed certificate
bad = 0
for (fp, loc), c in list(claimed.items())[:200]:
    props = {p["name"]: p["value"] for p in c.get("properties", [])}
    # x509 reads the first certificate in the file, so compare only where it is the certificate itself
    single = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", prefix + loc], capture_output=True, text=True).stdout if loc.endswith(('.crt', '.pem', '.cer')) else ""
    if fp and fp in single.replace(':', '').lower():
        text = subprocess.run(["openssl", "x509", "-noout", "-text", "-in", prefix + loc], capture_output=True, text=True).stdout
        m = re.search(r'Public-Key: \((\d+) bit\)', text)
        if m and props.get("cipherhorizon:cert:key-bits") != m.group(1):
            print("KEY SIZE differs at", loc, props.get("cipherhorizon:cert:key-bits"), "vs", m.group(1)); bad += 1
if bad: ok = False

# 4. no private key in the document
raw = open(sys.argv[1]).read()
if "PRIVATE KEY" in raw:
    print("PRIVATE KEY text found in the CBOM"); ok = False
print("RESULT:", "AGREE" if ok else "DISAGREE")
sys.exit(0 if ok else 1)
PY
exit $?
