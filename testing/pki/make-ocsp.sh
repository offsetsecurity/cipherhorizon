#!/usr/bin/env bash
# make-ocsp.sh builds the OCSP test fixtures in internal/pki/testdata with OpenSSL,
# so the producer of every stapled response is independent of the decoder under
# test (QA-PLAN-004 §3). The outputs are committed; re-run only to change them.
#
#   testing/pki/make-ocsp.sh            # needs OpenSSL 3.x on PATH
#
# Fixtures (all EC P-256, validity 2025-01-01 .. 2045-01-01):
#   root.pem, int.pem             a root and an intermediate CA
#   leaf.pem                      server leaf issued by int, OCSP URL set
#   leaf-muststaple.pem           as leaf, with the TLS Feature status_request (RFC 7633)
#   other.pem                     a second leaf from int (for "staple for another certificate")
#   responder.pem                 a delegated responder (EKU OCSPSigning) issued by int
#   ocsp-good.der                 leaf: good, signed by int
#   ocsp-revoked.der              leaf: revoked (keyCompromise), signed by int
#   ocsp-unknown.der              leaf: unknown, signed by int
#   ocsp-other.der                other: good, signed by int
#   ocsp-delegated.der            leaf: good, signed by the delegated responder
#   ocsp-trylater.der             a non-successful response (tryLater)
#   *.txt                         `openssl ocsp -resp_text` of each, the oracle the tests compare against
set -euo pipefail
export MSYS_NO_PATHCONV=1

out="$(cd "$(dirname "$0")/../.." && pwd)/internal/pki/testdata"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"

start=20250101000000Z
end=20450101000000Z

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key"; }

cat > ext.cnf <<'EOF'
[root]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[int]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.test
authorityInfoAccess = OCSP;URI:http://ocsp.pki.test/,caIssuers;URI:http://pki.test/int.der
authorityKeyIdentifier = keyid
[muststaple]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.test
authorityInfoAccess = OCSP;URI:http://ocsp.pki.test/
tlsfeature = status_request
authorityKeyIdentifier = keyid
[other]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:other.test
authorityKeyIdentifier = keyid
[responder]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
authorityKeyIdentifier = keyid
EOF

sign() { # name subject issuer section serial
  key "$1"
  openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
  if [ "$3" = self ]; then
    openssl x509 -req -in "$1.csr" -signkey "$1.key" -not_before $start -not_after $end \
      -extfile ext.cnf -extensions "$4" -set_serial "$5" -out "$1.pem"
  else
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -not_before $start -not_after $end \
      -extfile ext.cnf -extensions "$4" -set_serial "$5" -out "$1.pem"
  fi
}

sign root "/CN=CipherHorizon Test Root" self root 0x01
sign int "/CN=CipherHorizon Test Intermediate" root int 0x02
sign leaf "/CN=leaf.test" int leaf 0x1001
sign leaf-muststaple "/CN=leaf.test" int muststaple 0x1002
sign other "/CN=other.test" int other 0x1003
sign responder "/CN=CipherHorizon Test OCSP Responder" int responder 0x1004

subj() { openssl x509 -in "$1" -noout -subject -nameopt compat | sed 's/^subject=//'; }
exp=450101000000Z
printf 'V\t%s\t\t1001\tunknown\t%s\n' $exp "$(subj leaf.pem)" > idx-good
printf 'V\t%s\t\t1003\tunknown\t%s\n' $exp "$(subj other.pem)" >> idx-good
printf 'R\t%s\t250601000000Z,keyCompromise\t1001\tunknown\t%s\n' $exp "$(subj leaf.pem)" > idx-revoked
: > idx-unknown

respond() { # out cert index signer
  openssl ocsp -issuer int.pem -cert "$2" -no_nonce -reqout "$1.req"
  openssl ocsp -index "$3" -CA int.pem -rsigner "$4.pem" -rkey "$4.key" -reqin "$1.req" \
    -respout "$1.der" -ndays 7
}

respond ocsp-good leaf.pem idx-good int
respond ocsp-revoked leaf.pem idx-revoked int
respond ocsp-unknown leaf.pem idx-unknown int
respond ocsp-other other.pem idx-good int
respond ocsp-delegated leaf.pem idx-good responder

# tryLater: OCSPResponse { responseStatus 3 } with no responseBytes.
printf '\x30\x03\x0a\x01\x03' > "$out/ocsp-trylater.der"

# Paths handed to openssl stay relative: on Windows (Git Bash) a native openssl
# cannot open MSYS-style absolute paths.
for f in ocsp-good ocsp-revoked ocsp-unknown ocsp-other ocsp-delegated; do
  openssl ocsp -respin "$f.der" -resp_text -noverify > "$f.txt"
done
cp root.pem int.pem leaf.pem leaf-muststaple.pem other.pem responder.pem ocsp-*.der ocsp-*.txt "$out/"
echo "wrote fixtures to $out"
