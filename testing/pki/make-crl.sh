#!/usr/bin/env bash
# make-crl.sh builds the CRL test fixtures in internal/pki/testdata/crl with OpenSSL, so the
# producer of every CRL is independent of the code that judges it (CRYPTO-REVIEW-004 P1b). The
# outputs are committed; re-run only to change them.
#
#   testing/pki/make-crl.sh            # needs OpenSSL 3.x on PATH
#
# PKI (EC P-256, certificates valid 2025-01-01 .. 2045-01-01):
#   root.pem            the root
#   int.pem             an intermediate, CRL DP http://crl.pki.test/root.crl
#   leaf.pem            leaf 0x2001 from int, CRL DP http://crl.pki.test/int.crl
#   other.pem           leaf 0x2002 from int, same CRL DP
#   impostor.pem        a CA with int's name and a different key (signs bad.crl)
# CRLs (thisUpdate 2026-06-01, nextUpdate 2045-01-01):
#   int-revoked.crl     by int: 0x2001 revoked (keyCompromise, 2026-05-01); IDP fullName int.crl, onlyContainsUserCerts
#   int-empty.crl       by int: nothing revoked; same IDP
#   root-revoked.crl    by root: int revoked (cACompromise, 2026-05-15); IDP fullName root.crl, onlyContainsCACerts
#   int-partition.crl   by int: nothing revoked; IDP fullName int-2.crl (a different partition)
#   int-delta.crl       by int: a delta CRL (openssl crl -gendelta, int-base to int-revoked)
#   bad.crl             by impostor: int's name, wrong key
#   int-base.crl        by int: the older CRL (2026-05-01) the delta is computed from
#   *.txt               `openssl crl -text` of each, the oracle the tests compare against
set -euo pipefail
export MSYS_NO_PATHCONV=1

out="$(cd "$(dirname "$0")/../.." && pwd)/internal/pki/testdata/crl"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"

start=20250101000000Z
end=20450101000000Z
last=20260601000000Z

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
crlDistributionPoints = URI:http://crl.pki.test/root.crl
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:leaf.test
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.pki.test/int.crl
[other]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:other.test
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://crl.pki.test/int.crl
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

sign root "/CN=CipherHorizon CRL Test Root" self root 0x01
sign int "/CN=CipherHorizon CRL Test Intermediate" root int 0x02
sign leaf "/CN=leaf.test" int leaf 0x2001
sign other "/CN=other.test" int other 0x2002
sign impostor "/CN=CipherHorizon CRL Test Intermediate" self root 0x03

subj() { openssl x509 -in "$1" -noout -subject -nameopt compat | sed 's/^subject=//'; }
exp=450101000000Z

# gencrl NAME CA_CERT CA_KEY INDEX CRL_EXT_SECTION [LAST_UPDATE] [CRL_NUMBER]
gencrl() {
  cat > ca-$1.cnf <<EOF
[ca]
default_ca = this
[this]
database = $4
crlnumber = crlnumber-$1
default_md = sha256
crl_extensions = $5
[idp_int]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical,@idp_int_s
[idp_int_s]
fullname = URI:http://crl.pki.test/int.crl
onlyuser = TRUE
[idp_root]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical,@idp_root_s
[idp_root_s]
fullname = URI:http://crl.pki.test/root.crl
onlyCA = TRUE
[idp_part]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical,@idp_part_s
[idp_part_s]
fullname = URI:http://crl.pki.test/int-2.crl
[plain]
authorityKeyIdentifier = keyid
EOF
  echo "${7:-02}" > crlnumber-$1
  openssl ca -gencrl -config ca-$1.cnf -cert "$2" -keyfile "$3" -crl_lastupdate "${6:-$last}" -crl_nextupdate $end -out $1.pem
  openssl crl -in $1.pem -outform DER -out $1.crl
}

printf 'R\t%s\t260501000000Z,keyCompromise\t2001\tunknown\t%s\n' $exp "$(subj leaf.pem)" > idx-int-revoked
printf 'V\t%s\t\t2002\tunknown\t%s\n' $exp "$(subj other.pem)" >> idx-int-revoked
printf 'V\t%s\t\t2001\tunknown\t%s\n' $exp "$(subj leaf.pem)" > idx-int-empty
printf 'R\t%s\t260515000000Z,CACompromise\t02\tunknown\t%s\n' $exp "$(subj int.pem)" > idx-root
: > idx-none

gencrl int-revoked int.pem int.key idx-int-revoked idp_int
gencrl int-empty int.pem int.key idx-int-empty idp_int
gencrl root-revoked root.pem root.key idx-root idp_root
gencrl int-partition int.pem int.key idx-none idp_part
gencrl int-base int.pem int.key idx-int-empty idp_int 20260501000000Z 01
# A real delta CRL: what changed between int-base and int-revoked (-in is the base, -gendelta the newer).
openssl crl -in int-base.pem -gendelta int-revoked.pem -key int.key -out int-delta.pem
openssl crl -in int-delta.pem -outform DER -out int-delta.crl
gencrl bad impostor.pem impostor.key idx-int-revoked plain

# Paths handed to openssl stay relative: on Windows (Git Bash) a native openssl
# cannot open MSYS-style absolute paths.
for f in int-revoked int-empty root-revoked int-partition int-delta bad; do
  openssl crl -in $f.crl -inform DER -noout -text > $f.txt
done
cp root.pem int.pem leaf.pem other.pem impostor.pem ./*.crl ./*.txt "$out/"
echo "wrote fixtures to $out"
