# CRYPTO-REVIEW-003 · The owner's real scans, finding by finding (PRD-015)

Date: 2026-10-22. Reviewer role: cryptographer (PRD-015 REQ-ACC-10). Data: a copy of the owner's database
(`dist/cipherhorizon.db`, 55 TLS endpoints, one SSH server), re-evaluated with eval/12, and eight hosts scanned
again with this build (3des, rc4, dh-composite, dh-small-subgroup, superfish, revoked, null at badssl.com, and
www.google.com). badssl.com publishes what each host demonstrates, so each report is checked against a known
answer. The owner's own database was not changed.

## Verdict

**Signed off** after the fixes below. Every badssl.com host now reports the defect it was built to show, under the
right name and severity; no host reports a defect it does not have, with the two limits stated at the end.

## Host by host

| Host | It demonstrates | Before | Now |
|---|---|---|---|
| expired | an expired leaf | CERT.EXPIRED | same: correct |
| wrong.host | a name mismatch | CERT.NAME-MISMATCH | same |
| self-signed | a self-signed leaf | CERT.UNTRUSTED ("self-signed") | same |
| untrusted-root | an unknown root | CERT.UNTRUSTED | same, with "a root the stores checked do not hold" |
| revoked | a revoked certificate | Revocation **Good**, nothing said | Revocation **unknown**: no staple, the CA is not contacted (REQ-ACC-5) |
| incomplete-chain | a missing intermediate | CERT.CHAIN-INCOMPLETE | same: the leaf names its issuer's URL (AIA), so the intermediate is truly missing |
| sha384, sha512, extended-validation, 1000-sans, 10000-sans | (now) an expired leaf under a retired root | EXPIRED, and UNTRUSTED saying "a private or unknown root: add it to your CA bundle" | EXPIRED, and UNTRUSTED saying "either a private CA or a public root since removed" (REQ-ACC-6). DigiCert Global Root CA is absent from both bundled store snapshots. |
| superfish, edellroot, dsdtestprovider | a root whose private key is public | EXPIRED, **CHAIN-INCOMPLETE** (wrong) and UNTRUSTED | **CERT.COMPROMISED-ROOT** (critical) and EXPIRED (REQ-ACC-3, 4) |
| preact-cli, webpack-dev-server | a dev-server certificate with a published key | CHAIN-INCOMPLETE (wrong), UNTRUSTED | UNTRUSTED with "a root the stores checked do not hold" (the published key itself is not detectable: see limits) |
| 3des, rc4, rc4-md5, null, dh480, dh512 | weak suites | correct suite findings, but the **certificate was the no-SNI fallback** | on a new scan, the served `*.badssl.com` certificate, read from the raw TLS 1.2 flight (REQ-ACC-1); checked on 3des, rc4 and null, scanned again |
| dh480, dh512, dh1024 | a small DH prime | KX.DH-SMALL (high, high, medium) | same |
| dh2048 | a 2048-bit group (good) | nothing | nothing |
| dh-composite | a composite modulus | KX.DH-SMALL "a small prime, 2047 bits" (wrong word) | **KX.DH-COMPOSITE** (critical), no "small prime" (REQ-ACC-2) |
| dh-small-subgroup | a prime that is not a safe prime | nothing | **KX.DH-NOT-SAFE-PRIME** (low) |
| static-rsa | RSA key transport only | NO-FS, plus NULL and RC4 | same: the host's `kRSA` cipher string does accept the NULL and RC4 RSA suites |
| null | NULL and anonymous suites | CIPHER.NULL, CIPHER.ANON (critical) | same, now with the served certificate |
| mozilla-modern, -intermediate, -old | Mozilla's three profiles | as expected (old: DH-SMALL, 3DES; modern: HSTS short only) | same |
| no-sct | no CT proof | CT.NO-SCTS (with EXPIRED: the certificate has since expired) | same |
| client, client-cert-missing | a client-certificate request | FEAT.CLIENT-CERT-REQUESTED (info) | same |
| hsts, preloaded-hsts | HSTS | HTTP.HSTS-SHORT where max-age < 1 year | same |
| tls-v1-0, tls-v1-1, tls-v1-2 | one version each | PROTO.NO-TLS12 for 1.0 and 1.1 | same |
| www.google.com | (a large site) | RSA suites with "?" key exchange and signature | the RSA-2048 certificate is now read; TLS 1.3 suites rate *Acceptable* (112-bit authentication for a client offering only RSA signatures), consistent with rating every suite by the weakest key it can be authenticated with |

## Numbers and claims checked

- **Primality.** `math/big.ProbablyPrime(20)`: Miller-Rabin with 20 random bases plus Baillie-PSW, which has no
  known counterexample. A safe prime is p with (p-1)/2 prime; RFC 7919's groups are safe primes, and RFC 5114's
  are not but publish their subgroup order, so a prime matching a published group is not flagged.
- **A composite modulus.** The discrete logarithm modulo a composite reduces to logarithms modulo its factors
  (Pohlig-Hellman over the factorisation), so a 2047-bit composite gives far less than 2047-bit security.
  Critical, and Logjam-labelled: an attacker able to factor or who chose the modulus can read the sessions.
- **Not a safe prime.** Small subgroups exist; a server that reuses its exponent and does not check the peer's
  value leaks it piece by piece (CVE-2016-0701, Lim-Lee). Low: modern servers use fresh exponents.
- **Compromised roots.** Superfish (CVE-2015-2077), eDellRoot and DSDTestProvider (Dell, 2015) were installed with
  their private keys. Matched by the issuer's common name, which is enough here: the chain is untrusted by every
  store either way, and the finding names *why* that matters (any machine that installed the root trusts
  certificates anyone can make).
- **The missing-issuer guess.** Public CAs put an AIA caIssuers URL in every leaf they issue from an intermediate
  (the CA/Browser Forum Baseline Requirements' certificate profiles); a leaf with none was most likely signed by a root directly. On the owner's data
  this separates incomplete-chain (has AIA) from the five rogue roots (none) without error.
- **Revocation.** Without a verified stapled response saying *good*, revocation is unknown to a scanner that does
  not contact the CA. Let's Encrypt no longer runs OCSP at all (2025), so a CRL URL alone is now common.

## Defects found and fixed in this branch

1. The no-SNI fallback certificate stood in for the served one on servers Go's client cannot reach (scanner).
2. Google's RSA certificate was never read (scanner): every RSA suite had unknown parts.
3. Rogue-root leaves were "missing an intermediate" (evaluation).
4. Compromised roots were not named (evaluation).
5. Revocation read "good" with no evidence (evaluation, a new section status `unknown`).
6. The untrusted-root advice was wrong for public roots since removed (wording).
7. A composite DH modulus passed as "a small prime"; a non-safe prime was not seen (scanner and evaluation).
8. The weakest-strength figure chose RSA-2048 over 3DES at equal bits; at equal bits a disallowed algorithm is
   now the weaker (screen).

## Limits, stated on the page or in Help

- The CA's OCSP responder and CRL are not contacted (PRD-015, out of scope); revocation says *unknown*.
- A leaf whose private key was published with a tool (preact-cli, webpack-dev-server) is not recognised as such;
  it reads *untrusted root*, which is true.
- Scans made before this version keep the certificate they recorded; scanning again reads the served one.

## Sign-off

Signed off for PRD-015 REQ-ACC-10, cryptography.
