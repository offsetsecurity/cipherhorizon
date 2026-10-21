# PRD-015 · Accuracy on real scans

Status: draft 2026-10-22, from the owner's review of their own database (55 scans, mostly the badssl.com test
hosts, plus google.com, qualys.com and their own sites): "a lot of things don't make sense", "the alignment on many
of them is so bad", "things to fix looks broken", "the menus of TLS should be collapsed rather than expanded".
Reviewed as a cryptographer ([CRYPTO-REVIEW-003](CRYPTO-REVIEW-003-real-scans.md)), as QA and as the PM
([QA-REPORT-014](../program/QA-REPORT-014.md)).

## Why

badssl.com is built so that each host shows one defect; it is the fairest test of whether the report says the
right thing. On the owner's scans it did not, in six ways a cryptographer would catch at once:

1. **The wrong certificate.** On every server whose only suites Go's TLS client will not offer (3des, rc4, rc4-md5,
   null, dh480, dh512 at badssl.com), the only certificate the report held was the server's *no-SNI fallback*. The
   certificate section described a certificate the host never serves. Google's RSA certificate was never seen
   either, so every RSA suite showed "?" for its key exchange and signature.
2. **The wrong diagnosis.** A leaf signed straight by an unknown root (superfish, edellroot, dsdtestprovider,
   preact-cli, webpack-dev-server) was reported as a *missing intermediate*, with the advice to serve one.
3. **A known-compromised root not named.** Superfish, eDellRoot and DSDTestProvider are roots whose private keys
   were published; the report said only "untrusted".
4. **"Good" for revocation that was never checked.** revoked.badssl.com read Revocation: Good. The scan never
   contacts the CA, so the status is unknown.
5. **Advice that is wrong.** A chain ending at DigiCert Global Root CA (sha384, sha512, extended-validation), a
   public root absent from both bundled store snapshots (Mozilla retires website trust for roots past 15 years
   under its root-age policy), was "a private or unknown root: add it to your CA bundle".
6. **DH parameters judged by size alone.** dh-composite (a composite modulus) and dh-small-subgroup (a prime that
   is not a safe prime) passed or were called "a small prime".

And on the screens: Fix first listed every finding with two labels each (severity and urgency), rows and version
heads did not line up, and every TLS version opened by default.

## Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-ACC-1** | **The served certificate is always read.** When crypto/tls cannot complete a handshake (3DES, RC4, NULL, small DH, an RSA certificate a server keeps for RSA-only clients), the chain is read from the raw TLS 1.2-and-earlier flights the suite enumeration receives, where the Certificate message is plaintext. The no-SNI comparison runs after. | A server with only 3DES and RC4 suites has its SNI chain, sourced `raw-tlsv1.2` | `TestCertificateIsReadFromARawFlight` | P0 |
| **REQ-ACC-2** | **DH parameters are tested, not just measured.** The modulus is tested for primality and, when prime, for being a safe prime. A composite modulus is a critical finding (and not also "a small prime"); a prime that is not a safe prime and not a published group is a low one. | ffdhe2048 is a safe prime; 2^127-1 is prime, not safe; a product of two primes is composite | `TestDHPrimality`, `TestEveryRuleFiresAndIsCited` | P0 |
| **REQ-ACC-3** | **The missing issuer is named for what it most likely is.** "Missing intermediate" only when the served path stops at a certificate that names where its issuer can be downloaded (AIA caIssuers, as public CAs' leaves do); otherwise "a root the stores checked do not hold". | A private root's leaf served alone is untrusted, not incomplete | `TestT1TrustMatrix` | P0 |
| **REQ-ACC-4** | **Known-compromised roots are named.** A chain issued under Superfish, eDellRoot or DSDTestProvider is CERT.COMPROMISED-ROOT (critical, clients fail), in place of "untrusted". | | `TestCompromisedRootIsItsOwnFinding` | P0 |
| **REQ-ACC-5** | **Revocation is "unknown" unless a staple vouches for it.** With no stapled, verified, good OCSP response, the revocation area's status is *unknown* (a new section status), with the reason; its checks still count as run. The page says "not contacted: revocation status unknown". | | `TestRevocationIsUnknownWithoutAStaple` | P0 |
| **REQ-ACC-6** | **An untrusted root is described truthfully**: "a root the stores checked do not hold: either a private CA, or a public root since removed from them". | | `TestT1TrustMatrix` | P1 |
| **REQ-ACC-7** | **Fix first is a list of priorities**: the first three rows, each with one chip saying when to act (coloured by severity, the severity in its tooltip); the rest folded under one line that counts them by severity; numbering runs on. | | `script:testing/e2e/visual-phase.mjs#E2E-FIX-1` | P0 |
| **REQ-ACC-8** | **Every TLS version starts folded**, its head saying whether it should be on and how its suites rate (the only version opens by itself). | | `script:testing/e2e/visual-phase.mjs#E2E-VIS-FOLD` | P0 |
| **REQ-ACC-9** | **Things on one line are on one line**: Fix first chips beside their titles, titles in one column; each strength chip centred on its suite row; version heads on one grid; no empty rank column when the client picks the order; the weakest strength prefers a disallowed algorithm at equal bits. Measured in the browser. | | `script:testing/e2e/visual-phase.mjs#E2E-VIS-ALIGN` | P0 |
| **REQ-ACC-10** | **Sign-off**: the cryptographer checks every finding the owner's scans produce against what each badssl.com host demonstrates (CRYPTO-REVIEW-003); QA and the PM walk the screens on the owner's data (QA-REPORT-014). The evaluation is eval/12, so stored scans are re-evaluated on start. | | `report:docs/product/CRYPTO-REVIEW-003-real-scans.md`, `report:docs/program/QA-REPORT-014.md` | P0 |

## Out of scope

- Contacting the CA's OCSP responder or CRL. The URLs come from the certificate, which the target chose; fetching
  them is a request to an address an attacker picks, and stays a separate, opt-in decision.
- Detecting a published private key for a leaf (the preact-cli and webpack-dev-server certificates): it needs a
  list of key fingerprints this product does not carry. Those hosts read "untrusted root", which is true.
- Reports scanned before this version keep the certificate they recorded: scan them again to read the served one.
