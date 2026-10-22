# Methodology: readiness, TLS hygiene and evidence

What the UI and the API report, and exactly how each number is produced. The code is in `internal/eval`
(`readiness.go`, `hygiene.go`, `rules.go`, `citations.go`); this page is the reader's version. Version of the rules:
`eval/2` (shown on every result).

## Evidence tiers

Every fact and finding says how it is known:

| Tier | Meaning |
|---|---|
| `observed` | A server reply demonstrated it (a ServerHello, an alert, a certificate). |
| `inferred` | A consequence of what was observed, not tested directly (for example "POODLE-class" because SSLv3 with CBC suites is accepted). |
| `registry` | Stated by an authoritative registry (the IANA cipher-suite and supported-groups registries, retrieved 2026-09-21). |
| `not-measured` | This product does not measure it. It says so instead of implying it is fine. |

No rule fires without at least one citation; a test (`TestEveryRuleFiresAndIsCited`,
`TestEveryReadinessClaimIsCited`) enforces it.

## PQC readiness (L0 to L4)

**This scale is the project's own. It is not a standard.** Each fact behind a level is cited separately: the
IANA supported-groups registry and RFC 10024 (hybrid key agreement for TLS 1.3), FIPS 203/204 (ML-KEM, ML-DSA),
NIST IR 8547 (draft), and the CISA/NSA/NIST quantum-readiness factsheet for harvest-now-decrypt-later (HNDL).

The levels mean the same thing for every protocol: L1 exposed, L3 protected by a hybrid key exchange, L4
post-quantum authenticated. Each protocol states its own rules. The TLS rules are below; the SSH rules are in
[SSH](#ssh).

| Level | Rule (TLS) | HNDL-exposed |
|---|---|---|
| **?** Undetermined | The scan could not establish whether TLS 1.3 is supported (probes were inconclusive). | no |
| **L0** Not ready | TLS 1.3 is not supported. Post-quantum key exchange in TLS exists only as TLS 1.3 groups. | yes |
| **L1** Exposed | TLS 1.3 works, and no post-quantum group is accepted. | yes |
| **L2** Hybrid available | A standardised hybrid group is accepted, but a current client does not end up using it. | yes |
| **L3** Hybrid negotiated | A current client (Go `crypto/tls`, which offers `X25519MLKEM768` first) negotiates a standardised hybrid group; or the server ranks a hybrid group first. | no |
| **L4** PQ-authenticated | L3, plus post-quantum authentication: a presented ML-DSA / SLH-DSA certificate, or an ML-DSA signature scheme the signature stage proved accepted (control refused). The authentication dimension says which. | no |

Notes that matter when reading a result:

- **Obsolete draft groups do not count.** The pre-standard Kyber code points (`0x6399`, `0x639A`) are reported as
  "obsolete" and never raise the level.
- **Only key exchange protects recorded traffic.** Certificates are about future forgery, not about a recording
  made today, so a classical certificate does not stop an endpoint reaching L3; it is shown as a separate
  dimension, and only post-quantum authentication (a presented ML-DSA certificate, or one the signature stage
  proved the server holds) lifts L3 to L4.
- The overview shows three dimensions (key establishment, authentication, symmetric strength) each with its own
  evidence tier and sources, and an ordered list of next steps.

## TLS hygiene (0 to 100, in five bands)

**This score is the project's own. It is not a standard, and it is not another scanner's rating.** It is deliberately
simple, and it is worked out from nothing but the cited findings on the same result, so every point taken off can be
traced to a finding and every finding carries its sources.

1. Start at **100**.
2. Take off points for each finding, once per distinct problem (two certificates with the same fault are one
   problem), at the finding's worst severity:

   | Severity | Points |
   |---|---|
   | critical | 40 |
   | high | 20 |
   | medium | 10 |
   | low | 4 |
   | info | 0 |

3. Apply a ceiling so a serious problem cannot be averaged away: while any **critical** finding is present the score is
   at most **29**; while any **high** finding is present it is at most **74**.
4. Name the band:

   | Band | Score |
   |---|---|
   | **Excellent** | 90 to 100 |
   | **Good** | 75 to 89 |
   | **Fair** | 55 to 74 |
   | **Poor** | 30 to 54 |
   | **Failing** | 0 to 29 |
   | **Not rated** | no protocol version answered, so there is nothing to rate |

   Until PRD-011 the bands were Strong, Sound, Fair, Weak and Broken. They were renamed because *Strong* and *Weak*
   are suite-strength words, so one word meant two things on the same page (UX-REVIEW-010 U-1). Stored scans are
   migrated, and an evaluation stored with an old name is read as the new one.

**Post-quantum findings are never counted** (category `pqc`). Readiness answers that question, so a well-configured
endpoint that has not yet adopted post-quantum key exchange scores Excellent on hygiene and L1 on readiness, and it is
not marked down twice.

The result lists each deduction (rule ID, title, severity, points), any ceiling that changed the outcome, and what is
**not measured**: live revocation status (the staple is read; the CA is not asked), and active exploit probes
(Heartbleed, ROBOT, CCS injection). HTTP Strict Transport Security is measured by default (the HTTP stage sends one
`GET /`; `--http-checks=false` turns it off, and the HTTP section then says *Not checked* and why). Weaknesses
inferable from what a server offers (POODLE, Sweet32, FREAK, Logjam, CRIME, BEAST, RC4) appear as `inferred`
findings and are scored like any other; an attack name is a label on its finding, so it never counts twice.

The weights are a judgement call made for this project. If your policy weighs things differently, the findings
underneath are unchanged and are the primary output; the score is a summary of them.

`CERT.UNTRUSTED` fires only when **no** bundled root store (Mozilla, Chrome) and **no** private anchor validates the
chain. For internal endpoints, add the private CA to the system's CA bundle (or the server-wide `--ca-bundle`): the
result is re-evaluated at once and reads "trusted by your CA bundle". Private chains are exempt from the public
lifetime limit and the CT requirement. The readiness level is unaffected by trust.

### Rules and changes in eval/13 (CRYPTO-REVIEW-004)

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `CERT.DISTRUSTED-KEY` | critical (high for a CA root programs blocked without a key compromise) | a certificate on the served chain, or a root a path reaches, has a key or fingerprint on the bundled distrust list; also raised on certificates found on hosts, in files and in imports | CA/B Forum BR §4.9.1.2, RFC 5280, and the incident's own sources |

- **A distrusted key is a finding, not a gate.** The chain is still validated and every other rule still runs. Each
  store's result keeps the signature-valid path through the listed key, names the listed certificate and its
  position, and says why the store does not trust it ("the path goes through "EM OV TLS CA - G3C" whose private key
  is public …"). `CERT.UNTRUSTED` and `CERT.PARTIAL-TRUST` fire as usual alongside it.
- **Independent of the Go version.** Go 1.27.3 and later drop paths through a few hardcoded keys inside
  `crypto/x509` without saying why. When that happens the evaluation builds the paths itself (names chain, each
  signature verifies, served certificates as the only intermediates) and reports the listed key on them. A build
  with an older Go gives the same result.
- **The list** is matched by the SHA-256 of the SubjectPublicKeyInfo, which covers every certificate for the key
  (cross-signs, reissues), and by certificate SHA-256 for certificates known only by fingerprint (host collectors).
  First entry: the eight eMudhra intermediate CAs of October 2026, whose P-384 private keys are below 256.

### Rules and changes in eval/12 (PRD-015)

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `KX.DH-COMPOSITE` | critical | the DHE modulus fails a primality test (Miller-Rabin with 20 bases plus Baillie-PSW); `KX.DH-SMALL` is then not raised | RFC 7919, NIST SP 800-56A Rev. 3 |
| `KX.DH-NOT-SAFE-PRIME` | low | the DHE prime is not a safe prime ((p-1)/2 not prime) and is not a published group | RFC 7919, CVE-2016-0701 |
| `CERT.COMPROMISED-ROOT` | critical | the chain is issued under Superfish, eDellRoot or DSDTestProvider, roots installed with their private keys; `CERT.UNTRUSTED` is then not raised | CVE-2015-2077, RFC 5280 |

- **The certificate a server serves is always read.** When Go's TLS client cannot complete a handshake (3DES, RC4,
  NULL or small-DH suites only; an RSA certificate a server keeps for RSA-only clients), the chain is read from the
  plaintext Certificate message of the scanner's own TLS 1.2-and-earlier handshakes (source `raw-tlsv1.2`).
- **A missing issuer** is called a missing intermediate only when the served path stops at a certificate that names
  where its issuer can be downloaded (AIA caIssuers); otherwise it is a root the stores checked do not hold: a
  private CA, or a public root since removed.
- **Revocation** is *good* only when a verified stapled OCSP response says so. Otherwise its status is *unknown*: the
  scan does not contact the CA's OCSP responder or CRL. The revocation checks still count as run.

### Rules added in eval/3 (PRD-004)

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `CERT.CHAIN-INCOMPLETE` | high | only the leaf is served and its issuer is in no store | RFC 8446 §4.4.2, RFC 5246 §7.4.2 |
| `CERT.CHAIN-ORDER` | medium (low if TLS 1.3) | a certificate is not followed by its issuer | RFC 5246 §7.4.2, RFC 8446 §4.4.2 |
| `CERT.CHAIN-EXTRA` | info | a root, duplicate or unrelated certificate is sent | RFC 8446 §4.4.2 |
| `CERT.INTERMEDIATE-EXPIRES` | medium | a served CA expires before the leaf or inside its warning window | RFC 5280 |
| `CERT.LIFETIME` | medium | public, and validity exceeds the limit on its issue date | CA/B Forum BR §6.3.2 (SC-081v3) |
| `CERT.NO-SERVERAUTH` | high | the leaf has an EKU without serverAuth | RFC 5280 §4.2.1.12 |
| `CERT.CLIENTAUTH-EKU` | info | public, and a chain certificate also allows clientAuth | Chrome Root Program Policy |
| `CERT.PARTIAL-TRUST` | medium | some bundled stores trust it and others do not (constraints named) | RFC 5280 §6 |
| `CERT.WEAK-EXPONENT` | low | RSA public exponent below 65537 | CA/B Forum BR §6.1.6 |
| `CERT.NO-SNI-DIFFERENT` | info | without SNI the server presents another certificate (described, never judged as the endpoint's certificate: many sites serve a placeholder there on purpose) | RFC 6066 §3 |
| `OCSP.REVOKED` | critical | the valid stapled response says revoked | RFC 6960 |
| `OCSP.MISMATCH` | high | the staple is for another certificate, unusable, or its signature fails | RFC 6960 §3.2 |
| `OCSP.STALE` | medium | the staple's nextUpdate has passed | RFC 6960 §4.2.2.1 |
| `OCSP.UNKNOWN` | medium | the staple says unknown | RFC 6960 |
| `OCSP.MUST-STAPLE-MISSING` | high | a Must-Staple certificate is served without a staple | RFC 7633 |
| `OCSP.NO-STAPLE` | low | the certificate names an OCSP URL and nothing is stapled (CRL-only raises nothing) | RFC 6066 §8 |
| `CT.NO-SCTS` | medium | public, and no SCT from any of the three sources | RFC 6962, browser CT policies |
| `KX.DH-COMMON-PRIME` | medium | the DHE prime is an RFC-published group of ≤ 1024 bits | Logjam (CVE-2015-4000), RFC 7919 |
| `HTTP.HSTS-DISABLED` / `-SHORT` / `-INVALID` / `-NO-SUBDOMAINS` | medium / low / medium / info | max-age 0 / under one year / syntax or duplicate header / no includeSubDomains | RFC 6797; HSTS preload requirements |
| `CIPHER.CBC` | info | CBC suites in TLS 1.2 or earlier (label LUCKY13) | RFC 9325 §4.2 |
| `VULN.DROWN-SHARED-KEY` | high | the leaf's key is served on an SSLv2 endpoint elsewhere in the estate | CVE-2016-0800 |

`CERT.EXPIRING` now fires at min(30 days, a third of the lifetime) as medium and min(7 days, a tenth) as high, and
names the threshold: a 47-day certificate with 20 days left raises nothing.

### Sections and *Fix first*

Each finding belongs to one section of the endpoint page. A section's status is, first, its scan stage (skipped →
*Not checked*, inconclusive → *Inconclusive*, a report from before `tls-report/2` → *Not collected*), and otherwise
its worst finding: critical or high → *Problem*, medium or low → *Needs attention*, none or info → *Good*. *Fix first*
takes every finding except info, orders it by severity, then by whether it stops clients connecting (expired,
untrusted, name mismatch, missing intermediate, no serverAuth, Must-Staple missing, revoked), then by section order,
and shows the first three distinct rules.

## Classical strength (eval/9, PRD-010; classes and the hash part eval/10, PRD-011)

Every algorithm the product lists has a classical security strength in bits, computed with NIST's own methods.
Where no number applies, it says why instead: a cited break, or no rating. The derivation, with NIST's tables
reproduced to the decimal, is in [ENH-001 §5](product/ENH-001-cipher-strength.md#5-how-the-strength-is-calculated-nists-method-reproduced).
The code is `internal/algo/strength.go` and `strength_of.go`.

| What | Method | Source |
|---|---|---|
| RSA modulus, finite-field DH prime | General Number Field Sieve: E(L) = (1.923·∛(L·ln 2)·∛((ln(L·ln 2))²) − 4.69)/ln 2, rounded to the nearest multiple of eight, at most 256. 1024 → 80, 2048 → 112, 3072 → 128, 4096 → 152, 8192 → 200 | FIPS 140-3 IG D.B; SP 800-56B Rev. 2 Appendix D, Table 4; SP 800-56A Rev. 3, Table 26 |
| Elliptic curves | Half the bit length of the base point's order, taken to the nearest strength SP 800-186 assigns (80, 112, 128, 192, 224, 256): P-256 and Curve25519 → 128, P-384 → 192, Curve448 → 224, P-521 → 256 | SP 800-186 §3 and Table 1 |
| Symmetric ciphers | AES-k → k; 3DES (3TDEA) → 112, disallowed for encryption after 2023; DES, RC4, RC2 → broken. Ciphers NIST does not rate (ChaCha20, Camellia, ARIA, SEED, …) get the bound an exhaustive key search sets, labelled as such | SP 800-57 Part 1 Rev. 5 Table 2; SP 800-131A Rev. 2; RFC 7465 |
| Hashes and MACs | Signatures, where collision resistance is needed: SHA-256 → 128, SHA-384 → 192, SHA-512 → 256; SHA-1 and MD5 → broken. HMAC, a KDF or a PRF (the TLS PRF, HKDF): SHA-1 → 128, SHA-256 and longer → 256. A truncated MAC (hmac-sha1-96, umac-64) is bounded by its tag: the smaller of the two (eval/11) | SP 800-57 Part 1 Table 3; SP 800-107 Rev. 1 §5.3.5 |
| Signature algorithms | The weaker of the hash (collision strength) and the signer's key, in every spelling (ECDSA-SHA256, SHA256-RSA, sha256WithRSAEncryption, SHA256withRSA). Without the key's size, the hash, and the basis says the key was not given | SP 800-57 Part 1 Tables 2 and 3 |
| Post-quantum algorithms | The classical equivalent of their NIST category: ML-KEM-512/768/1024 → 128/192/256, ML-DSA-44/65/87 → 128/192/256, SLH-DSA by its level | FIPS 203, 204, 205 |
| Hybrids | Secure while either part is, so their stronger part: X25519MLKEM768 → 192 | RFC 10024, RFC 10042 |

**A TLS cipher suite is as strong as its weakest part.** Its parts are the bulk cipher; the key exchange (the
weakest group the server accepts for that version, the DH prime it sent, or, for RSA key transport, the certificate
key); the authentication (the weakest end-entity key the server presented that the suite can use); for a non-AEAD
suite, the MAC; and the hash that derives its keys: HKDF's in TLS 1.3, the PRF's in TLS 1.2 (SHA-256 unless the suite
names SHA-384, RFC 5246 §5), the MD5 and SHA-1 pair in TLS 1.0 and 1.1 (secure while either is, RFC 2246 §5, so
128). The hash part is rated in that use; with NIST's numbers it never lowers a suite today, but it counts like any
other part (PRD-011 OD-1), so a later change to the numbers needs no new rule.

| Word | When |
|---|---|
| **Insecure** | a part is broken (NULL, export, RC4, single DES, anonymous), or fewer than 80 bits |
| **Weak** | 80 to 111 bits, or a 64-bit block cipher (Sweet32; RFC 9325 §4.2), or no forward secrecy (RFC 9325 §4.1) |
| **Acceptable** | at least 112 bits, but below 128 or not AEAD (RFC 9325 §4.2 prefers AEAD) |
| **Strong** | at least 128 bits in every part, AEAD, forward secrecy |

An RSA-2048 certificate (112 bits) makes every suite it authenticates *Acceptable*: the honest reading of SP 800-57,
and the owner's decision OD-1. Each suite states its weakest part and the reason for its word. The words are this
product's own; the numbers are NIST's.

### Classes (PRD-011)

Every algorithm belongs to one class, from its CycloneDX primitive, and has a role within it:

| Class | Primitives | Roles |
|---|---|---|
| **Asymmetric** | `pke`, `signature`, `key-agree`, `kem`, `combiner` (hybrids) | key exchange, signature |
| **Symmetric** | `ae`, `block-cipher`, `stream-cipher`, `mac` | cipher, MAC |
| **Hash** | `hash` | hash (HKDF), hash (PRF), hash (signature) |

A TLS evaluation lists every algorithm the endpoint uses (`algorithms` in the API): its class, role, strength and
post-quantum status, the suites or certificates that use it, and the weakest of each class. A hash is listed once per
use, because its strength depends on the use: SHA-256 deriving keys is 256 bits, signing it is 128. The report's
Configuration ends with this list (*Every algorithm, by class*: a lane per class, a bits bar per algorithm, the weakest
ringed); the PDF, `tls scan --details` and the Inventory's *Class* filter show the same classes.

### One certificate, decoded (PRD-012)

Every certificate in a report's certificate chain and the CBOM tab opens the certificate's page,
`#/certificates/{sha256}`. The page is decoded from the DER the scan kept (`GET /api/v1/certificates/{sha256}/x509`), so
an older scan gains it without a rescan. In order, it shows: the chain it was served in, its validity (days
left on a lifetime bar), the public key and the issuer's signature as bits bars (the signature is the weaker of its hash
and the issuer's key) with their post-quantum status, the names it is valid for and what it may be used for (an
elliptic-curve key that claims key encipherment is marked, RFC 8813), every extension with its criticality and decoded
value (one this program does not decode is shown as OID and hex), the identifiers to copy (SHA-256, the SPKI
fingerprint, the serial, and SHA-1 as an identifier only) and the PEM, folded, to copy or download. A certificate known only from a machine inventory or an
imported CBOM keeps no DER; its page shows the fields that source gave and says so. Every value comes from the
certificate and is rendered as text.

## SSH

SSH servers share the readiness scale and the findings model. They are **not scored**: an SSH server is judged against
an **SSH baseline** ([ssh-scanning.md](ssh-scanning.md#the-ssh-baseline)), and the report says whether it meets it
and which `sshd_config` lines would make it. No list, total or sort ever adds an SSH result to a TLS hygiene score.

### Readiness, SSH rules

| Level | Rule (SSH) | HNDL-exposed |
|---|---|---|
| **?** Undetermined | The server's key exchange list was not read. | no |
| **L0** Not ready | The server speaks only SSH-1. | yes |
| **L1** Exposed | No post-quantum hybrid key exchange is offered. | yes |
| **L2** Hybrid available | A hybrid is offered, but a current client (OpenSSH 10.6's defaults, RFC 4253 §7.1) does not end up using it. | yes |
| **L3** Hybrid negotiated | A current client negotiates `mlkem768x25519-sha256` (RFC 10042) or `sntrup761x25519-sha512` (RFC 9941; noted Low as not FIPS 203). | no |
| **L4** PQ-authenticated | L3, plus a post-quantum host key: `ssh-mldsa44-ed25519`, `ssh-mldsa87-p384` (draft-miller-sshm-composite-sigs) or `ssh-mldsa-44/65/87` (draft-sfluhrer-ssh-mldsa). | no |

### SSH checks

| ID | Finding | Severity | Source |
|---|---|---|---|
| `SSH.PROTOCOL-1` | SSH protocol version 1 is accepted | Critical | CVE-2001-0144; OpenSSH 7.4 |
| `SSH.KEX-WEAK-GROUP` | A key exchange with a group or key under 2048 bits | High | RFC 9142; Logjam |
| `SSH.KEX-SHA1` | A key exchange hashed with SHA-1 | Low | RFC 9142; SP 800-131A |
| `SSH.HOSTKEY-DSA` | A DSA host key | High | FIPS 186-5; OpenSSH 10.0 |
| `SSH.HOSTKEY-RSA-SHA1` | `ssh-rsa` (SHA-1) signatures | Medium | RFC 8332; OpenSSH 8.8; SP 800-131A |
| `SSH.HOSTKEY-RSA-SMALL` | An RSA host key under 2048 bits (High); under 3072 (Low) | High | SP 800-131A; SP 800-57 |
| `SSH.HOSTKEY-BAD-SIGNATURE` | A host key signature did not verify | Medium | RFC 4253 |
| `SSH.CIPHER-NONE` | The `none` cipher | Critical | RFC 4253 |
| `SSH.CIPHER-RC4` | RC4 (arcfour) | High | RFC 8758 |
| `SSH.CIPHER-DES` | Single DES | High | SP 800-131A |
| `SSH.CIPHER-64BIT-BLOCK` | 64-bit block ciphers (3DES, Blowfish, CAST) | Medium | Sweet32; SP 800-131A |
| `SSH.CIPHER-CBC` | CBC modes | Low | CVE-2008-5161 |
| `SSH.MAC-NONE` | The `none` MAC | Critical | RFC 4253 |
| `SSH.MAC-WEAK` | MD5, truncated or 64-bit-tag MACs (a 64-bit UMAC alone is Low) | Medium | RFC 6151; RFC 6668 |
| `SSH.MAC-SHA1` | HMAC-SHA-1 | Info | RFC 6668; SP 800-131A |
| `SSH.MAC-NOT-ETM` | MACs over the plaintext (not encrypt-then-MAC) | Info | CVE-2008-5161; RFC 4253 |
| `SSH.COMPRESSION-PREAUTH` | Compression before authentication | Info | OpenSSH 7.4 |
| `SSH.TERRAPIN` | ChaCha20-Poly1305, or CBC with an ETM MAC, without strict key exchange | Medium (inferred) | CVE-2023-48795 |
| `SSH.PQ-NOT-FIPS` | The only hybrid is sntrup761, not FIPS 203 | Low | RFC 9941; FIPS 203 |
| `PQC.HNDL-EXPOSED`, `PQC.HYBRID-NOT-NEGOTIATED`, `PQC.CLASSICAL-AUTH` | Shared with TLS | as TLS | as TLS |

The baseline and the checks agree on what is wrong; they answer different questions. The checks say how bad each
problem is. The baseline says whether the server, as a whole, is configured as it should be.

## What a scan sends

A few dozen to a few hundred short TLS handshakes per endpoint (a ClientHello, a read of the server's reply,
close). No application data, no exploit traffic. Concurrency, connection budget and timeouts are bounded
(`--concurrency`, `--timeout`; hard cap of 2000 connections per scan, after which the result is flagged
incomplete). See [tls-scanning.md](tls-scanning.md) for the probe design and known limits. An SSH scan makes at most 24
connections and never logs in: [ssh-scanning.md](ssh-scanning.md#what-is-sent).

## Prioritisation: which systems to work on first

`GET /api/v1/estate` ranks systems by four rules applied **in order** (`internal/eval/priority.go`, version `priority/1`; the API returns the rules beside the ranking). There is **no composite score**: each rule decides between two systems only if every earlier rule tied, so any position can be explained in one sentence, and every row lists the facts behind it.

| # | Rule | Reads |
|---|---|---|
| R1 | **Harvest now, decrypt later.** A system with a TLS service whose key exchange a current client negotiates without post-quantum protection ranks first. Among those, systems whose data must stay confidential **past 2030** (the year NIST IR 8547 plans to deprecate classical public-key algorithms) rank above those where the lifetime is unknown or shorter; a longer lifetime ranks higher. No scanned service means exposure is *not known*, which is not the same as safe, and the row says so. | scan readiness (observed); data lifetime (entered) |
| R2 | **Exposure, then criticality.** Internet-facing before internal before restricted; high before moderate before low (the FIPS 199 vocabulary). | entered by a person |
| R3 | **Defects.** The worst severity among the system's current certificate findings (expired, expiring, not yet valid, weak key, broken signature hash, a quantum-vulnerable key outliving 2030 or 2035) and its scans' critical and high findings; then how many. | observed |
| R4 | **How well it is known.** Systems seen by this product's own scanner or collector before systems known only from imported documents; then name. | source classes |

Citations: CISA/NSA/NIST on harvest-now-decrypt-later, NIST IR 8547, RFC 5280, the CA/Browser Forum baseline requirements, NIST SP 800-57. The dates are those documents' dates, used as stated; this product does not predict when a quantum computer will exist.

A system for which nobody has entered exposure, criticality or data lifetime is still ranked, and its row says **"based on evidence only"** and lists what would change its position. Imported evidence ranks a system but is labelled unverified: treat such a position as a lead.
