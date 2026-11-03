# CRYPTO-REVIEW-004: eMudhra weak CA keys and what CipherHorizon can detect

Date: 2026-10-23 · Status: P0 built on branch `fix/distrusted-keys` (items 1–5; release 0.4.1 not cut). P1–P3 open.

P0 as built, and where it differs from the plan below:
- Refdata refreshed 2026-10-23. Mozilla removed three emSign roots; Chrome still has G3 until v43. Re-run after 27 Oct.
- The distrust list is hand-curated JSON (`internal/refdata/distrust.json`), not a generated `_gen.go`. The P3 importer
  will write to it. The eight eMudhra keys and 16 certificates were checked against the published certificates
  (parsed, re-hashed, private keys recovered by brute force), and a test re-derives each key from its private value.
- The path builder (`pki.Paths`) feeds the trust result only when `x509.Verify` fails or a returned path has a listed key.
  Verify stays the policy check for everything else. This is narrower than D6 (full replacement), on purpose for a patch release.
- Superfish, eDellRoot and DSDTestProvider stay matched by name in `CERT.COMPROMISED-ROOT`. No key hash for them was
  verified, and guessing one would be worse than the name match.
- Host-collected certificates match by certificate fingerprint. Collectors do not record the key hash yet (P2).

P1b (online revocation) as built, same branch, still eval/13 (unreleased):
- **CRL only, no OCSP.** CRLs are mandatory for every public CA, and an OCSP lookup would tell the CA which site is
  being checked. OCSP responders stay uncontacted.
- **Where the code is.** `pki.JudgeCRL` is pure. `internal/revocation` does the guarded fetching and caching.
  `tlsprobe` walks the served path in the revocation stage and records `CertResult.CRL` and `Report.CRLLookups`.
  The `REV.*` rules read those records.
- **Flags.** `--revocation` and `--revocation-private` on `tls scan` and `serve`.
- **Real servers, 2026-10-23.**
  - eMudhra test host: `REV.REVOKED`. G3B is revoked (cACompromise) on emSign Root TLS CA - G3's own CRL, and the
    signature verifies.
  - revoked.badssl.com: the leaf is revoked (keyCompromise). The chain was checked up to ISRG Root X1.
  - www.google.com: not revoked. The first run raised `REV.UNKNOWN` for a served cross-sign of GTS Root R4 whose
    issuer we do not hold. Fixed: the walk now stops at a served copy of a known anchor.
- **Not done.**
  - Per-system anchors are used as CRL issuers only in `serve` (`tls scan` has no `--ca-bundle`).
  - No CRLite or OneCRL feed yet (P3).
  - No UI toggle: the setting is a server flag, shown in Settings.
Trigger: IFF letter of 2026-10-22 on the compromise of eMudhra CA keys.

## 1. The incident in brief

- Eight eMudhra **intermediate CAs** had **ECDSA P-384 private keys that were integers below 256**
  (4, 56, 66, 115, 155, 156, 230, 237). A P-384 key should be a random number near 2^384.
  Anyone can recover such a key by computing 1·G, 2·G, … and comparing with the public key.
  That takes at most 255 point additions.
- Root cause (eMudhra, Bugzilla 2083449 comment 11): a key-ceremony script on 30 Apr 2025 tested a
  "wrap/unwrap" step. That created a second, weak key set in the HSM, and those keys were used by mistake.
  eMudhra says its RSA keys and the Entrust-generated "A / A-1" series are not affected.
- Warning sign missed: in May 2025 the CRLs of these CAs had invalid signatures (Bug 1970728).
- Hierarchy: six TLS CAs under *emSign Root TLS CA - G3*, two code-signing CAs under *emSign Root CS CA - G3*.
  All chain to **emSign ECC Root CA - G3**. All eight were **cross-signed by Sectigo "AAA Certificate Services"**,
  which Microsoft and Apple still trust.
- No leaf certificates under them were ever logged to CT. The danger is **forgery**: anyone can now
  mint a certificate for any name that chains to a still-trusted root. The exposed party is
  **every client (relying party) whose trust store or blocklist is not updated.** Servers are not the exposed party.
- Response: Mozilla OneCRL (17 Oct) and removal of the G3 root (NSS 3.131.1); Chrome CRLSet and root removal
  in Chrome Root Store v43 (around 27 Oct); Apple (19 Oct) and Microsoft Disallowed store (20 Oct);
  **Go 1.27.3 / 1.26.10** hardcode the eight key hashes into `crypto/x509`; certifi, curl, distro bundles updated.

### Indicators (verified)

The key hashes below are SHA-256 of the SubjectPublicKeyInfo. **We reproduced all eight locally** by
building P-384 keys from d = 4…237 (scratch test, 2026-10-23). The key-to-CA mapping is therefore exact.

| d | CA (subject CN) | SPKI SHA-256 | Cert SHA-256 (emSign-issued) |
|---|---|---|---|
| 4 | EM OV TLS CA - G3C | 63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8 | CB6E1516…7C3F |
| 56 | EM EV TLS CA - G3C | 5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0 | 432EC25F…61F3 |
| 66 | EM OV CS CA - G3B | ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6 | 9E39DE28…67B4 |
| 115 | EM EV TLS CA - G3B | e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41 | E7568FE6…3838 |
| 155 | EM OV TLS CA - G3B | 43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b | 98B89662…C25B |
| 156 | EM DV TLS CA - G3B | ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105 | 42C4ACCD…1493 |
| 230 | EM DV TLS CA - G3C | 49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f | 0164D7CE…4D19 |
| 237 | EM OV CS CA - G3C | 92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30 | 4B2460A4…30B1 |

The full certificate fingerprints, serials and the eight Sectigo cross-sign fingerprints are in
Bugzilla 2083449 comments 0 and 2. Match on the **SPKI hash**: one hash covers the emSign certificate,
the Sectigo cross-sign and any re-issue.
emSign ECC Root CA - G3 cert SHA-256: 86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b.

Sources: IFF (internetfreedom.in, 2026-10-22); emudhra.we-have-a-problem.com; Mozilla Security Blog
2026-10-20; Bugzilla 2083449 / 1970728 / 2084101; scotthelme.co.uk; fenko.nz; Cloudflare blog; CERT-In CIAD-2026-0050.

## 2. Would CipherHorizon detect it today?

| Scenario | v0.4.0 (Go 1.27.3) | v0.3.0 and older, or a source build with Go < 1.27.3 / 1.26.10 |
|---|---|---|
| TLS server sends a leaf chaining through one of the eight CAs | **Rejected, but for the wrong stated reason.** Go silently drops the chain. The report says "x509: no valid chains built" (CERT.UNTRUSTED), with no mention of compromise. | **False "trusted".** Our bundled Mozilla and Chrome stores (CCADB, 2026-10-02) still include emSign ECC Root CA - G3 with no constraint. |
| Same, via the Sectigo AAA cross-sign | Not trusted (AAA is not in our Mozilla/Chrome sets). Same unexplained message. | Not trusted, unexplained. |
| One of the eight CAs found in a host cert store, PEM file or CBOM import | **Not detected.** Host certificates are only checked for expiry, size, hash and PQ dates. A P-384 key passes. | Same |
| Host trust store still trusts emSign ECC Root CA - G3, or the host has no block for the eight keys | **Not detected.** We do not read the Windows Disallowed store and have no distrust list. | Same |
| Another CA, server or SSH host key with a tiny EC private key (the general weak-key class) | **Not detected.** The only key check is bit length. | Same |
| Software on a host that embeds an unpatched trust bundle (old Go binary, certifi, Java) | Not detected | Same |

Verified on 2026-10-23: a test chain through a d=4 P-384 intermediate passes `x509.Verify` on Go 1.27.0
and fails on Go 1.27.3 with "no valid chains built". The machine's default Go here is 1.27.0. go.mod pins
`toolchain go1.27.3` (commit da10257, in v0.4.0). A build with `GOTOOLCHAIN=local` would silently lose the block.

**Bottom line:** v0.4.0 is protected by accident (through the Go toolchain), not by design. It cannot explain
the finding, and it cannot detect this class of weakness in general. Our "stores" are **not up to date**:
the bundled root lists predate the incident, the signature DB holds collection recipes only (no keys or CAs),
and the only "compromised" list is three root names matched by CN (Superfish, eDellRoot, DSDTestProvider).

## 3. Cryptographer's assessment: what a scanner can and cannot do

1. **Known-bad lists (exact match).** These are cheap and certain, but only for keys someone has already found.
   Matching on SPKI hash beats matching on certificate fingerprint or CN.
2. **Structural weak-key tests.** These find the *next* eMudhra before anyone publishes a list:
   - **EC small scalar.** Test whether Q = ±k·G for |k| < 2^32 using baby-step giant-step: a table of about
     2^16 x-coordinates per curve, then at most 2^16 giant steps per key. Comparing x-coordinates also covers
     d = n − k. The table should cost single-digit MB and per-key cost should be milliseconds (both unmeasured).
     This would have caught all eight keys with a margin of 2^24.
     Also checks for P-256, P-521 and the SSH ECDSA host-key curves. Ed25519/X25519 clamp and hash the scalar,
     so a small seed does not give a small scalar. For those, only list matching applies.
   - **RSA:** ROCA fingerprint (Infineon); Fermat test for p ≈ q; trial division by small primes;
     **batch GCD across every RSA modulus in the estate** (shared-prime keys). Batch GCD is where an estate
     tool beats a single-host scanner. Plus a Debian-2008 / badkeys-style blocklist, if a licence-clear
     source exists (this was deferred in PRD-004 REQ-TCRT-6 for that reason).
   - **Key reuse:** the same SPKI under different subjects or issuers across the estate.
   - **What no test can show:** whether a properly random-looking key was in fact generated with low entropy
     (for example a seeded PRNG). Those keys look random to any test on the key alone. That is an audit or
     ceremony question, not a scanner question. Report it as a limit and do not imply coverage.
3. **Where the risk sits.** For CA compromises the action is on the **client side**: is this host,
   runtime or appliance still trusting the bad keys? CipherHorizon's host collector is unusual here. It can
   answer "which machines in my estate still accept forged eMudhra certificates?" A TLS server scanner alone cannot.

## 4. Plan

Ordered by value over effort. P0 is this week, while the incident is live.

### Principles (apply to every item)
- **Evaluate, never gate.** CipherHorizon is an evaluator, not a TLS client. A distrusted key, a revoked
  certificate, a compromised root or a weak key is a **finding on a fully evaluated chain**. It must not stop
  path building, hide the anchor, or suppress other findings: protocols, ciphers, key exchange, the other
  certificate checks and CBOM output all still run. When several problems apply, report all of them with
  their own evidence. Today that already holds per rule, but the trust verdict breaks it: Go 1.27.3's
  `x509.Verify` silently drops chains with a listed key, and there is no switch to turn that off.
- **Classes, not incidents.** eMudhra is one entry in a list and one fixture in a test corpus. Every mechanism
  below is generic: any distrusted key, any revoked CA, any weak key, any host that still trusts any of them.
  Rule names and texts describe the class. The incident name, date and sources come from the data entry.
- **Two separate questions per chain:** (1) *cryptographic path*: is there a signature-valid path from the
  leaf to a root in store X? (2) *policy and status*: what do the root programs, distrust lists, revocation
  and key tests say about each certificate on that path? (1) is computed once, without policy filtering.
  (2) is a set of findings layered on top.

### P0: correct, current, and not gated (small)
1. **Refresh refdata** from CCADB now, and again after Chrome Root Store v43 (around 27 Oct). Re-run the eval
   goldens. Note: once a root leaves a store, its chains become "no path to a root" in that store. Item 3
   keeps the reason visible.
2. **Distrust list in refdata** (`distrust_gen.go`), generic schema:
   `{spkiSHA256 | certSHA256, subject, kind: key-compromise | ca-distrust | weak-key | test-key, scope: tls | code | all,
   since, sources[], incident}`. Seed it with the eight eMudhra keys, the Superfish, eDellRoot and
   DSDTestProvider roots (moving those from CN to key matching), and the other entries in Go's
   `distrustedSPKIHashes`. Growing it is a data change, not a code change (see P3).
3. **Own path builder for evaluation** (`pki.BuildPaths`). Walk the served certificates plus the store roots by
   name, AKI/SKI and `CheckSignatureFrom`. Record every complete signature-valid path, with no distrust
   filtering. Then apply validity, EKU, name constraints and root-program constraints as **annotations** on
   each path. Keep `x509.Verify` as a cross-check: if it rejects a path our builder accepts, the report says
   which policy rejected it, never the raw "no valid chains built".
4. **Rule CERT.DISTRUSTED-KEY (Critical).** It fires for any certificate (served chain, host store, file,
   import, trust anchor) whose key or fingerprint is on the list. The finding names the entry's incident,
   date and sources, and the position (leaf, intermediate n, root). It also says whether a path to a trusted
   root exists anyway: "chains to *emSign ECC Root CA - G3* (Mozilla, Chrome snapshot 2026-10-02) through a CA
   whose private key is public". CERT.UNTRUSTED and CERT.PARTIAL-TRUST still fire as they apply. They are no
   longer suppressed by the compromise finding.
5. **Build guard:** a unit test that a d=4 P-384 intermediate yields CERT.DISTRUSTED-KEY **and** a complete
   path in the report, on any Go version. Keep `toolchain go1.27.3` or later anyway (clients built with it are safer).
6. **Patch release 0.4.1** with items 1–5, plus a release note.

### P1: detect the class (medium)
Each P1 test is a finding on the key wherever it appears. A weak key never removes the certificate from
path building or from any other check.

6. **EC small-scalar test** (BSGS, |k| < 2^32) on every EC key we see: served chain, host stores, files,
   imports, SSH host keys, anchors. New rule KEY.EC-SMALL-SCALAR (Critical). When it fires, the finding gives
   the recovered k as proof (k is public by then). Use `filippo.io/nistec` or
   the standard-library equivalent. Add a benchmark, and cache results by SPKI hash.
7. **RSA weak-key tests:** ROCA fingerprint, Fermat (bounded iterations), small-factor trial division.
   Rules KEY.RSA-ROCA, KEY.RSA-CLOSE-PRIMES, KEY.RSA-SMALL-FACTOR.
8. **Estate batch GCD and key reuse** across all stored RSA moduli and SPKIs. Run it as a background job on
   the estate. Rules KEY.RSA-SHARED-PRIME and KEY.REUSED.
9. **Self-test corpus** in `internal/pki/pkitest`: d=4 chains, ROCA-shaped moduli, shared-prime pairs,
   all with positive and negative goldens.

### P1b: online revocation checks (medium; lifts the PRD-004 REQ-TREV-5 deferral)
Why now: eMudhra revoked all eight CAs on its root CRLs on 18 Oct (reason cACompromise), and Sectigo revoked
its cross-signs. A CRL check would have flagged them a day after disclosure, for any key weakness and any
Go version. It also catches a warning sign we missed: in May 2025 these CAs published CRLs with **invalid
signatures** (Bug 1970728). A scanner that checks CRL signatures would have reported that 17 months early.

Design rules (a cryptographer's view):
- **Check each certificate against its *issuer's* revocation data, up the whole chain.** The CRL or OCSP
  for a forged leaf is signed by the compromised key itself, so the attacker controls it. Only the parent's
  CRL for the intermediate (signed by the uncompromised root) can be trusted.
- **CRL first, OCSP second.** CA/B Forum made OCSP optional and CRLs mandatory (SC-063). Let's Encrypt
  has turned OCSP off. Browsers use pushed lists (CRLite, CRLSet, OneCRL) rather than live OCSP.
  OCSP also tells the CA which site is being scanned; a CRL does not.
- **Validate the CRL fully:** signature by the issuer (or an indirect CRL issuer that is allowed to sign
  it), issuer name and AKI match, `thisUpdate`/`nextUpdate` freshness, IDP scope, and delta CRLs when used.
  New findings: REV.REVOKED (Critical, with reason and time), REV.CRL-BAD-SIGNATURE (High),
  REV.CRL-STALE (Medium), REV.UNREACHABLE (shown as *unknown*, never as a pass).
- **Revocation is a status, not a gate.** A revoked certificate stays on the path. The trust verdict, the
  other certificate findings and the rest of the scan are all reported. The finding says which certificate
  is revoked, by whom, when and why (for example cACompromise vs superseded). A cACompromise revocation
  also raises the severity of every certificate below it on the path.
- **Hostile input and SSRF.** CRL and OCSP URLs come from target-supplied certificates, so a server could
  make our scanner fetch internal addresses. Allow `http` only. Block loopback, link-local
  (169.254.0.0/16, including cloud metadata), private and ULA addresses unless the operator allows them.
  Cap body size (e.g. 20 MB), time and redirects. The CRL parser gets bounds and a fuzz target
  (REQ-TNFR-1).
- **Egress is opt-in** ("Online revocation checks", off by default, per PRD-004 D1). Cache by URL until
  `nextUpdate`. Offline estates can import CRL files, and the CI feed (P3) can ship OneCRL and CRLite-derived
  entries as an offline list.
- Apply the same check to CA certificates found in host stores (P2): "this host trusts a revoked CA".

### P2: client-side exposure across the estate (medium; the differentiator)
All driven by the distrust list. Each list entry can carry "fixed in" versions, so a new incident needs no code.

10. **Windows:** read the `Disallowed` store (wincerts currently skips it). Report per host, for every list
    entry, whether the key is blocked and whether its root still sits in Root or AuthRoot.
11. **Linux and macOS:** flag trust-store files that contain any distrusted root or CA, and `ca-certificates`
    packages older than an entry's fixed versions (signature-DB recipes plus a knowledge-base table).
12. **Embedded bundles:** read Go `buildinfo`, and detect certifi, Java cacerts, Node and Python runtimes.
    Compare them against each entry's fixed versions. Report "this binary may still trust <entry>".
13. **Estate view:** "Hosts exposed to a distrusted CA or key", filterable by entry (eMudhra Oct 2026,
    Superfish, …), with a remediation checklist built from the entry.

### P3: keep the stores current (process)
14. **Scheduled CI job** (weekly) that regenerates refdata from CCADB and the CT log list and opens a PR
    when anything changes. Distrust sources the generator imports and diffs: Mozilla OneCRL (public Remote
    Settings JSON), Go's `distrustedSPKIHashes`, Microsoft's public disallowed-certificate CTL, and CCADB
    revocation and incident data. A new entry in any source becomes a PR, so the next incident reaches users
    in a release without anyone hand-writing a rule.
15. Turn the 180-day staleness flag into a **finding** when the bundled store is older than N days
    (proposed: 30). Show the snapshot date next to every trust verdict.
16. Licence check on the badkeys blocklists (owner decision; this unblocks the Debian list deferred in PRD-004).

### Out of scope, stated as limits
- Low-entropy keys that look random (see §3). Ceremony quality is an audit question.
- CCA India (licensed hierarchy) roots are not in Mozilla or Chrome. A "CCA India" store could be added as a
  separate, optional store if Indian customers need it (owner decision).

## 5. Owner decisions
- D1: Ship P0 as **0.4.1** now? (recommended: yes)
- D2: Distrust list sources: hand-curated only, or also auto-import OneCRL? (recommended: both; OneCRL through the CI PR)
- D3: Use badkeys data, subject to its licence? (needs a licence read)
- D4: Add an optional CCA India store?
- D5: Online revocation checks (P1b): off by default with opt-in? (recommended: yes, CRL first)
- D6: Replace `x509.Verify` as the source of the trust verdict with our own path builder, keeping Verify as a
  cross-check (P0 item 3)? (recommended: yes; it is the only way to keep evaluating chains the Go standard
  library refuses)
