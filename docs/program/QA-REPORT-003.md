# QA report 003 — TLS scanner T1: PKI depth and the sectioned endpoint page

Executes [QA-PLAN-004](../product/QA-PLAN-004-tls-t1.md) against [PRD-004](../product/PRD-004-tls-scanner-t1-pki-depth.md)
as built per [ENG-HANDOFF-003](../product/ENG-HANDOFF-003-tls-t1.md). Run on 2026-10-02, Windows 11 (Go, Edge headless,
OpenSSL 3.5.7), with the fuzz campaigns on Linux (WSL Ubuntu). Requirement status lives in the [RTM](RTM.md).

## 1. Verdict

**T1 meets its exit criteria, with four P1 items deferred and named** (§6). Every P0 requirement is `done` in the RTM
with a test, script, oracle or this report as evidence. All seven success measures are met (§3). The mutation table
is 12 of 12. Nothing is committed; the owner reviews and commits.

## 2. Automated results

| Suite | Result |
|---|---|
| `go test ./...` | all packages pass (34 with tests) |
| `go vet ./...`, `golangci-lint run ./...` | clean |
| Browser journey (`testing/e2e/journey.mjs`, incl. the new `t1-phase.mjs`) | **126 / 126** pass, fresh database, demo targets |
| `testing/e2e/security.sh` | **69 / 69** pass (adds the T1 routes, key-block refusal on the API and on `--ca-bundle`, the 64 KiB limit, a hostile path parameter) |
| OpenSSL trust oracle (`testing/pki/oracle.sh`) | **15 / 15** fixtures agree |
| OCSP decoder vs OpenSSL (`TestOCSPAgainstOpenSSL`) | 5 OpenSSL-made responses, every decoded field equal to `openssl ocsp -resp_text` |
| DH primes vs OpenSSL (`TestDHPrimesMatchOpenSSL`) | 14 of 16 fingerprints equal to OpenSSL's built-in groups (OpenSSL has no Oakley 1 or 2) |
| Mutation checks (`testing/pki/mutations.py`) | **12 / 12** caught |

### Mutation table

| Guard | Mutation | Caught by |
|---|---|---|
| Missing intermediate | treat an AIA-reachable issuer as present | TestT1ChainMatrix |
| Distrust-after | ignore the Mozilla constraint | TestT1TrustMatrix |
| sct_not_after | ignore the Chrome constraint | TestValidate |
| OCSP for this certificate | skip the serial/issuer-hash match | TestT1RevocationMatrix |
| OCSP signature | skip the check | TestT1RevocationMatrix |
| Must-Staple | drop the rule | TestT1RevocationMatrix |
| Lifetime public-only | apply to private chains | TestT1TrustMatrix |
| Expiry scaling | revert to fixed 30/7 days | TestT1ChainMatrix |
| Anchor upload | accept key blocks | TestPrivateCATrustAnchors |
| Target-only traffic | add a lookup of another host | TestTargetOnlyTraffic |
| Parser bounds | remove an SCT length check | TestSCTList |
| Labels not double-counted | make each label its own finding | TestLabelsDoNotChangeHygiene |

### Fuzz campaigns {#fuzz}

Each target ran for 3 minutes on Linux from a test binary cross-compiled on Windows (`go test -c -fuzz`, run under
WSL), seeded with the committed fixtures:

| Target | Executions | Crashes / hangs |
|---|---|---|
| `FuzzParseOCSP` | 10,529,300 | 0 |
| `FuzzParseSCTList` | 10,341,059 | 0 |
| `FuzzServedChain` | 9,590,464 | 0 |
| `FuzzParseHSTS` | 6,436,015 | 0 |

On Windows the Go fuzz engine stalls (0 execs/s) on targets that call `encoding/asn1`, reproduced with a three-line
target that only calls `asn1.Unmarshal`; the decoder itself is fast on every saved input. CI's Linux fuzz job is
unaffected. SCT, chain and HSTS fuzzing also run on Windows.

## 3. Success measures

| Measure | Target | Result |
|---|---|---|
| T1-M1 fixture matrix detected | 100 %; 0 findings on clean | Every fixture of QA-PLAN-004 §3 asserted in `TestT1ChainMatrix`, `TestT1TrustMatrix`, `TestT1RevocationMatrix`, `TestT1HTTPKeyExchangeAndVulnerabilities`; the clean fixture raises no T1 finding |
| T1-M2 agreement with OpenSSL `verify` | 0 disagreements | 15 / 15 (clean, missing intermediate, wrong order, root included, duplicate, unrelated, expired leaf / intermediate, not yet valid, clientAuth only, no EKU, name constraint ok / violated, self-signed, wrong root) |
| T1-M3 parsers under fuzzing, fields agree with OpenSSL | ≥ 1 M each, 0 crashes | 6.4–10.5 M each, 0; OCSP fields equal on all fixtures |
| T1-M4 purpose line and status word in every section | 100 % | journey T1-E2E.6, T1-E2E.7 |
| T1-M5 Estate → cause | ≤ 2 clicks | 2 (system row → endpoint; *Fix first* names the missing intermediate) — journey T1-M5 |
| T1-M6 extra connections vs 0.2.0 | ≤ 5 | see §4 |
| T1-M7 legacy reports render | 100 % | see §4 |

## 4. Non-functional requirements

### Connection budget {#budget}

Standard scans by the 0.2.0 binary (built from commit `c702e06`) and this build, same demo targets, same flags:

| Target | 0.2.0 | T1 | Δ |
|---|---|---|---|
| modern-hybrid (address) | 38 | 39 | +1 (HTTP stage, now on by default) |
| classical TLS 1.3 | 21 | 22 | +1 |
| legacy TLS 1.2 | 31 | 32 | +1 |
| terrible SSLv3 | 19 | 19 | 0 (no full handshake, so no HTTP request) |
| private CA | 38 | 39 | +1 |
| `localhost:9440` (named, SNI) | 38 | 40 | +2 (adds the no-SNI handshake) |

### Legacy reports and the upgrade path {#legacy}

- The four stored `tls-report/1` samples (`artifacts/samples`) evaluate under `eval/3`, are marked legacy, and show
  Revocation as *Not collected* (`TestLegacyReportsEvaluate`).
- A database written by the 0.2.0 server (two scans, `eval/2`) was opened by this build: migration 7 ran, the stored
  evaluation was kept, and the endpoint page showed the previous layout with *Evaluated by an earlier version* and a
  **Re-evaluate** button. One click produced the sectioned report from the stored report, with Revocation *Not
  collected* and the reason; the stored report was not rewritten (also asserted in `TestPrivateCATrustAnchors`).

### Export {#export}

*Export report → PDF* prints the sectioned page (the index and *How we tested* are hidden in print); the JSON exports
carry the evaluation, which now includes the sections, *Fix first*, the PKI views and the attack list.

### Dependencies {#dependencies}

`go.mod` and `go.sum` are unchanged: OCSP, SCT and HSTS are decoded with the standard library and our own code.

### Safety and hostile input

- A scan contacts only the target: `TestTargetOnlyTraffic` records every lookup and dial, with an OCSP URL, an AIA URL,
  a CRL URL and a 301 to another host in play.
- Hostile certificate subject, organisation, SAN, OCSP URL and HSTS header (the `hostile-pki` demo target) render as
  text in every new section (journey T1-E2E.13); `TestNoInnerHTMLOrEval` still holds for the new modules.
- Phone width (390 px): no horizontal page scroll; the section index becomes a scrolling chip row. Dark mode uses the
  existing tokens throughout.

## 5. Defects found and fixed in this pass

1. **A correctly served private chain was reported as "missing intermediate"** (found by looking at the private-CA demo
   target). When the served path already ends at a CA certificate, the unknown issuer is now reported as an unknown
   (often private) root under `CERT.UNTRUSTED`, with the advice to add it to the CA bundle; `CERT.CHAIN-INCOMPLETE` is
   kept for a leaf served alone. Recorded as a deviation in ENG-HANDOFF-003 §6.
2. A non-HTTP service made the HTTP section *Inconclusive*; it is now *Not checked — not applicable* (REQ-THTP-3).
3. HSTS durations under a day read "0 days"; now in minutes/hours.
4. The anchor-add response returned a zero `addedAt`.
5. Two syntax errors in the new report module that a CommonJS `node --check` missed; modules are now checked as ES modules.
6. The CBOM gap list first claimed CycloneDX had no field for certificate extensions; the vendored 1.7 schema has
   `certificateExtensions`, so the 1.7 CBOM now carries them (`TestCertificateExtensionsOnlyIn17`).

## 6. Known limits and open items

- **Deferred (P1):** REQ-TCRT-6 beyond the exponent check (ROCA fingerprint, Debian weak-key list, shared modulus across
  the estate); REQ-TUI-10 (History marking changed sections); REQ-TUI-13 (Certificates page columns and filters for
  trust per store, OCSP and SCTs).
- **Not validated here:** SCTs carried inside an OCSP response (same decoder, no fixture produces one); the delegated
  responder's own validity period is not checked; SCT signatures and CT policy counts (T2); live OCSP/CRL lookups (T2).
- **Missing-intermediate heuristic:** a server that sends the lower of two intermediates and omits the upper one is
  reported as an unknown root rather than a missing intermediate.
- **Estate-wide SSLv2 index** reads the latest report of every endpoint on each evaluation; fine at current scale,
  worth an index table if estates grow large.
- **No real-world sweep:** validation is hermetic (fixtures, demo targets, OpenSSL oracle). A manual check against a
  handful of public sites was not run; it needs the owner's authorisation.
- The server-wide CA bundle is a flag only (`--ca-bundle`); `serve` has no configuration file.
