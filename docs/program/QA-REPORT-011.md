# QA-REPORT-011 · Algorithm classes, the flow, and the certificate viewer (PRD-011, PRD-012)

Date: 2026-10-21. Build: branch `feat/classes-and-x509` on top of `ee275af` (PR #19, PRD-010). Requirements:
[PRD-011](../product/PRD-011-algorithm-classes-and-flow.md), [PRD-012](../product/PRD-012-certificate-viewer.md),
[RTM](RTM.md) §PRD-011 and §PRD-012. Specs: [ENH-002](../product/ENH-002-algorithm-classes.md),
[ENH-003](../product/ENH-003-certificate-viewer.md), [UX-REVIEW-010](../product/UX-REVIEW-010-flow-and-self-explanation.md).

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | passed on the data layer (commit cb2f165); the final build is in [QA-REPORT-012](QA-REPORT-012.md) |
| Traceability | `TestRequirementsTraceability` (in the above) | 23 new rows (14 PRD-011, 9 PRD-012), all done, each with evidence |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| Fuzz | `FuzzX509Decode`, 120 s in WSL (the Windows engine stalls on ASN.1) | 6,071,367 inputs, no crash or hang |
| Decoder against OpenSSL | a demo target's certificate through `openssl x509 -text` and `x509view.Decode` | same extensions, criticality, names and SHA-256 |
| UI scripts parse | `node --check` on every module | all parse |
| Browser journey | `testing/e2e/journey.mjs` (CI setup) | 224 passed, 3 failed: the 3 were first-pass screens the owner then rejected, rebuilt by PRD-013 ([QA-REPORT-012](QA-REPORT-012.md)) |
| Screen walk | below | superseded: see below |

## What the new checks cover

- **Classes (REQ-CLS-1).** Every catalogue entry has a class, from its CycloneDX primitive. The names this program
  derives (RSA-2048, ECDSA-P256, the group names, every signature spelling) have one too.
- **The hash part (REQ-CLS-2).** Every registry suite gets its hash part, at every version that can carry it:
  - HKDF's hash in TLS 1.3;
  - the PRF's in TLS 1.2 (SHA-256 unless the suite names SHA-384);
  - the MD5 and SHA-1 pair in TLS 1.0 and 1.1.

  In no case does the hash part decide a word. It can tie, and the first part in order is then named.
- **Signatures (REQ-CLS-3).**
  - The Go, OID and Java spellings each split into hash and key.
  - The weaker of the two decides: SHA256-RSA with an RSA-2048 key is 112, ECDSA-SHA256 with a P-384 key is 128.
  - `SHA256withRSA` with no key is now 128.
- **The list (REQ-CLS-4, 5).** E2E-CLS-1 compares every algorithm the API lists, on six endpoints, with the card's
  row under its class: role, strength and weakest mark.
- **Parts (REQ-CLS-6).** E2E-CLS-2 opens a suite and checks one line per API part, each with a class, one marked
  weakest.
- **Inventory and CBOM tab (REQ-CLS-7).** `?class=hash` lists hashes only, a bad class is refused, and the CBOM tab
  shows bits.
- **PDF and CLI (REQ-CLS-8).** Every algorithm the evaluation lists appears in the PDF, under its class word. The
  CLI prints the classes and each suite's parts.
- **The bands (REQ-UXF-1).**
  - No band shares a word with suite strength (every score 0 to 100 is checked).
  - A v14 database's bands are migrated, and the scores are untouched.
  - Old names in stored evaluations read and rank as the new ones.
  - E2E-UXF-2 finds no old band name on the TLS endpoints page.
- **The Summary (REQ-UXF-2 to 5).** E2E-UXF-1 and E2E-UXF-2 cover:
  - the first-fix line;
  - the weakest suite;
  - the hygiene figure opening the score breakdown;
  - the not-rated reasons;
  - the Overview tile.
- **The certificate viewer (REQ-XV-1 to 9).**
  - `TestX509DecodeShowsEveryExtension` uses a generated chain that carries every decoded extension, plus an unknown
    private one, which must come back as OID and hex.
  - The SCT is named from the bundled CT log list.
  - The endpoint test decodes a real scan's certificate with and without `?scan=`, and checks the no-DER answer.
  - E2E-XV-1 to 5 check, in order:
    - every chain node links to its page, and Back returns;
    - the section order agrees with the API;
    - the PEM's SHA-256 is the fingerprint;
    - the hostile demo certificate (markup in its subject, names and URLs, and a `javascript:` OCSP URL) stays text,
      with no link made from it;
    - 375 px with no sideways scroll, and every control reachable by Tab.

## Defects found by QA and fixed before release

| # | Found by | Defect | Fix |
|---|---|---|---|
| Q1 | `TestSignatureAlgorithmIsHashAndKey` | With hyphens removed, `SHA384` starts with `SHA3`, so SHA-384 signatures were read as SHA3-84. | SHA-3 is recognised by its length too. |
| Q2 | `TestEvaluationListsAlgorithmsByClass` | A hybrid group's post-quantum status depended on the report's `hybrid` flag. A report without the flag listed X25519MLKEM768 with no status. | The status falls back to the catalogue name. |
| Q3 | `TestPDFListsAlgorithmsByClass` | The PDF's narrow columns broke "Asymmetric" and "quantum-vulnerable" across lines. | Wider columns; versions written "TLS 1.2". |
| Q4 | Screen walk (UX-REVIEW-010 U-7) | **Pre-existing.** The TLS hygiene figure on a report's Summary opened *About this report* (scan time, connections), not the score breakdown. | It opens Weaknesses at *How the TLS hygiene score was worked out*. |
| Q5 | `TestX509DecodeShowsEveryExtension` | Go 1.27 writes and reads certificate policies through `Policies`. The decoder read `PolicyIdentifiers`, which misses OIDs whose arcs exceed an int. | The decoder reads `Policies`. |
| Q6 | CI on PR #19, and a local run | The headless browser sometimes never opened its DevTools port (after an update), and the whole journey failed. | The journey waits 30 s, then starts a fresh browser on a new port, once. |

## Test changes, and why each is not a weakening

- **E2E-05.3** now expects the SSLv3 endpoint's band to be *Failing*: the band is renamed, and the threshold is
  unchanged.
- **The registry sweep in `TestSuiteHasItsHashPart`** pairs each suite only with the versions that can carry it.
  AEAD and SHA-2 MAC suites need TLS 1.2, and SCSVs are signalling values that are never accepted. The pairs it
  leaves out can never be negotiated.
- **`TestEvaluationCarriesStrength`** compares the version with `eval.Version` instead of a fixed `eval/9`.

## Screen walk

The first-pass screens of PRD-011 and PRD-012 (the Algorithms in use card, the suite part list, the certificate page as tables) were rejected by the owner as too texty before they shipped. PRD-013 rebuilt them as instruments; the walk of the screens that ship, at every width and in dark mode, is in [QA-REPORT-012](QA-REPORT-012.md). The data layer this report covers is unchanged by that rebuild.
