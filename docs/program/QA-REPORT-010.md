# QA-REPORT-010 · Classical strength (PRD-010)

Date: 2026-10-18. Build: branch `feat/classical-strength`, on top of [ENH-001](../product/ENH-001-cipher-strength.md)
and the NIST strength model (`42b1644`). Requirements: [PRD-010](../product/PRD-010-classical-strength.md),
[RTM](RTM.md) §PRD-010.

## Result

| Gate | Command | Result |
|---|---|---|
| Unit and integration | `go test ./...` | 44 of 44 packages pass |
| Traceability | `TestRequirementsTraceability` (in the above) | 9 PRD-010 rows, all done, each with evidence |
| Lint | `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| UI scripts parse | `node --check` on every module, as CI does | all parse |
| Browser journey | `testing/e2e/journey.mjs` (CI setup: `--sign-in on`, token, server log) | **217 passed, 0 failed** (214 at 0.3.0; 3 new strength checks) |
| Screen walk | below | 2 findings fixed, 1 PRD correction |

## What the new checks cover

- **The model (REQ-STR-1).** Tests reproduce NIST's own tables from NIST's own formulae:
  - the GNFS estimate for RSA and finite-field DH, against SP 800-56B Rev. 2 Table 4 and SP 800-56A Rev. 3 Table 26;
  - the curve rule against SP 800-186 Table 1, the binary curves included;
  - the symmetric ciphers and hashes against SP 800-57 Part 1 Rev. 5 Tables 2 and 3.

  Every catalogue algorithm has a strength, a cited broken status or "not rated" with a reason.
- **The suite rating (REQ-STR-2).** A table test covers the weakest-part rule and every suite in the IANA registry.
  Single DES is Insecure (#18).
- **One source for every surface (REQ-STR-3 to 5).**
  - The report, the PDF and the CLI read the evaluation; the two heuristic copies are deleted.
  - E2E-STR-1 compares every suite row on every scanned TLS report with `GET /api/v1/scans/{id}/evaluation`.
  - `TestPDFAndEvaluationAgreeOnStrength` does the same for the PDF.
- **Inventory, SSH, CBOM (REQ-STR-6 to 8).**
  - E2E-STR-2 reads the Inventory's column: 3DES "112 bits, disallowed", RC4 broken, AES-256-GCM 256.
  - `TestSSHAlgorithmsCarryStrength` rates RSA host keys by the size of the key fetched.
  - The CBOM's `classicalSecurityLevel` validates against the 1.6 and 1.7 schemas.
- **Help (REQ-STR-9).** E2E-STR-3: the report's strength legend opens Help at the Classical strength topic.

## Defects found by QA and fixed before release

| # | Found by | Defect | Fix |
|---|---|---|---|
| Q1 | CI on PR #16 (`TestAC02_ProgressIsLiveAndScanCanBeCancelled`, 8 then 7 connections) | **Pre-existing race.** Progress ticks from parallel probes could land out of order, and the progress write happened outside the lock, so the live connection count could go backwards. | `tick` keeps the maximum under the lock; `message` writes its event and progress under the lock. |
| Q2 | Journey (most report checks, then a `getComputedStyle` abort) | The chain diagram used the evaluation without being passed it. The Summary and Configuration tabs of every TLS report rendered nothing below the tab bar. | `servedDiagram` takes the evaluation. Every view was then rendered against every scanned endpoint without an exception. |
| Q3 | Screen walk | The legend's "How strength is worked out" opened Help at its top, eleven topics above the answer. | Help opens at `?topic=`; E2E-STR-3 checks it. The first version scrolled in `requestAnimationFrame`, which never runs in a hidden tab; it now scrolls at once. |

## Test changes, and why each is not a weakening

- **E2E-STR-3** first asked for the topic within 200 px of the top. On CI the heading lands at 214 px on every run
  (20 px locally), from a layout difference between the two machines, not a timing one. The check now states the
  requirement: the page has scrolled, and the topic's heading is in the top third of the window.

## Screen walk

Walked in light, dark and at 375 px:
- the TLS report's Summary and Configuration, with the suite and group tables and the certificate chain;
- the SSH report's algorithm tables;
- Inventory › Algorithms and Keys;
- Help › Classical strength.

No page scrolls sideways at 375 px.

- **Kept:** a suite's hint names its weakest part ("128 bits · x25519"). When parts tie, the first in §2's order
  (cipher, key exchange, authentication, MAC) is named.
- **Kept:** generic names that carry no size ("RSA", "ECDH", "AES", "SHA256withRSA" from imported CBOMs) read
  *not rated*, because their strength depends on a size the source did not give. Each has its reason in `basis`.
- **PRD correction:** REQ-STR-7 expected `hmac-md5` to read *broken*. RFC 6151 does not call HMAC-MD5 broken, and
  SP 800-57 gives it no strength because MD5 is not approved, so the model says *not rated* with that reason. The
  PRD now says so. REQ-STR-6 named the field `securityBits`; it ships as `classicalStrength` {bits, status, basis},
  and 3DES reads "disallowed" (SP 800-131A Rev. 2), not "deprecated".

## Changes a user will see

- Suites change word:
  - suites authenticated by an RSA-2048 certificate become *Acceptable* (OD-1, the weakest-part rule);
  - single DES becomes *Insecure*.
- Stored scans are re-evaluated on start (eval/9).
- New API fields: `suiteStrength` and `keyStrength` on the evaluation, `strength` on SSH algorithms, and
  `classicalStrength` on Inventory rows.
- The CBOM gains `classicalSecurityLevel`.
