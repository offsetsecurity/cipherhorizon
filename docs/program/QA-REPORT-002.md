# QA report 002 — the cryptographic estate model

Date: 2026-09-26. Build: the working tree on top of commit 2a2a16c (nothing committed, nothing tagged). Plan: [QA-PLAN-002](../product/QA-PLAN-002-estate-model.md). Requirements: [PRD-003](../product/PRD-003-cryptographic-estate-model.md), status in the [RTM](RTM.md).

**Independence.** The reviews behind this program (security review of each work package, the requirements review) were role-plays by the same author, not independent people. This report is the author's verification of the author's work, with every claim tied to something that can be re-run. It is not an independent assurance.

## 1. Verdict

The build meets its success measures M1 to M7 on the machine and fixtures it was tested on. It has **not** been validated on a live Linux host, on Windows Server or ARM64, in an elevated Windows session, or against a cdxgen document, and `govulncheck` was not run. The owner items in section 6 are open. The verdict is **ready for the owner to review and commit; not yet a release**: nothing is tagged, the module path is a placeholder, and the repository does not exist.

## 2. Automated results

| Check | Result |
|---|---|
| `go vet ./...` | clean |
| `golangci-lint run ./...` | 0 issues |
| `go test ./... -count=1` | 32 packages ok; 544 test and fuzz functions in the tree (8 fuzz targets) |
| Requirements traceability (`internal/archtest`) | every RTM row consistent with the PRD; every "done" row names tests or a script that exist |
| End-to-end journey (`testing/e2e/journey.mjs`, Edge over DevTools, real server, real scan targets) | **104 passed, 0 failed**; 45 screenshots |
| Live security checks (`testing/e2e/security.sh`) | **56 passed, 0 failed** (includes the new estate routes: token, forged and foreign-origin requests, wrong types, invalid imports) |
| First-run measure (`testing/e2e/first-run.mjs`) | **PASS**: 3 clicks, 9 seconds |
| Cross-compilation, `CGO_ENABLED=0`, both binaries, linux/darwin/windows x amd64/arm64 | all 12 build |
| Rename rehearsal (`scripts/rename.sh` on a copy) | builds, vets and passes the whole suite unedited |
| Windows certificate oracle (`testing/hostdiscovery/compare-certs.ps1`, this machine, today) | AGREE: 142 placements expected, 140 detected, 0 extra; the 2 missing are one certificate (`CN=Root Agency`) the sensor reported as unparseable, in two stores |

## 3. Success measures

| # | Measure | Result | Evidence |
|---|---|---|---|
| M1 | Real third-party CBOMs ingest with asset counts preserved | met | `TestRealDocumentsProjectWithoutLoss`, `TestEveryComponentIsAccountedFor`, `TestRealThirdPartyDocumentsValidate`: every component of every fixture and real document is interpreted or counted by reason. Real samples: CBOMkit and CBOM-Lens; cdxgen has no real sample (covered by the generic path only) |
| M2 | 0 false auto-confirmed joins on the synthetic estate; ambiguous and third-party joins are proposals | met | `TestAForgedImportCannotHijackOrBlockTheRealJoin`, `TestACertificateOnSeveralHostsIsAmbiguousAndJoinsNothing`, `TestAWildcardOnFortyHostsJoinsNothing`, `TestAForgedImportGetsAProposalAndTheRealJoinStands`; the journey shows four proposals, none automatic, from one imported document |
| M3 | Certificate sensor equals an independent oracle on the Windows machine | met | oracle AGREE (section 2). One certificate that the platform parses and the sensor does not is reported by the sensor as unparseable, in both stores it appears in |
| M4 | 0 occurrences of private key material in DB, CBOM, logs, UI | met for DB, CBOM and API; not asserted for logs | `TestOneCertificateSeenByAScanAndByAHostIsOneEntity` plants a decoy key beside the certificate and searches every API response (including the new estate, M-23-02 and OpenAPI routes), the uploaded CBOM, and the database file with its write-ahead log; a mutation (searching for a string that is in the file) makes it fail. `TestNoKeyMaterialIsReadOrReported` covers the sensor. The UI only draws API data. Server logs were not searched |
| M5 | 0.1.0 database migrates, nothing lost | met | `TestLegacyDatabaseMigratesWithoutLosingAnything` on a database built from the frozen migrations; `TestFrozenMigrationsAreUnchanged` pins them; an owner-only backup is made first |
| M6 | New CBOM validates against 1.7 (and 1.6 in compatibility mode) | met | `TestEncodedOneDotSevenValidatesAgainstTheOneDotSevenSchemaAndOneDotSixStillAgainstOneDotSix`, `TestScanCBOMDefaultsToOneDotSevenAndOffersOneDotSix`, dual golden files, negative controls (1.7 document under the 1.6 schema; an invented family) |
| M7 | A new user reaches "systems ranked with reasons" in at most 5 clicks and 10 minutes | met | `first-run.mjs`: Add endpoints, Add endpoint, Why. 3 clicks, 9 s, four cited rules shown |

## 4. Non-functional requirements

| Requirement | Result |
|---|---|
| NFR-1 performance | **Measured, not promised** (`TestListViewsAtScale`, `CIPHERHORIZON_SCALE=1`): 5,000 systems and 50,000 certificates on a developer laptop. Store queries, worst of five runs: systems 34 ms, certificates 590 ms, estate ranking 534 ms, entities 225 ms, correlation pass 472 ms. Through a real server: estate 0.56 s (4.4 MB), certificates 0.69 s (**22.6 MB**), systems 0.06 s. In the browser: Estate drawn in 0.7 s, Certificates in 1.1 s, after the UI was changed to draw at most 300 and 500 rows at once. Every list is under the 1 s target on the server; the certificate list's 22 MB response is the weak spot and has no server-side paging yet. A 32 MiB import: bounded by the limits layer and tested for clean refusal; its time was not measured |
| NFR-2 no cgo, all platforms, no new dependency | met. `golang.org/x/text` was already required and is now listed as direct; no new module |
| NFR-3 collector read-only, no subprocess, no network | met and enforced by architecture tests (ADR-0004, ADR-0006, ADR-0015) |
| NFR-4 no new external requests, CSP unchanged | met: `TestNoExternalRequests`, `TestPageHasNoInlineScriptOrStyle`, the CSP header check in `security.sh`, and no console or CSP violation in the whole journey |
| NFR-5 tests named in the RTM; lint, vet green; existing suite passes | met for tests, lint and vet. **`govulncheck` and a licence check were not run** (`govulncheck` is not installed and installing it needs a download; not done without asking) |
| NFR-6 accessibility on new views | keyboard reachability and accessible names checked on each new view in the journey; no horizontal scroll at 390 px or in dark mode. **Contrast was not measured by a tool**: the new classes reuse the existing tokens |

## 5. Defects found and fixed in this pass

| Defect | Found by | Fix |
|---|---|---|
| A finished scan was visible before its certificates and proposed joins were derived (a later read could miss the proposals) | intermittent failure of `TestAmbiguousMatchesAreProposedAndNeverAutomatic` in a full run | derived in the same transaction as the result, under a savepoint |
| Undocumented `409` on the asset diff route | OpenAPI parity test on its first run | documented |
| `why` lists overflowed at phone width; two-column grids forced 360 px | journey overflow check | responsive grid minimums |
| Estate refresh could collapse an open explanation | first-run script | refresh skips while a row is expanded |
| Three lint findings in WP-6 code | lint | fixed |

## 6. Known limits and open items

- **Not validated:** a live Linux host, Windows Server, ARM64, an elevated Windows session, cdxgen output, and a Linux CI job (needs the GitHub repository, REQ-REL-4).
- **Not run:** `govulncheck`; the licence check; `goreleaser check` (fails only because the repository has no remote); a real release build, which would clean the working `dist/` directory.
- **Display:** a bidirectional override character inside a name still reorders that name's own text on screen (it is displayed as text and cannot become markup).
- **Export gaps:** the supplier of software (M-23-02 item 5), the kinds of data (item 8); response bodies in the OpenAPI document are not described field by field, and the status codes of state-changing routes are documented but not checked by a test.
- **UI:** no server-side paging of certificates; no in-browser CSV import of system details; no estate graph view.
- **Decisions still with the owner:** OQ-1 (trademark and domain), OQ-2 (CBOM-Lens authentication, blocks ING-10), OQ-3 to OQ-5; GitHub owner, security contact and first tag and push (OA-1); approval of PRD-003 (OA-2); a Linux environment for live validation (OA-3).
