# QA-REPORT-001: Posture Workbench (R1)

| | |
|---|---|
| **Build under test** | `cbom-scan 0.1.0`, `CGO_ENABLED=0`, built from the final source (`artifacts/binaries/`) |
| **Plan** | [QA-PLAN-001](QA-PLAN-001.md) |
| **Requirements** | [PRD-001](PRD-001-posture-workbench.md) |
| **Environment** | Windows 11; Go 1.27.0 (module targets Go 1.25); Microsoft Edge (Chromium) driven headless over the DevTools protocol, plus exploratory sessions in the desktop app's built-in browser; pure-Go SQLite |
| **Targets** | Only servers started by `cmd/demo-targets` on loopback. No third-party host was scanned. |
| **Verdict** | **Pass for R1**, with the limits and open items in sections 4 and 5. |

## 1. Summary

| Check | Result | Evidence |
|---|---|---|
| Unit + integration (`go test ./...`, 15 packages) | **pass**: 222 test/sub-test results, 0 failures | `artifacts/logs/go-test-verbose.log`, `go-test-summary.log` |
| Timing-sensitive packages repeated (`server`, `tlsprobe`, `store`, 8 runs) | **pass** | `artifacts/logs/go-test-repeat8.log` |
| `go vet` / `golangci-lint` | **pass**: 0 issues | `go-vet.log`, `golangci-lint.log` |
| Fuzz, 3 wire parsers, 15 s each | **pass**: 1.24 M / 0.89 M / 0.89 M executions, no crash | `fuzz-15s-each.log` |
| Browser journey (real Edge, shipped UI) | **pass**: 44 of 44 checks, 32 screenshots | `artifacts/screenshots/results.json`, `logs/e2e-journey.log` |
| Live security checks against the binary | **pass**: 25 of 25 | `logs/security-live.log` |
| Manual and measured checks (restart, 500 endpoints, token prompt) | **pass**, one item not achievable | `logs/manual-and-perf-checks.txt` |

Release gates from PRD section 2:

| Gate | Target | Measured | Result |
|---|---|---|---|
| O1 fast first value | first result <= 5 min, scan <= 30 s | one command to start, no configuration; loopback scans 6 to 40 ms; the deliberately slow target ~20 s | pass (loopback; see limits) |
| O2 trustworthy | 100 % of findings and readiness claims cited | enforced by `TestEveryRuleFiresAndIsCited`, `TestEveryReadinessClaimIsCited`, `TestEveryRuleIsCited`; the journey also checks every finding card has a link | pass |
| O3 live workflow | visible <= 1 s; refresh <= 2 s | list polls every 1.2 s, endpoint page every 0.7 s while a scan is active | pass |
| O4 memory | every scan kept, diff on demand | history and diff exercised (L1 to L3 case) | pass |
| O5 safe by default | all refused | 25 live checks + `TestAC11_*` | pass |
| O6 self-contained | 0 external requests | `web/embed_test.go` (no external URLs, no `innerHTML`/`eval`, no inline script/style) + CSP `default-src 'none'`; 0 CSP violations across the journey | pass |

## 2. Traceability: PRD acceptance criteria to evidence

`Go:` names a test in `internal/...`; `E2E:` is a check in `testing/e2e/journey.mjs` (recorded in
`screenshots/results.json`); `SEC:` is a line of `logs/security-live.log`; `Shot` refers to `artifacts/screenshots/`.

### P0

| AC | Result | Evidence |
|---|---|---|
| 01.1 add one endpoint | pass | E2E-01.1 (submitted with a real Enter key press); Go `TestAC01_AddAssets`; Shot 02 |
| 01.2 bulk with per-line results | pass | E2E-01.2 (6 added, 1 duplicate, 2 invalid); Go `TestAC01_BulkAddReportsEveryLine`; Shot 04 |
| 01.3 duplicate refused | pass | Go `TestAC01_AddAssets`; bulk result "already present" in E2E-01.2. The single-add form's duplicate message was not exercised in the browser. |
| 01.4 normalised and validated | pass | E2E-01.4 (invalid target refused with a message); Go `TestAC01_TargetsAreNormalisedAndValidated`; Shot 03 |
| 01.5 edit; delete after confirmation | pass | E2E-01.5a/b/c (edit, cancel keeps, confirm deletes); Go `TestAC01_EditAndDeleteAsset`; Shot 22 |
| 02.1 queued and visible within 1 s | pass | E2E-02.1; Go `TestAC02_ScanCompletesWithResults`; Shot 06 |
| 02.2 stage, %, connections, log, refresh <= 2 s | pass | E2E-02.2; Go `TestAC02_ProgressIsLiveAndScanCanBeCancelled`; Shot 07 |
| 02.3 result appears without reload | pass | E2E-02.3; the list and endpoint page update themselves (observed in the exploratory session; Shot 06 vs 09) |
| 02.4 unreachable/non-TLS fails with a reason | pass | E2E-02.4; Go `TestAC02_UnreachableAndNonTLSEndpointsFailClearly` |
| 02.5 cancel | pass | E2E-02.5, E2E-02.5b; Go `TestAC02_Progress...` (asserts the log ends at "canceled by user"); Shot 08 |
| 02.6 one active scan per asset | pass | Go `TestAC02_Progress...` (a second request returns the first scan) |
| 03.1 scan all/selected, N at once, queue visible | pass | E2E-02.1 (7 endpoints); Go `TestAC03_BulkScanRespectsConcurrencyAndQueue` |
| 04.1 level, meaning, HNDL flag, three dimensions, next steps | pass | E2E-04.1, E2E-04.1.9440 to .9443; Shots 11 to 14 |
| 04.2 fleet distribution and HNDL count | pass | Shot 10; Go `TestFleetSummary`, `TestAC04_ReadinessOfRealEndpoints` |
| 04.3 legend visible, states the scale is the product's own | pass | E2E-04.3; Shot 27 |
| 04.4 real targets: hybrid L3, classical TLS 1.3 L1, TLS 1.2-only L0 | pass | E2E-04.4.9440/.9441/.9442/.9443; Go `TestAC04_ReadinessOfRealEndpoints`; `samples/*.evaluation.json` |
| 05.1 protocols, suites, groups, certificates, features | pass | Shots 15, 17 (exploratory review of every section); E2E-05.2 |
| 05.2 findings by severity with citations and remediation | pass | E2E-05.2 (cards and citations counted); Shot 16 |
| 05.3 TLS hygiene with every deduction, any ceiling, and what is not measured; labelled as the product's own | pass | E2E-05.3 (Broken for the SSLv3 target, not for the TLS 1.2 one), E2E-05.3b (each point taken off traces to a finding and the total adds up); Go `internal/eval/hygiene_test.go` (`TestEveryDeductionTracesToAFinding`, `TestCeilings`, `TestPostQuantumStateDoesNotChangeHygiene`, `TestRatingVocabularyIsOwn`); Go `web/embed_test.go` (no other scanner's name or "grade" vocabulary in the UI); Shot 14 |
| 05.4 incomplete scan flagged | **partial** | Verified by unit tests (`internal/tlsprobe/scan_test.go`, the silent-server and the connection-budget scans set `Incomplete`) and by reading the banner code. Could not be produced from outside (section 5), so the banner has not been seen in a browser. |
| 06.x dashboard KPIs, distributions, needs-attention, recent scans, trend | pass | Shot 10; `samples/fleet-summary.json`; Go `TestFleetSummary` |
| 07.1 every scan kept | pass | Go `TestHistoryAndRetention`; E2E-07.1; `samples/pq-toggle.history.json` |
| 07.2 per-asset trend chart | pass | E2E-07.3 (two points drawn); Shot 18 |
| 07.3 compare two scans, better/worse/neutral | pass | E2E-07.3; Go `TestAC07_HistoryTrendAndDiff`; `samples/pq-toggle.diff-L1-to-L3.json`; Shot 18 |
| 07.4 open a past scan read-only | pass | E2E-07.4; Shot 19 |
| 07.5 retention 200 per asset | pass | Go `TestHistoryAndRetention` |
| 11.1 loopback default; network bind needs a token | pass | SEC "serve --addr 0.0.0.0 without token exits non-zero"; Go `internal/app/serve_test.go` |
| 11.2 token required, else 401 | pass | SEC no/wrong/bare token -> 401, Bearer -> 200; token prompt exercised in the browser; Go `TestAC11_TokenIsRequiredWhenConfigured` |
| 11.3 foreign Host and Origin refused | pass | SEC Host `evil.example` -> 421, foreign Origin and `Sec-Fetch-Site: cross-site` -> 403, `text/plain` -> 415, missing header -> 403; Go `TestAC11_ForeignHostHeaderIsRefusedWithoutAToken`, `TestAC11_MutationsAreProtectedFromForgery` |
| 11.4 blocked network ranges refused | pass | E2E-11.4; SEC metadata, 0.0.0.0, loopback literal refused at add time and a name resolving to loopback refused at connect time; Go `TestAC11_ScansCannotReachBlockedNetworks` |
| 11.5 no external requests; strict CSP | pass | `web/embed_test.go`; SEC CSP header; NFR-sec.csp (0 violations) |
| 11.6 hostile text is inert | pass | E2E-11.6 (name and tag containing `<img onerror>`, `<script>`, `<svg onload>`: nothing executed or injected); Go `TestAC11_HostileStringsAreInertData`; Shot 21 |
| 11.7 authorised-use notice before the first scan | pass, with a note | The notice is in the Add dialog (Shots 02, 04), the About page and the CLI/server banners. It is not repeated on the Scan button. |
| 11.8 concurrency and connection budget enforced | pass | Go `TestAC03_...`; `internal/tlsprobe/scan_test.go` (budget-limited scan) |
| 12.1 one SQLite file | pass | Only `--db` is written; no other service |
| 12.2 interrupted scan marked failed | pass | Go `TestAC12_RestartMarksInterruptedScansFailed`; live kill -9 test: "failed, interrupted by a restart of the server" |

### P1

| AC | Result | Evidence |
|---|---|---|
| 08.1 per-asset schedule, next time shown, survives restart | pass | E2E-08.1; Go `TestAC08_ScheduledRescans`; live restart test kept `intervalSeconds` and `nextScanAt` |
| 09.1 CSV export; report/evaluation JSON | pass | E2E-09.1; Go `TestAC09_Export`; `samples/assets.csv`, `*.report.json`, `*.evaluation.json`. CSV cells that begin with `= + - @` are prefixed (formula-injection defence, tested). |
| 10.1 CBOM upload creates a host with verdicts | pass | E2E-10.1 to 10.4 (uploaded through the real file input); Go `TestAC10_HostCBOMIngest`, `TestAC10_IngestRejectsBadInput`; Shots 24 to 26 |

### Non-functional

| Requirement | Result | Evidence |
|---|---|---|
| Static binary, `CGO_ENABLED=0`, five OS/arch targets | pass (built); linux/darwin never executed | `artifacts/binaries/`; only the Windows binary was run |
| 500 endpoints list < 1 s | pass | 40 to 54 ms to all rows in the DOM; API median 5.6 ms |
| API p95 < 100 ms excluding scans | pass | p95 0.8 to 6.8 ms |
| Graceful shutdown | pass | Go `TestServeRunsAndShutsDownGracefully` |
| Keyboard, accessible names, dialogs | pass (basic) | NFR-a11y.3 (Escape), NFR-a11y.4 (every control named); not a full screen-reader audit |
| Narrow screens | pass | NFR-a11y.1/.2 (no horizontal page scroll at 390 px); Shots 30 to 32 |
| Light and dark | pass | Shots 28, 29 |
| Colour never the only signal | pass (review) | Level codes, band words with their scores, severity icons and words accompany every colour |

## 3. Defects found and their disposition

Found by the browser sessions unless noted. All fixed unless listed in section 5.

| # | Sev | Defect | Found by | Fix |
|---|---|---|---|---|
| D1 | P2 | The fleet donut chart drew every level as a filled disc: a CSS rule (`fill`) outranked `.donut-seg { fill: none }`. | screenshot review | Colour rules split so segments only set `stroke`. |
| D2 | P3 | After **Cancel**, a scan's log kept announcing "probing key exchange", "fetching certificates", "evaluating results", and the runner evaluated a partial report. | exploratory session (scan log via API) | Progress is silent once the scan's context is done, and the runner stops after a user cancel. Regression assertion added to `TestAC02_ProgressIsLiveAndScanCanBeCancelled`; fails before the fix. |
| D3 | P3 | The endpoint list re-sorted under the cursor when results arrived, so a click could open the wrong endpoint. | exploratory session (it happened to the tester) | Order is held while any scan is active. |
| D4 | P3 | Host verdict citations were serialised as `Title`/`URL`, so the UI showed no links. | building the UI | JSON tags added to `pqc.Reference`. |
| D5 | P3 | History chart: axis labels clipped at the left edge; first and last dots sat on the labels; two scans in one day showed the same date. | screenshot review | Wider margin, inset, time in the axis labels. |
| D6 | P4 | A focus ring drew around the whole page after every navigation. | screenshot review | Router-set focus on `<main>` no longer outlined. |
| D7 | P4 | Sub-second scans showed "0.0 s"; the large rating tile was uncoloured; cramped card headings; timestamps without seconds. | screenshot review | Shown in ms; the rating tile uses the readiness palette; spacing and seconds added. |
| D8 | P4 | `TestAC02_ProgressIsLiveAndScanCanBeCancelled` was timing-flaky (three polls could land inside one 250 ms progress write). | repeat runs | Test waits until the counter has moved. Stable over 15 + 8 repeats. |
| D9 | - | An early observation that Enter did not submit the Add dialog was a limitation of the pane's key injection: a real key event with its character submits it (E2E-01.1). Not a product defect. | exploratory session | none |
| D10 | change | **Rating redesigned after the first QA pass, at the owner's request.** The first build showed an A-F letter grade (with T/M and "A+") modelled on a third-party rating guide; that shared another scanner's terminology and scoring tables. It was replaced by the product's own **TLS hygiene** score (0 to 100; Strong / Sound / Fair / Weak / Broken) derived only from cited findings. | owner review | New `internal/eval/hygiene.go`; store columns `band` and `score` with a migration; UI, CSV (`hygiene_band`, `hygiene_score`), docs and demo text updated; guard tests added. All evidence in this report was regenerated on the new build. |

## 4. What was not tested, and what that means

- **Browsers:** Chromium (Edge) only. Firefox and Safari were not run. The UI uses plain ES modules, `fetch`, CSS variables and CSS grid.
- **Operating systems:** run on Windows only. The Linux, macOS and arm64 binaries are cross-compiled and were not executed. `go test -race` was not run locally (no cgo on this machine); CI runs it.
- **Go 1.25** (the module's minimum) was not run locally; everything ran on Go 1.27.0. CI uses `go.mod`'s version.
- **The new CI `e2e` job** (Chrome on Ubuntu, `--no-sandbox`) has never run. It is written but unproven until the first push.
- **Real networks:** all scans were against loopback demo servers, so timing does not reflect WAN round trips, and real-world server quirks (middleboxes, rate limiting, TLS-intolerant load balancers) are untested. STARTTLS is not supported.
- **Certificates:** every demo endpoint uses a self-signed certificate, so every demo endpoint with a clean protocol setup scores **Fair (56 to 60)** from the untrusted and short-lived certificate findings. Strong and Sound results (a *trusted* chain) and a post-quantum certificate (L4) are covered by unit tests but never appear in the browser evidence.
- **Screen readers and a formal WCAG audit** were not done.
- **Load:** 500 endpoints listed; scanning 500 was not attempted (it would connect to 500 hosts).
- **Upgrade paths:** the schema has two versions; the one upgrade (letter grades to TLS hygiene) is covered by `TestMigrationFromLetterGrades` on a database built with the old schema, and not on a large or long-lived database.

## 5. Open items at release

| # | Sev | Item | Recommendation |
|---|---|---|---|
| O1 | P3 | Incomplete-scan banner (AC-05.4) never seen in a browser. | Add a test hook or a demo target that stalls after the first answers, then extend the journey. |
| O2 | P3 | The dashboard trend groups by **UTC** day. A user east of UTC sees the newest column labelled with yesterday's date for part of the day. | Use the browser's local day boundaries, or state "UTC" in the chart. |
| O3 | P4 | An endpoint added without a name shows its address twice (name and address lines). | Show the address once when name equals address. |
| O4 | P4 | The single-add form's duplicate message was not exercised in a browser. | Add to the journey. |
| O5 | P4 | The authorised-use notice is at add time only (AC-11.7). | Consider a one-time confirmation on the first scan. |

No critical or high defect is open. Exit criteria in QA-PLAN-001 are met: all P0 acceptance criteria pass or are
listed above (one partial), P1 criteria pass, lint and fuzz are green, and the artifacts are collected and checksummed
(`artifacts/MANIFEST.md`).
