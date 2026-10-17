# QA-PLAN-007 · Charts, motion, port, CBOM

For [PRD-009](PRD-009-interactive-charts-motion-port-cbom.md). The results go in QA-REPORT-009.

## 1. Unit and integration (go test)

| Area | Tests |
|---|---|
| Port | `TestServePortFlag`: `--port 9000`; `--addr 0.0.0.0 --port 9000`; `--port 0` reports the real port. `TestServeAddrAndPortConflict`. `TestServePortFromEnvironment`: env only, env plus flag (the flag wins), a bad env value (named in the error). `TestHealthcheckFollowsPortEnvironment`. `TestServeBusyPortSaysWhatToDo`: a real listener holds a port and serve must fail with the hint. `TestServiceURLFollowsPort` (Windows build). |
| Inventory API | `TestInventoryFiltersByQuantumAndPurpose`: each `quantum` value; `purpose` matches the dashboard's byPurpose counts for every purpose; a bad value is a 400. |
| CBOM | `TestLegacySuiteCiphersAreAssets`, `TestNISTCurveGroupsAreAssets`, `TestCertificateSignatureVariantHasOID`, `TestCatalogueOIDsAreCited`, `TestCertificateSerialAndFingerprintIn17`, `TestSuiteAlgorithmsAreUnique`. The existing schema validation tests (1.6 and 1.7) run on the new goldens. |
| Web | `TestMotionRulesAreRespected`, `TestChartsAreKeyboardReachable` (a static check that `wireMarks` is used by every view that draws marks), `TestCountUpIsUsedOnlyForFigures`; the existing design, vocabulary and copy guards. |

## 2. Browser journey (testing/e2e/charts-phase.mjs, run by journey.mjs)

Against demo-targets, with endpoints at L3, L1, L0 and L4 and SSH servers scanned:

| ID | Steps | Pass |
|---|---|---|
| CHT-1 | On the Overview, read each level count; click each linked level | The list count equals the figure; the chip names the level |
| CHT-2 | Open each list with every filter in the address; change a control | The address changes with replace (history length unchanged); Back returns to the chart |
| CHT-3 | On Inventory, click each ring segment, a purpose segment, a protocol row, each certificate segment and a software row | Each list count equals its figure |
| CHT-4 | Click a severity chip, then an exposed note | Findings and list filtered; no nested `<a>` anywhere (`a a` selector empty) |
| CHT-5 | On a report with two or more scans, click the first history point | The report shows that scan |
| CHT-6 | Tab to a ring segment; press Enter. Hover a bar | Navigates; the tooltip is visible with text; siblings at opacity .35 |
| MOT-1 | Arrive at Inventory: `.enter` present, then removed; a forced repaint does not re-add it | Pass |
| MOT-2 | Read a stat figure during the first 100 ms and at 1 s | It counts, then holds; on a poll with no change, no re-count |
| MOT-R | Reduced motion emulated (CDP) | The computed `animation-name` is `none` on every chart mark; figures show their final value at once |

## 3. Screen walk (UX-REVIEW-009)

The PM and the design lead walk every rendered screen. Each one is captured in light and dark at 1440×900,
1024×768 and 390 px. Each finding is written down with a severity and a decision, fixed, and captured again.

## 4. Deploy

`testing/deploy/smoke.sh` PORT case. On Podman (WSL), run the image with `-e CIPHERHORIZON_PORT=9000
-p 127.0.0.1:9000:9000`. It must report healthy, and `/api/v1/health` must answer on 9000.

## 5. Regression

The full `journey.mjs`, `security.sh`, lint (`GOOS=linux` and `GOOS=windows`) and govulncheck. All green, and the
same count or more as QA-REPORT-008.
