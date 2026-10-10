# QA report 004 — Focused flows: a TLS scanner and a CBOM inventory

Executes [QA-PLAN-005](../product/QA-PLAN-005-focused-flows.md) against
[PRD-005](../product/PRD-005-product-focus-and-flows.md) as built per
[ENG-HANDOFF-004](../product/ENG-HANDOFF-004-focused-flows.md) (deviations D-1..D-7 in its §5). Run on 2026-10-03,
Windows 11, Go, Edge headless, fresh database and the demo targets. Requirement status lives in the [RTM](RTM.md)
(PRD-005 section).

## 1. Verdict

**PRD-005 meets its exit criteria.** Every requirement (30 P0, 6 P1) is `done` in the RTM with a test, a journey
check or this report as evidence. All six success measures are met (§3); F-M3 is met on the worst case by a narrow
margin (39.8 % against a 40 % limit). Nothing is committed; the owner reviews and commits.

What changed for a person opening the product: the first screen is a scan box; Enter gives a report; every report
stays under **Reports**; everything the product has seen is one **Inventory** with one **Download CBOM**; ranking
systems is the fourth entry, **Systems**, not the home page.

## 2. Automated results

| Suite | Result |
|---|---|
| `go test ./...` | all 34 packages with tests pass (incl. `TestInventoryIsTheMergedCBOM`, `TestPrimarySurfacesSpeakTheUsersWords`, OpenAPI parity, traceability with PRD-005 added) |
| `go vet ./...`, `golangci-lint run ./...` | clean |
| Browser journey (`journey.mjs` + `t1-phase.mjs` + `estate-phase.mjs`) | **140 / 140** pass |
| `testing/e2e/security.sh` | **75 / 75** pass (adds the three inventory routes to the token check) |

The journey was rewritten where it encoded the old information architecture (the Estate as home, the grouped menu,
the TLS overview's six cards, the sidebar collector button). Those checks now assert the new design (§4); none was
deleted without a replacement.

<a id="measures"></a>
## 3. Success measures

| ID | Measure | Before (RESEARCH-005) | Target | Measured | Evidence |
|---|---|---|---|---|---|
| F-M1 | Steps from empty install to a report | 4 + a menu change | 1 | **1** (type, Enter) | journey F-M1 |
| F-M2 | Top-level menu entries | 9 + 2 hidden | 4 | **4** | journey F-M2 |
| F-M3 | Report words visible by default | 1,959 | ≤ 40 % | **38.6 % / 39.8 % / 28.5 %** | §3.1 |
| F-M4 | Clicks to a whole-inventory CBOM | not possible | ≤ 2 | **2** (Inventory, Download CBOM) | journey F-M4 |
| F-M5 | Forbidden words on primary surfaces | many | 0 | **0** | `TestPrimarySurfacesSpeakTheUsersWords` |
| F-M6 | Old links that do not resolve | — | 0 | **0** of 11 | journey F-M6 |

<a id="f-m3"></a>
### 3.1 F-M3: the same scans under both builds

The T1 build (commit `0883f10`) and this build were run side by side on fresh databases, each scanning the same
three demo targets; words are `innerText` of the page body (closed disclosures are not rendered, so not counted).

| Endpoint | T1 report | This build | Ratio | Height (px) T1 → now |
|---|---|---|---|---|
| broken chain (127.0.0.1:9449) | 1,959 | 756 | 38.6 % | 7,590 → 3,021 |
| terrible legacy, SSLv3 (127.0.0.1:9443) | 1,960 | 780 | **39.8 %** | 7,947 → 3,642 |
| modern hybrid (127.0.0.1:9440) | 1,543 | 440 | 28.5 % | 6,548 → 2,064 |

The worst case first measured 41.3 %. Two repeats were removed to get under the limit, with nothing lost: the first
fact of a section repeated its verdict line (the verdict stays in the section line), and the suite table's flags
repeated "IANA discouraged" (the IANA column stays). The terrible-legacy endpoint has five open sections because five
have problems; a worse endpoint could exceed 40 %. **Recommendation**: if this matters, open only *Problem* sections by
default and leave *Needs attention* closed.

### 3.2 Pages (populated journey database, 1440×900)

| Page | Words before | Words now | Height before → now (screens) |
|---|---|---|---|
| Home (Estate → Scan) | 399 | 180 | 1.7 → 1.0 |
| Endpoint report (terrible legacy) | 1,960 | 780 | 8.8 → 4.0 |
| Findings (fleet) | 3,302 | **306** | 11.9 → 1.7 |
| Reports (was Endpoints) | 182 | 225 | 1.0 → 1.3 (adds the fleet summary) |
| Inventory (new) | — | 231 | 1.1 |
| Systems (was Estate) | 399 | 378 | 1.8 |
| About | 769 | 777 | 3.2 |

The fleet Findings list was not named in PRD-005, but it was the heaviest page in the audit, so it was regrouped as
one closed line per problem with the count of endpoints and machines, the fix once, then each place with its own
evidence and triage (ENG-HANDOFF-004 D-6; journey E2E-F.12). The audit's "first-screen words" and "buttons" columns
are no longer reliable on pages with closed disclosures (Chromium gives hidden disclosure content a layout box), so
words and height are the measures used here.

## 4. Requirement checks added to the journey

| Check | Requirement |
|---|---|
| E2E-F.0 scan box focused on load; E2E-F.2 refused target explained inline | REQ-HOME-1/2 |
| E2E-F.3 up to 8 recent reports with verdict or status; E2E-F.4 inventory card | REQ-HOME-3/5 |
| E2E-F.5 fleet summary and Endpoints/Findings/Activity tabs | REQ-RPT-1/2 |
| E2E-F.6 summary and Fix first on the first screen | REQ-RPT-4 |
| E2E-F.7 only Problem/Needs attention sections open; "Why and sources" closed | REQ-RPT-5/6 |
| E2E-F.8 purpose lines ≤ 15 words; one "About this report" | REQ-RPT-7 |
| E2E-F.9 Download and Copy link; Findings and History tabs kept | REQ-RPT-3/9 |
| E2E-F.10 Sources lists endpoint scans, machines and imported CBOMs | REQ-INV-6 |
| E2E-F.11 Systems tabs and the decision count in the menu | REQ-NAV-4, REQ-FSYS-2 |
| E2E-F.12 fleet Findings grouped and closed | follow-through |
| F-M1, F-M2, F-M4, F-M6 | measures |
| T1-E2E.6/.14/.17, T1-M5 rewritten for one-line sections and Reports | REQ-RPT-5, REQ-UNF-3 |
| E2E-20.1, E2E-22.3, E2E-27.1 rewritten for Systems and Inventory | REQ-FSYS-1/3, REQ-NAV-2 |

<a id="language"></a>
## 5. Language

`TestPrimarySurfacesSpeakTheUsersWords` checks the shell, Scan, Reports, Inventory and Systems source files for
*estate, asset, service, host, evidence class, observation, rung, stream, possible match, based on evidence only*
(a negative control proves the guard fires). README's first paragraph and the About page's first line now read: *scans
your TLS endpoints and collects your CBOMs into one cryptographic inventory, and tells you what is not ready for
post-quantum.* The brand line under the logo is the short form, "TLS scanner and CBOM inventory".

Not covered by the guard: older views embedded in the new pages (the Machines and Imported CBOMs sections of
Sources, the Decisions tab, the system and machine detail pages) and API field names. Their visible wording was
reviewed by hand; "host" and "service" were replaced with "machine" and "endpoint" in the machine upload dialog,
the Machines table and the Decisions tab. The system page and the methodology still say "service" where the model
means it.

<a id="look"></a>
## 6. Look and layout

Reviewed in the journey screenshots (light, dark, 390 px): the violet/amber identity and the labelled navigation are
kept; the generic dashboard (the TLS overview with six KPI cards and charts) is gone; no page scrolls sideways at
390 px (NFR-a11y.1/.2, T1-E2E.14, the estate phase's phone checks). The report's sections and the fleet findings use
the same one-line pattern: a coloured edge for status, a name, a status word, one sentence, a chevron.

## 7. Not validated, and known limits

- **Large inventories**: the merged CBOM is rebuilt on every Inventory request; with the 20,000-component cap it was
  only exercised at demo size (8 sources). No timing was taken at scale.
- **Systems page density**: 378 words, first in rank order with four rules per row; untouched by PRD-005 beyond its
  title and badge, and still the densest page after About.
- **REQ-RPT-4 at 1440×900**: checked at 1280×900 (a smaller screen, so a stricter check).
- **README demo GIF** (`docs/img/demo.gif`) shows the old Estate home and TLS overview; it needs re-recording.
- **Screen readers**: native `<details>` was chosen for its built-in semantics; not tested with a screen reader.
- **Real targets**: the journey uses the loopback demo targets only; no public endpoint was scanned for this report.

## 8. Owner actions

1. Review and commit (nothing is committed).
2. Re-record the README demo GIF.
3. Decide whether *Needs attention* sections should start closed (§3.1).
4. Still open from earlier: commit of the no-SNI placeholder fix, and whether correlated findings should count once
   in the TLS hygiene score.

## 9. Follow-up, same day: real PDF reports and the inventory dashboard

The owner reported that *Download → PDF* only opened the print dialog, and that Inventory did not look like it held
data. Both were rebuilt (ENG-HANDOFF-004 D-8, D-9) and re-verified.

| Suite | Result |
|---|---|
| `go test ./...`, `go vet`, `golangci-lint run ./...` | pass; clean |
| New tests | `TestDocumentIsWellFormedAndReadsBack`, `TestWrapKeepsLinesWithinTheWidth`, `TestEncodeShowsWhatTheStandardFontsHave` (writer); `TestEndpointReportHasEverySectionAndFinding`, `TestReportKindsChooseTheirSections`, `TestInventoryReport` (layouts, with hostile certificate text); `TestDownloadsAreGeneratedPDFs` (server: three kinds, 400/404, dashboard agrees with the lists, inventory PDF). A test-only reader (`internal/pdf/pdfcheck`) checks every cross-reference offset, decompresses the pages and reads back the text, links and outline. |
| Browser journey | **145 / 145** (adds F-M4 rewritten for the dashboard, E2E-D.1..3, E2E-P.1 three PDF kinds, E2E-P.2 *Download → PDF* saves a file and never calls `print`) |
| `security.sh` | **81 / 81** (the dashboard and both PDF routes behind the token) |
| Independent read | pypdf 6.19 opens every generated PDF (page count, outline, text); Edge's PDF viewer renders them (screenshots reviewed: cover band, summary tiles, Fix first, tables across page breaks with repeated headers, finding cards with linked sources, page numbers) |

Sizes on the demo data: full report 8 pages (~35 KB), TLS report 6, certificate report 4, inventory report 3–4.

**Limits.** The PDFs use the standard PDF fonts, so characters outside Windows-1252 (for example a Chinese
certificate subject) print as "?"; the page shows them correctly. The PDF is not PDF/A or tagged for screen readers.

## 10. Follow-up: inventory scripts, the vulnerabilities contradiction, failed scans

| Check | Result |
|---|---|
| `go test ./...`, `golangci-lint run ./...` | pass; clean |
| New tests | `TestLinuxFactsBecomeTheCollectorsCBOM` (dpkg + rpm packages, certificate files, a key-bearing file refused, a climbing path cleaned), `TestWindowsFactsUseTheCertificateStoreSensorOnly` (OS from the facts, no server-side sensor runs), `TestParseRefusesWhatIsNotAFactsFile`, `TestScriptPackageFilterCoversTheKnowledgeBase` (the script filter lets through every name the knowledge base knows), `TestShellScriptOnThisMachine` (runs the real script on Linux with dpkg: skipped on this Windows machine, runs in CI), `TestInventoryScriptsAndFactsUpload` (served text matches its SHA-256; text/plain accepted only on the upload route), `TestVulnerabilitiesSectionAgreesWithItsAttacks` (fails with the fix removed) |
| Real runs | The PowerShell script on this Windows 11 machine (non-admin): 143 store certificates, 224 KB facts file; uploaded, it became a 104-component CBOM with post-quantum verdicts. The shell script runs under Git Bash (syntax and logic; Git Bash has no package manager). |
| Owner's data | A copy of `dist/cipherhorizon.db` started on this build: the four latest results were re-evaluated to `eval/4`; morafinance's Vulnerabilities section is now "Needs attention" with LUCKY13 "Possible" and BEAST "Needs TLS 1.0 with CBC suites; not seen on this server." The owner's database itself was not touched. |
| Browser journey | **146 / 146** (E2E-12.2/12.3/14.2 rewritten for the scripts; E2E-14.3 uploads a facts file through the dialog; E2E-02.4b the failed-endpoint card) |
| `security.sh` | **85 / 85** (adds the script routes) |

**Not validated:** the shell script on a real Debian, RHEL or Alpine machine (no Linux or container runtime here; WSL
hangs on this machine). `TestShellScriptOnThisMachine` covers Debian-family on the Linux CI runner; RPM and Alpine
paths are covered only by the parser and converter tests.

## 11. Follow-up: the report reorganised (UX-DESIGN-004)

Owner feedback on `#/reports/1` (Google): cluttered and badly organised. The same finding appeared three times (Fix
first, inside its section, Findings tab); sections mixed facts, chips, finding cards and nested disclosures.

| Check | Result |
|---|---|
| Browser journey | **146 / 146**. Rewritten for the new layout: E2E-05.2 (each finding once, with sources), E2E-05.4 (vulnerabilities table), E2E-F.6..F.9 (verdict and fix list first; every finding once in Summary and no finding card in Details; header Scan again, Download, More; tabs Summary, Details, History), T1-E2E.4..8, .14 (no sideways scroll at 390 px on either tab), .16 (issue links Details → What to fix → Details), .17 (Details shows facts only and names its issues), T1-M5 |
| Google report, this build (copy of the owner's database) | Summary: 249 visible words, 1.5 screens at 1440 × 900; seven issues on the first screen; Details: 1,803 words, every fact in one place |
| `go test ./web ./internal/server` | pass |

Not changed: the data, the rules, the PDF and the API.

