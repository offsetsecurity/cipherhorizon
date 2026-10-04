# QA report 005 — Self-evident results, the CBOM up front, signature-driven inventory

Executes the checks named in [PRD-006](../product/PRD-006-self-evident-results-and-signatures.md) (§3 requirements,
§4 measures). Run on 2026-10-04, Windows 11, Go, Edge headless, fresh database and the demo targets; plus a copy of the
owner's database for the Google and morafinance reports. Requirement status lives in the [RTM](RTM.md) (PRD-006).

## 1. Verdict

**PRD-006 is met.** All 13 P0 and 3 P1 requirements are `done`, with tests, journey checks or this report as evidence.
Not validated: the shell engine on a real Linux machine (§5).

## 2. Results

| Suite | Result |
|---|---|
| `go test ./...`, `golangci-lint run ./...` | pass; clean |
| Browser journey (`journey.mjs` + phases) | **149 / 149** (new: E2E-05.5 every check, E2E-R.1 the version matrix, E2E-R.2 the CBOM tab; rewritten: E2E-05.2/05.4, E2E-F.6..F.9, F-M2, T1-E2E.5..7/.14/.16/.17, E2E-20.1) |
| `testing/e2e/security.sh` | adds the signature and script routes to the token checks |
| New Go tests | `TestChecksListEveryRuleConsideredAndAgreeWithFindings`; `TestTheDatabaseIsValid`, `TestValidationRefusesWhatAnEngineMustNotDo`; `TestSignatureFactsBecomeComponents`, `TestServedEnginesCarryTheirPlatformsSignatures`; the PDF tests now require the version table and the check list |

## 3. Measures

| ID | Measure | Target | Measured |
|---|---|---|---|
| R-M1 | Checks shown on the Google report | every rule considered | **55** (11 found: 7 problems and 4 notes; 44 not found) on Summary's coverage line, all listed in Weaknesses and in the PDF |
| R-M2 | Clicks from a report to its CBOM | 1 | **1** (the CBOM tab) |
| R-M3 | Engine lines changed to collect a new registry key, file or config line | 0 | **0**: a signature in `internal/signatures/signatures.json`; `TestServedEnginesCarryTheirPlatformsSignatures` proves engines carry none of their own |
| R-M4 | Collected items the UI lists | all | **16 / 16** signatures listed under *What the scripts collect* |

<a id="reeval"></a>
## 4. Re-evaluation of stored results

A copy of the owner's `dist/cipherhorizon.db` was started on this build: the log reads "re-evaluated the latest
results with the current rules endpoints=4 rules=eval/5", and each report then shows its check list. Older scans keep
the evaluation they were given.

<a id="engines"></a>
## 5. The engines on real machines

| Engine | Where | Result |
|---|---|---|
| PowerShell 2.0.0 | this Windows 11 machine, standard user | 4 seconds. 143 store certificates; the machine's Schannel cipher-suite order (15 suites); 10 crypto library files (Git's OpenSSL 3.5.7 and libssh2, Firefox NSS 157, GnuPG); PuTTY 0.85. Uploaded: a 141-component CBOM in which OpenSSL 3.5.7 provides ML-KEM, ML-DSA and SLH-DSA; coverage lists every signature |
| POSIX sh 2.0.0 | Git Bash on Windows | syntax and the certificate-file path only (Git Bash has no package manager or sshd) |
| POSIX sh 2.0.0 | Debian, RHEL, Alpine | **not run here** (no container runtime; WSL hangs on this machine). `TestShellScriptOnThisMachine` runs the served script on the Linux CI runner |

The first run found a real engine defect, fixed before this report: PowerShell ignores `-Include` with `-LiteralPath`,
so the file capability matched every file under Program Files.

<a id="flow"></a>
## 6. Flow

- Menu: Scan · Reports · Inventory. Systems (ranking, decisions, CA bundles) sits in the sidebar footer with its
  decision count; every old address still lands.
- A report links to the inventory from its CBOM tab; inventory rows link to reports and machines.
- The machine page now shows the configuration the signatures found and the software and libraries with versions and
  paths, besides the algorithms.

<a id="review"></a>
## 7. Owner review pass (same day)

The owner's review of the running build named five problems; each has a fix and a journey check.

| Problem | Fix | Check |
|---|---|---|
| Systems hidden at the bottom of the sidebar | back in the main menu | F-M2 |
| Reports list: unclear that a row opens a report, gaps, bad placement | five tiles; actions beside the filter; whole row opens the report; "Open report ›" per row | E2E-F.5, E2E-R.5 |
| Reports list said "none" findings for Google (4 medium, 3 low) | the list counts every severity (migration 8 adds low and info counts) | E2E-R.4 |
| Weaknesses: "✔ Certificate has expired — not found" is unclear | passed checks state what was confirmed (`eval/6`); Found / Passed / Not run groups and filter; Details toggle | E2E-05.5, E2E-05.6 |
| Version table: "✔ accepted (deprecated)" is unclear | "Enabled · should be off", "Disabled · good", and a one-line summary | E2E-R.3 |

Re-run: journey **153 / 153**, `security.sh` 87 / 87, `go test ./...` and lint clean. Checked on a copy of the
owner's database at 1440 px: the Reports table fits without sideways scrolling.

<a id="nav"></a>
## 8. Navigation (UX-DESIGN-005)

The owner found the menu confusing ("Reports, and then you see the data"). The analysis in
[UX-DESIGN-005](../product/UX-DESIGN-005-navigation.md) found seven structural problems (a label that did not predict
its page, machines three levels deep, findings hidden in a tab, reports scattered, no overview, scanning as a place,
no breadcrumbs) and rebuilt the menu on six principles drawn from comparable products.

| Check | What it proves |
|---|---|
| F-M2 | menu Overview · Endpoints · Machines · Findings · Inventory · Systems · Reports in two labelled groups, under "Scan a URL" |
| E2E-F.0, E2E-F.3, E2E-F.4 | Overview: focused scan box, latest results, what to fix first, six tiles each opening its place |
| E2E-F.5, E2E-R.4, E2E-R.5 | Endpoints list; a row opens the report, which shows the breadcrumb and lights up Endpoints |
| E2E-N.1, E2E-N.2 | Reports lists documents only, and a PDF downloads in one click |
| E2E-N.3 | Scan a URL works from another page (Inventory) and lands on the report |
| E2E-N.4, E2E-N.5 | Findings and Machines are places of their own; a machine's page names its home |
| F-M6 | every old address lands on its new place |
| NFR-a11y.1 | no sideways scroll at 390 px on any of the seven places |

Re-run: journey **158 / 158**, `security.sh` 87 / 87, `go test ./...` and lint clean.

## 9. Known limits

- Plain-language "why it matters" is per finding category, not per rule (PRD-006 D6).
- The scripts do not collect Windows CNG providers or program import tables; the machine page says so.
- Windows Schannel settings are reported only when set explicitly; a version absent from the registry is at the
  Windows default for that build, which the inventory does not infer.
