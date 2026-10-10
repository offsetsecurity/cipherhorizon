# PRD-005: Product focus — a TLS scanner and a CBOM inventory, in that order

| | |
|---|---|
| **Status** | Baselined 2026-10-03 on the owner's instruction ("Fix it"), with the recommendations of RESEARCH-005 §7 taken as decisions D1–D5. Owner may revise any decision; the change log records it. |
| **Research** | [RESEARCH-005](RESEARCH-005-product-focus-and-flows.md) |
| **Design** | [UX-DESIGN-003](UX-DESIGN-003-focused-flows.md) |
| **Build** | [ENG-HANDOFF-004](ENG-HANDOFF-004-focused-flows.md) |
| **Test** | [QA-PLAN-005](QA-PLAN-005-focused-flows.md) |
| **Traceability** | Requirement IDs use new prefixes (`REQ-NAV`, `REQ-HOME`, `REQ-RPT`, `REQ-INV`, `REQ-SYS`, `REQ-LANG`, `REQ-UNF`); the RTM gains a PRD-005 section and `internal/archtest` reads this PRD. |

## 1. Problem

The product does two jobs well underneath and presents neither first. A newcomer meets a ranked list of "systems",
13 surfaces and about 21 concepts; the TLS report is two menu levels down and eight screens long; there is no CBOM in
the menu and no inventory across sources (RESEARCH-005 §2). Successful products in both jobs lead with the primary
action, put a verdict and a short fix list first, give results one noun, converge inputs, and keep explanation
opt-in (RESEARCH-005 §3).

## 2. Goal

*CipherHorizon scans your TLS endpoints and collects your CBOMs into one cryptographic inventory, and tells you what
is not ready for post-quantum.* A first-time user can scan an endpoint from the first screen, read the verdict and what
to fix without scrolling, and find and download the CBOM inventory from the menu.

**Non-goals.** No change to scanning, evaluation, the data model or the API contract beyond the additions below. No
feature is removed: systems, ranking, match review, M-23-02 export, certificates, hosts and imports remain reachable.

## 3. Personas

| Persona | Job | Today | After |
|---|---|---|---|
| Engineer checking a server | Job 1, one endpoint, now | 4 steps + 8-screen report | Type, Enter, read the first screen |
| Security lead with many endpoints | Job 1 at scale | Endpoints list under "Monitor" | *Reports*: every endpoint, fleet summary, findings |
| Crypto inventory owner | Job 2 | No inventory view; CBOM per asset only | *Inventory*: one table, quantum status, download CBOM |
| Programme manager (M-23-02) | Prioritise systems | Home page | *Systems*: unchanged capability, one menu entry |

## 4. Requirements

### 4.1 Navigation (REQ-NAV)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-NAV-1** | The main menu has exactly four entries, in order: **Scan** (home), **Reports**, **Inventory**, **Systems**. A footer holds **About** only. | P0 |
| **REQ-NAV-2** | Every existing route keeps working: `#/assets`, `#/endpoints`, `#/overview`, `#/findings`, `#/scans` lead to Reports (and the matching tab); `#/assets/N` to that endpoint's report; `#/hosts`, `#/imports`, `#/cbom` to Inventory (Sources); `#/certificates` to Inventory (Certificates); `#/review` to Systems (Decisions). Detail pages (`#/hosts/N`, `#/certificates/FP`, `#/systems/N`) stay and mark their parent menu entry active. | P0 |
| **REQ-NAV-3** | The product sentence of §2 appears under the brand in the menu. | P1 |
| **REQ-NAV-4** | The pending match-decision count shows on **Systems**. | P1 |

### 4.2 Scan, the home page (REQ-HOME)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-HOME-1** | The home page leads with one input ("Host or host:port") and a **Scan** button; Enter scans. It finds the endpoint if it exists or adds it, starts a scan, and opens its report showing live progress. | P0 |
| **REQ-HOME-2** | The authorisation notice is one line under the input. A target the server refuses (SSRF guard, invalid) shows the reason inline, not in a dialog. | P0 |
| **REQ-HOME-3** | **Recent reports**: the last 8 scanned endpoints as one row each: name, PQC readiness, TLS hygiene, certificate days left, findings count, when; the row opens the report. Empty: one sentence. | P0 |
| **REQ-HOME-4** | Two secondary links under the input: *Scan many endpoints* (the bulk dialog) and *Add a CBOM or machine inventory* (Inventory's Add data). | P0 |
| **REQ-HOME-5** | An inventory card: counts of algorithms and certificates, how many are quantum-vulnerable, a link to Inventory. Hidden while the inventory is empty. | P1 |

### 4.3 Reports (REQ-RPT)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-RPT-1** | **Reports** lists every endpoint with its latest result (the current Endpoints table), with a fleet summary above it: endpoints by PQC readiness, by TLS hygiene band, certificates expiring within 30 days. | P0 |
| **REQ-RPT-2** | Reports has tabs: **Endpoints** (default), **Findings** (the fleet findings list), **Activity** (the scans list). The TLS overview's charts move to the fleet summary or are dropped. | P0 |
| **REQ-RPT-3** | A report has a stable address `#/reports/N` (and `?scan=ID` for a past scan) and, at the top, **Download** (PDF, JSON, CBOM) and **Copy link**. | P0 |
| **REQ-RPT-4** | The first screen of a report (1440×900) shows the verdict summary and *Fix first* (or "nothing to fix"). | P0 |
| **REQ-RPT-5** | Each section renders as **one line**: name, status (symbol + word), one-sentence verdict. Sections with *Problem* or *Needs attention* are open by default; others are closed. *Expand all* / *Collapse all* exist. | P0 |
| **REQ-RPT-6** | Inside a section, a finding shows its severity, title and fix; detail, evidence, labels and citations are behind **Why and sources**. Tables of data are behind **Show data**. | P0 |
| **REQ-RPT-7** | Section purpose lines are at most 15 words. *How we tested*, reference data, methodology and the TLS hygiene breakdown move into one **About this report** disclosure at the end. | P0 |
| **REQ-RPT-8** | With defaults, the visible text of a report is at most 40 % of the 0.2.0+T1 report for the same scan (measured on the broken-chain and terrible-legacy demo endpoints). Nothing is lost: expanding everything shows every fact the T1 report showed. | P0 |
| **REQ-RPT-9** | The report keeps its Findings (triage) and History tabs. | P0 |

### 4.4 Inventory (REQ-INV)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-INV-1** | **Inventory** opens on a summary: algorithms (and how many are quantum-vulnerable), certificates (and how many expire within 30 days), protocols and suites, sources. | P0 |
| **REQ-INV-2** | Tabs: **Algorithms**, **Certificates** (the current certificates view), **TLS** (protocols, suites, groups), **Software**, **Sources**. | P0 |
| **REQ-INV-3** | An inventory row shows the name, its quantum status (*quantum-vulnerable*, *quantum-safe*, *not applicable*, *unknown*, from the cited PQC classification the CBOM already uses), where it was seen (number of systems and endpoints/machines, expandable to the list), its sources (scan, collector, import) and when last seen. | P0 |
| **REQ-INV-4** | Filters: text, *only quantum-vulnerable*, source (scan/collector/import). | P0 |
| **REQ-INV-5** | **Download CBOM** (CycloneDX 1.7 default, 1.6 option) of the whole current inventory: the union of the latest CBOM of every endpoint and every machine, components merged by reference, each component carrying where it was seen. The document is valid against the vendored schema. | P0 |
| **REQ-INV-6** | **Sources** lists every source (endpoint scans, machine inventories, imported CBOMs) with when it last reported; rows open the existing detail pages. **Add data** offers the three inputs in one dialog: scan an endpoint, upload a machine inventory (with the collector download), import a CBOM. | P0 |
| **REQ-INV-7** | Imported CBOM components are included in the downloaded CBOM only when the user ticks *Include imported*; they keep the import as their source. | P1 |

### 4.5 Systems (REQ-FSYS)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-FSYS-1** | **Systems** holds the current ranked list (the Estate page) under its own title, with plain subtitles. | P0 |
| **REQ-FSYS-2** | Match decisions (the Review page) are a **Decisions** tab of Systems, with the count. | P0 |
| **REQ-FSYS-3** | The "based on evidence only" badge becomes "no owner details yet", linking to the system's details. | P1 |

### 4.6 Language (REQ-LANG)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-LANG-1** | Primary surfaces (menu, Scan, Reports, the report's first screen, Inventory summary) use only: *report, endpoint, machine, inventory, source, system, finding, certificate, algorithm*. They never show *estate, asset, service, host, evidence class, observation, rung, stream, possible matches, based on evidence only*. | P0 |
| **REQ-LANG-2** | A test fails if a forbidden word appears in a primary surface's text. | P0 |
| **REQ-LANG-3** | README's first paragraph and About lead with the product sentence. | P1 |

### 4.7 Non-functional (REQ-UNF)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-UNF-1** | From an empty install, a report is one action away: type a target, press Enter (journey-measured). | P0 |
| **REQ-UNF-2** | No API route is removed or changed incompatibly; additions are documented in OpenAPI (parity test). | P0 |
| **REQ-UNF-3** | 390 px wide and dark mode work on every changed page; no horizontal page scroll. | P0 |
| **REQ-UNF-4** | Target text stays `textContent`-only; CSP unchanged; the inventory CBOM export is bounded (size cap, streaming not required) and goes through the guarded mux. | P0 |
| **REQ-UNF-5** | The visual identity of the 0.2.0 polish pass is kept: shallow labelled navigation, the violet/amber colour identity, no generic dashboard look. | P0 |

## 5. Success measures

| ID | Measure | Today | Target |
|---|---|---|---|
| F-M1 | Steps from empty install to a report | 4 + a menu change | 1 (type, Enter) |
| F-M2 | Top-level menu entries (incl. hidden pages) | 9 + 2 hidden | 4 |
| F-M3 | Report words visible by default (terrible-legacy) | 1,959 | ≤ 40 % |
| F-M4 | Clicks from any page to a whole-inventory CBOM | not possible | ≤ 2 |
| F-M5 | Forbidden words on primary surfaces | many | 0 |
| F-M6 | Old links that do not resolve | — | 0 |

## 6. Decisions

| # | Decision | Source |
|---|---|---|
| D1 | Home is the scan input and recent reports | RESEARCH-005 §7 |
| D2 | Menu: Scan, Reports, Inventory, Systems; About in the footer | RESEARCH-005 §7 |
| D3 | Report sections collapsed unless they have a problem; explanation opt-in | RESEARCH-005 §7 |
| D4 | One inventory across sources, whole-inventory CBOM download | RESEARCH-005 §7 |
| D5 | Systems and ranking kept as a secondary area; decisions inline | RESEARCH-005 §7 |

## 7. Change log

| Date | Change | By |
|---|---|---|
| 2026-10-03 | Baselined on the owner's "Fix it" | PM |
