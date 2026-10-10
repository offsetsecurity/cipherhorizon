# RESEARCH-005: Why CipherHorizon does not read as a TLS scanner and CBOM tool, and what successful products do instead

| | |
|---|---|
| **Status** | Draft for owner review, 2026-10-03 |
| **Trigger** | Owner review of the 0.2.0 + T1 build: "overly populated with text… very confusing to consume… very difficult for anyone to know what the product does… the reports are hidden… it does not seem to be a TLS scanner and CBOM tool… so many mixed flows." |
| **Method** | (1) Audit of the running product with realistic data (the end-to-end journey's database: 10 endpoints, 2 hosts, 2 imports, 14 systems), every page measured by a script (`scratchpad/audit.mjs`): words, first-screen words, controls, page height. (2) A first-run audit on an empty database. (3) Teardown of products that succeeded at the same two jobs: checking a TLS endpoint, and collecting a bill of materials. |
| **Feeds** | PRD-005 (product focus and flows), UX-DESIGN-003, ENG-HANDOFF-004, QA-PLAN-005 |

## 1. The two jobs the owner wants done

From the owner's own words (2026-10-02): *"people should have a place to collect CBOM and the TLS scanner so that remote
TLS configuration can be checked."* That is two jobs, in this order of frequency:

1. **Check a TLS endpoint.** "Is this server configured well, is it ready for post-quantum, and what do I fix?" Done
   often, by anyone, in seconds. Success = a clear verdict and a short fix list, and a report you can keep or share.
2. **Collect cryptography into one inventory (CBOM).** "What cryptography do we have, where, and what is
   quantum-vulnerable?" Fed by scans, by the collector on machines, and by CBOMs from other tools. Success = one
   inventory you can browse and export as a CycloneDX CBOM.

Everything else (systems, ranking, correlation review, M-23-02 fields) serves these two jobs or is advanced.

## 2. What a newcomer meets today (evidence)

### 2.1 The first screen

An empty install opens on **"Estate — Your systems, in the order to look at them for the move to post-quantum
cryptography"** and a "Build your estate" panel offering three equal doors (scan a service, inventory a machine, import a
CBOM), each with a paragraph. 192 words before anything has happened. The words *TLS scanner* and *CBOM inventory*
do not appear as the product's purpose; "estate", "systems" and "ranks" do.

With data, the home page is a ranked list of "systems" named after addresses (`127.0.0.1:9441`), each tagged *based on
evidence only*, with owner *not provided*, and a banner about "3 possible matches between endpoints and systems". **No
TLS result, no score, no certificate and no CBOM is visible on the home page.** 541 words on the first screen.

### 2.2 Navigation: 13 surfaces, 21 concepts

Menu: Estate · *Manage*: Certificates, Review, Imports · *Monitor*: Endpoints, Hosts, Findings, TLS overview ·
footer: Get the collector, About. Two more pages exist with no menu entry: **Scans** and **CBOM**.

Concepts a user must learn: estate, system, service, endpoint, host, machine, asset, certificate, import, CBOM,
collector, review, match/link, finding, scan, source, observation, evidence class, coverage, readiness level, TLS
hygiene. Several name the same thing (endpoint = service = asset; host = machine).

### 2.3 Measurements per page (populated database, 1440×900)

| Page | Words | First-screen words | Controls (buttons+links) | Height (screens) |
|---|---|---|---|---|
| Estate (home) | 399 | 541 | 41 | 1.7 |
| Endpoint report | **1,959** | 251 | 65 | **8.4** |
| Findings | **3,302** | 203 | **242** | **11.9** |
| System | 525 | 211 | 21 | 3.2 |
| About | 769 | 198 | 8 | 3.2 |
| Endpoints list | 182 | 156 | 28 | 1.0 |
| CBOM (no menu entry) | 75 | 71 | 10 | 1.1 |

### 2.4 The two jobs, walked

- **Check a TLS endpoint**: Estate → *Add endpoints* (dialog: target, name, tags) → the endpoint is added and queued →
  go to *Monitor → Endpoints* → click it → the report. Four steps and a menu change, and the report itself is 8 screens.
  The Endpoints list is the closest thing to a TLS scanner in the product, and it is the fifth menu item under
  "Monitor".
- **Get a CBOM**: there is no CBOM in the menu. A CBOM is reachable as an *Export* option on an endpoint, as buttons on
  a host page, or as "CycloneDX 1.7" buttons in a system's services table. There is no single inventory of
  cryptography across sources, and no "download the whole inventory as a CBOM".

### 2.5 Diagnosis

1. **The product's centre moved.** STRATEGY-001 repositioned toward "cryptographic posture management" and made a
   ranked list of *systems* the home page. The data model (systems, correlation, evidence classes) is sound, but it is
   now the *face* of the product, and it is the least intuitive part of it. The two jobs the owner named are
   underneath it.
2. **Reports are pages, not things.** A scan result has no identity in the UI: no "report" noun, no list of reports,
   no share/download at the top, no URL that reads as a report.
3. **Inputs are scattered by source.** Scanning, uploading a host inventory and importing a CBOM are three menu
   entries (Endpoints, Hosts, Imports) plus a footer button, although all three *add data to one inventory*.
4. **Outputs are scattered by type.** Findings, TLS overview, Certificates and the Estate ranking are four views of
   one question ("what is wrong and where"), each with its own vocabulary.
5. **Every page explains itself in full, always.** Purpose paragraphs, evidence notes, citations, methodology and
   "how we tested" are all expanded by default. Correct and sourced, but the answer is buried under the explanation.
6. **Internal concepts leak.** "Based on evidence only", "evidence class", "observation", "source class", "rung",
   "possible matches" are engineering words a scanner user should never have to learn.

## 3. Products that succeeded at the same jobs

| Product | Job | What made it work | What we take |
|---|---|---|---|
| **Qualys SSL Labs Server Test** | Check a TLS endpoint | One input on the home page; the result *is* the page. A summary box first (one overall rating and four bars: certificate, protocol support, key exchange, cipher strength), then short coloured notices, then detail sections (Certificate, Configuration, Handshake simulation, Protocol details) as compact label/value tables. Recently seen and best/worst lists on the home page. | Input-first home; summary box with four dimensions; notices in one line each; detail as tables, not prose. (Not its letter grades: the product keeps its own TLS hygiene score.) |
| **internet.nl** | Check standards compliance | A handful of plain-language categories ("Secure connection?", "Security options set?"), each one icon + one sentence; a percentage score; every subtest collapsed to a line with *pass / fail / recommendation / information* and the explanation behind a toggle. Only *required* subtests count. | Section = question + one verdict line; detail and rationale behind a disclosure; info never looks like failure. |
| **Mozilla HTTP Observatory** (MDN) | Check HTTP security headers | One input; a score; a test table (test, pass/fail, score impact, one-line reason); "recommendation" column; history of scans of the same site. | One table of checks with the impact in one column. |
| **testssl.sh** | Check a TLS endpoint (CLI) | Fixed section order, one line per check, colour for state, nothing else. | One line per check is enough for experts. |
| **Hardenize → Red Sift Certificates** (founded by SSL Labs' author) | Monitor many endpoints and certificates | Grew the one-off test into continuous monitoring: an inventory of hosts and certificates, alerts on change and expiry; the per-host report keeps the one-off report's shape. | The list of scanned endpoints is an inventory with the same report behind each row. |
| **OWASP Dependency-Track** | Collect SBOMs | One object (a *project*) receives BOMs by upload or API; the portfolio shows components and their risk across projects; the BOM goes in, analysis comes out, export is one click. | "Add a BOM" is the one input for inventory; an inventory across sources; export from the top. |
| **CBOMkit (PQCA, ex-IBM)** | Generate and view a CBOM | Two inputs (scan a repo, upload a CBOM); an inventory of CBOMs; a viewer with statistics and a compliance check (quantum-safe / vulnerable) per component. | A CBOM viewer with a quantum-safe summary is the expected shape of "a CBOM tool". |
| **SandboxAQ AQtive Guard** | Enterprise crypto inventory | Sensors produce traces → *upload to a project* → analysis → dashboard of algorithms, keys, certificates by health; navigation is Dashboard, Projects, Sensors, Integrations. | Inputs (sensors/uploads) are one concept; the dashboard is the inventory. |

Common pattern across all of them:

1. **The home page is the primary action** (an input box, or "add a BOM"), plus what was done recently.
2. **The result leads with a verdict** (one score or rating, a handful of dimensions) and **a short list of what to
   fix**; detail follows in compact tables; explanation is opt-in.
3. **One noun for the result** ("report", "project", "scan") that you can list, open, share and download.
4. **Inputs converge** into one place; the source is a property, not a menu.
5. **Few top-level concepts**: SSL Labs has 1, internet.nl 3, Dependency-Track 4, AQtive Guard 4.

## 4. Why CipherHorizon fails against that pattern

| Pattern | Successful products | CipherHorizon today |
|---|---|---|
| Home = primary action | Input box / add BOM | A ranked list of systems |
| Verdict first | One score + few dimensions | Summary strip exists on the report, but under 2 menu levels |
| Short fix list | Notices, one line each | Fix first exists, then 1,959 words |
| Explanation opt-in | Behind toggles | Expanded everywhere |
| One noun for results | Report / project | None; "endpoint", "asset", "service" |
| Inputs converge | One "add" | Endpoints, Hosts, Imports, collector button |
| Few concepts | 1–4 | 13 surfaces, ~21 concepts |
| CBOM visible | Viewer + export | No menu entry; export hidden per asset |

What we have that they don't (the moat, kept): post-quantum key-exchange detection that offers rather than assumes
(offered vs negotiated), cited findings, evidence that says what was not seen, host-side inventory including native
Windows cryptography, and one inventory across scans, machines and imported CBOMs. The moat is real; the product hides
it behind its own model.

## 5. Recommended shape

**One sentence**: *CipherHorizon scans your TLS endpoints and collects your CBOMs into one cryptographic inventory,
and tells you what is not ready for post-quantum.*

**Navigation: three jobs, one utility.**

| Menu | Is | Replaces |
|---|---|---|
| **Scan** (home) | An input ("host or host:port", Enter scans), then *Recent reports* as compact rows with the verdict | Estate as home; Add-endpoints dialog for the single case |
| **Reports** | Every scanned endpoint, its latest report and history; bulk add/scan; fleet summary on top | Endpoints, Scans, TLS overview, fleet Findings |
| **Inventory** | One CBOM inventory across all sources: algorithms, certificates, protocols/suites, software; filters (quantum-vulnerable, source, system); *Add data* (upload a CBOM, run the collector, scan); *Download CBOM* | Imports, Hosts, CBOM page, Certificates (as a tab) |
| **Systems** (secondary) | Grouping, owner/criticality, migration order, M-23-02 export; match decisions shown inline | Estate ranking, Review |
| footer | Settings & about | About, Get the collector (moves into *Add data*) |

**The report** (job 1) follows SSL Labs and internet.nl: a summary box (verdict, PQC readiness, TLS hygiene, certificate)
and *Fix first* on the first screen; then each section as **one line** (status + one-sentence verdict), expanded only
when it has a problem; findings show title and fix, with detail and sources behind "Why"; *How we tested* and methodology
move to one "About this report" disclosure at the end. Download (PDF, JSON, CBOM) and a stable report URL at the top.
Target: the first screen answers "is it OK and what do I fix"; under 400 words visible by default.

**The inventory** (job 2) follows Dependency-Track and CBOMkit: one table of cryptographic assets with where each was
seen and its quantum status; a summary row (counts by status); sources as a filter and a list; one-click CBOM
download of the whole inventory or a filtered slice.

**Language**: user words only on primary surfaces (report, endpoint, machine, inventory, source); evidence classes,
observations and rungs stay in tooltips and exports.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Undoing PRD-003's estate home | Nothing is deleted: systems, ranking, review and M-23-02 stay under *Systems*; only the entry point and labels change. |
| The inventory view across sources needs a new API | The estate graph already holds entities with observations by source (`/api/v1/entities`, `/graph/stats`); an aggregate endpoint and an inventory CBOM export are bounded work. |
| Shorter reports hide detail an expert wants | Every fact stays one click away ("Show details"); exports carry everything; journey tests assert the detail still renders. |
| Breaking links and tests | Old routes redirect (`#/assets/N` → report); journey updated. |

## 7. Decisions for the owner (recommendations in bold)

| # | Question | Recommendation |
|---|---|---|
| D1 | Home page | **Scan input + recent reports** (not the systems ranking) |
| D2 | Top-level menu | **Scan, Reports, Inventory, Systems** + footer |
| D3 | Report default | **Collapsed sections, problems open; explanation opt-in** |
| D4 | CBOM | **One inventory across sources with a whole-inventory CBOM download** |
| D5 | Systems/ranking | **Keep, as a secondary area; review decisions inline** |

## Sources

- Qualys SSL Labs, SSL Server Rating Guide: https://www.ssllabs.com/projects/rating-guide/index.html
- internet.nl, explanation of test report: https://internet.nl/faqs/report/ ; scoring: https://github.com/internetstandards/Internet.nl/blob/main/documentation/scoring.md
- MDN HTTP Observatory: https://developer.mozilla.org/en-US/observatory
- OWASP Dependency-Track documentation: https://docs.dependencytrack.org/
- CBOMkit: https://github.com/cbomkit/cbomkit ; IBM Research, "Managing cryptography with CBOMkit": https://research.ibm.com/blog/quantum-safe-cbomkit
- SandboxAQ AQtive Guard, getting started and dashboard: https://aqtiveguard.sandboxaq.com/docs/getting-started/ , https://aqtiveguard.sandboxaq.com/docs/dashboard/
- Red Sift Certificates (formerly Hardenize): https://redsift.com/pulse-platform/certificates ; acquisition: https://blog.redsift.com/news/red-sift-becomes-the-recommended-certificate-monitoring-service-of-lets-encrypt/
- Internal: audit measurements and screenshots (scratchpad `audit/`, `audit-fresh/`), STRATEGY-001, PRD-003, PRD-004.
