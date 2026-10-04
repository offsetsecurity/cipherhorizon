# PRD-006: Self-evident results, the CBOM up front, and signature-driven inventory

Status: baselined 2026-10-04. Owner direction (2026-10-04): "give a URL, get all data"; a person with less knowledge
must see the action items; the CBOM and the reports are what people do not have elsewhere; show *everything that was
evaluated* (per TLS version, what was running), with a visual; weaknesses in their own place; evaluate the whole flow
and stop solving problems nobody has; inventory scripts must separate **capabilities** (how to pull) from
**signatures** (what to pull), kept in a database that is easy to maintain and lists everything pulled.

## 1. Evaluation of the product as it stands (walked 2026-10-04)

### 1.1 The two jobs, end to end

| Step | Today | Gap |
|---|---|---|
| Give a URL | Scan box accepts host, host:port or a URL; report opens and fills in | none |
| See what was evaluated | Summary lists **failures** only; Details lists suites in one table across versions | A reader cannot see which checks **passed**, nor what each TLS version ran side by side. "Not found" is invisible, so a clean result looks like an empty report |
| Understand what to do | "What to fix": titles plus RFC-heavy remediation | No plain "why it matters" or urgency for a non-expert |
| Get the technical weaknesses | Mixed into Summary (fix list), Details (vulnerabilities card), About (score breakdown) | Three places; no single technical record |
| Get the CBOM (the differentiator) | Download dialog option 5 of 5 | Not visible; the reader never sees that a CBOM was produced, or what is in it |
| Endpoint ↔ inventory | Inventory links to reports | A report does not link to its items in the inventory |
| Inventory a machine | One script per OS with the collection hard-coded | Adding a registry key, a config file or a library name means editing two scripts. Nobody can list everything collected without reading code. Windows collects certificates only |

### 1.2 Problems the product solves that nobody asked for

- **Systems as a top-level place.** The ranking of systems for migration (four rules, owner/exposure/data-lifetime
  metadata, M-23-02 export) and the *Decisions* queue for correlation are enterprise programme management. They add a
  menu entry, a badge, and "same machine as" linking on every report, for a user who came to scan an endpoint or
  inventory a machine. **Decision D3**: Systems leaves the main menu. It stays reachable (sidebar footer, *More*
  menu links, old addresses) because the private CA bundle and existing data live there; nothing is deleted.
- **A Findings tab, a Details tab and a fix list for the same findings** (fixed in UX-DESIGN-004, reorganised again here).

## 2. Decisions

| # | Decision |
|---|---|
| D1 | The endpoint report has five tabs: **Summary** (for anyone: verdict, coverage, action items in plain words), **Configuration** (what the server ran, per TLS version, as a matrix; certificate; key exchange; features; HTTP), **Weaknesses** (the technical record: every check run, found or not, with evidence, fix, sources, triage; the attacks; how the score was worked out), **CBOM** (the endpoint's CycloneDX CBOM shown as a table, with download), **History** |
| D2 | The evaluation records **every check it ran** with its result: *found*, *not found*, or *not checked* (stage skipped). Rules `eval/5`; the server re-evaluates outdated latest results on start (as for eval/4) |
| D3 | Systems leaves the main menu (see 1.2). The menu is **Scan · Reports · Inventory** |
| D4 | Machine inventory = **capability engines** + a **signature database**. Engines (PowerShell, POSIX sh) implement a fixed, small set of read-only capabilities. Signatures are data: one entry per thing to pull, naming the capability, its parameters, why it is pulled and how the server interprets it. The server publishes the database, embeds it in the script it hands out, and lists it in the UI |
| D5 | No signature can run a command: capabilities are read-only primitives (read registry values, list a certificate store, find files by name, read matching lines of a text file, list packages, list installed programs). A signature only parameterises one of them |
| D6 | Plain-language "why it matters" and urgency come from a table per finding category and severity, not per rule, so they stay consistent and maintainable |

## 3. Requirements

### 3.1 Report (REQ-RV)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-RV-1** | Tabs Summary, Configuration, Weaknesses, CBOM, History; old `?tab=` addresses (report, findings, details, tls) land on the nearest new tab | P0 |
| **REQ-RV-2** | Summary shows the verdict and four figures, a **coverage line** ("N checks run: F found, P not found, X not checked") and **action items**: each finding above informational once, in plain words: what, why it matters (by category), urgency (by severity), and the fix, with a link to its record in Weaknesses | P0 |
| **REQ-RV-3** | Configuration opens with a **protocol matrix**: one row per version from SSLv2 to TLS 1.3, showing accepted or not, and for an accepted version the number of suites by strength (strong, acceptable, weak, insecure) drawn as a bar, forward secrecy, the key-exchange groups, and who chooses the order. Opening a row lists that version's suites. Below: certificate, key exchange and post-quantum, features, HTTP | P0 |
| **REQ-RV-4** | Weaknesses lists **every check run**, grouped by area, with its result; a *found* check opens to evidence, why, the attacks it enables, fix, sources and triage. It also shows the attacks table and the score breakdown | P0 |
| **REQ-RV-5** | CBOM shows the endpoint's CBOM: counts by type, a table of components (name, type, detail, post-quantum status), download as CycloneDX 1.7 or 1.6, and a link to Inventory | P0 |
| **REQ-RV-6** | No horizontal page scroll at 800 px and 390 px; each finding title appears once per tab | P0 |

### 3.2 Evaluation (REQ-EV)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-EV-1** | The evaluation lists every rule it considered with its result (found, not-found, not-checked) and section; PQC findings included | P0 |
| **REQ-EV-2** | Results of older rule sets are re-evaluated on start (latest per endpoint) | P0 |

### 3.3 Signature-driven inventory (REQ-SG)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-SG-1** | A signature database (versioned JSON in the repository) lists every item the scripts collect: id, platform, title, why, capability, parameters, interpretation | P0 |
| **REQ-SG-2** | The database is validated at build and test time: known capabilities and interpretations only, unique ids, valid patterns, no parameter that names a key directory or key file | P0 |
| **REQ-SG-3** | The scripts are engines: they read the signatures embedded in them (or a file given on the command line) and run each with the matching capability; adding a signature needs no change to an engine | P0 |
| **REQ-SG-4** | The server serves each engine with the current database embedded, its SHA-256, and the database itself; the UI lists every signature (what, where from, how, why) | P0 |
| **REQ-SG-5** | Facts carry the signature id; the server interprets them with the collector's sensors (packages, certificates, library files) and adds configuration components (Windows Schannel protocols, SSH server algorithms and host keys, OpenSSL defaults, system crypto policy) to the CBOM | P0 |
| **REQ-SG-6** | Every signature that ran reports found, not found or denied, recorded as coverage in the CBOM | P1 |

### 3.4 Flow (REQ-FL)

| ID | Requirement | Pri |
|---|---|---|
| **REQ-FL-1** | Main menu Scan, Reports, Inventory; Systems reachable from the sidebar footer and old addresses | P0 |
| **REQ-FL-2** | A report links to its endpoint's items in Inventory, and Inventory lists link to reports | P1 |

## 4. Measures

| ID | Measure | Target |
|---|---|---|
| R-M1 | Checks shown on a report, Google endpoint | every rule considered (found + not found + not checked) |
| R-M2 | Clicks from a report to its CBOM | 1 |
| R-M3 | Engine code changed to add a new registry key, config file or library name | 0 lines |
| R-M4 | Things the scripts collect that the UI lists | all |
