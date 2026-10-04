# UX-DESIGN-005 — Navigation: one place per kind of thing

Status: accepted and built 2026-10-04. Supersedes the menu of PRD-005 (REQ-NAV-1) and PRD-006 D3. The pages'
content is unchanged; what changes is where each page lives, what the menu calls it, and how a person moves between
them.

## 1. Why

The owner, looking at the menu: *the side panel is confusing — Reports, and then you see the data.* The content
was judged right; the structure was not. An audit of the menu against the pages it opens:

| # | Problem | Where | Heuristic broken |
|---|---|---|---|
| P1 | **"Reports" opens a data table**: fleet tiles, a list of endpoints, fleet findings and scan activity. The documents a person would call reports (PDF, CBOM, CSV) are not on it. | `#/reports` | Match between the system and the real world: a label must predict its page |
| P2 | **Machines are three levels deep** (Inventory › Sources › a "Machines" heading), and a machine's page lights up "Inventory". | `#/inventory/sources`, `#/hosts/N` | Recognition rather than recall; one home per object |
| P3 | **Findings across endpoints and machines are a tab of Reports**, though the question "what do I fix?" spans both. | `#/reports?tab=findings` | Visibility of the most frequent task |
| P4 | **The real reports are scattered**: a Download menu on each endpoint, another on Inventory, a CSV on the Endpoints toolbar, standards exports inside each system. Nothing lists them. | several | Consistency; findability |
| P5 | **The home page is a single action** (scan one address) plus a list; there is no "how am I doing" view across endpoints, machines and the inventory. | `#/` | Visibility of system status |
| P6 | **Scan is both a menu place and the only way to start a scan.** From a report or the inventory, scanning another address means leaving for Scan. | `#/` | User control; efficiency |
| P7 | Detail pages say "← Reports" whatever the page; nothing says where in the product you are. | detail pages | Where am I? |

## 2. What people come to do

From the product's purpose (a URL in, everything about it out; the CBOM; reports for others) and the owner's
reviews, the jobs in order of frequency:

1. **Check an endpoint now** — type a URL, read the result.
2. **See where I stand** — across everything: how many problems, how ready for post-quantum, what expires.
3. **Fix things** — what is wrong, worst first, across endpoints and machines.
4. **Know my cryptography** — the CBOM: every algorithm, key, certificate, protocol and library.
5. **Add more** — scan more endpoints, inventory a machine with the script, import a CBOM.
6. **Hand something over** — a PDF for a manager or auditor, a CBOM for a tool, a CSV, a standards file.
7. **Plan the migration** — group into systems, decide which to move first.

## 3. How comparable products arrange this

| Product | Menu | What it teaches |
|---|---|---|
| Tenable Vulnerability Management, Qualys VMDR | Dashboards · Assets · Findings/Vulnerabilities · Scans · Reports | Menu items are **nouns**, one per kind of object; **Reports** means generated documents |
| Snyk | Dashboard · Projects · Issues · Reports · Integrations | Findings across everything are one top-level list; data sources are their own place |
| GitHub security overview | Overview · Alerts by tool · per-repo detail | An overview page summarises and links; each figure opens its list |
| Cryptographic inventory tools (IBM Guardium Quantum Safe, Keyfactor, SandboxAQ AQtive Guard) | Dashboard · Inventory · Findings/Risks · Data sources · Reports · Remediation | The **inventory** is a place of its own, separate from where data comes from |
| Qualys SSL Labs, Hardenize | One input, then the report | The **input** is always one step away |
| Gmail, Linear, Notion | A primary button at the top of the sidebar (Compose, New issue) | The main **action** is a button on every page, not a menu place |

## 4. Principles

1. **One menu item per kind of thing**, named by a plain noun: Endpoints, Machines, Findings, Inventory, Systems,
   Reports. A label says what the page lists.
2. **Every object has one home.** An endpoint's report lives under Endpoints, a machine under Machines, a
   certificate under Inventory. Its page lights up its home in the menu and starts with a breadcrumb.
3. **Actions are buttons, not places.** "Scan a URL" is the primary button at the top of the sidebar, on every page.
4. **Overview first.** The home page answers "where do I stand" with one tile per question, each opening its list,
   and keeps the scan box at the top: the product's promise stays the first thing on screen.
5. **Shallow and grouped.** Seven places in two labelled groups, the way a person thinks of them: what was found
   (Results), and what to do with it (Plan & share).
6. **Reports are documents.** The Reports page lists every document the product can produce, for every endpoint,
   machine and the inventory, and downloads each in one click.

## 5. The new menu

```
[ Scan a URL ]                 primary button, every page (opens the scan box)

Overview                       #/                 where you stand; the scan box on top
RESULTS
  Endpoints                    #/endpoints        websites and TLS services; open one for its report
  Machines                     #/machines         servers inventoried by script or CBOM
  Findings                     #/findings         what to fix, across endpoints and machines
  Inventory                    #/inventory        the CBOM: algorithms, keys, certificates, protocols, software
PLAN & SHARE
  Systems                      #/systems          group endpoints and machines; migration order
  Reports                      #/reports          PDF reports, CBOMs, CSV and standards exports

About                          footer
```

| Page | Lists | Detail page (home lights up) | Primary action |
|---|---|---|---|
| Overview | tiles: endpoints, machines, findings, post-quantum, inventory, certificates; recent results; what to fix first | — | scan box |
| Endpoints | every endpoint; tab *Scan activity* | `#/endpoints/N` (the report: Summary, Configuration, Weaknesses, CBOM, History) | Add endpoints, Scan all |
| Machines | every machine with its post-quantum counts | `#/machines/N` | Add a machine (the scripts) |
| Findings | one line per problem, across both | — | — |
| Inventory | dashboard, then lists; *Sources* lists what it is built from and imports CBOMs | `#/certificates/<sha256>` | Download CBOM, Import a CBOM |
| Systems | migration order; tab *Decisions* | `#/systems/N` | — |
| Reports | inventory report and CBOM; one row per endpoint (security PDF, TLS PDF, certificate PDF, CBOM); one row per machine (CBOM); CSV exports; standards exports per system | — | — |

## 6. Addresses

Old addresses keep working (replaced without a history entry):

| Old | New |
|---|---|
| `#/reports/N`, `#/assets/N` | `#/endpoints/N` |
| `#/reports?tab=findings`, `#/findings` | `#/findings` |
| `#/reports?tab=activity`, `#/scans` | `#/endpoints?tab=activity` |
| `#/assets`, `#/overview` | `#/endpoints`, `#/` |
| `#/hosts`, `#/hosts/N` | `#/machines`, `#/machines/N` |
| `#/imports` | `#/inventory/sources` |

`#/reports` itself now opens the Reports page (documents).

## 7. Acceptance

- The menu reads Overview · Endpoints · Machines · Findings · Inventory · Systems · Reports, in two labelled groups,
  with a "Scan a URL" button above them on every page.
- Each detail page lights up its home and shows a breadcrumb naming it.
- Reports lists the documents and each downloads in one click; it shows no fleet table.
- The scan button works from any page and lands on the new endpoint's report.
- Every old address in §6 lands on its new place.
- No page scrolls sideways at 390 px; the sidebar folds on a phone as before.
