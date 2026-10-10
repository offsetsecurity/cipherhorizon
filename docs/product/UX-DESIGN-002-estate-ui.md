# UX-DESIGN-002 — The estate UI

Status: design for WP-8. Requirements: PRD-003 REQ-UI-1…8, REQ-COR-7 (review queue), REQ-CERT-8, REQ-ING-1 and REQ-ING-7 (import flow). Threat model: SECARCH-001 (the UI shows text that hostile parties control: certificate subjects, imported document contents, system names).

## 1. Who the screens are for

| Person | Comes to answer | First screen | Then |
|---|---|---|---|
| Owner of the migration ("what do I fix first?") | Which of my systems is most exposed, and why? | **Estate** | a system's page |
| System owner | What does my system rely on; what is wrong with its certificates; is the record right? | **System** | edit details, export |
| Auditor | Give me the inventory in the memo's shape; how is each fact known? | **System → Export**, provenance columns | Imports |
| Operator | Did the tool join these correctly? What did that third-party file add? | **Review**, **Imports** | System |

The product is a **cryptographic inventory that ranks systems for post-quantum migration**. The interface says that on the first line of the first screen and nowhere calls itself a scanner-with-a-grade.

## 2. Information architecture

```
Estate            #/                 ranked systems (home)               REQ-UI-2
  System          #/systems/{id}     one system                          REQ-UI-3
Certificates      #/certificates     all certificates, filters           REQ-UI-4
  Certificate     #/certificates/{fp} where it is, findings
Review            #/review           correlation queue (count in nav)    REQ-UI-5
Imports           #/imports          list + import flow                  REQ-UI-6
Sources ▾
  Endpoints       #/assets           unchanged pages, retitled           REQ-UI-1
  Hosts           #/hosts            unchanged pages
  Findings        #/findings         unchanged page
  Overview        #/overview         the former dashboard: TLS endpoint hygiene
About             #/about
```

- The **CBOM** top-level page is gone. A CBOM is an export: it is offered on a system (M-23-02, CycloneDX per endpoint) and on an endpoint page, where the existing tree viewer stays reachable at `#/cbom` for old links but is not in the menu.
- **Dashboard** moves to *Overview* and is retitled "TLS endpoint overview". The hygiene score keeps its place there and on endpoint pages; it is one input to a *service*, never the headline of a system (REQ-PRI-2).
- Old addresses keep working (`#/assets/…`, `#/hosts/…`, `#/cbom`, `#/findings`).

## 3. Screens

### 3.1 Estate (REQ-UI-2)

A table of systems in ranked order. Columns: **#**, **System** (link), **Owner**, **Environment**, **Exposure**, **Why it is here** (the first reason, one line), **Evidence** (`observed` / `imported only` / `nothing yet`). Selecting a row's *Why* toggle reveals all four reasons, each with its cited sources as links (`https:` only, opened `noopener`). A row with `evidenceOnly` carries the visible marker **Based on evidence only** and a link to fill in the missing details (the system page's editor); `missing` is listed in words ("data lifetime, exposure").

- Above the table, one sentence: what the order means ("Systems whose recorded traffic is most exposed to later decryption come first. There is no score; each row says which rules put it here"), a link to the published rules (an expandable list of the four rules with citations), and export/import CSV of the system details.
- No number is shown as a score. Rank is a position.
- Empty state (REQ-UI-7): the guided first run (section 4).

### 3.2 System (REQ-UI-3)

Header: name, rank badge, tier text, "Based on evidence only" marker if it applies. Sections (one page, anchor links at the top, each a `<section>` with a heading; no tabs, so nothing is hidden from search or the keyboard):

1. **Why it is ranked here**: the reasons, as on the Estate.
2. **Details** (metadata editor): owner, environment, criticality, exposure, data lifetime (years), FISMA id, FIPS 199, HVA id, hosting, provider, notes; each labelled with what it is for and, for the M-23-02 items, its item number. A *reason for the change* field (optional). Saving sends only changed fields; a cleared field sends null. 409 (a merge conflict) shows the fields named by the server.
3. **Services and hosts**: the assets under this system, linking to the existing endpoint and host pages; latest scan result and readiness for endpoints, last upload for hosts.
4. **Certificates**: end-entity certificates with subject, **key algorithm and size**, signature algorithm, expiry (days, with words not colour alone), findings; roots and intermediates as a count line ("3 roots, 12 intermediates on this system"), never listed by default. For each place a certificate is held: "no key associated in this store / a key is associated (not read) / not checked", **never** "no private key exists".
5. **Links**: this system's correlation links with their explanation; confirm/reject for proposals; a link that joined automatically says **"Joined automatically because …"** and offers Undo (which is a rejection).
6. **Imported sources**: each import with tool, version, when, by whom (the token label), size, and what was not interpreted; withdraw.
7. **Coverage and blind spots**: from the host summary (what the collector could not see) and a plain statement when the system has no first-party evidence.
8. **Export**: M-23-02 (JSON, CSV) and CycloneDX for its endpoints (1.7, or 1.6). The M-23-02 button carries the wording "supports the structure of OMB M-23-02", never "compliant".
9. **History**: the audit trail (who, what changed, why, when).

### 3.3 Certificates (REQ-UI-4)

Filters: **expiry window** (expired, within 30/90 days, any), **key** (weak: RSA under 2048, unknown size), **signature algorithm**, **origin** (scan, host, imported), **quantum-vulnerable key**. A sort by expiry. A summary line for roots/intermediates and the *root set changes* between two uploads of a host, each with the names added and removed. Row → certificate page: identity, every place with the origin, method quality, position, location, key association wording, and the findings with citations.

### 3.4 Review queue (REQ-UI-5)

Proposed links first, strongest first; each shows the endpoint, the system it would join, **strength as a word**, the rule hits with the matched values, whether it competes with other proposals ("2 other systems also match"), and buttons **Confirm** and **Reject** (with an optional reason). Conflicts (409) show the fields. Below: **Decided** (confirmed/rejected, with who and when) and **Stale** (a confirmed join that lost its evidence: "Its evidence is gone. Review it"). The nav item carries the number of proposals awaiting review.

### 3.5 Imports (REQ-UI-6)

A list of imports (tool, version, system, received, status, observation count, what was not interpreted). **Import a document** flow, one dialog in three steps that are visible at once so nothing is a surprise:

1. Choose a CycloneDX JSON file (client-side limit 32 MiB; `.json`).
2. **Assign it to a system** — choose an existing one or name a new one. The text says: *The document's own idea of its subject is recorded but never decides where its data goes.*
3. Import. The result panel shows: the **detected producer** ("CBOM-Lens 1.7, recognised by its tool entry"), the schema version, "**N facts added**", and a table **Not interpreted** with counts by reason (so a person can see how much of the file was set aside), and the line *Imports add facts; they never overwrite what a scan or collector observed, and never claim a key was used.* A duplicate says so; the "already imported for another system" 409 says to withdraw first.

### 3.6 Wording and terminology

- "System", "service" (an endpoint), "host", "certificate". Never "asset" in the UI text.
- No SSL-Labs-style letter grades. The hygiene score is written "TLS hygiene score" wherever it appears.
- Strength: *strong*, *medium*, *weak* (words). Evidence class: *observed*, *inferred from files*, *imported*.
- Every empty state says what to do next. Every "not provided" says who could provide it.
- Private keys: "no key associated in this store" — the sensor checks a property only and reads no key.

## 4. Guided first run (REQ-UI-7)

An empty Estate shows one card, "Build your estate", with three doors of equal weight and a sentence each:

1. **Scan a service** (an address to probe over TLS) → Endpoints → Add.
2. **Inventory a machine** (the collector) → the existing collect dialog.
3. **Import a CBOM** from another tool → the import dialog.

Below, one line: "Every service and machine becomes part of a **system**; tell us who owns it and how long its data must stay secret and it moves to the right place in the order." As soon as one system exists the card is replaced by the table, and a one-line banner on the Estate names the next useful step: no details yet ("Add an owner and a data lifetime to 3 systems"), or proposals waiting ("2 possible matches need review").

## 5. States and behaviour

- **Loading**: skeleton card. **Error**: the existing `role="alert"` card with *Try again*. **401**: the token dialog. Nothing renders half a page.
- **Long text**: every value wraps (`overflow-wrap:anywhere`); tables scroll inside `.tablewrap`; no horizontal page scroll at 390 px.
- **Focus**: after a route change focus moves to `main` (existing). Dialogs trap and restore focus (existing). Expand/collapse controls are buttons with `aria-expanded`.
- **Colour is never the only carrier**: every tone has a word or symbol. Contrast meets WCAG AA in both themes (the existing tokens; new classes reuse them).
- **Keyboard**: every action is a button or link; the review queue works without a pointer.
- **Refresh**: views load once per navigation; after an action the affected section reloads and focus stays on the control's row.

## 6. Security rules for the UI (REQ-UI-8)

- All text goes through `h()` (`textContent`); there is no `innerHTML` and no string concatenation into markup. `href` values pass `safeHref` (`#/…` or `https://…` only); citation links are `https:` with `rel="noopener noreferrer"`.
- No external request of any kind; no new script or style source; the CSP stays as it is. Fonts are the bundled ones.
- Values from the API used in a *route* (ids, fingerprints) are validated as digits or 64 hex digits before they are placed in an address.
- The client never displays or sends a private key: there is no such field anywhere in the API.
- Hostile fixtures: system names, owners, notes, certificate subjects and SANs, import tool names, subject claims and link explanations contain markup, control characters, RTL overrides and very long strings; **every new view is opened with them** in `testing/e2e/security.sh` and `journey.mjs`, asserting no element or script appears from data and nothing overflows.

## 7. What is deliberately not in this release

- No graph visualisation of the estate (a table is the honest first version).
- No saved views, no bulk decisions in the review queue.
- No in-browser CSV import of system details (the API and CLI have it); the export button is present.
- No per-field permissions: there is one shared token, and the audit trail says so (`api-token`).

## 8. Acceptance

The journey script covers: first run offers three doors and reaches each; an estate of scanned, imported and metadata-less systems is ranked with reasons; entering a data lifetime moves a system and the row stops saying "based on evidence only"; the system page shows certificates with key size and the not-associated wording; the review queue confirms and rejects with the explanation shown; an import shows the detected producer and the not-interpreted table and refuses a system-less request; the M-23-02 download has nine items; hostile strings in every new view render inert; dark mode and 390 px width have no overflow; axe-style checks (names, roles, contrast) pass on each new view where the harness can run them.
