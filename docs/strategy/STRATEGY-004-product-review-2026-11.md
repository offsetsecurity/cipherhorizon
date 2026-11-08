# STRATEGY-004 · Product review, November 2026: five chairs, one verdict

| | |
|---|---|
| Date | 2026-11-08 |
| Trigger | Owner: "review the product as PM, crypto expert, UX designer, dev and QA; it will compete with Qualys and existing vendors and will be community; make a world-class product; crypto standards should be everything that can be done and consumed, with a good user story" |
| Basis | 0.4.1 on `main` (e7dc9b7), every screen walked on the 23 demo targets, the code and tests read, the ten standards documents read ([CRYPTO-REVIEW-005](../product/CRYPTO-REVIEW-005-standards-coverage.md)) |
| Outcome | The standards layer built in this session ([PRD-017](../product/PRD-017-standards.md), branch `feat/crypto-standards`); a ranked backlog below for the rest |

## 1. Verdict

CipherHorizon at 0.4.1 is a credible, unusually honest scanner with a measurement core ahead of its free and
commercial competitors on post-quantum, PKI and SSH, a coherent design language, and documentation most products
never reach. It was missing the one output the market consumes: conformance to named standards. That is now in.
What stands between it and "world class" is no longer depth; it is three things people expect from a scanner
(client simulation, resumption and 0-RTT, active probes, in that order), a handful of first-run and
fleet-scale UX gaps, and the operational polish of a product used by teams (notifications, ownership, API keys
per integration).

## 2. Product manager

**Position.** Self-hosted cryptographic posture for TLS and SSH with post-quantum readiness and, now, standards
conformance. Against Qualys SSL Labs: internal endpoints, SSH, STARTTLS, PQ depth, standards checklists, no data
leaves the network. Against testssl.sh and SSLyze: a product (history, fleet, PDF, roles) with the same wire depth.
Against commercial posture suites: a free, open, verifiable engine; not their discovery breadth.

**Who buys / adopts.** The security architect or PKI lead who must answer an auditor or a PQ mandate, and the
platform engineer who wants a CI gate. The compliance lead is the new persona the standards layer serves directly.

**Backlog, ranked by value to those people over effort.**

| # | Item | Why | Effort |
|---|---|---|---|
| 1 | **Standards, clause by clause** (built) | The output auditors consume; nobody else has it | done |
| 2 | **Client simulation** | The first operational question; closes the most visible SSL Labs gap; offline from existing data | M |
| 3 | **Resumption and 0-RTT probes** | Turns eight *not assessed* clauses into verdicts; required by BCP 195, NIST, ANSSI, BSI | M |
| 4 | **Notifications**: expiry, a lost standard, a lost readiness level, by webhook and e-mail | A scanner nobody is told by is a report nobody reads | M |
| 5 | **Ownership and tags that mean something**: owner, environment, criticality on systems; lists and PDFs filter by them | Fleet-scale use; already in STRATEGY-001 C5 | M |
| 6 | **Per-system choice of which standards apply** | Owners see their standard, not ten | S |
| 7 | **Scan every address a name resolves to** | SSL Labs does; load-balanced estates differ per address | S |
| 8 | **Opt-in active probes** | Audit scopes; after 2 and 3 | M–L |
| 9 | **Apple and Microsoft root programs** from CCADB | Trust per platform | S |
| 10 | **A public, no-login scanner** (separate repository, planned 2026-11-05) | Community reach; the engine is ready | M |

## 3. Cryptographer

See CRYPTO-REVIEW-005. In one paragraph: the measurement is right and cited; the standards are now consumable and
faithful (BSI and CNSA will surprise people, correctly); the gaps are client-side and behavioural, ranked in its §7;
the IR 8547 citation should move to the October 2026 final.

## 4. UX designer

**What is good.** One scan box; the readiness scale as legend; four instruments on every Summary; "Fix first" with
urgency words; every check listed as found or passed; breadcrumbs; the same tabs for TLS and SSH; charts that open
what they count; the Offset theme applied with restraint. The walk found no clipped badge or contradictory figure
on the demo data.

**What the standards layer added, by the same rules.** A Standards tab that leads with one card per standard
(verdict, tally bar), then a checklist per standard in the document's order; one verdict card on the Summary (chips,
not a sixth instrument, because a standard is a yes/no, not a measure); a `n of m` column on the lists; an Overview
panel of bars that open the lists; the same words everywhere (*Meets*, *Does not meet · n clauses*, *Not assessed*;
*met / not met / not followed / not assessed / does not apply*).

**Findings to fix next** (none blocking):

| # | Screen | Finding | Severity |
|---|---|---|---|
| U1 | Inventory | Renders blank for about two seconds with no skeleton while it loads; every other list shows a skeleton | Low |
| U2 | Endpoints list | Six columns plus Standards at 1100 px is dense; the Standards cell should fold under PQC readiness below 1000 px | Low |
| U3 | Report Summary | With the standards card the Summary is long; consider folding "By area" under a disclosure once standards exist | Low |
| U4 | Overview | The Standards panel sits below "What to fix first"; a compliance lead will want it above the fold: make the status band's Findings cell a sixth "Standards" cell with "k of n met" | Medium |
| U5 | Help | The standards catalogue is long; a sticky in-topic table of contents would help | Low |

## 5. Engineer

**Architecture.** The standards layer is pure functions over the evaluation context, like the rules: no new
probes, no new storage beyond one JSON column, no change to readiness or hygiene. Verdicts are re-derived on
re-evaluation, so a changed transcription or a passed BSI year applies to stored scans at launch. The engine stays
in `internal/`; a later public package can export `Standards()` and the result types unchanged.

**Debt noticed.** The upgrade-matrix test assumed no table grows across an upgrade, which the `upgrade_log` table
does by design; fixed to expect exactly one more row. `assetView` repeats `store.Asset`'s JSON; fine. The e2e
journey is the only check of the UI's behaviour; the standards tab should get a phase.

## 6. QA

Green on this branch: `go build ./...`, `go vet`, `golangci-lint` (0 issues), `go test ./internal/...` and
`./web/` (the OpenAPI coverage test, the vocabulary and copy tests included), the new `standards_test.go` matrix
(structure, exemplary, terrible, not-assessed, BSI years, CNSA, SSH). The server was restarted on the demo
database: schema 16→17 upgraded with a backup, 23 endpoints re-evaluated to `eval/14`, the API and the pages read
by hand (CRYPTO-REVIEW-005 §6). Not run in this session: the full browser journey (`testing/e2e/journey.mjs`),
which should be run before merge, and a standards phase added to it.

## 7. Owner decisions

| # | Question | Recommendation |
|---|---|---|
| OD-1 | Ship PRD-017 in 0.5.0 (with the refdata refresh, PR #34) or as 0.4.2 | **0.5.0**: it adds a schema step and a new tab; it is the release's headline beside the weekly refdata job |
| OD-2 | Order of the next three: client simulation, resumption/0-RTT, notifications | **Client simulation first**: it is the most-asked question and needs no new wire code |
| OD-3 | Keep BSI and CNSA verdicts as strict as the documents | **Yes**; the detail text names the table, and the Help topic says why OpenSSH defaults do not meet TR-02102-4 |
