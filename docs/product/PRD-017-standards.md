# PRD-017 · Published standards, clause by clause

| | |
|---|---|
| Date | 2026-11-08 |
| Status | Built on `feat/crypto-standards`; this document records what was decided and why |
| Roles | Product management, cryptography, UX, engineering, QA (one session, all five chairs) |
| Inputs | [CRYPTO-REVIEW-005](CRYPTO-REVIEW-005-standards-coverage.md) (the crypto analysis that asked for this), RESEARCH-004 §K (profile checks, P2 then), the owner's brief of 2026-11-08: "crypto standards should be everything that can be done and consumed; a good user story and how it will work, not something made out of the blue" |
| Where it shows | `docs/standards.md` (the reader's page), the Standards tab, lists, Overview, PDF, CSV, CLI, API |

## 1. Problem

CipherHorizon says a great deal about an endpoint, with sources, but it never answers the question the buyer's
organisation is actually asked: **does this meet the standard we are held to?** An auditor does not consume a
hygiene score or a readiness level; they consume PCI DSS 4.2.1, NIST SP 800-52, BSI TR-02102 or CNSA 2.0, clause by
clause. Today that mapping is done by hand, by the customer, from our findings. Qualys SSL Labs does not do it
either, which is the opening: a self-hosted scanner that produces the auditor's checklist from the scan it already
made.

The owner's constraint is the right one: the standards must be the real documents, transcribed from the documents,
with the user story written down, not a list of plausible rules.

## 2. Users and stories

| Who | Story | Done when |
|---|---|---|
| Compliance lead, auditor | "Show me, for this endpoint, each PCI DSS 4.2.1 requirement, whether it holds, and the evidence." | The Standards tab lists each clause with the requirement number, a status and what was seen; the PDF and a CSV carry the same list. |
| German federal supplier | "Which of my servers do not meet TR-02102-2 / -4, and which table do they break?" | The Overview's Standards panel opens the servers that do not meet; each report names the offending suite, group or signature and the table. |
| Security architect | "Across 300 endpoints, where do we stand against NIST SP 800-52 and Mozilla Intermediate?" | One bar per standard on the Overview; the CSV export has `standards_met` / `standards_not_met`. |
| Platform engineer in CI | "Fail the pipeline if the API gateway stops meeting BCP 195." | `cipherhorizon tls scan --fail-on standard=bcp195 api.example.com` exits 3 and names the clauses. |
| PQ programme owner | "What does CNSA 2.0 ask of us, and how far are we?" | The CNSA 2.0 profile shows the transition clauses met and the target clauses (ML-KEM-1024, ML-DSA-87) not yet. |

## 3. Requirements

| ID | Requirement | Priority |
|---|---|---|
| REQ-STD-1 | Every TLS and SSH evaluation carries a result per standard: verdict (meets / does not meet / not assessed), counts, and one result per clause with the document's section number, the clause text, its level (binding or recommendation), its status (met / not met / not assessed / does not apply) and what was seen. | P0 |
| REQ-STD-2 | Clauses are transcribed from the document itself; each standard names the edition read and links the document. No clause is taken from another scanner. | P0 |
| REQ-STD-3 | A clause the scan holds no evidence for is *not assessed*, never met; a standard with nothing assessed is *not assessed*. Each standard lists what a network scan cannot see. | P0 |
| REQ-STD-4 | A standard is met when no binding clause fails; recommendations not followed are counted beside the verdict. | P0 |
| REQ-STD-5 | Periods of use in a document (BSI's years) are applied on the day of evaluation. | P0 |
| REQ-STD-6 | Verdicts are stored beside each scan for lists and the fleet summary, and re-evaluation refreshes them. | P0 |
| REQ-STD-7 | Surfaces: a Standards tab on every report with a CSV per standard; a verdict strip on the Summary; a column and `?standard=ID&meets=0|1` filter on the lists; a Standards panel on the Overview whose bars open those lists; a page in the PDF; CSV export columns; a Help topic. | P0 |
| REQ-STD-8 | CLI: `tls standards` / `ssh standards`; the scan prints a Standards block, `--details` every clause; `--fail-on standard=ID`. | P0 |
| REQ-STD-9 | API: `GET /api/v1/standards`, `GET /api/v1/standards/summary`, `standards[]` on evaluations; OpenAPI updated. | P0 |
| REQ-STD-10 | The readiness level and the TLS hygiene score are unchanged by, and do not feed, any standard. | P0 |
| REQ-STD-11 | Tests pin, per standard, an endpoint that meets it and one that fails named clauses; a structural test checks every standard names title, publisher, edition, URL, scope and every clause an id, a section and a text. | P0 |
| REQ-STD-12 | The first set: BCP 195, NIST SP 800-52 Rev. 2, BSI TR-02102-2, ANSSI TLS v1.2, Mozilla Modern and Intermediate 6.0, PCI DSS v4.0.1 4.2.1, CNSA 2.0 TLS; BSI TR-02102-4 and CNSA 2.0 SSH. | P0 |
| REQ-STD-13 | Later: a per-system choice of which standards matter (owners see only theirs); Mozilla Old 5.7; NCSC-NL; CIS benchmarks for SSH; a standards view on the Findings page. | P2 |

## 4. Design

**Model.** `eval.Standard{ID, Title, Publisher, Edition, Protocol, URL, Scope, Requirements, NotAssessed}`;
`eval.Requirement{ID, Clause, Text, Level, check}`; `eval.StandardResult` and `RequirementResult` on
`Evaluation.Standards`. The checks read the evaluation context the rules read (`ctx`, `sshCtx`): versions, suites,
groups, DH parameters, hello-extension facts, chains with their trust, names, lifetime, staple and SCTs, HSTS, the
signature stage. Shared helpers (`versionsNotAllowed`, `suitesOnly`, `groupsOnly`, `minDH`, `minCurve`,
`certKeyAtLeast`, `certSignedSHA2`, `certValidityAtMost`, `etmWhenCBC`, `serverOrder`, `hstsAtLeast`, ...) keep the
transcriptions short and uniform; a BSI period-of-use map is resolved at evaluation time.

**Storage.** Schema 17 adds `scans.standards`, a JSON object of id to verdict; `ScanSummary.Standards` carries it to
lists; the fleet summary counts it. The full clause results live in the evaluation JSON as before.

**Screens.** The Standards tab leads with one card per standard (title, publisher, verdict, a tally bar), then one
checklist per standard: clause, requirement with its level tag, status, what was seen; a filter for clauses not
met; a CSV button; the document link; a folded list of what a scan cannot assess. The Summary gains a card of
verdict chips after the checks bar. The lists gain a "Standards" column (`n of m` met, tone by whole/partial/none)
and sort. The Overview gains a Standards panel (one bar per standard, segments open the lists). The Help topic
carries the user story, the verdict rules and the full catalogue from the API.

**Words.** *Meets*, *Does not meet · n clauses*, *Not assessed*; *met*, *not met*, *not followed* (a recommendation),
*not assessed*, *does not apply*. No grades, no percentages as a headline (the Overview shows a percentage only
beside the count it summarises).

## 5. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Standards are evaluated for every scan, not chosen per scan. | Cheap (pure functions over the report), and the fleet question "where do we stand against X" needs every endpoint judged. A per-system choice of *which matter* is a later filter, not a change to the data. |
| D2 | Faithful over flattering: BSI's tables exclude X25519, ChaCha20 and Ed25519; CNSA 2.0 excludes hybrids; BSI's PKCS #1 v1.5 period ended in 2025. All applied as written, with the detail naming the table. | The feature's value is that the verdict is the document's. Softening it would make it another opinion. |
| D3 | The CNSA 2.0 profiles are carried as the IETF individual drafts they are, named with their revision. | The NSA PDFs could not be re-read in this session; the drafts could, and they are what implementers follow. The 2033 timeline is quoted only as a policy date, not applied. |
| D4 | PCI DSS 4.2.1 is judged by its bullets plus the glossary's *Strong Cryptography* (112 bits; 128 recommended); scope is left to the assessor. | 4.2.1's text is about trusted certificates, secure versions, no fallback and adequate strength; the glossary gives the numbers. |
| D5 | Hygiene and readiness untouched (REQ-STD-10). | They answer different questions; mixing them would re-create the "one score, two meanings" problem STRATEGY-003 removed. |
| D6 | OpenSSH's `*-etm@openssh.com` MACs and `aes*-gcm@openssh.com` count as BSI's hmac-sha2-* and AEAD_AES_*_GCM. | Same algorithm, different negotiation name; the alternative would fail every OpenSSH server on a technicality BSI did not intend. Said in the standard's comment. |

## 6. Out of scope, stated

Probing beyond what the scanner does (0-RTT acceptance, ticket lifetimes, truncated HMAC, renegotiation attempts);
client-side duties; operational and key-management clauses; which endpoints are in a standard's scope. Each is
listed per standard under *Not assessed by a network scan*.

## 7. QA

`internal/eval/standards_test.go`: structure of every standard; an exemplary endpoint meets BCP 195, NIST, Mozilla
Intermediate and PCI and fails Modern, BSI (X25519) and CNSA on the named clauses; the terrible endpoint fails the
named clauses; a scan with stages skipped yields *not assessed* and *does not apply*, never met; BSI's years flip a
verdict between 2025 and 2026 and between 2026 and 2027; a CNSA-conformant endpoint meets the CNSA profile; SSH:
an OpenSSH hybrid server fails BSI on exactly the names outside the tables, a BSI-conformant server meets it, a
CNSA server meets CNSA 2.0, unread lists are not assessed. The demo targets were re-evaluated on a running server
and read by hand (CRYPTO-REVIEW-005 §6).
