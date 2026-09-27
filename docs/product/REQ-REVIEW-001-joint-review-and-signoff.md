# REQ-REVIEW-001: Joint requirements review — Product Manager and Security Architect

| | |
|---|---|
| **Date** | 2026-09-26 |
| **Reviewed** | PRD-003, SECARCH-001, RESEARCH-003 |
| **Outcome** | **Baselined**, with the changes below recorded |
| **Honesty note** | Both roles were performed by the same assistant working through the roles' checklists against each other's drafts. This review is a structured challenge process, **not** independent human sign-off. The product owner's approval (§4) is the actual authority, and this document lists what they are being asked to approve. |

## 1. How the review was run

1. PM drafted PRD-003 from the research; the Security Architect drafted SECARCH-001 from the same research and from the code.
2. Each role challenged the other's document with a fixed checklist: **PM →** is each security requirement testable, proportionate, and traceable to a user need; **Security Architect →** does each requirement introduce a threat not covered, is each trust assumption stated, is the default the safe one.
3. Disagreements were resolved by recording the decision and reason, not by averaging.

## 2. Challenges raised and how they were resolved

| # | Raised by | Challenge | Resolution | Effect |
|---|---|---|---|---|
| 1 | Security Architect | Original draft auto-joined an endpoint to a host on IP match. Addresses are shared through NAT/load balancers and names are spoofable. | IP/name matching is **medium** strength and only ever **proposes**. Only a unique fingerprint match from first-party data auto-confirms. | REQ-COR-1, -4; SR-05 |
| 2 | Security Architect | A UI-uploaded "collector" CBOM would inherit first-party trust and could auto-confirm links or overwrite evidence. | Trust follows the **authenticated channel**, not the document. UI/CLI uploads are `imported` unless an operator explicitly marks them, audited. | REQ-COR-4, REQ-ING-4; SR-03 |
| 3 | Security Architect | CBOM-Repository compatibility would add an unauthenticated write endpoint. | Demoted **P1 → P2**, default off, separate listener, write-only, mandatory token or allowlist, inbox for unassigned documents; blocked until OQ-2 (can Lens authenticate?) is answered. | REQ-ING-10; SR-09 |
| 4 | Security Architect | The subject a CBOM names for itself cannot be trusted (RESEARCH-003: one sample has none, one names the tool). | Operator assigns the subject; the document's claim is stored, shown, not used. | REQ-ING-3; SR-04 |
| 5 | Security Architect | "Never read private keys" must be verifiable, not a promise. | Decoy-key fixtures, skip-undecoded rule, and a **mutation check** (remove the guard → the test must fail) are acceptance criteria. Windows uses a property, never a key handle. | REQ-CERT-4; AC-CERT-2; SR-06 |
| 6 | Security Architect | Windows certificate-store enumeration is a new syscall surface. | Confined to `internal/winapi`, read-only flags, caps and timeouts, a **written syscall review as a merge gate**, oracle comparison. | REQ-CERT-1; SR-07 |
| 7 | Security Architect | Linux certificate directories are full of symlinks (Debian trust store); naive walking escapes the root, naive refusal finds nothing. | Explicit tested resolution rule (design note DN-4): follow only symlinks whose target stays inside the sensor's root and is a regular file. | REQ-CERT-2; SR-16 |
| 8 | Security Architect | The graph could hide a destructive migration. | Raw documents are immutable and authoritative; graph is a rebuildable projection; backup + transaction + failure-injection test. | REQ-MOD-1, -5; SR-10 |
| 9 | Security Architect | Mutating routes added later could miss CSRF/Host/token checks. | The security script enumerates mutating routes from the route table and asserts the three checks for each; a new route without the guard fails CI. | SR-12 |
| 10 | Product Manager | Security Architect wanted per-user identity and RBAC for the audit trail. | **Refused as out of scope** for 0.2.0 (a larger product decision). Audit records the token label; the limit is stated in SECARCH-001 §5 and PRD non-goals. | Non-goal |
| 11 | Product Manager | A per-certificate finding for every Windows root would bury users (hundreds of roots). | Roots/intermediates summarised as trust anchors; end-entity certificates itemised. Security Architect accepted, on condition that *changes* to the root set are reported. | REQ-CERT-5 |
| 12 | Product Manager | A single priority score would be easy but unexplainable and would need invented weights. | Ordered, cited **rules** with per-row explanation; no composite number. Security Architect agreed (an opaque score is also a manipulation target — an imported document could game it). | REQ-PRI-1 |
| 13 | Both | Should correlation carry a numeric confidence? | **No.** Three labels from a fixed table plus the fired rules. Consistent with the prior decision not to invent a confidence scale. | REQ-COR-2 |
| 14 | Product Manager | Performance targets can't be promised without measurement. | Targets kept as *design targets to be measured and reported*, not claims. | REQ-NFR-1 |
| 15 | Product Manager | M-23-02 language might read as a compliance claim. | Worded "supports the nine-item structure"; the sole source is CISA's strategy document, not the memo itself. | REQ-EXP-3 |
| 16 | Security Architect | Imported data could mask a weakness by contradicting first-party observations. | Imports add; never delete or downgrade first-party; conflicts side by side. | REQ-ING-8; SR-18 |
| 17 | Product Manager | Too much for one release. | Seven increments with gates; P1/P2 may slip only with PM sign-off; REQ-ING-10 and REQ-EXP-4 explicitly deferred. | PRD §6 |

## 3. Checklist results

| Check | Result |
|---|---|
| Every P0/P1 requirement testable (has an acceptance criterion) | Pass — AC-* ids in PRD §5 |
| Every requirement traceable to a research finding or a stated need | Pass — RTM *Source* column; REQ-UI/REL/NFR items trace to STRATEGY and existing rules |
| Every threat has a testable mitigation | Pass — SR-01…SR-18 each mapped in RTM |
| Defaults are the safe ones (opt-in listener, imports untrusted, no auto-confirm on third-party data) | Pass |
| Unresolved decisions named with an owner | Pass — OQ-1…OQ-5 |
| Terminology rule (no SSL-Labs-style grades) respected | Pass |
| Existing guarantees not weakened (ADR-0004/5/6/9/13, CSP, no external requests) | Pass — restated as REQ-NFR-2…4 |

## 4. Approval requested from the product owner

The owner is asked to confirm (or change) these decisions; the build proceeds on the defaults meanwhile, and none blocks I1–I3:

1. **Name:** keep CipherHorizon (ADR-0014), overriding the earlier preference for CipherAtlas/Cryptograph; run trademark and domain checks before launch.
2. **Scope order:** model → certificates → ingest → correlation/prioritisation → export → UI → QA.
3. **Non-goals** accepted (no RBAC, no source/container scanning, no Postgres, no macOS certificates in 0.2.0).
4. **CBOM-Repository-compatible endpoint** stays P2 and default-off.

## 5. Sign-off

| Role | Decision | Date |
|---|---|---|
| Product Manager | Approved | 2026-09-26 |
| Security Architect | Approved, conditional on the WP-CERT-WIN syscall review before merge | 2026-09-26 |
| Product owner | **Pending** | — |
