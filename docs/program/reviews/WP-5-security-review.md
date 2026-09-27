# WP-5 security review (correlation)

Reviewer role: Security Architect (performed by the assistant against SECARCH-001; not independent). Date 2026-09-26.

## Scope

`internal/estate/correlate.go` (the pure rules), `internal/store/links.go` (persistence, states, merge and split), `internal/server/links.go`, migration 6, the hooks that run correlation after evidence changes.

## Checks and results

| # | Check | Result |
|---|---|---|
| 1 | Only deterministic keys; no fuzzy matching (RESEARCH-003 §4.2) | Pass. J1 (certificate SHA-256), J2 (the endpoint's host name exactly equals a host's machine name), J3 (the presented certificate names the host exactly). Tests assert a near-collision name ("shop" vs "shop.example.test"), an IP address and a name prefix do not match. |
| 2 | Auto-confirmation only on first-party, unique, strong evidence (SR-05, REQ-COR-4) | Pass. Conditions: strength strong (J1), not ambiguous, and every datum first-party (scanner for the endpoint's certificate, collector for the holder, first-party assets for any name). A forged imported document with a real fingerprint gets a proposal of its own; it is never confirmed, and it neither makes the legitimate join ambiguous nor takes it over (ambiguity is judged among first-party holders only). Three mutation checks. |
| 3 | Ambiguity is shown, not resolved (SR-05) | Pass. The same certificate on several systems yields a proposal per holder, each marked ambiguous and medium with the count and its competitors; none joins. Defence in depth: ambiguity both downgrades strength and blocks auto-confirmation; removing both fails two tests. |
| 4 | Shared infrastructure joins nothing (SR-15) | Pass. More than 25 systems holding one certificate produces no candidate (exactly 25 still does, as ambiguous). Only leaf certificates an endpoint presents can join; chain and CA certificates never do. |
| 5 | A rejected link stays rejected (REQ-COR-5) | Pass across a rescan and a new upload; a person's unlink is recorded as a rejection so the pair is not proposed again. |
| 6 | A confirmed join whose evidence disappears is reviewed, not undone | Pass: flagged `stale`, kept confirmed, systems not split; unflagged when the evidence returns. |
| 7 | A join never overwrites operator-set values (DN-1) | Pass. An automatic confirmation that would conflict is refused inside a savepoint, the link stays a proposal and says why on its record; a person's confirmation is refused with 409 and the field names; nothing changes on either. Resolving the disagreement lets it through. |
| 8 | Every decision is attributed and audited (SR-11) | Pass: `auto`, the token label, or `operator`; merge, split, confirm and reject are on the system's audit trail with the reason. |
| 9 | New routes are guarded (SR-12) | Pass: `links` routes are in the route table and covered by the token, forgery, Host and content-type tests. |
| 10 | Resource use (SR-15) | Pass. The pure pass took about 10 ms for 3,000 endpoints against 3,000 hosts. Explanations are bounded (80 characters per name or location) and stripped of control characters; hostile names are tested. |
| 11 | Explanations are honest | Pass: each rule states the values that matched and where each was seen; nothing is a score. |

## Findings

| # | Sev | Finding | Disposition |
|---|---|---|---|
| W5-1 | Medium | **Found by the forged-import test:** an imported document's source was never marked current, so its sightings were ignored by correlation and by "current" views. The forged proposal was silently absent. Not exploitable in the unsafe direction (it under-proposed), but it also meant imported certificates showed as not current. | Fixed: a source that belongs to a system directly (an import) is its own current picture until withdrawn. |
| W5-2 | Low | A manual link recorded its actor as the literal "operator". | Fixed: the token label is recorded (`local` without a token, `api-token` with one). |
| W5-3 | Info | An auto-confirmed join changes the systems list (an endpoint disappears into its host's system). This is intended, audited and reversible by rejecting the link, but it will surprise a user who does not know. | The UI (WP-8) must announce automatic joins on the affected system and in the review queue. |
| W5-4 | Info | The joining datum for J2 and J3 is a host name from an uploaded document unless the host has a collector source. | Such names produce medium or weak proposals only, never an automatic join (tested). |

## Mutation checks

| Guard | Mutation | Failed tests |
|---|---|---|
| Ambiguity | remove both the strength downgrade and the auto-confirm check | `TestACertificateOnSeveralHostsIsAmbiguousAndJoinsNothing`, `TestAmbiguousMatchesAreProposedAndNeverAutomatic` (removing only the auto-confirm check does not fail: the downgrade alone holds, which is the intended redundancy) |
| First-party only | allow untrusted data to auto-confirm | `TestAForgedImportCannotHijackOrBlockTheRealJoin`, `TestAForgedImportGetsAProposalAndTheRealJoinStands` |
| Rejection persists | re-propose rejected links | `TestAmbiguousMatchesAreProposedAndNeverAutomatic` |
| Shared-infrastructure cap | remove | `TestAWildcardOnFortyHostsJoinsNothing` |
| Stale flag | never flag | `TestAConfirmedLinkThatLosesItsEvidenceIsFlaggedNotRemoved` |
| Leaf-only | let chain certificates join | `TestChainCertificatesNeverJoin` |

Sign-off: approved for the WP-5 gate.
