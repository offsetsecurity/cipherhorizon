# UX-REVIEW-010 · Does the flow explain itself?

Date: 2026-10-21. Asked by the owner: "Is the flow of the UI good? Is it self-explaining?" Walked as a first-time
reviewer on `feat/classical-strength` (PR #19), on the e2e journey's data. The path: Overview → scan → TLS report
(Summary, Configuration) → a certificate → Inventory.

## Verdict

**The first level explains itself; the second level does not yet.**
- **What works:**
  - The path from scan to the report's Summary to *what to fix* is clear: one scan box, one headline, the action
    items first, every check with its source.
  - Navigation is plain (Results / Plan & share), with breadcrumbs everywhere.
  - TLS and SSH reports have the same tabs.
- **Where a reader gets stuck:**
  - one level down, two scales share words;
  - the Summary does not say how strong the crypto is;
  - the details a reviewer wants (the algorithm parts, the certificate) are hidden or missing.

## Findings

| # | Sev | Screen | What a first-time reader meets | Recommendation |
|---|---|---|---|---|
| U-1 | **High** | Overview, report, Help | **Two scales share words.** The TLS hygiene score's bands are Strong, Sound, Fair, Weak, Broken. PRD-010's suite strength is Strong, Acceptable, Weak, Insecure. "Weak" and "Strong" mean different things one tab apart, and the Overview says "0 rated Strong or Sound". | Give each scale its own words (OD-1). |
| U-2 | Medium | Report › Summary | A red headline "1 thing to fix" is followed first by good news ("Post-quantum: … recorded traffic is protected"). The thing to fix (an untrusted chain) only appears in the next card. | The line under the headline names the thing to fix; the post-quantum sentence moves to the L3 tile, which already says it. |
| U-3 | Medium | Report › Summary | The Summary never says how strong the classical crypto is. *Cipher suites* reads "8 suites accepted: 6 AEAD, 2 CBC". | The row says the weakest suite and its bits ("weakest: Acceptable, 112 bits, RSA-2048 key"), linking to ENH-002's *Algorithms in use*. |
| U-4 | Medium | Report › Configuration | Each suite shows its weakest part only; the classes (asymmetric, symmetric, hash) are never named. | ENH-002. |
| U-5 | Medium | Report › Certificates | The chain cannot be clicked, and the panel called *every field* shows 14 of the recorded fields. | ENH-003. |
| U-6 | Low | Inventory › Algorithms | Generic names (RSA, ECDH, AES, DH) read *not rated* with no reason on the row; the reason (size not known) is only in the API. | Show the reason as the cell's hint: "not rated · size not given". |
| U-7 | Low | Report › Summary | The TLS hygiene tile ("74 Fair") does not say what moves it, or link to how it is worked out. | The tile links to Help › TLS hygiene, as the strength legend now does. |
| U-8 | Low | Overview › TLS endpoints tile | "6 scanned, 1 failed; 0 rated Strong or Sound; 4 exposed to harvest-now-decrypt-later" is four facts in one tile. | Keep the count and one fact (exposed); the rest belongs on the TLS endpoints page. |

## Decision (owner, 2026-10-21)

- **OD-1: which scale changes its words? Decided: rename the hygiene bands; keep the suite words.** The new bands
  are Excellent (90+), Good (75+), Fair (55+), Poor (30+) and Failing (below 30). Old stored band names are mapped
  when a scan is read, and the CHANGELOG says so in words.
  - *Why:* the suite words (Strong, Acceptable, Weak, Insecure) are close to NIST SP 800-131A's own usage
    ("acceptable", "disallowed"), and they have just shipped in PRD-010.
  - *Cost:* the API's band names change, so the change carries a read-time mapping of old names, a test for it and
    a CHANGELOG note.
  - *Rejected:* renaming the suite words, and dropping them in favour of bits only.

## Plan

U-1, U-2, U-3, U-6, U-7 and U-8 are small. They go together as one UX fix (PRD-011's UI part), after OD-1. U-4 is
ENH-002 and U-5 is ENH-003.
