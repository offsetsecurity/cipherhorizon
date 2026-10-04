# UX-DESIGN-004: The endpoint report, reorganised

Follows owner feedback on 2026-10-03 ("the reports are so cluttered and badly organised it is difficult to see what's
happening") on `#/reports/1` (www.google.com:443). Supersedes the report layout of UX-DESIGN-003 §4; the data, rules
and PDF are unchanged.

## 1. What was wrong (measured on the Google report)

| Problem | Evidence |
|---|---|
| Every finding appears three times | "TLS 1.0 is enabled" in *Fix first*, again as a card inside *Protocols*, again in the *Findings* tab |
| Sections mix four kinds of content | an opened section stacks a purpose line, bullet facts, coloured chips, finding cards with their own "Why and sources", then "Show data" |
| Facts and actions are interleaved | the reader cannot answer "what do I fix?" without reading the facts, nor "what does it accept?" without wading through fixes |
| Six header controls of equal weight | Scan now, Rescan, Download, Copy link, Edit, Delete (red, as loud as Scan now) |
| Overflow at ~800 px | section lines and suite tables run past the right edge; the tab bar shows a stray scroll control |
| Unrelated card at the bottom | "Linked assets" on every report |

## 2. The pattern that works elsewhere

SSL Labs, internet.nl and Hardenize all separate **the verdict and its actions** from **the configuration as
observed**: a short summary a person acts on, and a reference section read only when needed, with one row per fact
and no repeated text. internet.nl adds a checklist of test areas, each with a pass/warn/fail mark and one sentence.

## 3. The new report

Three tabs: **Summary** (default), **Details**, **History**.

**Summary** answers "is it OK, and what do I do?":
1. *Verdict*: one headline ("4 things to fix" / "Nothing to fix") with the readiness sentence, and the four figures
   (PQC readiness, TLS hygiene, certificate, not checked).
2. *What to fix*: every finding above informational, once, worst first. One line each: severity, title, area. Opening
   a line gives the fix, what was seen, the sources and the triage buttons. Informational findings sit in a closed
   "Also noted" list.
3. *Checks*: one row per area (internet.nl style): status mark and word, one sentence, a link into Details.

**Details** answers "what exactly does it accept?": one card per area with the facts and tables only, never a finding
card. A card that has issues lists them by title, each linking back to its line in *What to fix*. The index of areas
is a row of chips at the top. *About this report* (how it was scored and tested) ends the tab.

**Header**: name, address and when it was scanned; *Scan again* and *Download*; everything else (copy link, rescan
schedule, edit, link to a machine, delete) in one *More* menu. Linked machines show as one line under the address,
only when there are any.

The *Findings* tab is gone: its content is *What to fix* (with triage). `?tab=findings` opens Summary at that list.

## 4. Acceptance

- No finding title appears more than once in the Summary tab, and no finding card appears in Details.
- At 800 × 600 and at 390 px wide, no horizontal page scroll; tables scroll inside their card.
- The Summary tab of the Google report fits the verdict, the fix list and the first checks within two screens.
- The journey, PDF and API are unchanged in substance.
