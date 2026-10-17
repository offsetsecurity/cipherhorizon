# UX-REVIEW-009 · Screen walk: charts you can act on, and motion

Status: walked 2026-10-18, before release 0.2.0, for [PRD-009](PRD-009-interactive-charts-motion-port-cbom.md) and
[UX-DESIGN-008](UX-DESIGN-008-interactive-charts-and-motion.md).

**How it was walked.** The PM and the design lead each opened every changed screen. The data came from demo-targets:
- TLS endpoints at L0, L1, L3 and L4;
- SSH servers at L1, L3 and L4.

The screens were seen at 1440×900 and at 375×812 (phone), in light and dark mode. On each, every mark was clicked
and its list counted. Each finding below has a severity and a decision.

## Screens walked

| Screen | What was checked |
|---|---|
| Overview | The level rows (one protocol: the row is the link; both: "2 TLS · 1 SSH"); the status band links; nested links; count-up; 375 px |
| TLS endpoints, SSH servers | `?level=` and `?exposed=1`; the level chip and its ×; the address rewritten in place; Back |
| Findings | `?severity=`; the select shows it; cross-fade on change |
| Inventory dashboard | The ring, legend, purpose, protocol, certificate and software marks; tooltips; sibling dimming; sweep and bar growth; dark mode |
| Inventory lists | `quantum`, `purpose`, `name` and their chips; the keys note |
| Certificates | `?expires=31-90` and `later`; the select shows them |
| A report's history | Point tooltip; click and Enter open that scan; the "Viewing a past scan" banner |
| Help | The new topics *Charts and filtered lists* and *Running the server* |

## Findings

| # | Sev | Screen | Finding | Decision |
|---|---|---|---|---|
| W1 | High | Overview | The L0 row lost its layout when it became a link: copying the mark's attributes replaced the row's own classes. | **Fixed.** Classes are added, not replaced. Captured again: the row is laid out like the others. |
| W2 | High | Inventory | The ring says "18 quantum-vulnerable" (algorithms **and** keys), but it opened the algorithms list, which held 12. The figure and the list disagreed. | **Fixed.** The algorithms list now says "6 public keys are quantum-vulnerable too · Open the keys". 12 + 6 = 18. The journey checks that every mark's list adds up to its figure. |
| W3 | Medium | Inventory | *Replace first* "X25519" opened a text search that also listed X25519MLKEM768 and mlkem768x25519-sha256. | **Fixed.** Exact `name=` filter, with a chip naming the item; rows open one item. |
| W4 | Medium | Report history | A point focused by keyboard was scrolled into view, and that scroll hid its tooltip. | **Fixed.** Scrolling hides the tooltip only when no mark has focus. |
| W5 | Medium | Overview (375 px) | "3 exposed to harvest-now-decrypt-later" is now a link, but it looked like the notes around it. | **Fixed.** A faint underline in the note's own colour. |
| W6 | High | Help | Help showed "Something went wrong": an edit had put a raw line break inside a string. | **Fixed.** Caught here and by the journey (E2E-04.3, E2E-14.2). Every module is syntax-checked before a build, as CI does. |
| W7 | Low | Overview | The Post-quantum card's "5 exposed" stays plain text. | **Kept.** It spans both protocols, and there is no single list to open. The TLS and SSH cards carry the links. |
| W8 | Low | Inventory | The *Algorithms by purpose* legend has no counts and no links. | **Kept.** A legend row there would stand for a status across all purposes; the segments are the doors. |

## Motion, judged against DESIGN.md §9

- **On arrival only.** The ring sweeps segment by segment; the bars grow; the history line draws, then its points
  appear. Nothing moves afterwards: hovering, polling and repaints do not replay it.
- **Count-up.** Figures count once and end on their value, even in a hidden tab.
- **Filters.** A list cross-fades over 220 ms instead of flashing. Rows do not stagger again.
- **Hover.** The accent edge on clickable cells and tiles grows in; nothing lifts, glows or casts a shadow.
- **Reduced motion.** Every animation is off and figures show at once (journey E2E-MOT-R).
- **Not added:** page-transition slides, hover lifts, skeleton shimmer on charts. See UX-DESIGN-008 §5.

## Result

Every High and Medium finding is fixed and captured again. Two Low findings are kept, with reasons.
