# UX-REVIEW-008: screen-by-screen product and design review

2026-10-09. This review walks every screen as it renders after PRD-007, on demo data, from two roles:

- **Product manager:** what the screen is for, and whether it serves the vision.
- **Design lead:** whether it reads as a professional enterprise tool or as generated decoration.

It was triggered by owner feedback on PRD-007:

1. The logo is not good. It should be a plain flat icon, not modelled on the Offset mark.
2. Sign-in should be optional and configurable, and off by default. Many people only want to scan TLS.
3. About mixes the product page with help.
4. Nobody walked the finished screens before calling the work done.

## The vision each screen is judged against

> Type an address, get a verdict you can act on: how ready the endpoint is for post-quantum, what is weak, what to
> fix first. Keep track over time, and when you need it, inventory machines and hand over one CBOM and a report.

**Who it is for.** Most people arrive for the first half: a TLS and post-quantum scan, alone, on their laptop. The
second half is for teams (inventory, systems, accounts, audit), and it must not tax the first.

## Findings by screen

Severity: **P0** wrong or broken; **P1** works against the vision; **P2** polish.

### Shell (every screen)

| # | Sev | Finding | Decision |
|---|---|---|---|
| S1 | P1 | The product mark imitates Offset's angled bars and reads as a different company's logo (owner item 1). | A plain flat app icon: a blue rounded square with a white padlock. Offset stays as the "Developed by" credit, nowhere else in the brand. |
| S2 | P1 | "by Offset Security" sits under the product name, everywhere. | The product name stands alone, with a tagline saying what it is: *TLS and post-quantum scanner*. |
| S3 | P1 | Sign-in is forced on everyone (owner item 2). A person who wants one TLS scan first creates an administrator from a code in a log. | Sign-in is off by default and turned on when wanted: from Settings in the interface, or with `--login` on the server. A database that already has accounts keeps sign-in on. |
| S4 | P1 | About is reference, how-to and settings in one 4,000-pixel page (owner item 3). | About: what the product is, this installation, credits and licences. Help: how to use it, with a contents list. Settings: sign-in and the server's configuration. |

### Overview

| # | Sev | Finding | Decision |
|---|---|---|---|
| O1 | P1 | The readiness scale on the right is a permanent legend: the same five lines for every user on every visit. | Each level shows how many of *your* endpoints are at it. The legend becomes the fleet's readiness at a glance, and it is a filter link. |
| O2 | P2 | KPI tiles say the same thing twice ("5 scanned; 0 rated Strong or Sound", "2 of 5 endpoints use post-quantum key exchange"). | One number and one short line per tile. |

### Endpoints

| # | Sev | Finding | Decision |
|---|---|---|---|
| E1 | P1 | Each row has two actions that do the same thing (the name link and *Open report*). | The row opens the report; *Open report* goes. |
| E2 | P1 | Up to seven coloured chips per row (level, score, four severities, tag): a rainbow that DESIGN.md forbids (two badges at most). | Findings become one count with the worst severity named ("8 · 3 critical"). |
| E3 | P1 | A STARTTLS endpoint looks like any other. | The protocol shows under the address ("SMTP · STARTTLS"). |

### Endpoint report

| # | Sev | Finding | Decision |
|---|---|---|---|
| R1 | P1 | Post-quantum readiness, the product's reason to exist, is one tile of four, at the same weight as "Not checked: 0". The L0 to L4 scale appears only on the Configuration tab. | The summary leads with the readiness level on the L0 to L4 scale, then the TLS hygiene score and the certificate. A "Not checked" tile shows only when something was not checked. |
| R2 | P0 | The certificate tile shows "89 days left" in red because the chain is untrusted: the colour contradicts the number. | Days left are coloured by time; trust is said in words beneath. |
| R3 | P2 | The verdict box is red-edged even when the news is good. | The edge follows the worst finding. |

### Findings

| # | Sev | Finding | Decision |
|---|---|---|---|
| F1 | P0 | The "quantum-vulnerable" badge overflows into the title. | A wider fixed column, and the shorter word *PQC*. |

### Machine

| # | Sev | Finding | Decision |
|---|---|---|---|
| M1 | P1 | 27 algorithms in alphabetical order; the five that matter (quantum-vulnerable) are scattered between 22 that do not. | Quantum-vulnerable first. The quantum-safe ones fold under one line ("22 quantum-safe algorithms"). |
| M2 | P2 | "Why this verdict" under every row. | The reason opens from the verdict itself. |

### Inventory

| # | Sev | Finding | Decision |
|---|---|---|---|
| I1 | P0 | "Replace first" counts spill out of their card. | The count column fits its card. |
| I2 | P0 | The numbers disagree: 35 algorithms in one tile, "of 36 algorithms and keys" in the next; 8 quantum-vulnerable in one card, 7 in another. | Fixed in section 3: each figure says what it counts, and the same thing counted twice gives the same number. |

### Reports

| # | Sev | Finding | Decision |
|---|---|---|---|
| P1 | P2 | The OMB M-23-02 row has one button per system, which does not scale. | A system picker and one button. |

### About, Help, Settings

These are covered by S3 and S4. Help also takes the reference material About had:

- the inventory scripts;
- the levels and the TLS hygiene score;
- what is not measured;
- the HTTP check;
- the reference data.

## Not changed, deliberately

- **The Offset palette, type and 4px shape.** Owner item 1 is about the mark, not the theme.
- **The Configuration and Weaknesses tabs.** They are long because they are complete, and that is their job. The
  summary is where the reader is helped.

## How this review is checked

- The screens are captured again after the changes and compared.
- The journey asserts the decisions above:
  - no *Open report* button;
  - the readiness counts on the Overview;
  - Help and Settings exist and About is short;
  - sign-in off by default and turned on from Settings.

## Addendum: what turning sign-in off does (owner question, 2026-10-09)

> "If someone has login enabled and they disable it, what happens to all users, their views, their actions?"

### What the first build did

The first build answered this badly in four ways:

- **Inconsistent rights.** Sessions survived the switch. A viewer whose browser was still signed in kept a viewer's
  limits, while an anonymous visitor on the same server had every right.
- **Lost attribution.** Every action while sign-in was off was recorded as "local", with no clue who or where.
- **Account takeover.** Accounts could still be changed while sign-in was off. Anyone could reset an
  administrator's password and own that account once sign-in came back.
- **A one-click switch.** One administrator click turned it off, with no re-confirmation of who was asking.

### Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Accounts are kept** (names, roles, passwords, lock-outs). Turning sign-in on again restores them as they were. | Turning sign-in off is not deleting a team. |
| D2 | **Every session ends** when sign-in is turned off. While it is off, a session cookie is ignored: everyone is the same anonymous operator with every right. | One rule for everyone; no stale, half-applied roles. |
| D3 | **Accounts are frozen while sign-in is off.** They can be listed but not added, changed, deleted, reset or unlocked. | Nobody can prepare an account to take over when sign-in returns. |
| D4 | **History stays and keeps its names.** Everything done while sign-in was on keeps its author: findings triaged, systems edited, scans started and changes made. Actions while it is off are recorded as *Anyone (sign-in off)* with the client's address. The switch itself appears in the activity log, so the gap is visible. | Accountability does not disappear with the switch. |
| D5 | **Turning it off asks for the administrator's own password,** and the dialog says what will happen: sessions end, accounts are frozen and kept, actions become anonymous. | A team-wide change of rights needs a deliberate, re-authenticated step. |
| D6 | **Turning it on again with accounts already present** needs no new account. Everyone signs in with the account they had, the person turning it on included, so they must know a password. If nobody does, `cipherhorizon user reset-password` on the server is the way back. | No path back in that skips a password. |

"Their views" means the reports, filters and dashboards people look at. None of it is stored per person: every view
is computed from the shared data, so nobody loses a view when sign-in goes off or comes back.
