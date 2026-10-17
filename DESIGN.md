# CipherHorizon: DESIGN.md (v2, the Offset theme)

The visual source of truth for the web UI (`web/static`). Read it before building or changing a page. When this
file and the code disagree, the code is wrong. The audit that led here is in
[docs/product/UX-AUDIT-006-visual-redesign.md](docs/product/UX-AUDIT-006-visual-redesign.md).

---

## 1. Brand

**What it is.** A self-hosted TLS scanner and cryptographic inventory (CBOM). Give it an address and it reports
what that endpoint runs, what is weak, how ready it is for post-quantum cryptography, and a CycloneDX CBOM. Run a
script on a machine and it reports the cryptography inside it.

**Who it is for.** Security engineers, PKI and platform teams, and the people who answer to auditors: technical
readers who check evidence, and their managers, who read the summary and the PDF.

**Personality.** An instrument, not a campaign. Precise, calm, evidence first. It measures and says what it
measured, in plain words, with sources. It never dramatises a finding and never decorates a fact.

**Positioning.** A credible engineering tool from a security company. The design earns trust the way a good
oscilloscope does: everything visible has a reason, numbers line up, states are unambiguous.

**Emotional response.** "I can see exactly what was checked, I know what to fix first, and I could hand this to an
auditor."

**The Offset theme.** CipherHorizon is an Offset Security product and looks like one: Offset's warm paper and
navy ink, its blue, its three typefaces, its 4px shape and its one signature angle (−27.6°, the angle of the Offset
logo). The values below were read from offsetsecurity.net's own stylesheet
([docs/launch/05-brand-and-messaging.md](docs/launch/05-brand-and-messaging.md)).

**Logo.** A flat app icon: a white padlock on a rounded square of Offset blue (`--primary`).
- **Plain.** One colour per shape: no gradient, stroke, glow or shadow. It borrows nothing from the Offset mark;
  Offset appears only as the "Developed by" credit in the sidebar and in the documentation.
- **Files** (`web/static/img/`): `mark.svg` (blue, also the favicon), `mark-on-navy.svg` (the same; blue reads on
  navy), `mark-mono.svg` (a navy tile, for one-colour print). `brandMark()` in `dom.js` and the PDF cover draw the same
  shapes.
- **Lockup:** the icon, *CipherHorizon* in Geist 600, and under it the tagline *TLS · SSH · post-quantum readiness* (STRATEGY-003 §4).
- **Why a padlock:** it says "TLS" and "cryptography" at 16 pixels, where anything subtler turns into a smudge.

---

## 2. Design principles

1. **Evidence over decoration.** Every element shows data, explains data or acts on data. If it does none, remove it.
2. **One state, one meaning.** A state reads the same everywhere: a symbol, a word and a colour together, never
   colour alone (for example ✖ *Enabled · should be off*).
3. **Hierarchy by type and space, not boxes.** Prefer a heading, whitespace and a hairline to another card. Nest at
   most one container level.
4. **Density where people scan, air where people read.** Tables and lists are compact (14px, 8–10px row
   padding). Explanations and reports get a 70ch measure and 1.6 line height.
5. **Quiet chrome, loud data.** Neutral surfaces, one accent for action, semantic colours only for real states.
6. **Rhythm.** Vertical spacing comes from the 4px scale: 8 within a group, 16 between related blocks, 32 between
   sections, 48 around the page's first block.
7. **Composition.** Left-aligned text and a strong left edge. Centre only things that are alone on screen (sign-in,
   empty states).

---

## 3. Typography

| Role | Family | Size / line height | Weight | Tracking | Use |
|---|---|---|---|---|---|
| Display | Newsreader | 40 / 46 px | 500 | −0.015em | The Overview and sign-in headlines only |
| H1 | Newsreader | 30 / 36 px | 500 | −0.012em | Page title |
| H2 | Geist | 17 / 24 px | 600 | −0.01em | Section and panel titles |
| H3 | Geist | 15 / 22 px | 600 | 0 | Sub-sections, group headings |
| Body | Geist | 15 / 24 px (1.6) | 400 | 0 | Prose, explanations, reports |
| UI | Geist | 14 / 20 px | 450–500 | 0 | Tables, controls, lists |
| Small | Geist | 13 / 18 px | 450 | 0 | Secondary lines, hints |
| Label | Geist | 12.5 / 16 px | 550 | 0 | Field and figure labels, **sentence case** |
| Figure | Geist, tabular | 28 / 32 px | 600 | −0.02em | Big numbers in the status band |
| Machine | Geist Mono | 13 / 20 px | 400–500 | 0 | Addresses, cipher suites, fingerprints, versions, commands |
| Eyebrow | Geist Mono | 11.5 / 16 px | 500 | 0.04em, uppercase | At most one per screen, above a headline (`.eyebrow`) |

- **Three families, all SIL OFL and served from this origin** (`web/static/fonts`, licences beside them):
  - **Newsreader** speaks only in page titles and the two headlines.
  - **Geist** carries the interface.
  - **Geist Mono** is the *machine voice*. It is for values a machine produced or will consume, and the one eyebrow.
- **Numbers** use `font-variant-numeric: tabular-nums` wherever they line up.
- **The eyebrow** is the only uppercase tracked label, apart from table column headers (12px, weight 600, sentence case). It is preceded by a small skewed bar in the accent.
- A headline is at most two lines; body text at most 70ch.
- **No em-dash or en-dash in visible copy.** Use a full stop, a comma or a colon. An empty value is written as a word ("none", "not set") or a muted middle dot in tables.

---

## 4. Colour

All colours are tokens in `style.css` `:root`, with a dark set under `prefers-color-scheme: dark`. Never write a
hex value in a component. `TestStyleTokensMatchDesign` checks the tables below against the stylesheet, and
`TestTokenContrast` checks the text pairs against WCAG AA.

### Neutrals (Offset paper and ink; dark mode from the navy scale)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--gray-50` | #F7F7F5 | #070C18 | Page canvas (`--bg`) |
| `--gray-0` | #FFFFFF | #0E1729 | Panels, tables, inputs (`--surface`) |
| `--gray-100` | #F1F1EE | #15213D | Table headers, hover rows (`--surface-2`) |
| `--gray-200` | #DEDDD7 | #1E2C4E | Hairlines (`--border`) |
| `--gray-300` | #C5C4BC | #2E3E64 | Input borders (`--border-strong`) |
| `--gray-900` | #0B1428 | #E8ECF4 | Primary text, Offset ink (`--text`) |
| `--gray-600` | #2B3140 | #C3CBDA | Secondary text, Offset body (`--text-2`) |
| `--gray-500` | #5A5F6B | #A3AEC2 | Meta, hints (`--muted`) |
| `--rail` | #0B1428 | #050A14 | The navigation rail: Offset navy |
| `--rail-text` | #A3AEC2 | #A3AEC2 | Rail items |
| `--rail-accent` | #9DB6FF | #9DB6FF | The current-place bar and counts in the rail |

### Accent (one, locked: Offset blue)

| Token | Light | Dark | Use only for |
|---|---|---|---|
| `--primary` | #2457D6 | #9DB6FF | Primary buttons, focus ring, selected tab, the eyebrow bar |
| `--primary-h` | #1B45B0 | #B9CBFF | Hover and pressed |
| `--primary-soft` | #E7EDFB | #16244A | Selected row, current item fill, focus halo |
| `--on-primary` | #FFFFFF | #0B1428 | Text on primary |
| `--link` | #1B45B0 | #9DB6FF | Links |
| `--eyebrow` | #1B45B0 | #9DB6FF | The eyebrow's text |

Flat. **No gradients, no glows, no coloured shadows.**

### Semantic (states only)

| Meaning | Token | Light fg / bg | Dark fg / bg |
|---|---|---|---|
| Critical, bad, problem | `--crit`, `--bad` | #B42318 / #FDECEA | #FF8A80 / #3A1714 |
| High | `--high` | #B54708 / #FDF0E6 | #FFA866 / #3A2312 |
| Medium, warn, attention | `--med`, `--warn` | #9A5B0B / #FBF3DF | #E9B949 / #33280F |
| Low | `--low` | #2F5FAF / #EAF0FA | #8DB2FF / #16233D |
| Info, neutral | `--info-c` | #515863 / #EFF1F3 | #B3B9C2 / #1C2025 |
| Good, passed | `--good` | #1D7A4C / #E7F4EC | #6BD49A / #0F2A22 |
| Readiness L0–L4 | `--lv0`…`--lv4` | red, orange, blue, green, violet | lighter of the same |

---

## 5. Layout

- **Shell:** a 232px navigation rail on the left (full height, sticky) and the work area. Below 860px the rail
  becomes a top bar that scrolls sideways.
- **Content width:** pages max 1240px, centred in the work area. Reading blocks (reports, explanations) max 72ch.
- **Gutters:** 32px page padding at ≥ 1080px, 24px at tablet, 16px at mobile.
- **Grid:** a 12-column mental model; in practice pages use a single column, two columns (1.4fr / 1fr) for the
  Overview's lower area, and auto-fit grids of `minmax(260px, 1fr)` for lists of equal things.
- **Section spacing:** 32px between sections, 16px between a section title and its content.
- **Spacing scale (px):** 4, 8, 12, 16, 20, 24, 32, 40, 48, 64. Nothing else.

---

## 6. Shape and depth

- **Radii:** Offset's 4px for controls, panels, tables and menus; 6px for dialogs; 3px for badges and tags. 999px
  only for avatars and progress tracks.
- **The angle.** `--skew` (−27.6°) is the one signature shape, used sparingly. It appears only:
  - as the bar before the eyebrow;
  - as the current-place bar in the rail.
  Never skew text, buttons or panels.
- **Depth comes from surfaces and 1px hairlines, not shadows.** Panels have a border and no shadow. Shadows exist
  only for things that float above the page: menus, dialogs, toasts (`--shadow-float`).

---

## 7. Components

**Navigation rail.**
- Brand at the top, then the places. The rail holds places only; actions live on pages: the scan box on the
  Overview, and one *Add* button per list page (*Add TLS endpoints*, *Add SSH servers*) whose dialog scans by default.
- The rail fits a laptop screen without a scroll pane of its own; on a very short window the whole rail scrolls.
- Group labels (*Results*, *Plan & share*) are 12px, sentence case and muted.
- Items are 36px high with an 18px icon, colour `--rail-text` and white on hover.
- The current item gets a navy-2 fill, white text and a 4px skewed accent bar on its left edge.
- The foot holds Settings, Help and About (32px rows), then the account, then one quiet line with the credit and the version.

**Buttons.** 36px high (32px small), 4px radius, weight 550.
- *Primary:* solid accent, white text. At most one per view region.
- *Secondary:* surface fill, strong border.
- *Ghost:* no border, text colour, for row actions.
- *Danger:* solid critical.
- Hover changes colour only. Pressed darkens. Never lift, never glow.

**Links.** Accent colour, underline on hover. A cross-reference inside prose (`.xlink`) is text colour with a
hairline underline.

**Panels (`.card`).**
- Surface, 1px border, 4px radius, 24px padding (20px on mobile), no shadow.
- A panel holds one topic. Its title is H2 with optional meta text on the right.
- Use a panel only when content needs a boundary from its neighbours.

**Status band.** One panel divided by vertical hairlines into figures (label, figure, one line of context). It
replaces rows of identical metric cards. Each figure links to its list.

**Badges and tags.** 3px radius, 12px text, weight 600, tinted background, no border.
- Severity badges carry a glyph and a word (*▲ high*).
- Use a badge for a state, never for decoration. At most two badges per row in a list.

**Tables.**
- Surface with a 1px border and 4px radius.
- Header: 12px, weight 600, sentence case, `--surface-2`.
- Rows: 10px vertical padding, a hairline between rows, a hover fill.
- Numbers are right-aligned and tabular. Identifiers are in mono.
- A row that opens something is clickable as a whole and has an explicit last-column action.

**Forms.**
- The label sits above the field (13px, weight 550). Fields are 38px high with a strong border.
- Focus: accent border plus a 3px soft accent ring.
- Errors show inline under the form, in critical tint.

**Alerts and callouts.** A left border of 3px in the state colour, the tinted background and text colour. One
sentence, one action at most.

**Tabs.** Text tabs on a hairline, 14px weight 550. The selected tab has text colour and a 2px accent underline.

**Dialogs.** 6px radius, a floating shadow, a title row with a hairline, max 560px (wide: 860px).

**CTAs.** A page has one primary action, top right in its header (or the scan form on the Overview). Duplicate
intents are not allowed: one label per action across the product.

**Footer.** In the rail: Settings, Help, About, the account, then the "Developed by" credit and the version on one muted line.

**Sign-in gate.** Two columns: the navy value panel (§8) and the form, 400px wide, labels above fields, a
full-width primary button, the error inline above the fields.

---

## 8. Hero (Overview)

**Purpose.** Say in one look what the product does and let the person do it: *scan an address*.

**Composition.** A two-column band at the top of the Overview, left-aligned, no background image:
- Left (≈ 60%): headline, one supporting sentence (≤ 20 words), the scan form, then one line of secondary
  actions.
- Right (≈ 40%): the **readiness scale**, L0 to L4, each a coloured level code with its meaning. It is the legend
  for the level badges used everywhere else. It decorates nothing, so it may stay.

**Hierarchy.**
- The headline is Display, the sentence is Body in `--text-2`, and the form is the largest interactive element:
  a 48px input with the primary button inside.
- Secondary actions are small links.
- Five text elements at most on the left (eyebrow, headline, sentence, form hint, secondary links).

**Copy.**
- Eyebrow: *POST-QUANTUM READINESS · TLS SCANNER · CBOM* (the product's three claims, the screen's one eyebrow).
- Headline (Newsreader): *Scan an endpoint for post-quantum readiness*.
- Sentence: *A deep TLS scan, a readiness level from L0 to L4, every check with its source, and a CycloneDX CBOM, from one address.*

**Sign-in.** The same story, once, before anything else: a navy panel (Offset's band) with the lockup, the eyebrow,
the headline *Quantum-safe before it's urgent.* (Offset's own line for its PQC practice), the three pillars, and a
link to Offset Security's post-quantum readiness practice. The form sits beside it; on a phone the panel stacks
above, pillars reduced to their titles.

**Responsive.**
- Below 1100px the readiness scale moves under the form and becomes a horizontal strip of five levels.
- Below 600px the strip wraps to two columns and the headline drops to 28px.

**Not allowed.** Gradient backgrounds, blobs, glows, fake screenshots, version labels, scroll cues, a "trusted by"
strip.

---

## 9. Motion

Motion explains a change, once; nothing moves on a page where nothing is changing (UX-DESIGN-008).

| Use | What | Duration | Easing |
|---|---|---|---|
| Page change | content fades in and rises 4px, once | 180ms | `cubic-bezier(.16,1,.3,1)` |
| Rows | rows and list items rise in, 18ms apart, at most 10 | 180ms | same |
| Ring | segments sweep from nothing to their share, 60ms apart | 600ms | same |
| Bars | inventory bars grow from the left | 500ms | same |
| History line | the line draws, then its points fade in | 600ms + 160ms | same |
| Figures | count to their value once, and again only when it changes | ≤ 600ms | ease-out cubic |
| Filter change | the list cross-fades: out, redraw, in; rows do not stagger again | 80ms + 140ms | ease |
| Chart hover / focus | the other marks of the chart fade to 35%; a tooltip fades in | 120ms | ease-out |
| Clickable cell hover | background tint and a 2px accent edge that grows in on the left | 120 to 180ms | ease-out |
| Button press | settles 1px while pressed | 80ms | ease-out |
| Current place | the menu's current-place bar grows in when the place changes | 180ms | `cubic-bezier(.16,1,.3,1)` |
| Disclosure | chevron rotates 90° | 150ms | ease-out |
| Dialog | fade plus a 4px rise | 160ms in, 120ms out | ease-out / ease-in |
| Toast | slide in 12px from the right | 200ms | ease-out |
| Live state | progress shimmer, running dot pulse: **only while something is running** | 1.4–1.8s loop | linear |

- Animate `opacity` and `transform` only; SVG lines and rings may also draw (`stroke-dasharray`, `stroke-dashoffset`).
  `TestMotionRulesAreRespected` checks every keyframe and transition.
- Draw-ins happen when a page arrives, never on a poll or a repaint.
- No hover lifts, no bobbing icons, no looping decoration, no parallax.
- `prefers-reduced-motion: reduce` turns every animation and transition off, counting included.

### Charts you can act on

A chart mark that counts a set of things opens that set, already filtered: a readiness level opens the endpoints at
it, a ring segment the algorithms with that status, an expiry bar the certificates in that window. The filter lives
in the address and shows as a removable chip on the list. Every mark is a link with a name that says what it opens,
reachable by Tab and opened with Enter; a mark that counts nothing is not interactive. See UX-DESIGN-008.

---

## 10. Responsive behaviour

| Range | Behaviour |
|---|---|
| ≥ 1440 (large desktop) | Content stays at 1240px; extra space goes to the margins |
| 1080–1439 (desktop) | Full rail, two-column Overview, status band in one row of six |
| 860–1079 (tablet landscape) | Rail narrows to 208px; status band 3 + 3; tables scroll inside their frame |
| 600–859 (tablet) | Rail becomes a top bar; one column; hero scale under the form |
| < 600 (mobile) | 16px gutters; status band two per row; tables scroll horizontally inside their frame; never the page |

Touch targets are at least 40px. Nothing may scroll the page sideways at 390px (the journey checks this).

---

## 11. Accessibility

- WCAG 2.2 AA: text at least 4.5:1, large text and UI parts at least 3:1, in both modes.
- Visible focus everywhere: a 2px accent outline offset 2px. Never remove it without a replacement.
- State never by colour alone: symbol plus word.
- Every control has a name; every form field a label above it; errors are announced (`role="alert"`).
- The skip link, landmarks (`nav`, `main`), `aria-current` on the current place, real tables for tabular data.
- Everything a scanned server or a document supplied is rendered as text (`textContent`), never as HTML.

---

## 12. Do's

- Do start a page with H1 and one sentence saying what it lists.
- Do put the one primary action top right in the page header.
- Do show identifiers in mono and numbers tabular.
- Do say what passed as well as what failed.
- Do use the status band for figures and a table for anything with more than five rows.
- Do write states as *state · judgement* ("Enabled · should be off").

## 13. Don'ts

- Don't use gradients, glows, coloured shadows, glass, blobs or noise.
- Don't add a card around a single number, or a grid of identical cards.
- Don't add a second accent colour, or use semantic colours for decoration.
- Don't use uppercase tracked labels (column headers aside) or more than two badges in a list row.
- Don't animate anything that is not changing.
- Don't centre page content (sign-in and empty states aside).
- Don't use em-dashes or en-dashes in copy.

## 14. Anti-slop rules

Before a change ships, check:

1. Would a strong product-design team choose this on purpose? If it is there "to look modern", remove it.
2. No gradient (the loading skeleton and the running-scan shimmer excepted), glow, glassmorphism or floating decoration anywhere; every logo flat (`TestNoDecorativeGradients`, `TestLogosAreFlat`).
3. No repeated 3-up grids of icon + title + text cards.
4. Each badge marks a real state; each animation explains a change; each panel separates a topic.
5. Copy: specific, plain, no hype, no em-dashes, no fake numbers or names.
6. One radius system, one accent, one shadow (for floating things only).
7. Light and dark both checked; 390px checked.
