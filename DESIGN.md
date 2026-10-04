# CipherHorizon: DESIGN.md

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

**Logo.** The hexagon mark (violet to amber, keyhole cut) and the word *CipherHorizon* stay as they are. The
mark's gradient belongs to the mark only and is never reused in the interface.

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
| Display | Inter | 34 / 40 px (2.125rem) | 650 | −0.028em | The Overview hero headline only |
| H1 | Inter | 26 / 32 px | 650 | −0.022em | Page title |
| H2 | Inter | 17 / 24 px | 650 | −0.012em | Section and panel titles |
| H3 | Inter | 15 / 22 px | 600 | −0.006em | Sub-sections, group headings |
| Body | Inter | 15 / 24 px (1.6) | 400 | 0 | Prose, explanations, reports |
| UI | Inter | 14 / 20 px | 450–500 | 0 | Tables, controls, lists |
| Small | Inter | 13 / 18 px | 450 | 0 | Secondary lines, hints |
| Label | Inter | 12.5 / 16 px | 550 | 0.01em | Field and figure labels, **sentence case** |
| Figure | Inter, tabular | 28 / 32 px | 600 | −0.02em | Big numbers in the status band |
| Machine | JetBrains Mono | 13 / 20 px | 450–500 | 0 | Addresses, cipher suites, fingerprints, versions, commands |

- **Two families, both served from this origin:** Inter (UI) and JetBrains Mono (the *machine voice*). Mono is for
  values a machine produced or will consume, never for headings or prose.
- **Numbers** use `font-variant-numeric: tabular-nums` wherever they line up (tables, figures, scores, times).
- **No uppercase tracked eyebrows**, except table column headers, which are 12px, weight 600, sentence case.
- A headline is at most two lines; body text at most 70ch.
- No em-dash or en-dash in visible copy. Use a full stop, a comma or a colon. An empty value is written as a word
  ("none", "not set") or a muted middle dot in tables.

---

## 4. Colour

All colours are tokens in `style.css` `:root`, with a dark set under `prefers-color-scheme: dark`. Never write a
hex value in a component.

### Neutrals (graphite, slightly cool)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | #F4F5F7 | #0D0F12 | Page canvas |
| `--surface` | #FFFFFF | #14171B | Panels, tables, inputs |
| `--surface-2` | #F1F2F4 | #1B1F24 | Table headers, hover rows, quiet fills |
| `--border` | #E2E4E8 | #252A31 | Hairlines |
| `--border-strong` | #C9CDD4 | #353C45 | Input borders, dividers that must show |
| `--text` | #15171B | #ECEEF1 | Primary text |
| `--text-2` | #474D57 | #B5BBC4 | Secondary text |
| `--muted` | #697080 | #8C939D | Meta, hints (≥ 4.5:1 on surface) |
| Sidebar | #0B0D10 | #0B0D10 | The navigation rail, the same in both modes |

### Accent (one, locked)

| Token | Light | Dark | Use only for |
|---|---|---|---|
| `--primary` | #4B3FCB | #A99FFF | Primary buttons, links, focus ring, selected tab, active nav bar |
| `--primary-h` | #3D32AE | #BDB5FF | Hover and pressed |
| `--primary-soft` | #EEECFB | #221E3D | Selected row, current item fill |
| `--on-primary` | #FFFFFF | #12101F | Text on primary |

The accent is a deep indigo-violet taken from the logo, flat. **No gradients, no glows, no coloured shadows.** The
logo's amber is not a UI colour.

### Semantic (states only)

| Meaning | Token | Light fg / bg | Dark fg / bg |
|---|---|---|---|
| Critical, bad, problem | `--crit`, `--bad` | #B42318 / #FDECEA | #FF8A80 / #3A1714 |
| High | `--high` | #B54708 / #FDF0E6 | #FFA866 / #3A2312 |
| Medium, warn, attention | `--med`, `--warn` | #8A5A00 / #FBF3DF | #E9B949 / #33280F |
| Low | `--low` | #2F5FAF / #EAF0FA | #8DB2FF / #16233D |
| Info, neutral | `--info-c` | #515863 / #EFF1F3 | #B3B9C2 / #1C2025 |
| Good, passed | `--good` | #15723F / #E7F4EC | #6BD49A / #10291C |
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

- **Radii:** 6px for controls (buttons, inputs, selects), 8px for panels, tables and menus, 12px for dialogs,
  4px for badges and tags. 999px only for avatars and progress tracks.
- **Depth comes from surfaces and 1px hairlines, not shadows.** Panels have a border and no shadow. Shadows exist
  only for things that float above the page: menus, dialogs, toasts (`--shadow-float`).

---

## 7. Components

**Navigation rail.**
- Brand at the top, then the primary action *Scan a URL* as a full-width solid accent button, then the places.
- Group labels (*Results*, *Plan & share*) are 12px, sentence case and muted.
- Items are 36px high with an 18px icon, colour `#A4ABB6` and white on hover.
- The current item gets a 6% white fill, white text and a 2px accent bar on its left edge.
- The account chip, About and the publisher credit sit at the foot.

**Buttons.** 36px high (32px small), 6px radius, weight 550.
- *Primary:* solid accent, white text. At most one per view region.
- *Secondary:* surface fill, strong border.
- *Ghost:* no border, text colour, for row actions.
- *Danger:* solid critical.
- Hover changes colour only. Pressed darkens. Never lift, never glow.

**Links.** Accent colour, underline on hover. A cross-reference inside prose (`.xlink`) is text colour with a
hairline underline.

**Panels (`.card`).**
- Surface, 1px border, 8px radius, 24px padding (20px on mobile), no shadow.
- A panel holds one topic. Its title is H2 with optional meta text on the right.
- Use a panel only when content needs a boundary from its neighbours.

**Status band.** One panel divided by vertical hairlines into figures (label, figure, one line of context). It
replaces rows of identical metric cards. Each figure links to its list.

**Badges and tags.** 4px radius, 12px text, weight 600, tinted background, no border.
- Severity badges carry a glyph and a word (*▲ high*).
- Use a badge for a state, never for decoration. At most two badges per row in a list.

**Tables.**
- Surface with a 1px border and 8px radius.
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

**Dialogs.** 12px radius, a floating shadow, a title row with a hairline, max 560px (wide: 860px).

**CTAs.** A page has one primary action, top right in its header (or the scan form on the Overview). Duplicate
intents are not allowed: one label per action across the product.

**Footer.** In the rail: account, About, the "Developed by" credit and the version, all muted.

**Sign-in gate.** Centred, 400px wide, brand above, one panel, labels above fields, a full-width primary button,
the error inline above the fields.

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
- Four text elements at most on the left.

**Copy.**
- Headline: *Scan a website or endpoint*.
- Sentence: *TLS configuration, certificate, weaknesses, post-quantum readiness and a CBOM, from one address.*

**Responsive.**
- Below 1100px the readiness scale moves under the form and becomes a horizontal strip of five levels.
- Below 600px the strip wraps to two columns and the headline drops to 28px.

**Not allowed.** Gradient backgrounds, blobs, glows, fake screenshots, version labels, scroll cues, a "trusted by"
strip.

---

## 9. Motion

| Use | What | Duration | Easing |
|---|---|---|---|
| Page change | content fades in and rises 4px, once | 180ms | `cubic-bezier(.2,.7,.2,1)` |
| Hover | colour and border colour only | 120ms | ease-out |
| Disclosure | chevron rotates 90° | 150ms | ease-out |
| Dialog | fade plus a 4px rise | 160ms in, 120ms out | ease-out / ease-in |
| Toast | slide in 12px from the right | 200ms | ease-out |
| Live state | progress shimmer, running dot pulse: **only while something is running** | 1.4–1.8s loop | linear |

- Animate `opacity` and `transform` only.
- No hover lifts, no bobbing icons, no looping decoration, no parallax.
- `prefers-reduced-motion: reduce` turns every animation and transition off.

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
2. No purple-blue gradient, glow, glassmorphism or floating decoration anywhere.
3. No repeated 3-up grids of icon + title + text cards.
4. Each badge marks a real state; each animation explains a change; each panel separates a topic.
5. Copy: specific, plain, no hype, no em-dashes, no fake numbers or names.
6. One radius system, one accent, one shadow (for floating things only).
7. Light and dark both checked; 390px checked.
