# UX-AUDIT-006: visual redesign audit and reference research

2026-10-05. Audit-first redesign of the web UI, following the *Taste Skill* redesign methodology
(`design-taste-frontend` and `redesign-skill`, read from github.com/Leonxlnx/taste-skill; not installed, see §5) and
the *Awesome DESIGN.md* collection (github.com/VoltAgent/awesome-design-md) as research. The resulting source of
truth is [DESIGN.md](../../DESIGN.md).

**Brief inference.** Reading this as a data-dense product application (not a marketing site) for security and PKI
engineers and their managers, with a calm, evidential, instrument-like language, leaning towards an enterprise
product system (Linear's restraint, IBM Carbon's hairline discipline). Dials: variance 4, motion 2, density 6.

## 1. What exists (inventory before changes)

| Area | Found |
|---|---|
| Routes | Overview, Endpoints (+ report with five tabs), Machines, Findings, Inventory (+ six lists), Systems, Reports, About, Account, Users, sign-in gate |
| Stack | Plain HTML, ES modules and one CSS file (`style.css`, 1,623 lines), embedded in the Go binary; strict CSP (no inline styles, same-origin fonts) |
| Type | Inter (variable) and JetBrains Mono, self-hosted |
| Colour | Neutral grey ramp; primary blue (#2451E0), overridden by indigo-violet (#5B3FE0) and amber in a later layer |
| Icons | Hand-drawn 20px stroke icons in the rail; Unicode symbols for states |
| Charts | Hand-drawn SVG (rings, bars), colours from tokens |
| Motion | Page-entrance rise, hover lifts, a bobbing empty-state icon, glow pulse, shimmer |
| Logo | Hexagon mark, violet-to-amber gradient with a keyhole cut |

## 2. Findings

**Strong, preserved**
- The information architecture (UX-DESIGN-005): one place per kind of thing, the scan action always available,
  breadcrumbs.
- A dark navigation rail as the brand anchor; the logo.
- Honest content: states as symbol and word, plain-language action items, sources on every finding.
- Accessibility basics: skip link, landmarks, `aria-current`, `textContent`-only rendering, reduced-motion support.
- Self-hosted fonts, no external requests.

**Dated or generic (AI-slop tells)**
- Purple gradients on primary buttons and the active menu item, with tinted glow shadows.
- Radial glows behind the brand mark and the sidebar, and an ambient wash across the top of every page.
- Hover lifts on cards and buttons (`translateY` plus a growing shadow).
- A bobbing empty-state icon; a glowing gradient rank pill.
- Six identical metric cards in a 3×2 grid on the Overview; four more on the report summary; four more on the
  Inventory.

**Inconsistent**
- Tokens declared three times (base, "0.1.0 refinement", "visual identity refresh"); radii 5, 7, 9, 10, 14 and
  18px; three shadow strengths on resting panels.
- Uppercase tracked labels in eight places (tiles, table headers, facts, certificates, sources, group labels),
  each with its own size and tracking.
- Pills for everything: states, kinds, tags, counts.
- Em-dashes and en-dashes used as empty values and in sentences (about 60 in the UI code).

**Weak hierarchy**
- Overview hero: centred, a headline over a full-width input, then three tiny links. It does not say who the
  product is for or why it matters, and the input reads as the page's only content.
- Report summary: verdict, coverage, four tiles and twelve action items all at similar weight; "Why it matters" is
  the same sentence for every item of one category.
- Headings and figures compete: figures at 2rem weight 700, headings at 1.1rem.

**Unnecessary complexity**
- Cards inside cards (tile grids inside panels, findings cards inside section cards).
- Several decorative status dots and coloured borders without a state behind them.

## 3. Decisions (summary of DESIGN.md)

| Topic | Decision | Why |
|---|---|---|
| Accent | One flat indigo-violet, from the logo; no gradients | Keeps the brand, removes the generic glow look (Taste "Lila rule", Linear's single accent) |
| Neutrals | Cool graphite, warmer than the old blue-grey | A calmer, more instrument-like canvas; dark mode re-tuned for contrast |
| Depth | Hairlines and surface steps; shadows only for floating things | IBM and HashiCorp principle; removes visual noise |
| Shape | 6 / 8 / 12px, 4px badges | One radius system (Taste shape lock) |
| Type | Inter for UI with tabular figures; JetBrains Mono as the machine voice for identifiers | Fonts already bundled and offline; identity from the pairing and the scale |
| Labels | Sentence case; uppercase only for table headers | Carbon guidance; removes eight competing label styles |
| Figures | A status band (one panel, hairline-separated) instead of card grids | Removes the repeated 3-up grids |
| Hero | Left-aligned: headline, sentence, form; the readiness scale as a legend on the right | Says what it is and what L0–L4 mean; no decoration |
| Motion | One page fade, colour-only hover, live-state loops only while running | Motion must explain a change |
| Copy | No em-dashes; empty values as words | Taste copy rules |

## 4. Reference comparison (principles borrowed, identities not)

| Reference | Borrowed principle | Not borrowed |
|---|---|---|
| Linear | One chromatic accent, used only for action and focus; depth from a surface ladder and hairlines; negative tracking on display type; 8px controls | Its near-black canvas as the only mode, its lavender, its type family |
| IBM (Carbon) | Hairlines instead of shadows; sentence-case labels; dense tables; tabs with a 2px underline; one accent | Square 0px corners, Plex, IBM Blue |
| Sentry | Dense UI copy at 1.5 line height versus airy prose; mono for machine values; focus colour reserved | Its mascots, lime and pink, uppercase buttons |
| HashiCorp | Tight display line heights with relaxed body; cards lift by surface change, never shadow | Its black canvas, product colours, eyebrows on every section |
| Taste Skill | Audit before change; brief inference; one accent; one radius system; hero ≤ 4 text elements; no em-dashes; motion must be motivated; no repeated card grids; the pre-flight checklist | Its React, Tailwind and GSAP stack defaults (this UI is dependency-free by design) |

## 5. About installing the resources

The brief asked to install the Taste Skill with `npx skills add …` and to clone Awesome DESIGN.md. I did not run
either: both download and execute third-party code from outside this repository, which I do not do without
confirming the source first. Their content was read from GitHub instead and applied as above. If you want them
installed in the project, confirm, and they can be added with the commands from the brief.
