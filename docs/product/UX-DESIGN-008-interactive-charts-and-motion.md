# UX-DESIGN-008 · Charts you can act on, and quiet motion

Status: agreed 2026-10-18, for [PRD-009](PRD-009-interactive-charts-motion-port-cbom.md) WP-1 and WP-2. Builds on
DESIGN.md §8 (charts) and §9 (motion), and replaces §9's table with the one in §4 below.

## 1. Principles

These are the decisions the rest of this document applies.

1. **A mark is a question; clicking it answers.** Every mark that counts a set of things opens that set, already
   filtered. A mark that counts nothing (a track, an axis, a zero) is not interactive and does not pretend to be.
2. **The address is the filter.** A list's filters live in its URL (`#/inventory/certificates?expires=30`). That gives:
   - a link from a chart that is just a URL;
   - Back that returns to the chart;
   - a filtered list that can be bookmarked and shared;
   - nothing extra to keep in step.
3. **Show where you are.** A list reached from a chart shows its filter as a chip ("Expires within 30 days ×") above
   the table, so the reader can see why the list is short and undo it in one click.
4. **Motion explains a change, once.** Things arrive by showing their value (a ring sweeps to its share, a figure
   counts to its number), then hold still. Nothing moves on a page where nothing is changing. This is the
   difference between an instrument and a screensaver.
5. **Restraint is the identity.** No hover lifts, glows, parallax, bouncing or springs. Colour, opacity and small
   transforms only, 120 to 600 ms, one easing curve (`--ease`). Reduced motion removes all of it.

Benchmarks looked at: Linear's insights views, Vercel's analytics, Stripe's dashboard, and GitHub's insights.
All four make every bar a filter link, use one hover treatment for every chart, and animate only on first draw.
None animates on poll or loops decoration. We follow the same conventions.

## 2. Interaction model for a chart mark

| State | Treatment |
|---|---|
| Rest | As today. Interactive marks get `cursor: pointer`. |
| Hover / focus on a mark | The other marks of the same chart fade to 35% opacity (120 ms). The hovered mark stays at 100%, and a ring segment also gets a 2px wider stroke. The tooltip appears beside the pointer, or above the mark on keyboard focus. |
| Tooltip | A small floating panel (surface colour, the one shadow, radius-sm). Line 1: the label in bold. Line 2: the count and its unit. Line 3, muted: "Click to open the list". It never covers the mark, flips at viewport edges, and is `aria-hidden` (the mark's accessible name carries the same text). |
| Focus | The existing 2px accent outline. On SVG marks this is drawn as an `outline` on the `<g>` where supported, and as a stroke otherwise. |
| Press | Navigate. No animation of its own; the next page's arrival is the feedback. |
| Zero or decoration | Not focusable, no pointer, no tooltip. |

A mark is a `<g>` (SVG) or `<li>` (HTML legend) with `role="link"`, `tabindex="0"`, `aria-label` and `data-href`. One
delegated handler (`charts.js: wireMarks(root)`) does hover, focus, tooltip, Enter, Space and click for every
chart on the page. Legends are links too: clicking "Quantum-safe 41" in the legend is the same as clicking the green
segment. Bigger targets matter on touch.

## 3. Where each chart goes

| Page | Mark | Opens |
|---|---|---|
| Overview | Readiness level row (one protocol at the level) | `#/endpoints?level=N` or `#/ssh?level=N` |
| Overview | Readiness level row (both protocols) | The count becomes two links: "2 TLS" and "1 SSH" |
| Overview | Severity chip on *Findings* | `#/findings?severity=critical` |
| Overview | "N exposed to harvest-now-decrypt-later" | `#/endpoints?exposed=1` or `#/ssh?exposed=1` |
| Inventory | Ring segment and legend row | `#/inventory/algorithms?quantum=vulnerable` (or `safe`, `unknown`) |
| Inventory | *Replace first* row | `#/inventory/algorithms?q=<name>` |
| Inventory | *By purpose* bar segment | `#/inventory/algorithms?purpose=<purpose>&quantum=<tone>` |
| Inventory | *Protocol versions* row | `#/inventory/protocols?q=<version>` |
| Inventory | *Certificates* bar segment and legend row | `#/inventory/certificates?expires=expired` (or `30`, `90`, `later`) |
| Inventory | *Cryptographic software* row | `#/inventory/software?q=<name>` |
| Endpoint report | History point | `#/endpoints/ID?scan=SCAN&tab=summary` |

The filter chip reads, for example:
- "PQC readiness L1 Exposed ×"
- "Quantum-vulnerable ×"
- "Purpose: Key exchange ×"
- "Expires within 30 days ×"
- "Severity: critical ×"

The × clears that one filter (address replaced, list redrawn). When a list has its own controls (a select or a
checkbox), the control shows the same value; the chip is for filters the page has no control for, such as `level`
and `purpose`.

## 4. Motion (replaces DESIGN.md §9's table)

| Use | What | Duration | Easing | New |
|---|---|---|---|---|
| Page change | Content fades in and rises 4px, once | 180 ms | `--ease` | |
| Rows | Table rows and list items rise in, staggered 18 ms, at most 10 | 180 ms | `--ease` | |
| Ring / donut | Segments sweep from 0 to their share, each 60 ms after the previous | 600 ms | `--ease` | ✓ |
| Horizontal bars | Grow from the left (scaleX) | 500 ms | `--ease` | ✓ (inventory) |
| History line | Draws left to right; points fade in after it | 600 ms + 160 ms | `--ease` | points ✓ |
| Figures | Count from 0 (or the old value) to the new value, once | ≤ 600 ms | ease-out cubic | ✓ |
| Filter change | List cross-fades: out 80 ms, in 140 ms; no row stagger | 220 ms | ease | ✓ |
| Chart hover | Sibling marks fade to 35% | 120 ms | ease-out | ✓ |
| Tooltip | Fades in and rises 2px | 120 ms | `--ease` | ✓ |
| Clickable row, tile, stat hover | Background tint; a 2px accent edge grows in on the left (scaleY) | 120 ms | ease-out | edge ✓ |
| Primary button press | Background darkens; translateY 1px while pressed | 80 ms | ease-out | ✓ |
| Active nav indicator | Grows in (scaleY 0 to 1) when the place changes | 180 ms | `--ease` | ✓ |
| Disclosure | Chevron rotates 90° | 150 ms | ease-out | |
| Dialog | Fade plus a 4px rise | 160 ms in, 120 ms out | ease-out / ease-in | |
| Toast | Slide in 12px from the right | 200 ms | ease-out | |
| Live state | Progress shimmer, running-dot pulse: **only while something is running** | 1.4 to 1.8 s loop | linear | |

Rules:
- Animate only `opacity`, `transform`, and SVG `stroke-dashoffset` (the history line and the ring sweep). Never
  animate layout properties (width, height, top).
- Draw-in happens on arrival only: `playEnter` adds `.enter`, and polling repaints do not.
- Reduced motion (`prefers-reduced-motion: reduce`) and print switch everything off, count-up included: the figure
  is simply shown.
- No hover lifts, shadows on hover, glows, bounces, springs, parallax or looping decoration (DESIGN.md §13 and
  §14 stand).

## 5. Rejected, and why

| Idea | Why not |
|---|---|
| A chart library (Chart.js, ECharts) | A new dependency and a bigger bundle. Its styles fight the CSP (no inline styles). It would add a visual dialect we would then have to suppress. |
| Click a mark to filter the dashboard in place (cross-filtering) | The dashboard is a summary; the list is where work happens. Opening the list is one model everywhere. |
| Animated page transitions (slide between routes) | Slower navigation and motion sickness risk, for no information. |
| Hover lift and shadow on cards | Forbidden by DESIGN.md; reads as template UI. The accent edge says "this opens" without moving anything. |
| Count-up on every repaint | It would turn a live list into a slot machine. Count only when the value changes. |
| Skeleton shimmer on charts | The existing skeleton covers loading; a shimmering chart looks like data. |

## 6. Accessibility

- Every interactive mark has an accessible name naming its count and destination. Legends are real links in text.
  The SVG keeps `<title>` for older readers.
- Keyboard order follows reading order: ring segments in legend order, bars top to bottom.
- Tooltips are supplementary (`aria-hidden`). Nothing is available only on hover.
- Targets: a legend row is at least 32 px high. Marks smaller than 24 px have an invisible hit area of at least
  24 px (WCAG 2.2 target size).
- State is never shown by colour alone: the chip and the legend carry words.
