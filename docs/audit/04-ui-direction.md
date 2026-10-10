# 04 · UI direction: calm, clear, self-explaining

**Role:** Design lead. **Brief:** a sleek, subtle, thoughtful interface in the spirit of Apple's human-interface guidance;
anyone who opens it should know what to do next; everything nicely arranged and explained.

This is a direction for *this* product, not a copy of another one. The product's own vocabulary and scale stay.

## Principles, and what each changes

| Principle | In practice here |
|---|---|
| **Clarity** | One idea per card. Each page opens with a sentence that says what it shows. Jargon is explained where it first appears (harvest-now-decrypt-later, readiness levels, hygiene score). |
| **Deference** | The content leads, the chrome recedes: lighter borders, softer shadow instead of lines, a quieter sidebar, no decoration that carries no meaning. |
| **Depth, gently** | Cards sit on a subtly tinted canvas with a larger radius and a very soft shadow; hover lifts a little; nothing bounces. |
| **Restraint with colour** | Colour is for state. Red is kept for things that are actually critical; "quantum-vulnerable" and "not scanned" use calmer tones so the one thing that needs action stands out. |
| **Progressive disclosure** | Long rationale and citations are behind a disclosure; the default view is the answer, not the proof. The proof is one click away and always present. |
| **Always a next step** | Every empty state and the dashboard say what to do next, with the button that does it. |
| **Typography carries hierarchy** | A slightly larger, tighter page title; a clear step between title, section heading, body and caption; tabular numerals for figures. Inter and JetBrains Mono stay (self-hosted). |

## Concrete changes (all in `web/static`)

1. **Tokens:** canvas `#f5f5f7`-family neutrals, radius 12/16, softer shadows, calmer semantic tints, in light and dark.
2. **Get started** (empty dashboard): two side-by-side cards, *Check a server's TLS* and *Inventory a machine*, each with
   the one action and one line of explanation.
3. **Next-step banner** on the dashboard: one sentence and one button chosen from the data.
4. **Dashboard grid:** six KPI cards in 3×2 (2×3 on a phone); a caption under the card that needs a definition.
5. **Hosts:** an in-page "How do I collect?" panel with the exact command and a copy button; the list gains
   operating system and coverage.
6. **Host detail:** an *Inventory coverage* card (what was scanned, what was not seen, privilege level and the
   elevation nudge), then a compact algorithm list with disclosures.
7. **Sidebar:** quieter section labels and active state; the version stays visible.
8. **Not found / small copy:** neutral icon and wording; `#/endpoints` alias.

## Not changed, on purpose

The information architecture, the readiness and hygiene vocabulary, the strict CSP (no inline styles, no external
requests), keyboard and reduced-motion behaviour, and every existing route. A design pass that broke the security
posture or the E2E journey would fail the gate.

## Verification

Screenshots at 1280 px and 390 px, light and dark, before and after; the extended browser journey; contrast spot
check on the new tints; a check that the CSP is not violated (no console errors).
