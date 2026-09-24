# 02 · Usability and UI audit (pre-0.1.0)

**Role:** UX reviewer. **Method:** a fresh instance with an empty database, then a populated one (five endpoints scanned,
one real Windows host inventory uploaded). Every screen was captured at 1280 px and 390 px and read as a person who has
never seen the product. Question asked of each screen: *do I know where I am, what this means, and what to do next?*

## What already works

- One clear primary action per screen; consistent status badges; the readiness scale and the hygiene score are
  explained on the About page and linked from the dashboard.
- Findings cite their sources; hostile text is always rendered as text; the empty, loading and error states exist.
- Motion is restrained and switches off for people who ask for that.

## Findings

| ID | Sev | Screen | Finding | Fix |
|---|---|---|---|---|
| UX-01 | **High** | First run | The empty dashboard offers only "Add endpoints". Nothing says the product also inventories machines (Hosts, the collector), so half the product is invisible to a new user. | A "Get started" screen with two clear paths: *check a server's TLS* and *inventory a machine*. |
| UX-02 | **High** | Hosts | No guidance on how to produce an upload: which program, which command, why run it elevated. The page says only "Upload CBOM". | An in-page how-to with the exact command and a copy button, on the empty state and behind a "How do I collect?" button. |
| UX-03 | **High** | Host detail | The page cannot tell you how complete the inventory is. The collector records its privilege tier, coverage, and what it could not see (`cipherhorizon:coverage`, `:not-seen`, `:privilege-tier`), and the UI shows none of it. A standard-user run looks as authoritative as an Administrator run. | An "Inventory coverage" card: operating system, privilege level, what was scanned, what was not seen, and a plain nudge to re-run elevated. |
| UX-04 | Medium | Host detail | The algorithm table is a wall: every row repeats a paragraph of rationale, and "provided by" lists the same file several times. | Show the verdict and one line; put the rationale and citations behind a disclosure; de-duplicate and truncate "provided by". |
| UX-05 | Medium | Hosts list | Columns say "Packages" for a Windows file inventory; nothing shows the operating system or how complete the run was. | "Components"; add operating system and a coverage badge. |
| UX-06 | Medium | Dashboard | Six KPI cards wrap as five plus one orphan; on a phone each takes a full row. | A grid that fits six (3×2) and two-up on narrow screens. |
| UX-07 | Medium | Dashboard | "Exposed to harvest-now-decrypt-later" is unexplained where it first appears. | A one-line explanation under the card and a tooltip. |
| UX-08 | Medium | Dashboard | No "what should I do next" line. Findings are ranked but the page never says which one to do first. | A single next-step banner driven by the data (add something → scan → fix the top finding → re-scan). |
| UX-09 | Low | Navigation | The menu says "Endpoints" and the address says `#/assets`; "Scans" has no menu entry; typing `#/endpoints` gives "Page not found". | Accept `#/endpoints` as an alias; keep Scans reachable from the dashboard. |
| UX-10 | Low | CBOM page | Name and address are printed twice when they are the same; the page duplicates what each detail page already offers. | Print the address only when it differs. |
| UX-11 | Low | Visual | Saturated red is used for many different things at once, so nothing stands out; cards are flat and the type scale is tight. | The visual pass in `docs/audit/04-ui-direction.md`. |
| UX-12 | Low | Not found | The "page not found" page uses the shield icon of a success state. | Neutral icon and wording. |

## Command line and first-run text

- `cipherhorizon serve` prints a two-line notice and the address. It does not say where the data is kept or how to add
  the first target. **UX-13 (Low):** print the next step ("open the address, then Add endpoints").
- The collector prints a privilege warning when it is not elevated (good) but ends with only the output path.
  **UX-14 (Low):** end with the next step: "upload this file on the Hosts page of your CipherHorizon server."

## Accessibility spot check

Keyboard focus is visible, dialogs trap focus, colour is never the only carrier of meaning (badges have words), and
reduced motion is honoured. Not measured: a screen-reader pass and contrast ratios of the new palette; both are part of
the QA plan.
