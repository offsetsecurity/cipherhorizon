# UX report 003: polish and motion

Follows [UX-REPORT-002](UX-REPORT-002-premium-visual-redesign.md). The visual system was in place but the
product still felt static and "naive": everything appeared at once, nothing acknowledged an action, and live
state (a running scan) looked the same as idle state. This pass adds motion where it carries meaning.

## Principles

1. **Motion explains a change**: something arrived, something is working, something was copied, something
   closed. Nothing loops for decoration except two deliberately slow, low-amplitude cases (the empty-state icon,
   the running-scan indicator).
2. **Short, decelerating, cheap**: 120-450 ms, one easing curve (`--ease`), `transform` and `opacity` only, so
   nothing forces layout.
3. **One-shot, never on a timer.** Several views repaint every 1.5-7 s while scans run. Entrance animation is
   applied by a class (`.enter`) that the router adds once per navigation (and on tab/filter change) and removes
   again after ~0.9 s, so a refresh never replays it and never flickers. Figures animate (count-up) only when
   their value actually changed.
4. **Reduced motion is a first-class mode**: with `prefers-reduced-motion: reduce` every animation and
   transition is off and the UI is fully usable; nothing depends on an animation finishing. Print disables it too.
5. **No new dependencies, no external requests**: CSS keyframes and ~60 lines of JS in `ui.js`; the strict CSP is
   unchanged (stagger delays are set through the CSSOM, never inline styles).

## What moves

| Where | Motion | Why |
|---|---|---|
| Page and tab content | sections rise and fade in with a 42 ms stagger; table rows fade in | orients the eye after navigation |
| Dashboard figures | count up to their value when it changes | shows a scan changed the number |
| Charts | donut sweeps in, trend columns grow from the baseline, history line draws, bar lists fill, level badge pops | makes the data feel measured |
| Sidebar | active-page indicator grows in; icon eases on hover; brand mark turns on hover; running version shown | wayfinding and identity |
| Buttons, cards, KPIs | subtle lift on hover, press-down on click | affordance |
| Tabs | the underline slides in | shows which panel you are in |
| Scan in progress | pulsing status dot, a moving sheen on the progress bar, a ring on the active step | the only things that are really happening move |
| Dialogs and toasts | dialogs scale in and out; toasts slide in and out | arrival and dismissal are visible |
| Certificate chain | detail panel eases open; serial and fingerprint have a copy button that confirms with a check | small, useful feedback |
| Empty states | an icon that gently floats | the page reads as intentional, not broken |

## Verification

- 44/44 browser journey steps pass, including the 390 px no-horizontal-scroll checks and dialog Escape
  handling (dialogs now close after a 150 ms exit animation).
- In a live browser: `.enter` is present ~150 ms after navigating and gone after 1.3 s; zero elements are
  animating on a settled dashboard; the sidebar indicator renders; no console errors.
- Every animation is disabled under `prefers-reduced-motion` by a single rule at the end of `style.css`.

## Not done

- No page-to-page cross-fade (would need a view-transition API fallback); entrance only.
- Motion was checked in Chromium (Edge) only.
