# PRD-009 · Charts you can act on, quiet motion, a chosen port, and a complete CBOM

Status: baselined 2026-10-18. Requests (owner, 2026-10-18):
- "make the graph in the UI interactive: clicking on some graph takes it to that";
- "a little animation across the site, subtle";
- "the port to run should be customisable when running it";
- "review whether the CBOM has OIDs missing or is doing it right".

Screens and motion: [UX-DESIGN-008](UX-DESIGN-008-interactive-charts-and-motion.md). Architecture and work packages:
[ENG-HANDOFF-006](ENG-HANDOFF-006-charts-motion-port-cbom.md). CBOM findings: [CBOM-REVIEW-002](CBOM-REVIEW-002-oids-and-completeness.md).
Tests: [QA-PLAN-007](QA-PLAN-007-charts-motion-port-cbom.md). Status per requirement: [RTM](../program/RTM.md).

## 1. Problem

**Charts are pictures, not doors.** The Overview readiness scale counts the endpoints at each level, but a reader
who sees "3 at L1 Exposed" cannot open those three. The inventory dashboard has the same problem:
- its ring, purpose bars, protocol bars and certificate-expiry bar look clickable and are not;
- only the card footers link, and always to the unfiltered list;
- a reader who wants "the certificates expiring within 30 days" must open the list and set the filter again.

Every figure is a question the reader has just asked. The answer should be one click away.

**The site is still.** Motion today is limited to the page rise, the history line and the running-scan pulse
(DESIGN.md §9). Values appear without showing where they came from:
- rings and inventory bars snap in;
- figures do not count;
- hovering a chart does nothing but show a native tooltip after a second's delay.

A product that sells precision should feel precise. Done badly, though, motion is decoration: DESIGN.md forbids
hover lifts, bobbing and looping, and that stays.

**The port is fixed in practice.** `serve --addr 127.0.0.1:8080` can be changed, but:
- a user who only wants another port must retype the host;
- containers and services hard-code `8080` in four places;
- a port already in use ends with a raw `bind: address already in use` / `Only one usage of each socket address`.

**The CBOM leaves out real cryptography and OIDs that exist.** See CBOM-REVIEW-002:
- 3DES, RC4 and the NIST P-curve groups a server accepts are missing;
- certificate signature algorithms and ChaCha20-Poly1305 have no OID although one exists;
- the 1.7 certificate fields for the serial and the fingerprint are unused.

## 2. Goals and measures

| # | Goal | Measure |
|---|---|---|
| G-1 | Every chart mark that stands for a set of things opens that set | Each mark listed in REQ-CHT-1 to 6 navigates to a list already filtered to exactly what it counted (the counts match) |
| G-2 | Motion explains change and is never decoration | Every animation is on the UX-DESIGN-008 motion table; none loops on a still page; reduced motion turns all of it off |
| G-3 | Running on another port is one flag or one variable | `serve --port 9000`; `CIPHERHORIZON_PORT=9000` in a container, service or shell; a busy port says what to do |
| G-4 | The CBOM lists everything the scan saw, with every authoritative OID | CBOM-REVIEW-002 §5 "Done when" passes |

**Non-goals.**
- No chart library and no new dependency. The SVG stays hand-drawn, under the existing CSP (no inline styles).
- No new chart types, no dashboards rearranged.
- No drag, zoom or brushing.
- No auto-selection of a free port at start-up (`--port 0` is allowed and reported, but never chosen silently).
- No CBOM vocabulary of our own for C-7 to C-10.

## 3. Users and jobs

| Persona | Job | What this gives them |
|---|---|---|
| Security engineer | "Which endpoints are the three at L1?" | Click L1 on the Overview: the TLS list filtered to L1 |
| PKI lead | "Show me the certificates expiring within 30 days" | Click that segment of the expiry bar: the certificate list filtered |
| Crypto inventory owner | "Where is RSA used?" | Click RSA in Replace first: the algorithm list filtered to it |
| Ops | "8080 is taken on this box" | `cipherhorizon serve --port 8090`, or a message naming the flag |
| Auditor / GRC tool | "Import this CBOM into our crypto inventory and match by OID" | The P-curves, 3DES/RC4 and per-hash signatures are there, with OIDs |

## 4. Requirements

### Charts you can act on (WP-1)

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-CHT-1** | **Readiness scale on the Overview.** Once something is scanned, each level row with a count opens the list of what is at that level. With one protocol at the level, the row links to that protocol's list (`#/endpoints?level=N` or `#/ssh?level=N`). With both, the count shows as two links ("2 TLS", "1 SSH"). A level with nothing is not a link. | The L1 row shows 2 and opens the TLS endpoints list showing those 2 | `script:testing/e2e/charts-phase.mjs#CHT-1` | P0 |
| **REQ-CHT-2** | **Lists accept the filter from the address.** The TLS and SSH lists read `level` and `exposed=1` from the address and show the filter as a removable chip ("Level L1 Exposed ×"). The findings list reads `severity`, `status` and `kind`. The certificate list reads `expires` (expired, 30, 90), `key` and `origin`. Each inventory list reads `q`, `vulnerable=1`, `quantum` (vulnerable, safe, unknown), `purpose` and `source`. Changing a filter on the page updates the address (replace, no new history entry), so Back returns to the chart. | Every link in REQ-CHT-1, 3 and 4 lands on a list whose count equals the figure clicked | `TestInventoryFiltersByQuantumAndPurpose`, `script:testing/e2e/charts-phase.mjs#CHT-2` | P0 |
| **REQ-CHT-3** | **Inventory dashboard marks.** Each mark opens its list, filtered: <br>• each ring segment and its legend row: algorithms filtered by `quantum`; <br>• each *Replace first* row: algorithms with `q` set to the name; <br>• each *By purpose* bar segment: algorithms by `purpose` and `quantum`; <br>• each protocol bar: protocols with `q` set to the version; <br>• each certificate-expiry segment and its legend row: certificates by `expires`; <br>• each software row: software with `q` set to the name. <br>The status tiles keep their links, and "Quantum-vulnerable" opens the same filtered list as the red ring segment. | Clicking the "Within 30 days" segment shows exactly the `within30` count of certificates | `script:testing/e2e/charts-phase.mjs#CHT-3` | P0 |
| **REQ-CHT-4** | **Overview status band chips.** Each severity chip on *Findings* ("2 critical") opens findings filtered by that severity. "N exposed to harvest-now-decrypt-later" opens that protocol's list with `exposed=1`. | Clicking "2 critical" lists 2 critical problems | `script:testing/e2e/charts-phase.mjs#CHT-4` | P1 |
| **REQ-CHT-5** | **History chart.** Each point of *Readiness over time* is a control. Hover or focus shows a tooltip (date, level, measure). Click opens that scan's report (`?scan=ID`), as the history table's *Open* link does. | Clicking the first point opens the report of that scan, labelled as an earlier scan | `script:testing/e2e/charts-phase.mjs#CHT-5` | P1 |
| **REQ-CHT-6** | **One way to read a mark.** Every interactive mark: <br>• shows a styled tooltip on hover and on keyboard focus within 120 ms, with the native `<title>` kept for screen readers; <br>• dims the other marks of its chart while hovered; <br>• is reachable by Tab, opens with Enter or Space, and has an accessible name that says what it opens ("12 quantum-vulnerable algorithms: open the list"); <br>• shows the pointer cursor and the focus ring. <br>A mark that opens nothing (a zero, or a decoration) is none of these. | axe-style checks in the journey: every `[data-href]` mark has role link, a name, `tabindex=0`; Enter navigates | `TestChartsAreKeyboardReachable`, `script:testing/e2e/charts-phase.mjs#CHT-6` | P0 |

### Motion (WP-2)

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-MOT-1** | **Charts arrive by drawing their value once.** <br>• ring and donut segments sweep from 0 to their length (staggered by segment); <br>• horizontal bars grow from the left; <br>• the history line draws, then its points fade in. <br>Once per page arrival only: not on poll repaints, not on a filter change. | The journey sees `.enter` on arrival only; a repaint by polling does not restart it | `script:testing/e2e/charts-phase.mjs#MOT-1` | P1 |
| **REQ-MOT-2** | **Figures count to their value.** The Overview status-band figures, the readiness-scale counts and the inventory tiles count up once on arrival (≤ 600 ms, ease-out), and again only when a value changes. "3 of 7" counts both parts. | Polling with an unchanged value does not re-count | `TestCountUpIsUsedOnlyForFigures`, `script:testing/e2e/charts-phase.mjs#MOT-2` | P2 |
| **REQ-MOT-3** | **Filters cross-fade.** A filter change (select, chip, checkbox) fades the list out and in (≤ 180 ms total) instead of snapping. Rows do not stagger again. | Visual check in the screen walk | `report:docs/product/UX-REVIEW-009-charts-and-motion.md` | P2 |
| **REQ-MOT-4** | **Quiet hover and press feedback.** <br>• chart marks dim their siblings; <br>• clickable rows, tiles and stats show a 2px accent edge on hover; <br>• primary buttons darken and settle 1px on press; <br>• the active nav item's indicator grows in when the place changes. <br>Colour and transform only, 120 to 180 ms. No lifts, glows or shadows on hover. | `TestNoDecorativeGradients` and the design guards pass; the screen walk confirms | `TestMotionRulesAreRespected`, `report:docs/product/UX-REVIEW-009-charts-and-motion.md` | P1 |
| **REQ-MOT-5** | **Motion rules hold.** Only `opacity`, `transform` and SVG `stroke-dashoffset` animate. Nothing loops except live state (running scan). Every new animation and transition is off under `prefers-reduced-motion: reduce` and in print. DESIGN.md §9 is updated with every new row. | A test reads style.css: every `@keyframes` animates only the allowed properties and appears in the reduced-motion reset | `TestMotionRulesAreRespected` | P0 |

### Port (WP-3)

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-PORT-1** | **`serve --port N`** sets the port and keeps the host of `--addr` (default `127.0.0.1`). `--addr` may now be a host alone (`--addr 0.0.0.0`). `--port` given together with an `--addr` that has a port is an error naming both flags. Valid ports are 1 to 65535, and 0, meaning any free port: the start-up line prints the port actually used. | `serve --port 9000` listens on 127.0.0.1:9000; `--addr 0.0.0.0:80 --port 81` fails with a clear message | `TestServePortFlag`, `TestServeAddrAndPortConflict` | P0 |
| **REQ-PORT-2** | **Environment defaults.** `CIPHERHORIZON_PORT` and `CIPHERHORIZON_ADDR` set the defaults; flags win. `healthcheck` reads the same defaults, so a container moved to another port still reports healthy without its health command being edited. | With `CIPHERHORIZON_PORT=9100`, `serve` and `healthcheck` both use 9100 | `TestServePortFromEnvironment`, `TestHealthcheckFollowsPortEnvironment` | P0 |
| **REQ-PORT-3** | **A busy port says what to do.** If the address is in use, the error names the port and suggests `--port` with the next port. Exit code 1. Windows and Unix both. | Start two servers on one port: the second prints "port 8080 is already in use … start with --port 8081" | `TestServeBusyPortSaysWhatToDo` | P0 |
| **REQ-PORT-4** | **Every way of running it follows.** <br>• The Dockerfile `CMD` is `--addr 0.0.0.0` with the port from `CIPHERHORIZON_PORT` (default 8080). <br>• compose, the Quadlet, the systemd env file and the launchd plist document the variable. <br>• The Windows service's "open at" URL follows `--port`. <br>• INSTALL.md, README and `serve --help` show `--port`. | Container on Podman with `-e CIPHERHORIZON_PORT=9000 -p 127.0.0.1:9000:9000` serves and is healthy | `TestServiceURLFollowsPort`, `script:testing/deploy/smoke.sh#PORT` | P1 |

### CBOM completeness (WP-4)

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-CBM-1** | **Every bulk cipher the catalogue knows is referenced** by the suites that use it: 3DES, RC4 (any key size) and DES, besides AES and ChaCha20. NULL stays unreferenced. (CBOM-REVIEW-002 C-1) | The SSLv3 demo CBOM lists 3DES and RC4 assets with classical status | `TestLegacySuiteCiphersAreAssets` | P0 |
| **REQ-CBM-2** | **Every accepted classical group is an asset**: secp256r1/384r1/521r1 as `ECDH-P256/P384/P521` (id-ecDH, with the curve), x448 as `X448` (1.3.101.111). All are judged quantum-vulnerable by the existing rules. (C-2) | The hybrid demo CBOM lists `ECDH-P256` with `ellipticCurve` secg/secp256r1 | `TestNISTCurveGroupsAreAssets` | P0 |
| **REQ-CBM-3** | **Certificate signatures carry their OID**: ECDSA-SHA256/384/512, sha256/384/512WithRSAEncryption, RSASSA-PSS, from the certificate's own signature OID. Falls back to the family only when no variant exists. (C-3) | The ECDSA demo certificate references `ECDSA-SHA256` @ 1.2.840.10045.4.3.2 | `TestCertificateSignatureVariantHasOID` | P0 |
| **REQ-CBM-4** | **ChaCha20-Poly1305 carries OID 1.2.840.113549.1.9.16.3.18** (RFC 8103). The catalogue comment is corrected. (C-4) | | `TestCatalogueOIDsAreCited` | P1 |
| **REQ-CBM-5** | **1.7 certificates carry `serialNumber` and `fingerprint`** (SHA-256). 1.6 keeps the `cipherhorizon:cert-serial` property. (C-5) | Both validate against the vendored schemas | `TestCertificateSerialAndFingerprintIn17` | P1 |
| **REQ-CBM-6** | **A suite lists each algorithm once.** (C-6) | `TLS_RSA_WITH_3DES_EDE_CBC_SHA` lists RSA once | `TestSuiteAlgorithmsAreUnique` | P2 |
| **REQ-CBM-7** | **The documentation says what the CBOM holds.** docs/cbom-model.md: "Known limits" and the review history are updated; C-7 to C-10 are listed as known limits with their reasons. | | `report:docs/product/CBOM-REVIEW-002-oids-and-completeness.md` | P1 |

## 5. Release

This is a minor feature release, **0.2.0**. The CBOM changes add components and fields, and consumers keyed on
component counts will see more. The release follows docs/engineering/RELEASING.md: a PR with the CHANGELOG entry,
CI green, merge, tag `v0.2.0`, then the release workflow.

## 6. Risks

| Risk | Mitigation |
|---|---|
| Clickable marks inside cards that already link (tiles) nest links | Marks are `<g role="link">` with their own handler; no `<a>` inside `<a>`; the journey checks for nested links |
| Address filters drift from on-page controls | One `readFilters(query)` / `writeFilters()` per list; the control state is always derived from the address |
| Motion that reads as "AI slop" | The UX-DESIGN-008 table is the whole list; the screen walk (UX-REVIEW-009) is required before done |
| CBOM consumers break on new components | Additive only; golden diffs reviewed; CHANGELOG says what is new |
| `CIPHERHORIZON_PORT` set to garbage in a container | Same validation as the flag; the error names the variable |
