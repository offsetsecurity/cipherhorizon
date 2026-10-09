# 05 · Brand and messaging: the Offset theme, a flat logo, and saying what the product is

2026-10-08.

## 1. The Offset design system (read from offsetsecurity.net's live stylesheet)

| Token | Value | Role on offsetsecurity.net |
|---|---|---|
| `--canvas` | #F7F7F5 | Warm paper background |
| `--band` | #ECECE8 | Alternate section band |
| `--surface` | #FFFFFF | Cards, panels |
| `--line` / `--line-strong` | #DEDDD7 / #C5C4BC | Hairlines |
| `--ink` / `--navy` | #0B1428 | Headings, primary buttons, dark bands |
| `--navy-2` / `--navy-3` | #15213D / #1E2C4E | Raised areas on navy |
| `--body` | #2B3140 | Body text |
| `--muted` | #5A5F6B | Secondary text |
| `--blue` | #2457D6 | The brand blue (logo mark) |
| `--blue-ink` | #1B45B0 | Links, eyebrows, navigation |
| `--blue-wash` | #E7EDFB | Tinted backgrounds |
| `--on-navy` / `--on-navy-muted` / `--on-navy-accent` | #E8ECF4 / #A3AEC2 / #9DB6FF | Text on navy |
| `--success` / `--warning` / `--error` | #1D7A4C / #9A5B0B / #B42318 | States |
| Type | **Newsreader** (display serif), **Geist** (sans), **Geist Mono** (eyebrows, 11.5px uppercase, +0.04em) | Editorial headlines, clean UI, technical labels |
| Shape | 4px radius; a **−27.6° skew** (the logo's parallelogram) | Restraint; one signature angle |
| Motion | `cubic-bezier(.16,1,.3,1)`, 160/320ms | Calm |
| Elevation | A single `--float` shadow for floating things | As in DESIGN.md |

**What carries over to CipherHorizon.**
- **Kept from Offset:** the palette, the three typefaces, the 4px shape and the skew as a sparing accent.
- **Kept from DESIGN.md:** the principles (evidence over decoration, one accent, hairlines over shadows, sentence-case UI labels, mono for machine values).

The result reads as an Offset product.

**One adaptation.**
- **Offset blue becomes the accent** (#2457D6 for actions, #1B45B0 for links).
- **Navy carries the rail** and the hero bands.
- **Newsreader appears only** on large headings (page title, hero, report cover), never in the dense UI.
- **Geist Mono uppercase eyebrows** appear at most once per screen, the way Offset uses them.

**Fonts.** Geist, Geist Mono and Newsreader are all SIL OFL. They must be bundled, because the CSP and the offline
promise forbid a font CDN, which means downloading their `.woff2` files once from the upstream releases.

## 2. Flat logos

**Today:** the CipherHorizon mark is a hexagon with a violet-to-amber gradient, a keyhole cut, a hairline stroke and
a glow behind it in the rail. The Offset logo in the app is already flat (blue mark, navy wordmark).

**Rule:** every logo is flat. One colour per shape, no gradient, no stroke, no glow, no shadow. Each comes in three
versions: colour (blue mark, navy wordmark), on-navy (blue-light mark, white wordmark) and one-colour (for the PDF and
the favicon).

**Concepts for the CipherHorizon mark** (shown side by side in the agreement step):

| Concept | Description | For | Against |
|---|---|---|---|
| A · Flat hexagon | Today's silhouette and keyhole, solid Offset blue | Recognisable continuity | The hexagon has nothing to do with Offset's angle |
| B · Horizon parallelograms | Three stacked parallelograms at Offset's −27.6° skew, the lowest one cut by a keyhole: a horizon and a lock | Reads as a sibling of the Offset mark; distinctive | New shape to learn |
| C · Hexagon with a horizon | A navy hexagon crossed by one blue skewed band (the horizon), keyhole in the band | Keeps the hexagon; brings in the angle | Two colours, busier at 16px |

**Lockup:** `CipherHorizon` set in Geist 600, and under it `by Offset Security` in Geist Mono. The "Developed by"
credit in the rail stays, flattened.

## 3. Messaging

**One-liner (for GitHub, the image label and the sign-in screen):**
> Post-quantum readiness for every TLS endpoint you run: a deep TLS scan, a readiness level from L0 to L4, and a
> CycloneDX CBOM, self-hosted.

**Headline (Offset's own voice, which it already uses for its PQC practice):**
> Quantum-safe before it's urgent.

**Three pillars:**

| Pillar | Promise | Proof in the product |
|---|---|---|
| **Post-quantum readiness** | Know which endpoints would leak recorded traffic to a future quantum computer, and what to do first | L0–L4 per endpoint; hybrid ML-KEM detection; harvest-now-decrypt-later exposure; migration order by data lifetime |
| **A TLS scanner that shows its work** | Every protocol from SSLv2 to TLS 1.3, every suite and group, every check, passed or failed, with sources | Own wire implementation; 55 checks with RFC/NIST/IANA citations; a version-by-version matrix |
| **An inventory you can hand over** | One CBOM for endpoints and machines; reports an auditor accepts | CycloneDX 1.6/1.7, PDF reports, OMB M-23-02 export, signed releases |

**Proof points to repeat:**
- **Standards:** NIST IR 8547's 2030/2035 dates; FIPS 203/204/205; CNSA 2.0; CycloneDX.
- **Trust:** self-hosted, nothing leaves your network, a single binary, signed releases with an SBOM.
- **Dogfooding:** it passes its own scan (after audit L-06).

**Words to avoid:** "military-grade", "AI-powered", "quantum-proof", letter grades, "revolutionary".

## 4. Where the product advertises itself (inside the tool)

| Place | Today | Proposed |
|---|---|---|
| Sign-in screen | A form | Two columns: a navy panel with the headline, the three pillars and "by Offset Security"; the form on the right |
| Overview hero | Functional headline | An eyebrow (*POST-QUANTUM READINESS · TLS SCANNER · CBOM*), a Newsreader headline, the scan form; the L0–L4 scale stays as the legend |
| About | Reference tables | A short product page: pillars, standards, what it does not do, Offset credit, links (docs, GitHub, Offset PQC Readiness) |
| PDF reports | CipherHorizon wordmark | The flat lockup, *by Offset Security* and the standards line on the cover; optional client and assessor fields |
| Empty states | Instructions | Instructions plus one sentence of why |
| CLI | Raw output | A summary block with the readiness level and score, and the one-liner in `--help` |

## 5. Outside the tool

- **README:** rewritten with the one-liner, a report screenshot, a GIF of a 30-second scan, the quick start, the
  three pillars, a comparison table (testssl.sh, SSL Labs, PQC CLIs), standards, security and trust, and the Offset
  credit.
- **Docs site (GitHub Pages):** a landing page in the Offset theme, plus docs for getting started, deployment, the
  CLI and CI, the API, methodology and FAQ.
- **Launch posts:**
  - Show HN: why it exists and its limits.
  - r/netsec, r/selfhosted and r/sysadmin.
  - LinkedIn from Offset: the PQC Readiness practice and the free tool.
  - A data post: "We scanned the top N sites for post-quantum readiness."
- **Communities:** the CycloneDX tool centre, PQCA, awesome-pqc, awesome-selfhosted.
