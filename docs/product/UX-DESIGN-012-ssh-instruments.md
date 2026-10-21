# UX-DESIGN-012 · The SSH report, as instruments (addendum to UX-DESIGN-011)

Status: draft 2026-10-21 for [PRD-014](PRD-014-ssh-instruments.md). It applies
[UX-DESIGN-011](UX-DESIGN-011-instruments-not-paragraphs.md) to the SSH server report, which kept the PRD-008 layout
(UX-DESIGN-007 §4) apart from its algorithm tables. It replaces UX-DESIGN-011 §3.5. Everything in UX-DESIGN-011 §1
(principles), §2 (components) and §4 (responsive and accessible) holds here unchanged.

## 1. What changes, and why

Today's SSH Configuration has:
- a baseline card of prose: a verdict sentence, a hint paragraph, a requirement list with a bullet list of citations
  under each requirement, and the changes as a bullet list of sentences;
- six fact cards, each a verdict sentence, then bullets that repeat it, then a table;
- a readiness panel of three paragraphs, each with its own citation list.

The same facts are said two or three times, once in a sentence and once in a table. The rebuild draws each fact
once, as an instrument, in the order an SSH reviewer checks, and moves every source into a tooltip or a link.

## 2. Report › Summary (SSH)

1. **Instruments**: four tiles in the TLS strip's order (label, figure, instrument):
   - **Post-quantum readiness**: level and `levelStepper`;
   - **Baseline**: *Meets* / *N changes* / *Not judged*, and the baseline's name;
   - **Weakest classical strength**: the bits and the algorithm, with a `bitsBar`;
   - **Host key**: the key a current client verifies, post-quantum or classical, and its fingerprint's start.

   Each opens its part of Configuration. An SSH server has no score, so there is no gauge.
2. **Fix first**: the baseline is the first numbered line when the server does not meet it, in the same row
   shape as every finding (number, a severity chip, title, what to do, a link to its lines). The
   "Why it matters" block goes.
3. **Checks** bar and **By area** tiles: shared with TLS, unchanged.

## 3. Report › Configuration (SSH): the one-stop check

A sticky `jumpNav`, each chip with its part's state dot, then six parts in a reviewer's order. Each part is a
`section.card.cfg` and ends with its issues (the findings that belong to it, each linking to its evidence) and the
baseline changes that fall in it.

| # | Part | Draws |
|---|---|---|
| 1 | **Version and software** | The banner *A current client gets*: key exchange + host key + cipher + MAC (or "AEAD, no MAC"), the post-quantum key exchange marked. Status tiles: protocol (SSH-2 only / SSH-1 accepted / SSH-1 only), software (as announced; vendor advisories are not checked), lines before the identification. The identification string is the protocol tile's raw detail. |
| 2 | **Key exchange** | The readiness row (level, stepper, the three dimensions as chips, each dimension's detail and sources in its tooltip); the algorithm rows (§3.1); a *Strict key exchange* tile (Terrapin countermeasure). The next steps as a short numbered list, as on TLS. |
| 3 | **Host keys** | A ribbon of key cards, one per key fetched: algorithm and size, post-quantum glyph, *verified* chip (the key signed the exchange), the host-key names it answers to as chips, the SHA-256 fingerprint in mono, and a certificate line when the key is an OpenSSH certificate. A key the scan could not fetch is a dashed card that says why. Then the host-key algorithm rows. |
| 4 | **Ciphers** | The algorithm rows. |
| 5 | **MACs and compression** | The MAC rows. When a current client's cipher is an AEAD, the aside says no MAC is used. Compression as one status tile per method offered (none / delayed until after login / before login). |
| 6 | **Baseline changes** | The verdict as a status tile beside the baseline's name; each requirement as a status tile (met / not met, the reason as its state), linking to its source, the source's name in the tooltip; the changes as chips (− remove, + add, ↑ upgrade, ⟲ replace the key), each change's reason and source in its tooltip; the `sshd_config` lines in a mono block with *Copy the lines*, the one instruction on where to put them in one muted line. A server that meets the baseline shows no lines block. |

*About this report* follows, collapsed. Published attacks stay on Weaknesses, as on TLS.

### 3.1 The algorithm row

One row per algorithm, in the order the server lists them, under a shared `bitsAxis`:

| Name | Strength | Post-quantum | Baseline |
|---|---|---|---|
| the SSH name in mono; under it, what it is (the registry's display name) | `bitsBar` (basis in the tooltip); compression has none | `pqGlyph` for key exchange and host keys; a dot for ciphers and MACs (no quantum question) | ✓ *allowed* or ✕ *should be off*; a name the program does not know says so in the tooltip |

- The row a current client uses is tinted, with an *in use* chip whose tooltip names the client (OpenSSH 10.6
  defaults).
- No rank numbers: in SSH the client's order decides (RFC 4253 §7.1), so the server's order is not a preference
  and is not drawn as one. The part's aside says so once.
- A row that should be off is ringed in the problem tone; nothing else repeats it.

## 4. What goes

- The baseline card's verdict sentence and its hint paragraph.
- The bullet lists of citations (requirements, readiness dimensions): each source is a tooltip and a link.
- The fact cards' verdict sentences and fact bullets.
- The readiness panel of paragraphs (replaced by the readiness row).
- The algorithm tables' *What it is* column (now the row's sub-line) and the *used by OpenSSH 10.6* badge column.
- The old summary strip markup (`lvscale`), replaced by the shared stepper.

## 5. Responsive

- Rows: four columns at ≥ 861 px; at ≤ 860 px the baseline mark moves under the name, and at ≤ 520 px the bar's
  value goes under the track (as on the TLS lanes).
- The key ribbon scrolls sideways inside itself; the `sshd_config` block scrolls inside itself.
- The page never scrolls sideways at 1440, 1100, 860 and 375 px.
