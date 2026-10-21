# UX-DESIGN-011 · Instruments, not paragraphs

Status: approved by the owner 2026-10-21 ("let's build it"), from the concept canvas
(<https://claude.ai/artifact/7eFsXya4o5ieXGuqfySEXF>) and its three review comments. It answers
[UX-REVIEW-010](UX-REVIEW-010-flow-and-self-explanation.md) and the owner's verdict on the first PRD-011 screens:
"very texty… double symmetric writing with text and bullet points". The data and the story are settled. This
document is the layout, the order and the visual encodings. Requirements: [PRD-013](PRD-013-visual-rebuild.md).
It works inside [DESIGN.md](../../DESIGN.md): Offset theme, flat, one accent, symbol + word + colour.

## 1. Principles for this rebuild

1. **Encode first, explain on demand.** Every fact that is a quantity is drawn: bits on a scale, days on a
   timeline, a score on a gauge, counts as a stacked bar. Its source and reasoning go in the element's tooltip
   (`title`) or one click away, never in a paragraph above it.
2. **One label per thing.** A class, a version or a state is named once, in the place a reader looks for it. No
   pill that repeats a heading, and no sentence that repeats a table.
3. **Order by the reviewer's question.** Each screen follows the order an experienced reviewer checks in, and a
   sticky jump row shows every section with its state.
4. **Every state is a tile:** a symbol, a word and a colour (✓ good, ! needs attention, ✕ problem, – does not apply
   or not probed), with the finding in its sub-line.
5. **The same instrument means the same thing everywhere.** The bits bar on the Configuration, the certificate page,
   the Inventory and the SSH report is one component with one scale.

## 2. Components (`web/static/js/viz.js`)

| Component | Draws | Rules |
|---|---|---|
| `bitsBar(strength, opts)` | A track 0 to 256 bits with four hard bands (below 80 broken, 80 to 111 weak, 112 to 127 acceptable, 128 and up strong), a fill to the value in its band's ink, the value in mono to its right, and an optional "weakest" ring | A *broken* status fills the track with a hatched red. *Not rated* draws an empty track and the words "not rated". `title` holds the basis. `role="img"` with an aria-label in words. |
| `bitsAxis()` | The tick row (0, 80, 112, 128, 192, 256) for a column of bars | Shared by every column that uses bars. |
| `strengthChip(word)` | Strong, Acceptable, Weak or Insecure, as a tinted chip | It is the only place a suite's word appears. |
| `partCell(part, weakest)` | One heat cell: the bits in mono on its band's tint, a ring when it is the weakest, "–" when the part is not used (AEAD has no MAC) | `title` = part name and strength. |
| `pqGlyph(status)` | A shield with a check (quantum-safe), a shield with a cross (quantum-vulnerable), a middle dot (no quantum question) | Always has an accessible name. |
| `statusTile(name, state, tone)` | A small bordered tile: a glyph, a bold name and a one-line state | `tone` is good, attention, problem or na. |
| `lifetimeBar(notBefore, notAfter, now)` | Days used against the lifetime, with a "today" mark | Green while more than 30 days are left, amber within 30, red when expired. |
| `gauge(score, band)` | A 180° arc 0 to 100 in the band's colour, the score, and the band word | Used once, for TLS hygiene. |
| `levelStepper(level)` | Five segments L0 to L4, filled up to the level | Used for readiness. |
| `stackBar(segments)` | A proportional bar of counts, with a legend of counts | Coverage of checks, the Inventory's classes. |
| `jumpNav(sections)` | A sticky row of chips, each with a state dot, that scrolls to its section | Configuration only. |

## 3. Screens

### 3.1 Report › Summary (TLS)

1. **Instruments.** Four tiles in one band:
   - readiness (level and stepper);
   - TLS hygiene (gauge, and the ceiling that capped it, if any);
   - the weakest classical strength (bits bar and the algorithm that sets it);
   - the certificate (days left, lifetime bar, a trust chip per store).

   Each tile opens its section.
2. **Fix first.** A numbered list, worst first: a severity chip, the title and the one-line *what to do*, with
   *Evidence* on the right. The grouping by "why it matters" goes; the why is in the evidence.
3. **Checks.** A stacked bar (problem, to note, passed, could not run, does not apply) with its counts. It replaces
   the coverage sentence.
4. **By area.** One status tile per area: the area and its one-line verdict. It replaces the list of sentences.

### 3.2 Report › Configuration (TLS): the one-stop check

A sticky jump row, then, in a reviewer's order:

1. **Protocols and suites.**
   - The negotiated connection as a banner: version + suite + group, post-quantum marked.
   - For each version that is on, a header: name, the number of suites, who picks the order, forward secrecy, and
     its groups as chips (post-quantum marked).
   - Under it, its suites in the server's order, one row each:
     - rank;
     - full IANA name, with a fact line (key exchange, AEAD or CBC, IANA status);
     - the five part cells: cipher, key exchange, signature, MAC, hash;
     - the strength chip.
   - Versions that are off share one line of ✓ chips. A version that is on but should be off gets a red header
     ("should be off").
2. **Certificate chain.** A ribbon of cards, leaf first, each opening the certificate's page. Each card shows:
   - role;
   - common name;
   - key and signature strength chips;
   - self-signed or not;
   - a lifetime bar;
   - names (on the leaf).

   A missing intermediate or untrusted root is drawn as a dashed card that says what to do. Trust per store and
   the name match are chips beside the title.
3. **Key exchange and signatures.** Labelled rows of chips:
   - groups per version, in preference order;
   - finite-field DH and its prime;
   - TLS 1.3 signature schemes;
   - certificate key types.

   Readiness (level, stepper and the three dimensions) is a compact row here, not a panel of paragraphs.
4. **Revocation and transparency.** Status tiles: OCSP stapling, must-staple, OCSP and CRL pointers, SCTs (counted,
   with the logs in the tooltip).
5. **Features.** Status tiles: secure renegotiation, extended master secret, downgrade protection, compression,
   encrypt-then-MAC, session tickets, ALPN, client certificates, heartbeat. Each says what was found and whether
   that is right. HSTS joins here.
6. **Everything above, by class.** The crypto map:
   - one lane per class (asymmetric, symmetric, hash), each named once;
   - a row per algorithm: name and role, a bits bar on the shared axis, the post-quantum glyph, and its uses;
   - the weakest of each class ringed.
7. *About this report*, collapsed, as today.

The vulnerabilities list stays on Weaknesses.

### 3.3 One certificate

Top to bottom:
1. **Chain ribbon:** this certificate highlighted, its issuer and root linked, a root that was not sent shown dashed.
2. **Header:** common name (display face), organisation and issuer, chips for type, validation and version, then
   Copy PEM and Download .pem.
3. **Validity:** a lifetime bar with the dates and "today".
4. **Two meters,** public key and the issuer's signature: a bits bar, the post-quantum glyph, and the basis in one
   muted line.
5. **Names and uses,** as chips: names typed by colour (DNS, wildcard, IP, e-mail, URI); key usage and EKU with a
   *critical* flag.
6. **Every extension,** as a definition list: name and OID, then the values as chips or mono. An undecoded one says
   so.
7. **Identifiers:**
   - SHA-256 and SPKI fingerprints, serial, and SHA-1 (identifier only);
   - each with a copy button.
8. **PEM,** collapsed.
9. **Seen on,** as linked cards, then the findings.

### 3.4 Inventory › Algorithms

1. **By class:** for each class, its count and a stacked bar by post-quantum status. Each opens the list filtered
   to that class.
2. **By classical strength:** a histogram (broken, 80, 112, 128, 192, 256, not rated). Each column opens the list
   filtered to it (a new `strength=` filter).
3. **Controls:** search, a segmented class control (All, Asymmetric, Symmetric, Hash), *Only quantum-vulnerable*,
   and the source.
4. **The list, weakest first:** name, class and role, a bits bar with its words, the post-quantum glyph, and where
   it was seen. Not-rated rows give their reason in the tooltip and a muted sub-line.

### 3.5 SSH report

The algorithm tables use `bitsBar` and `pqGlyph` in place of the words column. Superseded by
[UX-DESIGN-012](UX-DESIGN-012-ssh-instruments.md) (PRD-014), which rebuilds the whole SSH report.

## 4. Responsive and accessible

- Measured at 1440, 1100 and 860 px wide, at 680 px high, and at 375 px.
- Wide tables (suite rows, the Inventory list) scroll inside their own box; the page never scrolls sideways.
- Ribbons scroll sideways inside themselves.
- Every instrument has a text alternative (aria-label in words).
- Every link and button is reachable by Tab; status is never colour alone.
- Dark mode uses the existing tokens.
- Text meets 4.5:1 (`TestTokenContrast` and the journey's contrast checks).

## 5. What goes

- The class pills.
- The "Every algorithm this endpoint uses…" and legend paragraphs.
- The fact-sentence bullets on Configuration.
- The `Cipher suites` and `Key exchange` fact cards.
- The separate part-by-part table.
- The long label/value cards on the certificate page.
- The Inventory's unsorted long table on top.
