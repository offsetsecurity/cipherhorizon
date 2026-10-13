# UX-DESIGN-007 · A page per protocol, and the SSH baseline

| | |
|---|---|
| Date | 2026-10-13 |
| Requirements | [PRD-008](PRD-008-pq-signatures-and-ssh.md) WP-D (REQ-SHW, amended) and WP-G (REQ-SHB) |
| Decisions | [STRATEGY-003](../strategy/STRATEGY-003-multi-protocol-product.md) §9, answered by the owner: a page per protocol, baseline conformance, the new positioning |
| Supersedes | [UX-DESIGN-006](UX-DESIGN-006-ssh-endpoints.md) wherever they differ: the mixed Endpoints list, the Service/Protocol filter on it, and "SSH hygiene" |
| Bar | [DESIGN.md](../../DESIGN.md); UX-DESIGN-005 (one place per kind of thing, nouns, a label that predicts its page); UX-REVIEW-008 (one primary action per page) |

## 1. The rule

**Protocol is a place in the menu. Readiness is the one thing every protocol shares.** No screen puts a TLS
measure and an SSH measure in the same column, sort or total. Cross-protocol screens (Overview, Findings, Systems,
Inventory, Reports) answer only the questions that are the same everywhere:
- is recorded traffic exposed?
- what's the readiness level?
- what should be fixed first?
- what cryptography do we have?

Words on screen:
- **TLS endpoint**: a website, mail, directory or database service reached over TLS or STARTTLS.
- **SSH server**.
- **Endpoint**: the generic word for either, used only where both are meant.

The words "SSH endpoint" and "SSH hygiene" don't appear on any screen.

## 2. Navigation and addresses

```
Overview
Results
  TLS endpoints        #/endpoints          (list)      #/endpoints/{id}   (report)
  SSH servers          #/ssh                (list)      #/ssh/{id}         (report)
  Machines             #/machines
  Findings             #/findings
  Inventory            #/inventory
Plan & share
  Systems · Reports
```

- **TLS endpoints keeps `#/endpoints`.** Every bookmark, PDF link and earlier redirect still lands on TLS.
- **`#/endpoints/{id}` for an SSH server** is replaced, without a history entry, by `#/ssh/{id}`. Both menu items
  light up for their own reports.
- **Icons.** SSH servers uses the existing terminal glyph style of the icon set: a plain flat stroke icon, like its
  neighbours. TLS endpoints keeps the globe.
- **Both pages have their own Scan activity tab**, filtered to that protocol.
- **The sidebar tagline** reads **TLS · SSH · post-quantum readiness**.

## 3. TLS endpoints (list)

The current list, minus SSH:

- **Columns:** Endpoint, PQC readiness, TLS hygiene, Findings, Certificate expiry, Last scan.
- **Header:** title *TLS endpoints*. Sub-line *Websites and the TLS services behind mail, directories and databases.
  Open one for its full report.*
- **Primary action:** *Scan a URL*.
- **The add dialog's Protocol select** offers Automatic, TLS and the STARTTLS protocols, plus SSH. Choosing SSH
  sends the new server to SSH servers, and the toast says so: *Added to SSH servers*.
- **The Protocol filter on this page is removed.** The page itself is the filter.

## 4. SSH servers

### 4.1 List

| Column | Content | Sort |
|---|---|---|
| Server | Name, and under it `host:port · OpenSSH_10.0` | name |
| PQC readiness | Level chip, as TLS | level |
| Baseline | **✓ Meets** (good colour) · **N changes** (problem colour) · *not judged* (muted, with a tooltip saying why) | meets first, then by changes |
| Findings | Counts by severity, as TLS | worst first |
| Host key | `Ed25519`, `ML-DSA-44 + Ed25519`, `RSA 2048` | — |
| Last scan | Relative time | time |

- **Header:** title *SSH servers*. Sub-line *Servers you reach over SSH, judged against the CipherHorizon SSH
  baseline 2026. Nothing logs in.*
- **Primary action:** *Add SSH servers*. The dialog is the shared add dialog with Protocol preset to SSH, and the
  placeholder `bastion.example.com or bastion.example.com:2222`.
- **Empty state:** *No SSH servers yet* · *Add the SSH servers you want to assess. A scan reads what the server offers
  and runs a few key exchanges; it never logs in.* · button *Add SSH servers*.
- **Bulk add and scan all** work here as on TLS endpoints, limited to SSH servers.

### 4.2 Report: Summary

The hero shows two tiles side by side, then the same narrative and next steps as TLS:

```
┌ PQC readiness ──────────────┐ ┌ Baseline ───────────────────────────────────┐
│ L3  PQ-protected            │ │ ✗ Does not meet  ·  4 changes               │
│ A current client (OpenSSH   │ │ CipherHorizon SSH baseline 2026             │
│ 10.6) negotiates            │ │ Remove hmac-sha1, umac-64 and 2 more MACs.  │
│ mlkem768x25519-sha256.      │ │ [See the sshd_config lines →]               │
└─────────────────────────────┘ └─────────────────────────────────────────────┘
```

- **When the server meets the baseline:** *✓ Meets the CipherHorizon SSH baseline 2026*, plus a one-line reason:
  *Every algorithm offered is on the baseline, a post-quantum hybrid is offered, strict key exchange is on.*
- **When the server can't be judged:** *Not judged*, plus the reason, for example *the server's algorithm lists were
  not read*.
- **The link** opens Configuration at the block (§4.3).
- **No 0 to 100 number, band or "hygiene" word** appears anywhere on an SSH report.

### 4.3 Report: Configuration

1. **"Make this server meet the baseline"**, only when it doesn't. It holds:
   - a monospace block of the generated `sshd_config` lines, with a **Copy** button (copies the text exactly);
   - a line underneath: *Put these lines at the top of /etc/ssh/sshd_config, or in a file under
     /etc/ssh/sshd_config.d/ that is read first: sshd uses the first value of each keyword. Check with `sshd -t`, reload
     sshd, and scan again.*

   Comments in the block (`# needs OpenSSH 9.9 or later`) are shown as part of the text, in the muted colour.
2. **"What the baseline requires"**: three rows, each with ✓ or ✗ and its source:
   - *A post-quantum hybrid key exchange*;
   - *Strict key exchange (Terrapin, CVE-2023-48795)*;
   - *RSA host keys of at least 3072 bits*.
3. **Algorithms by kind** (key exchange, host keys, ciphers, MACs, compression), in the server's order:

   | Column | Content |
   |---|---|
   | Name | Monospace |
   | What it is | The registry's display name |
   | Baseline | **Allowed** · **Should be off** (problem colour) |
   | Post-quantum | Marked for PQ entries |
   | Used | *used by OpenSSH 10.6* on the negotiated one |

4. **Host keys**: fingerprint, type, size, the algorithms each key serves, and certificate details. Unchanged from
   UX-DESIGN-006.

Weaknesses, CBOM and History are unchanged from UX-DESIGN-006, except that Weaknesses no longer shows a score
breakdown.

## 5. Overview

**Scan box.** One input. As soon as the input parses, a chip appears at its right edge:
- **Scan as TLS** or **Scan as SSH**, chosen the way Automatic chooses (scheme, then port);
- a second, quieter word, *change*, flips it;
- the button reads **Scan**.

So `bastion.example.com:22` shows *Scan as SSH* before anything is sent. The hint under the box reads *A hostname,
URL, host:port, or ssh://host*.

**Readiness across everything.** The L0 to L4 distribution counts every endpoint of every protocol. The scale's
explanation shows each level's meaning, then its rules in two short lines: **For TLS** … and **For SSH** …

**One card per protocol**, side by side, each linking to its page:

| TLS endpoints card | SSH servers card |
|---|---|
| *12 TLS endpoints* · *5 exposed to harvest-now-decrypt-later* | *4 SSH servers* · *1 exposed* |
| Hygiene bands as a small bar (Strong … Broken) | *2 of 4 meet the baseline* as a small bar |
| *3 certificates expire within 30 days* | *1 offers SSH-1* (only when non-zero) |

A protocol with nothing added shows its card with an *Add …* link, not an empty bar. "Needs attention" lists
endpoints of both protocols. Each row names its protocol and shows readiness and finding counts; it never shows a
score.

## 6. Findings

- **Filter.** A *Protocol* select (All protocols, TLS, SSH) joins the existing filters. It narrows the problem groups
  to those with at least one endpoint of that protocol, and the counts follow.
- **Tag.** Every affected endpoint inside a group carries a small tag, **TLS** or **SSH**. Shared problems (for
  example *Traffic is exposed to harvest-now-decrypt-later*) still form one group.

## 7. Systems, Reports, Inventory

- **Systems:**
  - A system's member list shows endpoints of both protocols, each tagged.
  - The ranking is by readiness, then exposure, then critical and high findings. No score column.
- **Reports.** Documents are grouped under *TLS endpoints*, *SSH servers* and *Inventory*. The PDFs are titled *TLS
  security report* and *SSH security report*.
- **Inventory.** Unchanged, merged. The Sources tab names SSH scans as a source.

## 8. Positioning copy

| Surface | Text |
|---|---|
| One-liner (README, CLI `--help`, About, Help, sign-in panel, container label) | Post-quantum readiness for the protocols your organisation runs on: TLS, SSH and, next, VPN. A deep scan of each, a readiness level from L0 to L4, and one CycloneDX CBOM, self-hosted. |
| Overview eyebrow | Post-quantum readiness · TLS · SSH · CBOM |
| Overview hero line | *See what each protocol you run would expose to a future quantum computer, and what to change first.* |
| About pillars | Post-quantum readiness, protocol by protocol · Scanners that show their work · An inventory you can hand over (STRATEGY-003 §4) |
| Help | A *Protocols* section: what a TLS scan sends, what an SSH scan sends (never a login), and how each is judged (TLS hygiene, SSH baseline) |

## 9. States and accessibility

- **The Copy button** announces *Copied* through the live region. The block is a `<pre>` with `aria-label="sshd_config
  lines"`.
- **Baseline cells** carry text, not colour alone (*Meets*, *4 changes*, *Should be off*).
- **The scan-box chip** is a button with `aria-label="Scan as SSH; change to TLS"`.
- **The two new list pages and the report changes** must be walked in the PM and design screen walk at 1440 and 390
  wide before this is called done.
