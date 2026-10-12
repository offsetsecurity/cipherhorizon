# STRATEGY-003 · CipherHorizon is no longer a TLS scanner

| | |
|---|---|
| Date | 2026-10-12 |
| Role | Product management |
| Trigger | Owner, after the SSH build: SSH, and later IKE, may need to be separate, with their own kind of evaluation. Mixing TLS scoring with SSH scoring (and later VPN) will confuse. Re-look at the product as a whole: positioning, marketing, UI. |
| Inputs | The SSH build on `feat/pq-signatures-and-ssh` (screens walked 2026-10-12). [STRATEGY-001](STRATEGY-001-product-review.md), [STRATEGY-002](STRATEGY-002-cryptolyzer-evaluation.md). ssh-audit (jtesta/ssh-audit, MIT). sshcheck.com. |
| Status | Analysis and recommendation. Owner decisions in §9 block the UI work. |

## 1. What has changed

Until this branch, every part of the product assumed one kind of network target: a TLS endpoint. That assumption
is everywhere:

| Surface | What it says today |
|---|---|
| Sidebar tagline | "TLS and post-quantum scanner" |
| Overview eyebrow and hero | "Post-quantum readiness · TLS scanner · CBOM"; "A deep TLS scan" |
| CLI one-liner, README, Docker label | "Post-quantum readiness for every TLS endpoint you run" |
| Readiness scale | L0 is defined as "no TLS 1.3" |
| The 0–100 score | "TLS hygiene" |
| PDF reports | "TLS security report", "TLS configuration report", "Certificate report" |
| Endpoints list columns | Certificate expiry, TLS hygiene |

The SSH build made the product **multi-protocol** underneath:
- its own prober;
- its own rules (18, cited);
- its own readiness rules;
- its own CBOM builder;
- its own PDF;
- its own CLI (`ssh scan`).

On top, the UI folds SSH into the TLS page as "another endpoint". That was the quickest integration, and the
owner is right that it doesn't scale. IKE/IPsec (VPN gateways) is next on the roadmap (STRATEGY-002 C6), so this is
the moment to decide the shape.

## 2. Problems found in the current integration (the honest list)

I walked every screen of the SSH build. These are design problems, not bugs:

| # | Problem | Where | Why it matters |
|---|---|---|---|
| P1 | **One "Hygiene" column holds two different scores.** An SSH 90 and a TLS 74 sit side by side and sort together, though they come from different rule sets. | Endpoints list, Overview "rated Strong or Sound", Systems ranking | The numbers look comparable and are not. A reader will conclude the SSH server is "better" than the web server. |
| P2 | **"Certificate / key" is a column for two unrelated things.** Expiry days for TLS, a key type for SSH. | Endpoints list | A column should answer one question. |
| P3 | **One readiness scale, two definitions.** L0 means "no TLS 1.3" or "SSH-1 only". L3 means Go's TLS client, or OpenSSH 10.6. | Overview scale, Help, methodology | The headline (L0–L4) works across protocols; the rules behind it don't, and the UI explains only one at a time. |
| P4 | **The brand says TLS.** Tagline, eyebrow, one-liner, README, PDF titles. | Everywhere | SSH is invisible to a first-time visitor, and the marketing claim is narrower than the product. |
| P5 | **The SSH evaluation is a TLS evaluation in SSH's clothes.** A 0–100 score with TLS's weights. | SSH report | SSH practice judges against a *policy* or baseline (ssh-audit's built-in policies per OS version, BSI TR-02102-4), and reports pass/warn/fail per algorithm. A score gives an SSH administrator less than a list of the `sshd_config` lines that break the baseline. |
| P6 | **Findings mixes protocols without a protocol filter.** "Traffic is exposed to harvest-now-decrypt-later" groups TLS and SSH (good). But nothing lets a reader see only the SSH problems. | Findings | An SSH admin and a web team are different people. |
| P7 | **Scan box ambiguity.** "Scan an endpoint" plus a pasted `host:22` silently becomes SSH. | Overview | It works, but a person who doesn't know the product chose SSH for them can't see it. |

What is right and should stay:
- **One readiness question across everything:** is recorded traffic exposed to harvest-now-decrypt-later? That's
  the product's reason to exist, and it groups across protocols.
- **One inventory.** The merged CycloneDX CBOM across TLS, SSH, machines and imports is the unique selling point.
  Splitting it by protocol would throw that away.
- **The engines.** The SSH prober, rules, CBOM, PDF and CLI are protocol modules already. The oracle against real
  OpenSSH 9.2 and 10.0 agreed on every list, fingerprint and negotiated choice.

## 3. How others organise this

| Tool | How it is organised | How it judges |
|---|---|---|
| **ssh-audit** (MIT) | SSH only; server **and client** audit | Per-algorithm **fail / warn / info** with notes (introduced, deprecated, why). **Policies**: built-in hardening baselines per OS/OpenSSH version, custom policies, exit 0/1 for CI. Hardening guides. GEX modulus tests. Post-quantum: warns on non-PQ key exchange (since 3.9). No numeric score. |
| **sshcheck.com** | SSH only, a web form | Lists algorithms and host keys; Terrapin. No grade. |
| testssl.sh, SSLyze | TLS only | Per-check severities; testssl.sh adds a letter rating. |
| CryptoLyzer | Many protocols, **one CLI per protocol** (`tls`, `ssh`, `ike`, `dns`, `http`) | Per-algorithm traffic lights; no cross-protocol score. |
| Posture platforms (AQtive Guard, AgileSec) | **By asset type** (network services, hosts, code, cloud); protocol is a facet | Risk and inventory across sources; no per-protocol "grade" mixed with another. |

The pattern:
- **Protocol is a first-class dimension.** No tool mixes per-protocol scores.
- **Cross-protocol views exist only for questions that are genuinely the same everywhere.** Here that's inventory,
  post-quantum exposure and "what to fix first".
- **SSH practice is baseline conformance, not a score.**

## 4. What the product is now

**Category (unchanged from STRATEGY-001):** cryptographic posture and post-quantum readiness, self-hosted.

**What changes:** the product covers the **network protocols that carry an organisation's long-lived secrets**
(TLS today, SSH now, IKE/IPsec next), and **the machines** (host inventory), in **one inventory**.

Proposed one-liner (to replace "…for every TLS endpoint you run…"):

> **Post-quantum readiness for the protocols your organisation runs on: TLS, SSH and, next, VPN. A deep scan of
> each, a readiness level from L0 to L4, and one CycloneDX CBOM, self-hosted.**

Pillars (README, sign-in panel, About):

1. **Post-quantum readiness, protocol by protocol.** One question across everything (is recorded traffic exposed?)
   and an honest answer per protocol.
2. **Scanners that show their work.** A TLS scanner and an SSH auditor with their own wire implementations. Every
   check is cited. Verified against real servers (OpenSSH oracle, OpenSSL trust oracle).
3. **An inventory you can hand over.** TLS, SSH, machines and imported CBOMs merged into one CycloneDX CBOM.

Comparison table (README): add a row for SSH, and ssh-audit as a column. Say plainly that ssh-audit has client
auditing and DHEat stress tests and we don't (DHEat is a DoS test, out of scope by design). Say that we add the
fleet view, history, CBOM and readiness.

## 5. The model: protocol modules on a shared spine

```
                      ┌──────── shared spine ─────────────────────────────────────────────┐
  TLS module ───────▶ │ target + scan lifecycle (queue, schedule, guard, history)          │
  SSH module ───────▶ │ findings (cited, severity, triage)                                 │
  IKE module (next) ▶ │ post-quantum readiness: one question, L0–L4, per-protocol rubric   │
  Machines ─────────▶ │ CBOM: one merged inventory                                         │
                      └───────────────────────────────────────────────────────────────────┘
  each module owns:  its prober · its rules · its report layout · its own quality measure · its PDF · its CLI verb
```

| Concern | Shared or per protocol | Rule |
|---|---|---|
| Readiness (L0–L4, HNDL) | **Shared scale, per-protocol rubric** | Same names and meaning at the top: L1 exposed, L3 protected by a hybrid, L4 PQ-authenticated. Each protocol's page states its own rules. Fleet views may count and sort by it across protocols. |
| Quality measure (today "hygiene") | **Per protocol, never mixed** | TLS keeps its 0–100 TLS hygiene score. SSH gets **baseline conformance** (§6). IKE gets its own when built. No column, sort or total ever combines them. |
| Findings | Shared model, **protocol facet** | Fleet Findings groups by problem across protocols (the HNDL line is legitimately shared), with a protocol filter and a protocol tag on every row. |
| Inventory / CBOM | **Shared** | Unchanged: one merged CBOM is the USP. |
| Systems, ranking, migration order | Shared, by readiness and exposure | Ranks by readiness and data lifetime, which is cross-protocol, not by a hygiene number. |
| Reports (PDF) | Per protocol | "TLS security report", "SSH security report", later "VPN security report"; the inventory report stays merged. |
| CLI | Per protocol verb | `tls scan`, `ssh scan`, `ike scan`: done. |

## 6. SSH gets its own evaluation: baseline conformance

The owner's instinct matches SSH practice (ssh-audit's policies, BSI TR-02102-4). Proposal:

- **The SSH report's headline is the readiness level plus "Meets / does not meet the SSH baseline"**, not a 0–100
  number.
- **A baseline** is a named, versioned, cited set of allowed and required algorithms and key sizes:
  - **CipherHorizon SSH baseline 2026** (default, our own, every entry cited: RFC 9142, RFC 8332, RFC 8758,
    RFC 10042, FIPS 186-5);
  - **BSI TR-02102-4** (the German federal SSH guideline; public, citable);
  - P1: **CNSA 2.0** for national-security systems (ML-KEM-1024 only, and so on).
- **Per algorithm, the verdict ssh-audit users expect:** *required / allowed / should be off* against the chosen
  baseline. We already compute per-algorithm verdicts (`eval.SSHAlgorithm`); the baseline makes them explicit
  and switchable.
- **The output an SSH admin wants: the `sshd_config` lines that would make the server conform.** A generated
  `KexAlgorithms / HostKeyAlgorithms / Ciphers / MACs` block, with the OpenSSH version each needs.
- **CI:** `ssh scan --baseline bsi-tr-02102-4 --fail-on baseline` (exit 3), like ssh-audit's policy mode.
- **Findings stay** (cited, per rule), so fleet Findings and triage work unchanged. The 0–100 SSH score is
  **removed** from every view (it's still computable internally, but nothing shows or ranks it).

TLS can adopt the same baseline idea later (NIST SP 800-52r2, BSI TR-02102-2) without dropping TLS hygiene, which
TLS users understand. That's a later decision, not part of this change.

## 7. Information architecture

Constraint from earlier owner feedback: a shallow, labelled navigation, nouns not verbs, one item per kind of
object, a label that predicts its page (UX-DESIGN-005, UX-REVIEW-008).

| | Option A: one Endpoints page with protocol tabs | **Option B: a page per protocol (recommended)** | Option C: today (one mixed list) |
|---|---|---|---|
| Nav (Results) | Endpoints · Machines · Findings · Inventory | **TLS endpoints · SSH servers · Machines · Findings · Inventory** (VPN gateways added when IKE ships) | Endpoints · Machines · Findings · Inventory |
| Columns | Per tab | **Per page: each protocol's own columns and measure** | Mixed (P1, P2) |
| Scales to IKE | One more tab | One more item (6 in Results: still within one group) | Gets worse |
| Says what the product is | Partly (hidden in a tab) | **Yes: the menu itself lists the protocols** | No |
| Cost | Medium | Medium (the pages exist; it's a split, plus the SSH list's columns) | none |

**Recommendation: B.** The protocols are the product's offer, so they belong in the menu. Each list gets the
columns that answer its users' questions:
- **TLS endpoints:** readiness, TLS hygiene, findings, certificate expiry, last scan.
- **SSH servers:** readiness, baseline (meets / does not meet, by how many lines), findings, software, host key,
  last scan.

Cross-protocol pages:
- **Overview:**
  - one scan box that says what it'll scan ("Scan as TLS / SSH" chip after typing, with Automatic chosen from the port);
  - readiness across everything;
  - one card per protocol (counts, exposure, worst problems).
- **Findings:** by problem across protocols, with a protocol filter and tags.
- **Inventory:** merged, with protocol as a facet.
- **Systems:** a system lists its endpoints of every protocol, ranked by readiness and exposure.
- **Reports:** documents grouped by protocol, plus the merged inventory report.

Wording rule: the user's words per protocol are "TLS endpoint" (website, mail, directory, database), "SSH server",
and later "VPN gateway". "Endpoint" alone stays the generic word for any of them.

## 8. What this means for the open branch

The SSH engines stay. The integration changes. Proposed split:

| Ship | Content | State |
|---|---|---|
| **PR 1: ML-DSA fix (now)** | WP-A: ML-DSA in TLS 1.3 hellos, signature stage, L4 rule, CBOM, PDF, demo, Go 1.27 | Built, tested; independent of the SSH question. Split it out and merge it first. |
| **PR 2: SSH module (after §9)** | Everything SSH built so far (prober, rules, CBOM, PDF, CLI, store, API), **plus** the IA split (B), the SSH baseline evaluation (§6) replacing the SSH 0–100 score in every view, the multi-protocol positioning (§4) across tagline, README, Help, About, PDF titles and the one-liner, and the per-protocol readiness rubric on the Overview and in Help | Engines built and QA'd (unit, hermetic, fuzz 3–5M execs each, real-OpenSSH oracle AGREE 33/33). UI to be reworked. Journey SSH phase written, to be re-pointed at the new pages. |
| PR 3+ (later) | IKE/IPsec module on the same pattern; SSH client audit (a listener, as ssh-audit `-c`); TLS baselines | Roadmap |

Updated scope documents needed before PR 2's UI: a PRD-008 amendment (baseline evaluation, IA), UX-DESIGN-007
(protocol pages, Overview cards, scan-box chip), and an ENG-HANDOFF-005 addendum (the baseline data model).

## 9. Decisions for the owner

1. **Navigation:** a page per protocol (B, recommended), protocol tabs on one page (A), or keep one list (C)?
2. **SSH evaluation:** baseline conformance with per-algorithm verdicts and a generated `sshd_config`
   (recommended), or keep a 0–100 SSH score shown only on SSH pages?
3. **Which SSH baselines first:** our own cited baseline plus BSI TR-02102-4 (recommended); CNSA 2.0 later?
4. **Split the PR:** ship the ML-DSA fix as PR 1 now, SSH as PR 2 after the rework (recommended)?
5. **Positioning:** adopt the one-liner and pillars in §4 (the product name stays)?
