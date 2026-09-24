# Handoff 01 — Security Research → Platform Research

```
FROM      Agent 1 (Security / Cryptography Researcher)
TO        Agent 2 (OS / Platform Researcher)
DATE      2026-09-24
FULL DOC  artifacts/agent-01-security-research.md
```

**Agent 2: this is an input to your reasoning, not a specification.** Your first task is to attack it (see
"Why you should care" and the challenge list at the end).

## WHAT WE KNOW (read in a primary source or in the repo)

- The regulatory object to inventory is an **active** implementation (OMB M-23-02, via CISA's ACDI strategy).
  Presence and capability alone are not that.
- Of M-23-02's nine data items, **only three** (algorithm/service/key length, COTS-vs-custom, OS version) are
  automatable at all. A host collector cannot claim the rest.
- CISA lists the discovery types as **network, file system, database, software package**. Host discovery is
  the file-system and software-package pair. Embedded/custom crypto is explicitly a known gap.
- CycloneDX's own guide says `provides` "does not imply that the implementation is in use", models
  **configuration** as a component the algorithms depend on, and asks for **variant-level** algorithm identity
  (AES-128-GCM, not AES).
- CycloneDX 1.6 evidence records **how** something was found (closed technique list + per-technique
  confidence) but has **no field for what kind of claim** it supports.
- Prior art (IBM `cbomkit-theia`) discovers certificates, keys, secrets, `java.security` and `openssl.cnf` on
  a filesystem and scores "executability" 0–1; it does no source scanning.
- A real large-organisation case study found evidence quality is **uneven across legacy/modern systems** and
  that an explicit evidence-confidence field prevented spending on false positives.

## WHAT WE PROVED

Nothing about the platforms. This stage proved only that **the sources agree** on: (a) presence ≠ capability
≠ use, (b) configuration is inventory-worthy, (c) certificates are the best direct host evidence, (d) host and
network evidence are separate streams, (e) uncertainty must be explicit.

## WHAT WE ASSUME (attack these)

| # | Assumption | Where it bites |
|---|---|---|
| A1 | Two axes — **claim rung** and **method quality** — describe the evidence better than one ladder or one confidence score. **[H]** | If the platforms make method quality nearly constant, the second axis is dead weight |
| A2 | The claim ladder is `present → capable → policy → provisioned → bound → loaded → exercised`. **[H]** | Your platform reality may merge or reorder these (e.g. on Windows `provisioned` may be far easier than `policy`) |
| A3 | Certificate/key **metadata** is obtainable without exposing key material, and a private key's **presence/protection state** can be established without reading it. | If a platform needs to open the key to learn its size/protection, SR-1 forbids it there |
| A4 | Policy evidence (with direction `permits/forbids/unspecified`) is common enough to be worth a discovery level. | If most hosts yield `unspecified`, level 3 adds cost without reducing false positives |
| A5 | "Capable" is best modelled as *knowledge applied to present evidence*, not as a collector. | Windows has no package→algorithm mapping of the same shape; the capability source may be the OS itself (CNG providers) |

## WHAT WE DON'T KNOW

- The **false-positive rate** of host-side crypto discovery (no source measured it; the false-positive point
  in §3 of the research doc is a hypothesis).
- What the NCCoE test results say about which tool categories detect what (the page returned 403).
- Whether an **enterprise buyer** accepts "candidates and upper bounds" wording. (A1 in the doc.)
- How much crypto on a *typical* host lives outside the package manager.

## WHAT FAILED

- NCCoE SP 1800-38 practice-guide page: HTTP 403 (its content is second-hand).
- PDF fetches returned binary; recovered by local text extraction.
- No search located a quantitative evaluation of host crypto scanners.

## WHAT NEEDS TO BE DONE (your work)

Answer, per platform, and mark each with `✓ reliable / △ partial / ✗ unavailable / ? needs validation`, plus
the privilege it needs and the mechanism (API, file, subprocess):

1. Can the **five evidence kinds** (`present, capable, policy, provisioned, bound`) plus `loaded` and
   `exercised` be obtained, and how? Windows and Linux in depth (Debian, Ubuntu, RHEL-family, SUSE, Alpine,
   Amazon Linux, Kali-as-test-environment). macOS: research only.
2. **Privilege ladder** for each: what is possible as an ordinary user, what needs root/Administrator, what
   needs a process-inspection capability.
3. **Secret-safety analysis** (SR-1..SR-12): where does each collection path come closest to key material,
   and can it be made structurally incapable of reading it?
4. **Cost and stability** of each path (SR-9).
5. What can be **validated now** on the available Windows machine and (once reachable) Kali — and what needs
   containers/VMs/CI. Tell Agent 3 which cells of the matrix are *tested* vs *researched*.
6. The **signed-distribution** research workstream (Authenticode, MSI/MSIX, Intune/SCCM; DEB/RPM/signed
   repos; macOS as future) — separate from evidence, and input to the deployment architecture.

## WHY THE NEXT AGENT SHOULD CARE

Agent 1's hierarchy is only worth adopting if the platforms can *fill* it. If, for example, Windows offers rich
`provisioned` evidence but almost no `policy` evidence without registry scraping, or Linux `bound` evidence
needs root, then the ladder and the level order should change — and Agent 3 must be told **before**
designing. A ladder no platform can populate is a schema, not an inventory.

## CHALLENGES AGENT 2 SHOULD EXPECT TO MAKE (and I would welcome)

- Is "claim × method quality" over-engineered relative to a single confidence field a customer will read?
- Is `present` really different from `capable` on Windows, where capability is a property of the OS build?
- Does "never stronger than the weakest link" make the graph too pessimistic to be useful?
- Is separating `bound` (static) from deployment-enabled worth two rungs, or one rung with a flag?
- Is the SR-1 "fixed-length armor prefix" idea actually safe, or should key files be identified by metadata
  only?

## OPEN ITEM I AM EXPLICITLY NOT DECIDING

Whether host `exercised` evidence (e.g. a local TLS connection log) is host evidence or network evidence. It
sits on the boundary; Agent 3 should rule on it.
