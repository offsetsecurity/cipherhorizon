# ADR-0002 — Claim rungs, strength classes, two capability kinds, and no invented confidence

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24
- **Related:** ADR-0001, `artifacts/evidence-model.md`

## Context

The brief listed nine words (`installed … used`). Agent 1 argued evidence has two axes (claim, method quality).
Agent 2 measured that: capability can be *probed* from the OS (CNG opened ML-KEM/ML-DSA) or *mapped* from
citations; the cheap-first order differs by platform; and some sources fail **silently** (`Process.Modules`
returns a one-entry stub for protected processes). Prior art uses a single 0–1 "executability" score
(`cbomkit-theia`) or High/Medium/Low (KU Leuven case study).

## Options considered

1. **One linear ladder + one confidence number.**
2. **Claim rungs (partial order) × declared method quality; strength classes for composition; `unknown` as an outcome.**
3. **Numeric probabilistic confidence per fact.**

## Evidence

- No source measured a false-positive rate (Agent 1 §11); a number would be uncalibrated.
- Windows shows the order differs by platform (Agent 2 §1.1 A2/A4) and that absence can be an artefact of the
  observer (§2.7).
- CycloneDX records *how* something was found (closed technique list) but not *what strength of statement* it
  supports (Agent 1 §2.2).

## Decision

Option 2:

- Rungs: `present`, `provisioned`, `capable` (`probed`|`mapped`), `policy` (`permits|forbids|unspecified`),
  `bound` (typed edge kinds), `loaded`, `exercised`.
- Classes for composition: **E0 existence < E1 reachable < E2 loaded < E3 exercised**. A path takes the class of its
  weakest edge; wording follows the class.
- `policy` is a **modifier**: `forbids` marks a path `blocked` without deleting it; `unspecified` is never `none`.
- Outcomes: `observed`, `confirmed-absent` (authoritative methods only), `unknown(reason)`; `unknown` propagates as
  `incomplete`.
- Method quality (`authoritative|parsed|heuristic|sampled`) declared per method; a fact may override **downward** only.
- **No numeric confidence.** CycloneDX numeric confidence is emitted only for authoritative methods (1.0).
  *Found while building L1:* the 1.6 schema **requires** a numeric `confidence` on every
  `evidence.identity` method. So the identity block is written only for authoritative methods
  (package databases); loose-file findings carry their technique and quality in
  `cipherhorizon:method` / `cipherhorizon:method-quality` instead of an invented number.

## Why

It keeps the two things separate that every source confuses, is computable, and refuses to invent precision.

## Trade-offs

More concepts to explain; the enum is coarse; consumers who want a single score must be told why there isn't one.

## Consequences

- Reports must use the class-appropriate wording (candidate / could use / has loaded / observed).
- L1 uses only `present` and `capable(mapped)`; the rest is defined so later levels cannot break the model.
- If calibration data ever exists, numbers can be added with their calibration source; this ADR is then revisited.
