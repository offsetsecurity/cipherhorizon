# ADR-0007 — Distribution: signed standalone collector + native packages; persistent agent deferred

- **Status:** Proposed (Agent 3), direction only; a separate workstream
- **Date:** 2026-09-24

## Context

An unsigned executable running on enterprise endpoints is a legitimate objection, and the distribution model
changes the threat model (persistence, network, updates). The brief asks whether CipherHorizon needs a signed
standalone collector, native packages, ephemeral execution, a persistent agent — "do not assume one model".

## Options considered

1. Signed standalone executable only.
2. Native packages only (MSI/MSIX; `.deb`/`.rpm` from signed repositories).
3. Both, plus optional ephemeral execution; persistent agent decided separately.
4. Persistent agent as the primary model.

## Evidence

- Windows: Authenticode removes "Unknown publisher"; SmartScreen judges publisher and file-hash reputation,
  reputation is tied to the certificate thumbprint and resets on renewal, and the EV shortcut was removed in
  2024 (Agent 2 §10, secondary). Enterprises deploy MSI/MSIX via Intune/SCCM (details not retrieved).
- Linux: trust is via the package manager — signed APT repositories (`InRelease`, `signed-by=`), RPM GPG and
  `repo_gpgcheck` (secondary).
- macOS (future, not validated): Developer ID + notarization + stapling; MDM delivery.
- This repository already builds cosign keyless signatures, SLSA provenance and SBOMs for standalone archives.

## Decision

Direction: **(3)** — signed standalone collector *and* native packages *and* optional ephemeral execution.
**The persistent agent is a separate architecture decision** because it changes SR-2, SR-3, SR-7 and SR-10.
Nothing here is on the critical path of L0/L1.

## Why

The evidence shows the two platform families are managed differently; one model would fit neither. Ad-hoc and
air-gapped use wants one verifiable file.

## Trade-offs

Two release pipelines to maintain; signing certificate cost and reputation building on Windows; repository
infrastructure for Linux.

## Consequences

- **Not built, and must not be claimed:** Authenticode signing, MSI/MSIX, `.deb`/`.rpm`, signed repositories, notarization.
- **Built:** cosign/SLSA/SBOM for the standalone archives (verified in the release engineering work).
- A follow-up ADR is needed before any persistent-agent work.
