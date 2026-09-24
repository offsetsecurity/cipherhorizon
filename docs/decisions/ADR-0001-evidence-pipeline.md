# ADR-0001 — Host discovery is an evidence pipeline, not a set of collectors

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24
- **Related:** ADR-0002, ADR-0004, `artifacts/evidence-model.md`, `artifacts/collector-contract.md`

## Context

Today `collector.Collector.Collect` returns `CryptoAsset` — a CycloneDX component plus `provides`/`dependsOn`.
The collector (apt) decides CBOM structure *and* emits inferred capability edges at collection time, so
observation (a package is installed) and derivation (that package can do ML-KEM) are fused in one plugin, and
the output cannot say which is which beyond a property. Adding a Windows collector the same way would copy the
fusion into a second platform and make the CBOM's claims depend on each collector author's discipline.

## Options considered

1. **Keep `CryptoAsset` and add Windows plugins alike.** Least change; repeats the fusion; every collector must
   remember to label inference.
2. **Normalised evidence records (`Observation`, `Coverage`) → normalise → derive (knowledge) → project (CBOM).**
   More structure; observation and derivation separate; OS code stops at the record.
3. **A generic graph database / knowledge graph.** Powerful, heavy, and not needed by any current requirement.

## Evidence

- CycloneDX's own guide: `provides` "does not imply that the implementation is in use" (Agent 1 §2.2).
- Agent 2 §1.3-3: the same capability mapping must apply to a package *and* a loose DLL — impossible while the
  mapping lives inside a package collector.
- CISA/M-23-02: the object of interest is *active* use, so the model must carry how strong each statement is.

## Decision

Adopt option 2. Sensors emit `Batch{Observations, Coverage}` only. Capability mappings move to a versioned
**knowledge base** keyed by (family, version range). A **derive** stage produces derived facts, each listing
`BasedOn`. The CBOM is a **projection** of the resulting graph. Platform-specific packages may not be imported by
normalise, derive or project (enforced by test).

## Why

It is the smallest structure that makes the rule "no claim stronger than its weakest evidence" *mechanical*, and
the only one that lets the same knowledge apply regardless of how an artefact was found.

## Trade-offs

More types and a migration of the apt plugin; L0 adds work before user-visible value; risk of over-building.

## Consequences

- The apt plugin is refactored (packages → `present`); its capability rules move; existing Debian/Ubuntu output
  must be provably unchanged (compat test).
- New sensors are cheaper to review: they can only emit observations.
- Levels above L1 add sensors and derivation rules, not new output formats.
