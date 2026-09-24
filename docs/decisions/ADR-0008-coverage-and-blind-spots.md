# ADR-0008 — Coverage and blind spots are first-class output

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24

## Context

A host inventory that says nothing about what it could not see invites the reading "nothing found = safe". The
sources are explicit that host discovery has blind spots (embedded/custom crypto, HSM-held keys, third-party
services, runtime-computed configuration) and that evidence quality is uneven (CISA; KU Leuven case study).
Agent 2 found two ways a collector can *manufacture* a false negative without any error (the module stub; the
empty static-import list).

## Options considered

1. Document blind spots in the README only.
2. Emit per-collector **Coverage** records and put them in the CBOM.
3. Fail the run when coverage is incomplete.

## Evidence

- Agent 1 §6 (blind-spot table) and Recommendation 7.
- Agent 2 §2.7 (stub trap) and §1.3 (static imports miss dynamic loading).
- Case study: an explicit evidence-confidence field prevented spending on false positives.

## Decision

Option 2. Every sensor returns `Coverage{Method, Scope, Status, Reason, Limits, Unseen}` alongside its
observations. Coverage is summarised in the CBOM (`metadata.properties`) and available in detail. A hit budget
is `partial`, never `complete`. A known-silent-failure source is wrapped so its suspicious results are
`unknown(stubbed-source)`. **A "not found" statement is allowed only from an `authoritative` method that
completed** (`confirmed-absent`).

## Why

It converts silence into data and makes the collector's limits auditable.

## Trade-offs

More output; a risk of "unknown fatigue" (mitigated by summarising by reason and scope); the `Unseen` lists
need maintenance as platforms evolve.

## Consequences

- Every release's wording must include what the host collector cannot see.
- The Gatekeeper checks that coverage exists for every collector run.
- Reports may not present an empty result as an all-clear.
