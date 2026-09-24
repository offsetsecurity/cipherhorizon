# ADR-0006 — Host and network evidence stay separate; correlation is a labelled Assessment

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24

## Context

CipherHorizon has `tls scan` (observes an endpoint from outside) and `cipherhorizon run` (looks inside a machine).
The brief: they are complementary and **must not become one scanner**; correlation must never silently become
fact. Agent 1 left one boundary case open: host-observed evidence *about* network activity (e.g. a local log of
a handshake).

## Options considered

1. Merge both into one evidence store keyed by asset.
2. Two streams; a third artefact (Assessment) joins them with explicit provenance.
3. No correlation at all.

## Evidence

- NIST/NCCoE treat network services as a separate discovery domain (Agent 1 §5, secondary); the KU Leuven case
  study treats handshake telemetry as its own input.
- The product already has a **manual** host↔endpoint link (UI "Link a host"); linking can be wrong (load
  balancers, NAT, shared certificates, containers).

## Decision

Option 2. A record's **stream** is defined by *who observed it*: a host collector's record is host evidence even
when about network activity; `tls scan`'s records are network evidence. An **Assessment** joins them, names both
source records, and carries the **link's own evidence** (manual / certificate match / address match). An
Assessment's class is capped by the weakest of its inputs *and its link*, and it is never written back into
either stream.

## Why

It preserves each stream's provenance and makes the uncertainty of the join visible instead of hiding it.

## Trade-offs

Users see three artefact kinds; correlation output is less "clean" than a merged view.

## Consequences

- Level 7 is a joining layer, not a collector; it needs no new sensors.
- `exercised` is a network-stream rung; the host collector never produces it (evidence-model §7).
- The existing manual link becomes the first link *kind*; automated link kinds must be added with their own evidence.
