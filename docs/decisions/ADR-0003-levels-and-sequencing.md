# ADR-0003 — Discovery levels: add L0, put certificates before policy, build L0 + L1 first

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24

## Context

The brief proposed seven levels (installed → capability → configuration → certificates/keys → application
association → runtime → correlation) and explicitly allowed merging, splitting, reordering or adding levels.
Agent 2 tested Windows on one machine and researched (but could not run) Linux.

## Options considered

1. Keep the brief's order and start with L1 on Windows and Linux.
2. Add an explicit foundation level; make L2 a derivation stage; move certificates before configuration;
   implement only what has been validated.
3. Implement Windows completely (L1–L4) before touching the model.

## Evidence

- Certificates were the cheapest direct evidence on Windows (6 stores, unelevated) and found RSA-1024/512
  trust anchors; they are CISA item-4 data (algorithm, key length) (Agent 1 §2.1, Agent 2 §2.5).
- Policy is strong only where a system policy framework exists (RHEL-family, AL2023, SLE 15 SP4+, Windows);
  weak on Debian-family (Agent 2 §3.2).
- Capability needed no new Linux sensor and depends on knowledge (Agent 1 §8); on Windows it is probable from the OS.
- No Linux mechanism was executed by any agent (Agent 2 §13).

## Decision

Levels: **L0 foundation · L1 present · L2 capable · L3 provisioned (certificates, key metadata) · L4 policy ·
L5 bound · L6 loaded · L7 correlation (a joining layer, not a collector).** Each level's derived facts must list
their inputs. **The first implementation is L0 + L1, with today's capability mapping re-expressed as L2-mapped
derivation.** Debian/Ubuntu (existing) and Windows (tested) only. macOS is **not implemented**.

## Why

It is the highest-value increment whose every mechanism has been validated, and it installs the contract every
later level needs.

## Trade-offs

A foundation level with no user-visible feature; Linux distros beyond Debian/Ubuntu wait; ordering differs from
the brief.

## Consequences

- Per-platform status is published with every release (what is tested where, on what).
- Levels are increments by *evidence kind*, delivered per platform, not one order for all platforms.
- The Gatekeeper judges each level against its acceptance table (handoff-03).
