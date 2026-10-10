# ADR-0004 — Collectors use APIs and file parsing, never subprocesses; PowerShell is a test oracle only

- **Status:** Proposed (Agent 3), pending Agent 4 challenge
- **Date:** 2026-09-24

## Context

Every Windows probe in Agent 2's research was first written in PowerShell. It is convenient and was the fastest
way to test feasibility. Shipping the collector as a PowerShell wrapper (or shelling out to `certutil`, `netsh`,
`winget`, `openssl`, `update-crypto-policies`) would be the shortest path to a Windows version.

## Options considered

1. Shell out where convenient.
2. Pure-Go APIs and file parsing; PowerShell/`openssl` only in tests.
3. A separate helper binary per platform.

## Evidence

- SR-4 (Agent 1): host data must not drive subprocess execution; command injection is a top risk.
- Agent 2 §2 and Recommendation 10: every probe run has an in-process equivalent — `x/sys/windows` (certificate
  store open/enumerate; registry), `x/sys/windows/registry`, `debug/pe`, file/version APIs, and thin `LazyDLL`
  bindings for the rest (CNG probe, `CertGetCertificateContextProperty`).
- PowerShell 5.1 (this box) vs 7 differ; execution policy and constrained language mode vary in enterprises.
- The repository already has **no `os/exec` use in library code** (checked), and the collectors read via `fs.FS`.

## Decision

Sensors do not execute subprocesses (`os/exec` forbidden in sensor packages, enforced by an import test).
PowerShell, `openssl`, `update-crypto-policies` etc. are used **only by the test harness** as an independent
oracle to cross-check the Go collector's output.

## Why

It removes a class of vulnerabilities and an environment dependency, and makes ground-truth testing stronger
because the oracle is independent of the implementation.

## Trade-offs

More Go code, including a hand-written syscall layer for calls `x/sys` does not wrap (which is itself the
highest-risk code, see ADR-0005); slower to first Windows result.

## Consequences

- `golang.org/x/sys` moves from an indirect to a direct dependency (already in the module graph).
- The syscall layer is small, fixed, review-gated and forbidden-symbol-tested.
- Where an API needs elevation the sensor reports `unknown(permission)` rather than escalating.
