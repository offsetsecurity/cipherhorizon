# Host cryptographic discovery — engineering program

Turning `cipherhorizon run` from a Debian/Ubuntu package inventory into an evidence-driven host discovery
engine, one validated level at a time. **Product boundary:** `tls scan` observes endpoints from outside;
`cipherhorizon run` looks inside a machine; their evidence stays separate and is joined only by a labelled
assessment (ADR-0006).

Workflow per level: **Security research → Platform research → Architecture → Implementation → Security review →
Test / ground truth → CBOM review → Gatekeeper** (fail or research-needed sends the work back).

## Status

Level 0 (foundation) and Level 1 (present) **passed the gate** ([gate decision](../artifacts/gate-decision-level-1.md)),
with a scope statement that must travel with it: **Windows at the standard-user tier on one machine; Debian-family on
fixtures only.** Levels 2-7 have not been started.

| # | Agent | Artefact | Status |
|---|---|---|---|
| 1 | Security / cryptography research | [agent-01](../artifacts/agent-01-security-research.md), [handoff-01](../artifacts/handoff-01-security-to-platform.md) | Done |
| 2 | OS / platform research | [agent-02](../artifacts/agent-02-platform-research.md), [handoff-02](../artifacts/handoff-02-platform-to-architecture.md), [MACOS_SUPPORT](platform/MACOS_SUPPORT.md) | Done |
| 3 | Security architecture | [agent-03](../artifacts/agent-03-architecture.md), [evidence-model](../artifacts/evidence-model.md), [collector-contract](../artifacts/collector-contract.md), [handoff-03](../artifacts/handoff-03-architecture-to-builder.md) | Done |
| 4 | Implementation architect | [agent-04](../artifacts/agent-04-implementation-design.md) | Done (challenged Agent 3: replaced the adapter, cut Authenticode and the uninstall registry, zero syscalls at L1) |
| 5 | Builder (L0 + L1) | [agent-05](../artifacts/agent-05-build-report.md) | Done |
| 6 | Security reviewer | [security-review-level-1](../artifacts/security-review-level-1.md) | Done: 2 findings fixed, 1 open (elevated run) |
| 7 | Test engineer / ground truth | [test-report-level-1](../artifacts/test-report-level-1.md), [testing/hostdiscovery](../testing/hostdiscovery/README.md) | Done for Windows; Linux harness ready, **not run** |
| 8 | Evidence / CBOM reviewer | [cbom-review-level-1](../artifacts/cbom-review-level-1.md) | Done |
| 9 | Gatekeeper | [gate-decision-level-1](../artifacts/gate-decision-level-1.md) | **PASS with conditions** |

## Decisions (`docs/decisions`)

| ADR | Decision |
|---|---|
| [0001](decisions/ADR-0001-evidence-pipeline.md) | Evidence pipeline: sense → normalise → derive → project |
| [0002](decisions/ADR-0002-claim-strength-model.md) | Claim rungs, strength classes, probed vs mapped capability, no invented confidence |
| [0003](decisions/ADR-0003-levels-and-sequencing.md) | Levels L0–L7; certificates before policy; build L0 + L1 first |
| [0004](decisions/ADR-0004-no-subprocess-no-powershell.md) | No subprocesses in collectors; PowerShell is a test oracle only |
| [0005](decisions/ADR-0005-secret-safety-by-construction.md) | Secret safety by construction; canary gate; privilege tiers |
| [0006](decisions/ADR-0006-host-network-separation.md) | Host and network evidence separate; correlation is an assessment |
| [0007](decisions/ADR-0007-distribution-model.md) | Signed standalone + native packages; persistent agent deferred |
| [0008](decisions/ADR-0008-coverage-and-blind-spots.md) | Coverage and blind spots are first-class output |
| [0009](decisions/ADR-0009-privilege-disclosure-and-redaction.md) | Privilege warning; minimise-by-default redaction |
| [0010](decisions/ADR-0010-sensor-replaces-collector.md) | `Sensor` replaces `collector.Collector`; no adapter |
| [0011](decisions/ADR-0011-separate-endpoint-collector.md) | A separate ~4 MB collector program for endpoints; enforced by a test |
| [0012](decisions/ADR-0012-file-roles-imports-hashes-identifiers.md) | File roles (provider/consumer), static-import links, SHA-256 and file-identity `purl` (Windows stage 1) |

ADR-0001 to ADR-0008 were proposed by Agent 3 and stand after Agent 4's challenge (ADR-0002 amended). ADR-0009 to ADR-0011 were accepted at implementation (ADR-0011 on the user's challenge).

## What is researched, implemented, tested, validated

| Platform | Researched | Implemented | Tested | Validated |
|---|---|---|---|---|
| Windows (standard user) | yes | **L0 + L1** | fixtures + this real machine: 22/22 agreed with an independent oracle, 0 false positives, real-host canary passed | **yes, on one machine** |
| Windows (Administrator) | yes | same code | **not run** | **no** |
| Debian / Ubuntu | yes | L0 + L1 (refactor of the existing collector) | fixtures; output proven unchanged against the frozen legacy goldens | **fixtures only** |
| Kali | yes (test environment, atypical) | same code | not reachable | **no** |
| RHEL / SUSE / Alpine / Amazon | yes (desk) | no | no | **no** |
| macOS | desk research | no | no | **no: not supported** ([note](platform/MACOS_SUPPORT.md)) |

Nothing in this program may be described as "supported" beyond the last column.

## Directory map

The brief's directory layout is honoured by keeping agent outputs in `artifacts/` (as specified), durable
decisions in `docs/decisions/`, and platform notes in `docs/platform/`. Research, evidence and architecture
documents live under `artifacts/` until a level is accepted; the Gatekeeper then promotes the durable parts to
`docs/`.
