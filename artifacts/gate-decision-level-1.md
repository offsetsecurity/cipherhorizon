# Gate decision — Level 1

```
AGENT      9 — Program Architect / Gatekeeper
DATE       2026-09-24
RECEIVED   agent-01..05, handoffs 01-03, evidence-model, collector-contract, ADR-0001..0010,
           security-review-level-1, test-report-level-1, cbom-review-level-1, the code and the real outputs
```

## Outcome

# PASS — with a scope statement that must travel with it

**Level 0 (foundation) and Level 1 (present) are complete for:**
- **Windows, standard-user tier, tested on one machine** (Windows 11 Pro build 26200);
- **Debian-family (Debian, Ubuntu, Kali) on fixtures only**, with the existing behaviour proven unchanged.

**Not passed, and not to be claimed:** any live Linux host; the Administrator/root tier; macOS; RHEL/SUSE/Alpine/Amazon;
certificates, policy, application association, runtime, correlation.

## Acceptance table (handoff-03 / agent-04 §7)

| # | Gate | Evidence | Verdict |
|---|---|---|---|
| 1 | Existing output preserved | `TestLegacyOutputIsPreserved`: same components, edges and every legacy property for both fixtures; diffs are additive only | **PASS** |
| 2 | Claim discipline | `TestGraphRejectsOverClaimingDerivedFact`; projection re-checks the whole graph; real-CBOM audit: 0 `dependsOn`, every `provides` labelled and cited | **PASS** |
| 3 | No decoy false positive | synthetic (`TestDecoyIsInventoriedButNeverCapable`) **and** real host (2 text decoys: present, heuristic, uncredited) | **PASS** |
| 4 | No secret reads | spying-filesystem proof that only recognised libraries are opened; real-host canary: 0 markers in output, 0 key/credential files inventoried | **PASS** |
| 5 | Honest coverage | budget hit -> `partial`/`budget`; denied -> counted (129 on the real machine); hostile names reported; failed sensors visible | **PASS** |
| 6 | Privilege warning | printed and recorded in the CBOM at user tier, absent at admin; exit code unchanged | **PASS** |
| 7 | Determinism | identical IDs and bytes across runs | **PASS** |
| 8 | Ground truth on this machine | 22 agreed / 0 version mismatches / 0 false positives; PE parser 400/400 identical to the oracle; 5 real gaps found and listed; 5 more fixed after the first run | **PASS**, adjudication provisional (single reviewer) |
| 9 | Wording | README/docs/ADR index carry the scope; Linux marked fixtures-only; macOS unsupported | **PASS** (see condition C-1) |

## Backtracks that happened (the loop worked)

| Found by | Problem | Sent back to | Resolution |
|---|---|---|---|
| Agent 5 (schema) | CycloneDX 1.6 requires numeric `confidence` on identity methods | Architecture (ADR-0002) | identity block for authoritative methods only |
| Agent 5 (compat test) | citation order changed | Builder | table order preserved |
| Agent 6 | hostile names abort the whole run (HIGH) | Builder | `SafeText`/`Clean`, skipped-and-reported, 4 tests |
| Agent 6 | device identifier emitted by default | Builder / ADR-0009 | only with `--redact-host` |
| Agent 7 | 5 cheap recognition gaps (`openssl.exe`, MSYS names) | Builder | patterns + lookalike negatives, rerun 16 -> 22 |
| Agent 7 | Linux harness accepted a fatal exit code | Test | fixed, negative control |
| Agent 8 | version provenance unstated | Builder | `version-source` |

## Conditions attached to the PASS

- **C-1 Wording.** Any release note, README or report must say: *Windows: standard-user tier, one machine. Debian
  family: fixtures. Linux live, elevated, macOS: not validated.* (Done in `docs/host-discovery-program.md`.)
- **C-2 Elevated tier.** No claim of elevated behaviour until `compare-windows.ps1` has run from an elevated shell and
  time/coverage are recorded (security review F6).
- **C-3 Linux.** "Validated" requires `lab-debian.sh` to have run on a real Debian-family host, as user and as root,
  with MISSING adjudicated.
- **C-4 Adjudication.** The 39-item adjudication is the author's. A second reviewer should confirm it before it is
  quoted as a recall figure.
- **C-5 Wording of capability.** Reports built on this output must say "can provide", never "uses" (cbom-review §6).

## Carried forward (not blockers)

| Item | For |
|---|---|
| Per-file capability mapping (libssl vs libcrypto) | L2 |
| OpenSSL provider modules (`legacy.dll`, `fips.dll`): generic names, need a provider concept | L2 / RESEARCH |
| Five unrecognised crypto artefacts | knowledge entries |
| Offline-only signature verification (no revocation network I/O) | RESEARCH REQUIRED before any Authenticode use |
| Timeout/scale of an elevated walk (`WindowsApps`, key stores) | L1.1 measurement |
| A second-reviewer pass on recognition patterns | ongoing |

## Decision on the next level

**Proceed, in this order** (each with its own research -> architecture -> build -> review -> test -> gate loop):

1. **Validate what exists before adding more:** run the Linux harness in WSL and an elevated Windows run. These convert
   two "not validated" entries to evidence at almost no build cost, and they can change the design (an elevated walk
   may need budgets; a real Debian host may disagree with the fixtures).
2. **L2 (capable):** the Windows CNG algorithm *probe* (Agent 2 measured that ML-KEM/ML-DSA open on this machine
   while Schannel offers only classical suites) as a `capable (probed)` observation, plus per-file mapping.
3. **L3 (provisioned):** certificate stores and key metadata (the only host source of direct algorithm and key-length
   evidence), which introduces the hand-written syscall layer and therefore needs the security review Agent 6 said it
   would. Windows certificate enumeration was already proven unelevated in the platform research.

`macOS` remains `RESEARCHED / NOT IMPLEMENTED / NOT VALIDATED`.

## What the user needs to do (nothing else blocks this)

1. `wsl --install -d Debian` in an **elevated** PowerShell, reboot (or provide SSH to the Kali box).
2. Once, run `compare-windows.ps1` from an **elevated** PowerShell and paste the output.
3. Say whether to commit this work, and whether to proceed to L2/L3 after those two validations.
