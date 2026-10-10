# QA-PLAN-002: Cryptographic estate model

Verifies [PRD-003](PRD-003-cryptographic-estate-model.md). Written **before** the code so tests are derived from the requirements, not from the implementation. QA evidence is recorded in the [RTM](../program/RTM.md); the outcome goes into `QA-REPORT-002` (WP-9).

## 1. Principles

1. **Requirement-first.** Each test names the requirement or acceptance criterion it proves (test name contains the ID or the RTM cites it).
2. **Independent oracles.** Where the product reports facts about the outside world (what is in a certificate store, how many assets a document holds), an independent program computes the same thing and the results are compared — as was done for the Windows collector (`compare-windows.ps1`, `compare-hashes.ps1`, `compare-cng.ps1`).
3. **Negative controls and mutation checks.** A guard is not tested until removing it makes a test fail. Every SR in the RTM coverage table names its mutation.
4. **Hostile data everywhere.** Every string that comes from a certificate, a document or a host is attacker-controlled; fixtures contain markup, control characters, bidi characters, very long values and invalid UTF-8.
5. **Report honestly.** Not-run and not-validated items are listed; a measured miss is a finding, not an omission.

## 2. Test levels

| Level | Tooling | Scope |
|---|---|---|
| Unit / golden | `go test` | projection, correlation, prioritisation, importer layers, sensors, emitters |
| Property | `go test` with generated inputs | correlation determinism (same inputs, shuffled order → same links); projection rebuild equals incremental |
| Fuzz | `go test -fuzz` (fixed time budget in QA) | import token/limits layer, importer profiles, certificate parsing wrapper, CSV import |
| Migration | fixture DB from 0.1.0 | AC-MOD-2, AC-MOD-4 |
| Oracle | scripts in `testing/` | `compare-certs.ps1` (Windows store), ingest counts via independent script |
| API/contract | Go tests + parity test | OpenAPI ↔ route table; error shapes |
| Security script | `testing/e2e/security.sh` extended | every mutating route: 401 / 403 Origin / Host; hostile inputs; export requires token; DB permissions |
| Browser journey | `testing/e2e/journey.mjs` extended | every new view with hostile fixtures; keyboard reach; no console errors; no external requests; CSP |
| Build / release | goreleaser snapshot, cross-compile | all platforms, both binaries |
| Real host | Windows dev machine | certificate sensor vs oracle; **Linux and admin tier: not validated unless run** |

## 3. Fixtures

| Fixture | Location | Content |
|---|---|---|
| 0.1.0 database | `testdata/db/v0.1.0.sqlite` (built by a script from the tagged schema) | scans, snapshots, manual links, finding statuses |
| Estate | `testdata/estate/` | unique certificates, a certificate on 3 hosts, a wildcard on 40 hosts, a host with two addresses, name-collision decoy, forged imported CBOM carrying a real fingerprint; golden expected links and ranking |
| Decoy keys | `testdata/certs/decoys/` | `.key`, PKCS#8 PEM, encrypted key, `.p12`, key inside a `certs/` dir, certificate + key in one PEM file |
| Symlinks | built at test time (`t.TempDir`) | Debian-style farm, escape, loop, directory, FIFO (skipped where unsupported) |
| Third-party CBOMs | `testdata/interop/` + `MANIFEST.md` (source, licence, SHA-256) | CBOMkit Keycloak/Kafka, Theia, CBOM-Lens 1.6/1.7; regenerated equivalents where licence unclear (OQ-5) |
| Hostile documents | `testdata/hostile/` | depth bomb, million-component, oversize, wrong schema, markup strings, invalid UTF-8 |
| Hostile strings | shared list used by unit tests and the journey | cert subject/SAN/issuer, component names, properties, owner/notes fields |

## 4. Test design by requirement family

| Family | Key tests (names finalised when written; the RTM records the final ones) |
|---|---|
| MOD | rebuild==golden; migration row counts and finding parity vs pre-migration capture; failure injection leaves DB intact; observation NOT NULL constraints; stream separation preserved (host record never becomes network) |
| CERT | Linux sensor decoys (none parsed/emitted, mutation); symlink fixtures; caps; per-store Windows oracle (0 missing / 0 extra); fake `winapi` tests for error paths (handles freed, timeout, cap); TLS+store same entity; every rule cited; roots summarised, end-entity itemised; unknown key length says why |
| COR | golden link set on the estate fixture; ambiguity → no auto; widely shared cap; import-derived → proposed only; reject persists; unsupported confirmed link flagged; explanation lists matched values; determinism |
| ING | sample counts vs independent script; subject never from document; provenance stored; idempotent re-import; evidence mapping table (no `bound/loaded/exercised`); precedence (import cannot downgrade first-party); "not interpreted" counts; hostile documents; fuzz |
| SYS/PRI | CSV round trip and error lines; audit rows written with mutation; ranking golden; lifetime tie-break; missing-metadata labelling; rule citations |
| EXP | 1.7 schema validation + negative control; 1.6 compat; registry mapping table (unmapped listed); M-23-02 nine items provided/not-provided; OpenAPI parity; export requires token |
| UI | journey per view; hostile strings inert; keyboard reach; no external requests; screenshots reviewed |
| REL/NFR | `CGO_ENABLED=0` cross-builds; dependency diff empty (or ADR); collector import rules (arch test); performance measurements reported against the design targets |

## 5. Entry and exit criteria

- **Entry to QA (WP-9):** all packages' gates passed; RTM P0 rows `done`; fixtures and oracles in the repository.
- **Exit:** RTM complete per the release gate; success measures M1–M7 each recorded as pass/fail with the measurement; all Sev-1/2 closed; Sev-3/4 listed; not-validated list published; QA report reviewed by PM and Security Architect.

## 6. Not planned / known limits

Linux live host (until a runner exists), Windows admin tier, Windows Server, ARM64, macOS, third-party key storage providers, non-English locales, large-scale load beyond the stated design targets, multi-user concurrency beyond the existing single-token model.
