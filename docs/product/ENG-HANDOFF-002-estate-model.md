# ENG-HANDOFF-002: Cryptographic estate model

Implements [PRD-003](PRD-003-cryptographic-estate-model.md) under [SECARCH-001](SECARCH-001-threat-model-and-security-requirements.md). Read those first. Requirement IDs (`REQ-*`), acceptance criteria (`AC-*`) and security requirements (`SR-*`) are referenced, not repeated. Progress is tracked in [TRACKER](../program/TRACKER.md); "done" is asserted only in the [RTM](../program/RTM.md).

## 1. Design decisions

| # | Decision | Reason | Requirement |
|---|---|---|---|
| D1 | **Raw documents stay authoritative and immutable.** `scans.report_json` and `host_snapshots.cbom_json` are not rewritten. New tables hold a **projection** (entities, observations) that can be dropped and rebuilt; a `projection_version` row triggers a rebuild when the projection code changes. | Migration safety; lets us fix projection bugs without data loss | REQ-MOD-1, -5; SR-10 |
| D2 | **Unification is one store and one entity space, not one merged claim.** Streams (`host`, `network`) stay separate on every observation (ADR-0006). Imports add a third stream value, `imported`. The evidence package's existing validation (`ClassOf`, "no relationship may claim more than the weakest evidence") is reused, not bypassed. | ADR-0006 stays valid; correlation is an Assessment | REQ-MOD-6 |
| D3 | **System vs asset.** Keep `assets` (an observed thing: a host or an endpoint) untouched as the observation anchor. Add `systems` (the owned unit that carries metadata). Every asset belongs to exactly one system (`assets.system_id`). Migration creates one system per asset, then merges assets joined by an existing manual `asset_links` row. A *link* proposes moving an asset into another system; confirming performs the merge (audited). | Smallest change that keeps every 0.1.0 API/UI route working while giving metadata and correlation a home | REQ-SYS-1, REQ-COR-2 |
| D4 | **Certificates are entities keyed by SHA-256 fingerprint**; algorithms by `evidence.AlgorithmKey`; software/providers by existing keys (`ArtefactKey`, `ProviderKey`). One `entities` row per (kind, key); `observations` say *who saw it, where, how, when*. | Same certificate from TLS, store and import is one entity (REQ-CERT-6) | REQ-MOD-2 |
| D5 | **New evidence kind `certificate`** with an allow-list of attributes (no free-form): `fingerprint`, `serial`, `notBefore`, `notAfter`, `keyAlg`, `keyBits`, `curve`, `sigAlg`, `isCA`, `selfSigned`, `keyUsage`, `origin`, `privateKey` (yes/no/unknown). Subject/issuer/SANs are **display strings** with a length cap, stored as attributes flagged untrusted, escaped on render. Rung: `provisioned` (host holds certificate material, metadata only) — already defined in `evidence.Rung`. | ADR-0005 allow-list rule; hostile strings | REQ-CERT-3; SR-02, SR-06 |
| D6 | **Correlation is a pure function** `estate.Correlate(observations, existingLinks, now) → []Link`, deterministic, with no I/O, so it is testable against golden fixtures. Persistence and state transitions live in `store`. | REQ-COR-8, AC-COR-4 | REQ-COR-* |
| D7 | **Prioritisation is a pure function** over (system metadata, observations, findings) returning an ordered list where each row carries its explaining facts and citations; **no composite score**. | REQ-PRI-1 | REQ-PRI-* |
| D8 | **Audit log is append-only** and written in the same transaction as the mutation it records. | SR-11 | REQ-SYS-2, REQ-COR-2 |
| D9 | **Import parsing is layered:** (1) size/depth/count limits on a token stream, (2) schema validation, (3) producer profile detection, (4) mapping to observations. Each layer is independently testable and fuzzed. Profiles are data plus small functions, never scripts. | SR-01, REQ-ING-6 | REQ-ING-* |
| D10 | **CycloneDX 1.7 by default, 1.6 by option**, from one internal model; the emitter chooses field names per spec version. The 1.7 schema and cryptography-defs are vendored like 1.6 and gated by `internal/schematest`. | REQ-EXP-1 | |
| D11 | **No new Go dependency.** JSON streaming, CSV, hashing, X.509 are stdlib; the OpenAPI document is hand-written with a parity test. | SR-14, REQ-NFR-2 | |

## 2. Data model

Tables arrive with the package that first uses them. **Migration 4 (WP-1, built)** creates `systems`, `assets.system_id`, `sources`, `entities`, `observations`, `audit_log` (append-only by trigger), `projection_state`, and adds `host_snapshots.source_class` / `submitted_by`. `links` arrives with WP-5 and `imports` with WP-4. Differences from the first sketch below, decided while building: `systems.name` is **not** unique (a display name; two systems may share it); observations carry no `system_id` (it is derived through the asset or the source, so a merge cannot leave it stale); `entities` carry no first/last-seen columns (computed from observations, so retention cannot leave them stale); `sources.is_current` marks the latest picture of each asset.

```
systems(id PK, name UNIQUE NOT NULL, owner, environment, criticality, exposure,
        data_lifetime_years INTEGER, fisma_id, fips199, hva_id, hosting, hosting_provider,
        notes, created_at, updated_at)                        -- all metadata columns nullable = "not provided"
assets.system_id  REFERENCES systems(id)                      -- backfilled by the migration (D3)

sources(id PK, class CHECK IN ('scanner','collector','imported','operator'), stream CHECK IN ('host','network','imported'),
        ref_kind CHECK IN ('scan','host_snapshot','import'), ref_id INTEGER,
        tool_name, tool_version, sha256, size, received_at, submitted_by,
        subject_claim TEXT,                                    -- what an imported document says about itself; never used for placement
        system_id REFERENCES systems(id),                      -- operator-assigned subject for imports
        status CHECK IN ('active','withdrawn'), not_interpreted_json)
imports(id PK, sha256 UNIQUE, cbom_json BLOB, spec_version, created_at)   -- raw imported documents (only place a new raw blob lives)

entities(id PK, kind NOT NULL, key NOT NULL, first_seen, last_seen, attrs_json, UNIQUE(kind,key))
observations(id PK, source_id REFERENCES sources ON DELETE CASCADE, system_id, asset_id NULL,
             entity_id REFERENCES entities, relation, rung, class, method, method_quality,
             observed_at, attrs_json)                          -- NOT NULL on source_id, rung, method, observed_at (AC-MOD-3)
links(id PK, asset_id REFERENCES assets, system_id REFERENCES systems,        -- "asset belongs to system"
      state CHECK IN ('proposed','confirmed','rejected'), strength CHECK IN ('strong','medium','weak'),
      rules_json, evidence_json, decided_by, decided_at, created_at,
      UNIQUE(asset_id, system_id))
audit_log(id PK, at, actor, object_kind, object_id, action, before_json, after_json, reason)  -- append-only
projection_state(version INTEGER, built_at)
```

Indexes: `entities(kind,key)`, `observations(entity_id)`, `observations(system_id)`, `observations(source_id)`, `links(state)`, and an index on certificate fingerprints for the correlation pass (SR-15).

## 3. Design notes

- **DN-1 Merging systems.** Confirming a link merges the asset's current system into the target. If the merged-away system has operator-set metadata that differs from the target's, the confirm is refused with a conflict listing the fields; the operator resolves it (keep target / keep source per field). Never silently overwrite operator data. Merges are audited and reversible by an "unmerge" that recreates the system from the audit `before_json`.
- **DN-2 Projection.** `internal/estate.Project(source) []Observation` per source kind (scan report, host CBOM/evidence batch, imported document). Rebuild = delete observations for active sources, project again inside one transaction. A projection golden per source kind pins the output.
- **DN-3 Imported evidence mapping (REQ-ING-5).** static-source producers (CBOMkit, cdxgen, Theia): `capable` (kind `mapped`, method quality `heuristic`). Host/network producers (CBOM-Lens): algorithm/protocol inventories from files → `present`; certificates → `provisioned`; nothing → `bound`/`loaded`/`exercised`. Unknown producer: `present` at method quality `sampled`, class E0/E1 only. Producer detection reads `metadata.tools`, `metadata.component`, and `properties` but its result is a *label for the human*, not a trust input.
- **DN-4 Linux symlinks.** Walk with `fs.WalkDir`; for a symlink entry, resolve with `fs.ReadLink` only when the fs supports it; accept iff the resolved path stays inside the sensor root **and** is a regular file, resolved at most once (no chains). Test fixtures: Debian-style symlink farm (accepted), symlink to `/etc/shadow`-like path outside root (rejected), symlink loop (rejected), symlink to directory (skipped), FIFO (skipped).
- **DN-5 Windows store enumeration.** `winapi.EnumCertStores(location, storeName)` returns copied DER bytes and a `PrivateKeyPresent` tri-state read via `CertGetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID)`; store opened with `CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG`; caps: 64 stores, 20,000 certificates per store, 64 KiB per certificate; 15 s per store; every context freed on every path. Parsing of DER is stdlib `crypto/x509` in the sensor, not in `winapi`. Certificate contexts flagged "not parseable" are counted, not dropped (`unknown(unsupported)`). Roots are summarised (REQ-CERT-5) at projection time.
- **DN-6 Correlation rules.** Inputs: certificate observations (fingerprint) with their system/source classes; host names/machine ids from host snapshots; endpoint host/port and SANs from TLS scans. Output strength table (fixed): J1 unique + first-party → `strong`; J1 ambiguous → each `medium`, none auto; J2 exact FQDN or reported address → `medium`; J2+J3 together → `medium`; J3 alone → `weak`. Only `strong` may auto-confirm and only when all inputs are first-party (REQ-COR-4).
- **DN-7 Prioritisation rule order.** (1) HNDL: quantum-vulnerable key establishment observed on a service of the system **and** data lifetime known and extending past 2030 (deprecation) — each date and wording cited to NIST IR 8547; (2) internet exposure then criticality; (3) certificate/hygiene defects count and severity; (4) evidence strength as tie-break. Systems missing lifetime/exposure/criticality are ranked with the missing inputs named.
- **DN-8 Migration.** Automatic timestamped backup `<db>.bak-<version>-<time>` before the first migration of a version; refuse if the backup cannot be written. Failure injection test aborts mid-transaction. Backups are created with the same restrictive permissions as the DB.
- **DN-9 API additions** (all through the guarded mux; each documented in OpenAPI; each mutating route in the security script):
  `GET/PUT /api/v1/systems/{id}` (metadata), `GET /api/v1/systems`, `POST /api/v1/systems/import-csv` and `GET …/export.csv`, `GET /api/v1/systems/{id}/certificates`, `GET /api/v1/certificates`, `GET /api/v1/links?state=`, `POST /api/v1/links/{id}/confirm|reject`, `POST /api/v1/imports` (multipart: file + system), `GET /api/v1/imports`, `POST /api/v1/imports/{id}/withdraw`, `GET /api/v1/estate` (ranked list), `GET /api/v1/systems/{id}/m2302.json|csv`, `GET /api/v1/audit?object=`. Old routes remain and keep their shapes.

## 4. Work packages

Order is the delivery order. A package is done when every listed requirement's RTM row has code, test and evidence, its security requirements are verified (mutation check where noted), and the gate in [PROGRAM](../program/PROGRAM.md) passes.

| WP | Title | Requirements | SR | Deliverables | Gate specifics |
|---|---|---|---|---|---|
| **WP-1** | Model, migration, systems metadata, audit | REQ-MOD-1…7, REQ-SYS-1/2, REQ-COR-2 (storage) | SR-10, SR-11, SR-13 | Migration; `internal/estate` types + projection for scans and host snapshots; `systems` API + CSV; audit log; rebuild command `cipherhorizon db rebuild-graph`; 0.1.0 fixture DB in `testdata/` | Migration fixture test; rebuild-equals golden; failure-injection test; existing suite green; journey unchanged |
| **WP-2** | Certificate entities + Linux certificate sensor + findings | REQ-CERT-2…8 (Linux, TLS unification) | SR-06, SR-16, SR-17 | `certificate` evidence kind; sensor `certs` (fs-based); TLS scan projection to certificate entities; rules with citations; decoy-key fixtures | Mutation check on the private-key guard; symlink fixtures (DN-4); citation invariant |
| **WP-3** | Windows certificate sensor | REQ-CERT-1 | SR-06, SR-07 | `winapi.EnumCertStores`; sensor wiring (Live only); `compare-certs.ps1` oracle | **Written syscall review before merge**; oracle 0 missing / 0 extra; architecture test still passes |
| **WP-4** | Third-party CBOM ingest | REQ-ING-1…9 | SR-01…04, SR-18 | `internal/importer`; profiles; API/CLI/UI-less; fixtures with licence manifest; native fuzz target | Real samples ingest (AC-ING-1); hostile documents; fuzz budget clean; forged-collector test |
| **WP-5** | Correlation | REQ-COR-1, 3…8 | SR-05, SR-15, SR-12 | `estate.Correlate`; store transitions; review API; estate fixture with hostile decoys | Golden link set; determinism; reject persistence; security script covers new routes |
| **WP-6** | Prioritisation | REQ-PRI-1…3 | — | `estate.Prioritise`; methodology doc with citations | Golden ranking; every rule cited |
| **WP-7** | Export and standards | REQ-EXP-1, 2, 3, 5, 6 | SR-08, SR-14 | 1.7 emitter + vendored schema; registry mapping table; M-23-02 export; OpenAPI + parity test | 1.7 validation + negative control; mapping test; parity test |
| **WP-8** | UX design and UI | REQ-UI-1…8 | SR-02 | `UX-DESIGN-002`; new views; hostile-string fixtures; journey extended | Journey green incl. hostile strings; no `innerHTML` check; CSP unchanged |
| **WP-9** | QA and release | REQ-REL-*, REQ-NFR-* | all | QA report; changelog; docs; release report | RTM 100% P0 done; no open Sev-1/2 |

Deferred: REQ-ING-10 (blocked on OQ-2), REQ-EXP-4, REQ-UI-7 (P1, only if time), REQ-REL-4 (needs the GitHub repository).

## 5. Test strategy summary (detail in [QA-PLAN-002](QA-PLAN-002-estate-model.md))

Unit and golden tests per package; **property tests** for correlation determinism; **fuzz targets** for the ingest path and certificate parsing; **fixtures**: 0.1.0 DB, estate, decoy keys, hostile strings, third-party samples; **oracles**: `compare-certs.ps1` (Windows), independent Python/`jq` counts for ingest; **journey** and **security scripts** extended; **mutation checks** recorded per guard.

## 6. Constraints carried over (do not regress)

`CGO_ENABLED=0`; only `internal/hostinfo` and `internal/winapi` may use `unsafe`/`x/sys/windows`; collector has no subprocess and no network beyond its authenticated push; strict CSP and no external requests; UI builds DOM with `createElement`/`textContent`; every finding rule has a citation and a test; no SSL-Labs-style vocabulary; no secret or key material anywhere.
