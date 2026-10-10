# Architecture

## Host inventory (`cipherhorizon run`): an evidence pipeline

```
 host filesystem ─► sensors ─► evidence graph ─► derive ─► cbom projection ─► pqc ─► CycloneDX 1.6
 (os.DirFS(root))   observe     one node per      cited     fail-closed,      cited     JSON
                    only        thing, every      capabil-  deterministic     verdicts
                                observation kept  ity
```

Design record: [docs/decisions](decisions) (ADR-0001 to ADR-0010) and the program in
[host-discovery-program.md](host-discovery-program.md). The rules, in short:

- **Sensors observe; they never infer.** A sensor (`internal/sense`) returns `evidence.Batch`:
  observations (a package is installed, a file exists) and *coverage* (what it looked at and what it could
  not see). It does not say what software can do, and it never says a fact is stronger than the method that
  found it.
- **Capability is knowledge, applied afterwards.** `internal/knowledge` holds the cited tables (which
  families provide which algorithms, from which version); `internal/derive` applies them to artefacts whose
  presence was established by an authoritative or parsed method. A name match alone (a file called
  `libcrypto-3-x64.dll`) is listed as present and is never credited with capability.
- **No claim is stronger than its weakest evidence.** Every derived fact names the observations it rests on;
  `evidence.Graph.Add` rejects one that claims more than they support, and the CBOM projection re-checks the
  whole graph before writing anything. See [evidence model](../artifacts/evidence-model.md).
- **Absence is earned.** A sensor that could not read something reports it (`Coverage`, `unknown(reason)`);
  the CBOM lists what was not seen (`cipherhorizon:not-seen`), and a run below Administrator/root says so
  ([ADR-0009](decisions/ADR-0009-privilege-disclosure-and-redaction.md)).
- **Operating-system code stops at the sensor.** `evidence`, `knowledge` and `derive` import no platform
  package and no CycloneDX; sensors import neither `cbom` nor `derive`, run no subprocess and use no
  network. `internal/archtest` enforces it.

Built-in sensors: `apt` (Debian, Ubuntu, Kali: the dpkg database), `pe-files` (loose crypto libraries on
Windows: a bounded walk of install locations plus a hand-written, fuzzed PE version-resource reader),
`windows-cng` (what Windows itself provides) and `cert-files` (X.509 certificates held as files on Linux: trust
stores and service directories; public metadata only, never a key; see ADR-0015 and
`docs/host-discovery/stage-3-certificates-report.md`).

### The sensor contract (`internal/sense`)

```go
type Sensor interface {
    Info() Info                                            // name, version, the methods it uses
    Detect(ctx context.Context) (bool, error)              // is this kind of thing present?
    Collect(ctx context.Context) (evidence.Batch, error)   // observations + coverage
}
```

- **`context.Context`** on `Detect` and `Collect`, so a run can be bounded and cancelled.
- **`Detect` has three outcomes**: `(true,nil)` present; `(false,nil)` absent, which is normal and skips
  silently; `(false,err)` could not tell, which is recorded as a failure.
- **Partial results are kept.** A non-nil error from `Collect` means the result is *incomplete*; the batch
  returned with it is still used. The runner reports `ok | skipped | partial | failed` per sensor and the CLI
  exits `2` when a sensor failed or a budget was hit. Unreadable locations alone are a privilege *warning*,
  not an error.
- **Sensors read the host only through `Env.FS` (an `fs.FS`).** Natively that is `os.DirFS` of the root; in a
  container with the host mounted it is `os.DirFS("/host")`; in tests it is `fstest.MapFS`.
- **Registration is by explicit name**, and the registry checks `Info().Name` matches it and that every
  method the sensor uses is declared.
- **Sequential, not concurrent.** Simple and deterministic; sensors need not be goroutine-safe.

`collector.CryptoAsset` (a `cyclonedx.Component` plus `Provides` / `DependsOn` edges) survives as the type
the CBOM builders exchange; it is produced by the projection, never by a sensor.

## Evidence, not heuristics

**A package proves capability, not use.** `libssl3 3.0.13` installed means the host *can* do RSA; it does
not mean anything on the host *does*. The pipeline keeps the two apart:

1. **Presence** (a fact a sensor read): every recognised crypto package or file appears as a `library` or
   `application` component with its version and, for packages, Package URL. It carries
   `cipherhorizon:claim = present`, the method that found it and that method's quality.
2. **Capability** (a cited claim): only families with a citable mapping get `provides` edges to algorithm
   assets, gated by version where the standard says so (for example OpenSSL >= 3.5 for ML-KEM / ML-DSA /
   SLH-DSA). The citations travel with the component as `cipherhorizon:capability-basis` properties, the
   component is marked `cipherhorizon:evidence` and `cipherhorizon:provides-claim = capable-mapped`.

Families with no citable mapping are inventoried and nothing more. Under-claiming is the rule; an unparseable
version drops the gated capabilities rather than assuming them.

## The algorithm catalogue and the vocabulary layer (`internal/algo`, `internal/cbom`)

CycloneDX enumerations are closed: one out-of-vocabulary value invalidates the whole document. So:

- The CBOM projection mints algorithm components only through `algo.MustGet(id)`, a total lookup table. Every field
  without an authoritative source (a generic OID for ECDSA or AES, a security category for RSA) is left
  unset, and therefore omitted.
- `cbom.Build` re-checks every closed-vocabulary field on every component, whoever built it, and *omits*
  anything out of vocabulary with a warning. Certificate, protocol and key-material assets are rejected
  until their vocabularies exist: it fails closed.
- `vocab_test.go` pins those vocabularies to the enumerations in the vendored `bom-1.6.schema.json`.
- The 1.7 registry fields (`algorithmFamily`, `ellipticCurve`) are never emitted: no authoritative lookup
  table backs them yet. They are the next step once 1.6 is solid.

### An SDK bug worth knowing about

`cyclonedx-go` v0.12.0's `EncodeVersion` does not recognise the `cryptographic-asset` component type in
any spec version and rewrites every crypto component to `application`. That output is schema-valid, so
schema validation cannot catch it. `cbom.Encode` therefore uses the SDK's plain `Encode` (targeting 1.6
natively), and `TestEncodeKeepsCryptographicAssetType` asserts the type in the emitted JSON.

## PQC classification (`internal/pqc`)

A plain function over a finished CBOM, not a plugin. Each verdict comes from a rule with a rationale and
citations (`TestEveryRuleIsCited`). A component matches by exact OID, then by OID subtree (an arc the
cited standard reserves for the family, e.g. PKCS #1's `1.2.840.113549.1.1`), then by exact catalogue
name. Nothing is matched by pattern, so `SHA256withRSA` with no OID stays **unclassified** rather than
guessed. `TestEveryCatalogueAlgorithmIsClassified` makes it impossible to add a catalogue algorithm
without its evidence.

Verdicts are written to each algorithm component as `cipherhorizon:pqc:*` properties (status, rationale,
matched-by, one `basis` per citation). A verdict is about the *algorithm*; the finding's `ProvidedBy`
shows which packages make it available, which is capability, not use.

## Output

Deterministic for a given input: components sorted by bom-ref, edges sorted, and the clock, serial number
and hostname injectable. `metadata` records the tool, an `operations` lifecycle and the host as the subject
component. Writes to a file are atomic (temp file + rename).

## Active TLS assessment (`internal/tlsprobe`)

A second, network-facing source of findings next to the host collectors: `wire` (own ClientHello builder and
server-flight parsers, fuzzed), `registry` (cipher suites and groups generated from IANA), `testserver`
(hermetic servers for tests) and the prober itself. It reports **observations with evidence** (a ServerHello,
an alert, a closed connection, or "inconclusive") and leaves judging them to the evaluation layer. Details,
method and limits: [tls-scanning.md](tls-scanning.md).

## Roadmap

Done: host inventory (apt), CBOM 1.6 builder, cited PQC algorithm verdicts, TLS probe engine (M1).

Next: cited evaluation rules, PQC-readiness and grading, CBOM `protocol`/`certificate` assets and an HTML
report (M2); listener discovery and the agent daemon (M3); the ingest server and store (M4); the web UI (M5).
Later: STARTTLS and SSH probing, drift/alerts, CycloneDX 1.7, more collectors.
