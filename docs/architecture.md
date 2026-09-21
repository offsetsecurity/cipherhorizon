# Architecture

```
 host filesystem ──► collector plugins ──► scan.Run ──► cbom.Build ──► pqc ──► cbom.Encode ──► stdout / file
 (os.DirFS(root))    (self-registered)     timeout,      vocabulary,    cited     CycloneDX
                                           panic-safe,   dedupe, edges  verdicts  1.6 JSON
                                           partial results
```

The core knows only the `collector.Collector` interface. One-shot mode and the future daemon
mode call `scan.Run` identically; only the trigger differs.

## The collector contract (`internal/collector`)

```go
type Collector interface {
    Metadata() PluginInfo                                  // name, version, source type
    Detect(ctx context.Context) (bool, error)              // is this ecosystem present?
    Collect(ctx context.Context) ([]CryptoAsset, error)    // findings, CycloneDX-shaped
}
```

Deliberate refinements over the bare three-method sketch:

- **`context.Context`** on `Detect` and `Collect`, so a daemon can bound a scan and cancel a hung read.
- **`Detect` has three outcomes**: `(true,nil)` present; `(false,nil)` absent, which is normal (the apt
  plugin on an RPM host) and skips silently; `(false,err)` could not tell, which is recorded as a failure.
- **Partial results are kept.** A non-nil error from `Collect` means the inventory is *incomplete*; any
  assets returned with it are still used. The runner reports `ok | skipped | partial | failed` per
  plugin, and the CLI exits `2` when anything was partial or failed.
- **Plugins read the host only through `Host.FS` (an `fs.FS`).** Natively that is `os.DirFS("/")`; in a
  container with the host mounted it is `os.DirFS("/host")`; in tests it is `fstest.MapFS`.
- **Registration is by explicit name**, and the registry checks `Metadata().Name` matches it.
- **Sequential, not concurrent.** Simple and deterministic; collectors need not be goroutine-safe.

A `CryptoAsset` is a `cyclonedx.Component` plus `Provides` / `DependsOn` edges (bom-refs). The same
component may be emitted by several plugins; the builder merges identical duplicates and rejects
conflicting ones.

## Evidence, not heuristics

**A package proves capability, not use.** `libssl3 3.0.13` installed means the host *can* do RSA; it does
not mean anything on the host *does*. The apt collector therefore works in two tiers:

1. **Inventory** (a fact from dpkg): every recognised crypto package appears as a `library` or
   `application` component with its version and Package URL.
2. **Capability** (a curated claim): only families with a citable mapping get `provides` edges to
   algorithm assets, gated by upstream version where the standard says so (for example OpenSSL ≥ 3.5 for
   ML-KEM / ML-DSA / SLH-DSA). The citations travel with the component as `cbom-scan:capability-basis`
   properties, and the component is marked `cbom-scan:evidence = installed-package-capability`.

Families with no citable mapping are inventoried and nothing more. Under-claiming is the rule; an unparseable
package version drops the gated capabilities rather than assuming them.

## The algorithm catalogue and the vocabulary layer (`internal/algo`, `internal/cbom`)

CycloneDX enumerations are closed: one out-of-vocabulary value invalidates the whole document. So:

- Plugins mint algorithm components only through `algo.MustGet(id)`, a total lookup table. Every field
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

Verdicts are written to each algorithm component as `cbom-scan:pqc:*` properties (status, rationale,
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
