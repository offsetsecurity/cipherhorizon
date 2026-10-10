# Exporting

What CipherHorizon writes out, in which standard shape, and what it does not claim. Requirements: PRD-003 REQ-EXP-1, 2, 3, 5, 6.

| Export | Where | Format |
|---|---|---|
| CBOM of a scan | `GET /api/v1/scans/{id}/cbom[?spec=1.6\|1.7][&download=1]`, `cipherhorizon tls scan --cbom [--spec]` | CycloneDX **1.7** (default) or 1.6 |
| CBOM of a host | `cipherhorizon-collector run [--spec]`, `cipherhorizon run [--spec]` | CycloneDX 1.7 (default) or 1.6 |
| A host snapshot as uploaded | `GET /api/v1/hosts/{id}/snapshots/{snapshotId}/cbom` | exactly what the collector sent; never converted |
| M-23-02 structure per system | `GET /api/v1/systems/{id}/m2302.json`, `.../m2302.csv` | JSON (`cipherhorizon-m2302/1`) and CSV |
| Systems metadata | `GET /api/v1/systems/export.csv` | CSV, editable and re-importable |
| Endpoints and results | `GET /api/v1/export/assets.csv` | CSV |
| The API itself | `GET /api/v1/openapi.json` | OpenAPI 3.1 |

Every route needs the token when the server was started with one (a test walks the real route table to prove it, so a route added later cannot skip it). An export contains only what the store holds: host names as the collector recorded them (ADR-0009 redaction happens at collection with `--redact-host`), certificate subjects and issuers (public), and system metadata a person entered. It contains no file paths outside certificate locations, no user names and no key material; the store has no field that could hold key material.

## CycloneDX 1.7

The default is 1.7; `--spec 1.6` (or `output.spec: "1.6"` in the configuration) writes 1.6 for consumers that have not moved. Any other value is refused with the two valid ones named, never silently defaulted. Both versions are validated in tests against the vendored schema of that version (`internal/cdxschema`), with negative controls: a 1.7-only document is rejected by the 1.6 schema, and an invented algorithm family is rejected by the 1.7 one.

One internal model is built and converted at the last step. The conversion does what 1.7 asks and nothing more:

- A construct 1.7 deprecates is **replaced**, not emitted beside its replacement. `certificateProperties.subjectPublicKeyRef` and `signatureAlgorithmRef`, and `relatedCryptoMaterialProperties.algorithmRef`, become `relatedCryptographicAssets` entries; `algorithmProperties.curve` becomes `ellipticCurve`, a name from the specification's registry (`secg/secp256r1`).
- `algorithmFamily` is set only where the registry has a family for the algorithm (table in `internal/cbom/spec17.go`, kept in step with the catalogue and the registry by a test that fails if either changes).
- Where the registry has no name for something, the older field is kept and nothing is invented. A curve the registry lacks stays in `curve`.

### Where the registry has no family

Of the 52 catalogue algorithms, these have no single registry family and are emitted **without** `algorithmFamily`, on purpose:

| Catalogue entry | Why |
|---|---|
| RSA | The registry names RSA by scheme (RSAES-OAEP, RSAES-PKCS1, RSASSA-PKCS1, RSASSA-PSS); a bare RSA key has none |
| ChaCha20-Poly1305 | An AEAD construction of two registry families (ChaCha20 and Poly1305) |
| X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 | TLS hybrid groups of two families (ECDH and ML-KEM) |

The list is printed by `cbom.Registry17Gaps()`; adding a catalogue entry without either a family or a stated reason fails `TestRegistryMappingIsCompleteAndValid`.

### Importing 1.7

The importer reads both the deprecated references and 1.7's `relatedCryptographicAssets`, so a 1.7 document from another tool yields the same certificate facts (key size, key algorithm, signature algorithm) as a 1.6 one, and this product's own 1.7 output re-imports without losing them.

## M-23-02 structure

OMB M-23-02 Section II asks for nine data items per cryptographic system. The CISA strategy for automated PQC discovery says only items 4, 5 and 6 can be collected by a tool. The export has all nine, each **provided** or **not provided**, with where the value came from:

| Item | Content | Filled from |
|---|---|---|
| 1 | FISMA system identifier | operator: system field `fismaId` |
| 2 | FIPS 199 categorisation | operator: `fips199` |
| 3 | High value asset identifier | operator: `hvaId` |
| 4 | Quantum-vulnerable elements: algorithm, service provided, key length | evidence: current end-entity certificates whose key algorithm has a cited quantum-vulnerable verdict, and non-post-quantum key-exchange groups observed in a handshake |
| 5 | Software package and supplier | evidence: software entities observed; the supplier is **not** recorded by any sensor and each row says `unknown(...)` |
| 6 | Operating system and version | evidence: the operating system each of the system's machines reported in its last collector upload; not provided when none did |
| 7 | Hosting | operator: `hosting` and `hostingProvider` |
| 8 | Data lifecycle: how long the data must stay protected | operator: `dataLifetimeYears` (the kinds of data are not modelled) |
| 9 | Notes | operator: `notes` |

A row of item 4 carries an algorithm, the service (digital signatures, key establishment), and a key length in bits or `unknown(reason)`; a length is never guessed. An item marked *provided* with no rows means the sources this system has observed no quantum-vulnerable element, and says that this is not a statement about what they could not see. An item nobody has supplied is *not provided* and names the field to fill in.

The document states, and the tests assert, that this **supports the structure** and is **not a statement of compliance**. It is a reading of the CISA document, not of the memorandum's own text.

Known gaps in this version: the supplier in item 5, and the kinds of data in item 8. Certificates and TLS groups are the only sources of item 4; a host's libraries that merely *can* provide a vulnerable algorithm are capability, not use, and are not listed as elements.

CSV: one line per item, and one line per item 4 or item 5 row; every cell that could be read as a spreadsheet formula is prefixed so it is text.

## OpenAPI

`internal/server/openapi.json` is written by hand and served at `/api/v1/openapi.json`. Tests fail if a registered route has no entry, if an entry names a route that does not exist, if an operation lacks a summary, unique operation id, tags or responses, if a path placeholder is undeclared, and if any GET route answers a status its entry does not list. It documents parameters and status codes for every route; response bodies are described as objects, not field by field (the schemas of the larger bodies are a future addition), and the status codes of state-changing routes are documented but not yet checked by test.
