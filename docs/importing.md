# Importing CBOMs from other tools

CipherHorizon reads CycloneDX **1.6 and 1.7** CBOMs made by other tools (IBM CBOMkit, CBOM-Lens, cdxgen, CBOMkit Theia and others) and shows them next to what its own scanner and collector saw. Earlier CycloneDX versions have no cryptographic assets and are refused.

```bash
cipherhorizon import --server http://127.0.0.1:8080 --new-system "billing-api" billing.cbom.json
cipherhorizon import --system 12 scan.json        # attach to an existing system
```

The token is the server's automation token (`--token` or `CIPHERHORIZON_TOKEN`; it acts as an analyst, see ADR-0018). The same operation is `POST /api/v1/imports?system=ID` (or `newSystem=NAME`) with the document as the body.

## You say which system it describes

Third-party documents often name no subject, or name the tool itself. So **the document never decides where its data goes**: you name the system, and what the document claims about itself is recorded and shown, nothing more.

## What it is read as

| Producer | Read as |
|---|---|
| Source scanners (CBOMkit, cdxgen) | **capable, from source**: what the code references, not what is deployed |
| Host and network scanners (CBOM-Lens; CipherHorizon's own output uploaded this way) | **present**; a certificate as held |
| Anything else | present, at the weakest reading |

Nothing imported is ever read as *bound*, *loaded* or *exercised*, and an import is **never** treated as first-party: a scan or collector fact is not replaced by an imported one. If an import disagrees (say, a different key size for a certificate a scan observed), the scan's value stays, and the disagreement is listed on the import and shown next to it.

## What is kept and what is counted

Everything the tool can model becomes observations (algorithms, certificates with key size, TLS protocols and suites, software). Everything else is **counted by reason** on the import, never silently dropped: for example `related crypto material: password (not modelled)` or `certificate without a SHA-256 hash`. Private keys, secret keys, passwords and tokens found by another tool are counted and **not stored in the graph**.

## Provenance, withdrawal, repeats

Each import records the producer the document claims, its SHA-256, size, time and who sent it. Importing the same file again changes nothing. `POST /api/v1/imports/{id}/withdraw` removes what it contributed and keeps the record. Limits: 32 MiB, 64 levels of nesting, 1,000,000 values, 200,000 components; a document over a limit is refused with the reason and nothing is stored.
