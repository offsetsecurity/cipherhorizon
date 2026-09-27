# Interoperability fixtures

**Synthetic.** Small documents written for this repository, modelled on the structure of what real
producers emit (IBM CBOMkit / sonar-cryptography, CBOM-Lens 1.7, CBOMkit Theia) and on the real
samples profiled in `docs/product/RESEARCH-003`. They are not copies: the licences of the real
samples are not all verified (PRD-003 OQ-5), so none is vendored.

To check against real documents, point `CIPHERHORIZON_INTEROP_DIR` at a directory of them; the
importer tests that read it are skipped otherwise.

| File | Modelled on | Notes |
|---|---|---|
| `cbomkit-like-1.6.json` | CBOMkit source scan | no subject; static-source evidence; a secret-key asset (counted, not modelled) |
| `cbomlens-like-1.7.json` | CBOM-Lens 1.7 | names itself "CBOM-Lens" as the metadata component; certificate with SHA-256 hash, key size through `subjectPublicKeyRef`; TLS suites with code points; a password asset; a certificate with no hash |
| `theia-like-1.6.json` | CBOMkit Theia | certificate identity only in the bom-ref (`@sha256:`) |
| `unknown-producer-1.6.json` | — | no tool metadata: read at the weakest level |
