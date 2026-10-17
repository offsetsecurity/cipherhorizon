# AUDIT-TLS-CBOM-001 · Remote TLS CBOM: accuracy, completeness, standards

Status: Phases A to D done 2026-10-18, on top of 0.2.0 (`4b19bc9`). Phase A is §1 to §6; Phases B to D
(remediation, verification, final report) are §7 and §8.

**Brief:** the owner's "Remote TLS CBOM Accuracy, Completeness and Standards Compliance Audit". Every claim below
was checked against the code, its tests and a generated CBOM. Nothing was taken from the brief on trust.
**Earlier work:** [CBOM-REVIEW-002](../product/CBOM-REVIEW-002-oids-and-completeness.md) (fixed in 0.2.0). Findings
it already closed are listed in §4 as *no longer applicable*.

## 1. The pipeline, stage by stage

| # | Stage | Where | What it produces |
|---|---|---|---|
| 1 | Target and connection | `internal/tlsprobe/scan.go` `Scan`; `probe.go`; `starttls.go`; the server's address guard `internal/server/guard.go` | One resolved address probed; SNI for names; STARTTLS for 7 protocols |
| 2 | Versions and suites | `scan.go` (protocols, `enumerateLegacy`, `enumerateTLS13`); `wire/` own hellos; `registry/suites_gen.go` (IANA CSV, generated, checksummed) | `Report.Protocols` (with evidence: server-hello, alert, closed, inconclusive), `Report.Suites` with the registry properties (Kx, Auth, Cipher, KeyBits, Mode, MAC) |
| 3 | Groups and signature schemes | `scan.go` (HRR-based TLS 1.3 groups, TLS 1.2 curves), `signatures.go` | `Report.Groups` (PQ, hybrid, obsolete), `Report.DH`, `Report.Signatures` (accepted schemes, control-checked) |
| 4 | Certificate retrieval | `certs.go` `fetchCertificates` (Go `crypto/tls`, plus ECDSA-only and RSA-only TLS 1.2, plus no-SNI) | `Report.Certificates[]` (source, chain as served, staple, SCTs), `Report.Negotiated` (version, suite, group via `ConnectionState.CurveID`) |
| 5 | Certificate parsing | `internal/certinfo/certinfo.go` `Describe`, `describeSignature`, `keyName` | `CertInfo`: subject, issuer, serial, SAN, validity, SHA-256, SPKI SHA-256, key (algorithm, **OID**, bits, curve, RSA exponent), signature (**name, OID**), KU, EKU, basic and name constraints, policies, AIA, CRL DP, must-staple, embedded SCTs |
| 6 | Chain processing | `tlsprobe` keeps the chain **as served**; trust is decided in evaluation (`internal/eval`, `internal/pki`) | Chain order and roles; trust, name match, OCSP and CT are evaluation facts |
| 7 | Normalisation | `internal/algo/catalogue.go` (cited OIDs), `tlscbom.go` `cipherCatalogueID`, `kxCatalogueID`, `authCatalogueID`, `groupCatalogueID`, `sigCatalogueID`; `cbom/certificate.go` `sigVariants`, `keyAlgorithm` | Catalogue IDs and derived variants (RSA-2048, ECDSA-P256, ecdsa-with-SHA256) |
| 8 | Evidence | `tlscbom.go` `observedEvidence` (one identity method, technique `other`, confidence 1.0) | The same "observed" evidence on every component |
| 9 | Capability derivation | `internal/pqc` (rules by OID, arc, exact name; cited); `markNegotiated` | `pqc:status` with basis; `negotiated` flags |
| 10 | Graph | `tlscbom.FromTLSReport`, `cbom.Build` | endpoint → protocol → algorithms; endpoint → certificate → key → algorithm; dependencies |
| 11 | Serialisation | `cbom/build.go` (1.6 model), `cbom/spec17.go` `To17`, validated by `schematest` against the vendored 1.6 and 1.7 schemas | JSON, 1.7 by default (`--spec 1.6`) |
| 12 | Output | `internal/app` `tls scan --cbom`; server `GET /api/v1/assets/{id}/cbom`, `/inventory/cbom` | CLI stdout; downloads |

## 2. Method

1. Read every function in the table above.
2. Built 0.2.0 and generated CBOMs from demo-targets:
   - 9440: hybrid, ECDSA P-256;
   - 9443: SSLv3, RC4, 3DES, NULL, export, anonymous;
   - 9448: private CA chain;
   - 9458 and 9459: ML-DSA-65, alone and with ECDSA;
   - SSH 9460 to 9464, for the shared builders.
3. Compared each CBOM with the same scan's `--json` report: every fact the scanner holds was looked for in the CBOM.
4. Checked identifiers against their RFCs and IANA (RFC 5280, 5480, 5758, 8017, 8103, 8410, 8446, IANA TLS
   parameters) and fields against the vendored CycloneDX 1.6 and 1.7 schemas and `cryptography-defs.schema.json`.

## 3. Findings (traceability matrix)

Severity is what a CBOM consumer loses: **High** means a wrong or lost identifier or claim; **Medium** a gap a
consumer would expect filled; **Low** a refinement.

| ID | Sev | Where (file · function) | Current behaviour | Expected | Reproduction (test to add) | Remediation |
|---|---|---|---|---|---|---|
| **A-1** | High | `cbom/certificate.go` · `signatureAlgorithm`; `certinfo` · `describeSignature` | An unknown signature OID becomes the name `unknown (1.2.3…)`; `emit` finds no catalogue entry and the certificate gets **no signature reference at all**. The OID the parser read is dropped silently. | The certificate references an algorithm component carrying the exact OID, marked unclassified, with no family guessed. | `TestUnknownCertificateSignatureOIDIsKept`: a certificate signed with a private-arc OID | Pass the OID into `CertFacts`; emit `crypto/algorithm/oid-<oid>` named by the OID, `pqc:unclassified-reason`, and a documented `cipherhorizon:identifier-status = unrecognised` |
| **A-2** | High | `cbom/certificate.go` · `keyAlgorithm` | A key whose algorithm the program cannot name gets **no key component**: the certificate loses `subjectPublicKeyRef`, and the SPKI OID the parser read is dropped. | A key component with its size if known, pointing at an unclassified algorithm that keeps the SPKI OID. | `TestUnknownKeyAlgorithmIsKept` | As A-1, for `KeyInfo.OID` |
| **A-3** | High | `certinfo` · `describeSignature`; `cbom` | RSASSA-PSS is identified (`RSASSA-PSS`, 1.2.840.113549.1.1.10), but its **parameters are not parsed**. Hash, MGF, MGF hash, salt length and trailer are unknown, so two PSS certificates with different hashes look the same. | The parameters decoded per RFC 8017 A.2.3 and stated; nothing assumed when absent (absent means the RFC's defaults: SHA-1, MGF1-SHA-1, salt 20, trailer 1, stated as defaults). | `TestRSASSAPSSParametersAreDecoded`: SHA-256/salt 32, SHA-384/salt 48, SHA-512/salt 64, and absent parameters | Decode the AlgorithmIdentifier parameters from the DER (bounded parser); record `cipherhorizon:signature-parameters` on the certificate (there is no CycloneDX field for them) |
| **A-4** | High | `tlscbom.go` · `protocolAsset`, `groupCatalogueID` | An accepted group with no catalogue entry (brainpool, binary curves, GOST, `curveSM2`, draft hybrids other than the obsolete Kyber pair) **vanishes**. Suites keep their name and IANA identifier; groups have no such fallback. | Every accepted group is recorded with its name and IANA code point, even when the catalogue has no algorithm for it. | `TestUnknownGroupsKeepTheirIdentifier`: `brainpoolP256r1tls13`, `sect571r1`, `GC256A` | Record accepted groups on the protocol (`cipherhorizon:accepted-groups` = `name(0xNNNN)`, …), next to the components the known ones already get |
| **A-5** | High | `tlscbom.go` · `observedEvidence` | Every component carries the same identity evidence: technique `other`, **confidence 1.0**, "observed". But many claims are different in kind. A suite's algorithms are **derived** from the IANA registry's description of an **accepted** suite. A negotiated flag comes from **one** handshake. Nothing says "not tested". | A defined evidence state per component (observed / accepted / negotiated / derived), and confidence only with a stated method. | `TestEvidenceStatesSayHowEachFactWasLearned` | Add `cipherhorizon:evidence` = `observed` · `accepted` · `negotiated` · `derived`, with `cipherhorizon:evidence-basis` (the probe or the registry and its retrieval date). Keep confidence 1.0, but define it (docs): it is used only for facts observed on the wire or derived by a fixed cited mapping, and never as a probability |
| **A-6** | High | `tlscbom.go` · `FromTLSReport` | The report's `Stages` (done, skipped with reason, inconclusive parts) and `Incomplete` **do not reach the CBOM**. A consumer cannot tell "the server does not accept X" from "the scanner did not test X" or "the probe timed out". | Coverage stated in the document. | `TestCBOMStatesWhatWasNotTested`: a report with the groups stage inconclusive and HTTP skipped | `metadata.properties`: `cipherhorizon:coverage:<stage>` = `done` · `not-tested (<reason>)` · `inconclusive (<parts>)`, and `cipherhorizon:scan-complete` = `true`/`false` |
| **A-7** | Medium | `tlscbom.go` · `certExtensions` | Facts the report holds but the CBOM does not write, though 1.7 names them as common extensions: **subjectAlternativeName** (DNS and IP SANs), **authorityInformationAccess** (OCSP and caIssuers URLs), **crlDistributionPoints**. Key and certificate identifiers are not parsed at all: **authorityKeyIdentifier**, **subjectKeyIdentifier**. | Each written by its 1.7 common name; AKI/SKI parsed and written as hex. | `TestCertificateExtensionsCarryEveryRecordedFact` | Extend `certExtensions` and `certinfo` (AKI, SKI) |
| **A-8** | Medium | `tlscbom.go`; `certinfo` | Extensions the parser does not decode (name constraints, TLS Feature / must-staple, and any unknown OID) are **not listed**. Name constraints and must-staple *are* decoded, but have no 1.7 common name. | Every extension listed by OID, with critical flag. Decoded ones get their value; others get `unsupported` and are never fabricated. | `TestUnknownCertificateExtensionsAreListed` | 1.7 `certificateExtensions` with `customExtensionName` = the OID (the schema's own escape for non-common extensions) and value; recorded in `certinfo` as `Extensions []{OID, Critical, Decoded}` |
| **A-9** | Medium | `tlscbom.go` · `certificateAsset` | A certificate's **source** (which handshake returned it: default, ECDSA-only, RSA-only, **no-SNI**) is not recorded. A no-SNI chain that differs from the SNI chain appears as if the endpoint sent it to every client. | Each certificate says where it was seen. | `TestCertificateSaysWhichHandshakeReturnedIt` | `cipherhorizon:seen-in` = sources (comma separated), and `cipherhorizon:no-sni` = `true` for the no-SNI chain |
| **A-10** | Medium | `tlscbom.go` · `certificateAssets` | A chain is not linked: an intermediate does not depend on, or name, the certificate that issued it, so a consumer cannot rebuild the **served** chain from the CBOM. | Leaf → issuer edges for the chain as served (never a chain built from a trust store). | `TestServedChainIsLinked` | `cipherhorizon:issued-by` = the issuer's bom-ref when the next certificate in the served chain is its issuer (subject/issuer and signature check already done in `pki`) |
| **A-11** | Medium | `tlscbom.go`; `algo` | The TLS 1.2 suite **MAC** (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-MD5) and the TLS 1.3 suite **hash** (SHA-256 or SHA-384 for HKDF) are not referenced. The suite name says it (CBOM-REVIEW-002 C-8). | The suite references them, derived (A-5). | `TestSuiteReferencesItsMACOrHash` | Catalogue `HMAC-SHA-384` (RFC 8018 1.2.840.113549.2.10); map `MAC`, and the TLS 1.3 suite hash to `SHA-256`/`SHA-384` |
| **A-12** | Medium | `cbom/certificate.go` | The SPKI SHA-256 and the RSA public exponent are in the report, not in the CBOM. 1.7 has `relatedCryptoMaterialProperties.fingerprint`. | Key fingerprint (1.7 field) and exponent (property). | `TestPublicKeyCarriesItsFingerprintAndExponent` | Write `fingerprint` in 1.7; `cipherhorizon:rsa-exponent` |
| **A-13** | Low | `tlscbom.go` · `signatureAlgorithms` | The TLS 1.3 signature schemes are listed by name on the protocol, but their IANA code points are not, and RSA-PSS schemes map to the RSA family. | Name and code point each, kept apart from certificate signature algorithms. | extend `TestEndpointCBOMListsAcceptedSignatureAlgorithms` | `accepted-signature-schemes` = `name(0xNNNN)` |
| **A-14** | Low | `tlscbom.go` · `markNegotiated` | `negotiated` is set on algorithm components shared across versions (AES-128-GCM in TLS 1.2 and 1.3). The protocol says which version, but the flag alone does not. | The flag says which version negotiated it. | `TestNegotiatedFlagNamesTheVersion` | Value `true` becomes the version (`TLSv1.3`). Kept compatible: any non-empty value means negotiated, and the docs say so |
| **A-15** | Low | `cbom/build.go` | Repeated scans of an unchanged server produce the same components, but `serialNumber` and `timestamp` differ (by design). Component order is sorted (good). | Determinism of everything but serial and time, tested. | `TestCBOMIsDeterministicApartFromSerialAndTime` | Test only |
| **A-16** | Low | `tlscbom.go` · `hybridComponent` | Hybrids do not point at their parts (CBOM-REVIEW-002 C-7). | Unchanged until CycloneDX models combiners. | none | **Not fixing**, documented |

## 4. Brief items checked and found not present, or no longer applicable

| Brief item | Verdict | Why |
|---|---|---|
| "Certificate signature algorithms only at RSA/ECDSA family level" | **Fixed in 0.2.0** | Exact variant with OID (CBOM-REVIEW-002 C-3); A-1 and A-3 remain |
| "TLS 1.2 ECDH/DH only at family level" | **Partly fixed in 0.2.0, otherwise correct** | Accepted named curves are `ECDH-P256/384/521`/`X448`/`X25519`. The negotiated curve comes from `ConnectionState.CurveID` (TLS 1.2 too) and is flagged. FFDHE groups are `DH`, with `Report.DH.PrimeBits` in the report. A suite's `ECDH`/`DH` component is the key-exchange *method* the suite names: correct, and it will be marked *derived* (A-5) |
| "TLS 1.3 suite confused with group" | **Not present** | Suites (`TLS_AES_128_GCM_SHA256`) reference only the AEAD; groups are separate components; the negotiated suite and group are separate properties |
| "Certificate signature confused with TLS signature scheme" | **Not present** | Separate: the certificate's `signatureAlgorithmRef` versus the protocol's `accepted-signature-schemes`. A-13 refines the latter |
| "Hybrid success implies whole connection PQ / PQ certificate" | **Not present** | The readiness level separates key exchange (L3) and authentication (L4); the CBOM states only what was accepted and negotiated |
| "Unobserved intermediate reported as sent" | **Not present** | The chain is kept as served; trust-store chains live in evaluation only. A-9 covers the no-SNI chain |
| "OCSP, revocation and trust conflated" | **Not present in the CBOM** | None of them is written as a CBOM fact; they are evaluation results (docs/cbom-model.md "Not in the CBOM") |
| "1.6 vs 1.7 inconsistency" | **Fixed in 0.2.0** | docs/tls-scanning.md said 1.6; it now says 1.7 by default. CLI, server and docs agree |
| "Duplicate components" | **Not present** | Components are keyed by bom-ref (`emit` and `emitAsset` index); certificates dedupe by SHA-256 |
| "Dependency direction" | **Correct** | endpoint → protocol → algorithm; endpoint → certificate → key → algorithm |
| "Confidence percentages" | **See A-5** | Only 1.0 is used; the methodology will be written down |
| Repeated-scan determinism | **Correct**, untested | A-15 adds the test |

## 5. Coverage audit (scanner vs catalogue vs CBOM)

| Scanner value | Count in registry | In the CBOM as an algorithm | Otherwise |
|---|---|---|---|
| Suite ciphers | AES 124, ChaCha20 8, 3DES 20, RC4 18, DES 16, RC2 3, NULL 23, CAMELLIA 66, ARIA 54, SEED 6, IDEA 3, SM4 2, GOST/KUZNYECHIK/MAGMA 7, AEGIS/ASCON 4 | AES, ChaCha20, 3DES, RC4, DES, RC2 | Others: suite name and IANA code point only (no catalogue entry, no cited verdict) |
| Suite key exchange / auth | RSA, DH(E), ECDH(E), DSS, ECDSA, PSK, SRP, anon, … | RSA, DH, ECDH, DSA, ECDSA | PSK, SRP: name only |
| Suite MAC / hash | SHA1, SHA256, SHA384, MD5, AEAD | none (A-11) | name only |
| Groups | 60 registry names | x25519, x448, secp256r1/384r1/521r1, ffdhe*, ML-KEM-512/768/1024, the 3 RFC 10024 hybrids, obsolete Kyber drafts (marked) | **Others dropped (A-4)** |
| Signature schemes (TLS 1.3) | 15 offered | ECDSA, RSA (PSS too), Ed25519, Ed448, ML-DSA-44/65/87 | names in a property (A-13) |
| Certificate signatures | Go's set plus ML-DSA, SLH-DSA by OID | exact variants (13), ML-DSA, SLH-DSA, Ed25519, Ed448 | **Unknown OIDs dropped (A-1)**; DSA-SHA256 at family |
| Certificate keys | RSA, ECDSA (P-256/384/521), Ed25519, ML-DSA, … | size and curve variants | **Unknown dropped (A-2)**; other curves at family |

## 6. Phase B: remediation plan, in the brief's priority order

| Order | Findings | Work |
|---|---|---|
| 1. Lost identifiers | A-1, A-2, A-4, A-13 | Keep every OID and IANA code point the scanner read |
| 2. Handshake interpretation | A-5, A-6, A-14 | Evidence states, coverage, versioned negotiated flag |
| 3. Key exchange and signature detail | A-3, A-11, A-12 | PSS parameters; suite MAC and hash; key fingerprint and exponent |
| 4. Chain and extensions | A-7, A-8, A-9, A-10 | SAN, AIA, CRL DP, AKI, SKI, unknown extensions by OID, sources, issued-by |
| 5. Determinism | A-15 | Test |
| 6. Docs | all | cbom-model.md: the evidence states, coverage properties, every new property; CHANGELOG |

**Constraints kept:**
- No new CycloneDX fields: every extension is a `cipherhorizon:*` property, or a schema-defined field such as 1.7
  `customExtensionName`, `fingerprint` or `serialNumber`.
- No CLI change.
- Additive to the JSON shape: new report fields are optional, and `tls-report/2` keeps its meaning.

**Integration suite (brief §9):** the existing hermetic servers (`internal/tlsprobe/testserver`, `pkitest`) and
demo-targets already cover cases 1, 2, 4, 5, 9, 11 to 14 and 16. Phase B adds fixtures for 6, 7 (PSS variants),
8 (Ed25519 and Ed448), 10 (unknown extensions), 15 (two virtual hosts on one address, by SNI), 17 (unknown
algorithms) and 18 (malformed responses: covered by the wire fuzzers; one end-to-end case is added). Case 3
(FFDHE): Go's TLS server has no finite-field DH, so it uses the existing legacy test server, or is recorded as
not run.

## 7. Phases B and C: what was changed, and how it was verified

All of §3 except A-16 is fixed on branch `fix/tls-cbom-audit`. Every change is additive:
- new components;
- `cipherhorizon:*` properties, each documented in docs/cbom-model.md;
- CycloneDX 1.7 fields the schema itself defines (`customExtensionName`, `fingerprint`).

No CLI flag changed. `tls-report/2` gains optional fields only.

| ID | Fix | Test (all pass) |
|---|---|---|
| A-1, A-2 | Unknown signature and key OIDs are kept as `crypto/algorithm/oid-<oid>` components, named by the OID, with `identifier-status = unrecognised` and no family. A value that is not a dotted OID is never used. | `TestUnknownCertificateSignatureOIDIsKept`, `TestUnknownKeyAlgorithmIsKept` |
| A-3 | `certinfo/params.go` decodes RSASSA-PSS-params (RFC 8017 A.2.3), marking defaults; written as `signature-parameters`. | `TestRSASSAPSSParametersAreDecoded` (SHA-256/384/512, from certificates made by crypto/x509) |
| A-4, A-13 | `accepted-groups` and `accepted-signature-schemes-iana` with IANA code points. | `TestUnknownGroupsKeepTheirIdentifier`, `TestSignatureSchemesCarryTheirCodePoints` |
| A-5, A-14 | `evidence` on every component; `negotiated-in`. | `TestEvidenceStatesSayHowEachFactWasLearned`, `TestNegotiatedFlagNamesTheVersion` |
| A-6 | `tlscbom.Coverage`, written by the CLI and the server's endpoint CBOM. | `TestCBOMStatesWhatWasNotTested` |
| A-7, A-8 | SAN, AIA, CRL DP, AKI, SKI and SCT presence by 1.7 common name; every other extension by OID as a custom extension. | `TestCertificateExtensionsCarryEveryRecordedFact` |
| A-9, A-10 | `seen-in`, `no-sni`, `issued-by` (served chain only). | `TestServedChainIsLinkedAndEachCertificateSaysWhereItWasSeen` |
| A-11 | `HMAC-SHA-384` catalogued (RFC 8018); suites reference their MAC, or their AEAD hash, from the IANA registry entry. | `TestSuiteReferencesItsMACOrHash` |
| A-12 | `key-fingerprint-sha256` (the 1.7 `fingerprint`), `rsa-exponent`. | in `TestCertificateExtensionsCarryEveryRecordedFact` |
| A-15 | none needed | `TestCBOMIsDeterministicApartFromSerialAndTime` |
| End to end | Real TLS servers on loopback serve an RSASSA-PSS certificate, an Ed25519 certificate, and a two-certificate chain with an unknown extension. They are scanned by `tlsprobe.Scan`, built into a CBOM and validated against the 1.7 schema. | `TestEndToEndCertificatesReachTheCBOMAsServed` |

### Independent comparison (demo-targets, OpenSSL 3)

| Fact | `openssl s_client` / `openssl x509 -text` | CBOM |
|---|---|---|
| 9440 certificate signature | `ecdsa-with-SHA256` | `ecdsa-with-SHA256` @ 1.2.840.10045.4.3.2 |
| 9440 key | `id-ecPublicKey`, `prime256v1` (P-256), 256 bit | `ECDSA-P256` @ 1.2.840.10045.2.1, `ellipticCurve` secg/secp256r1, size 256 |
| 9440 serial | `0x18df6c9bf7a40b58` | `serialNumber` `18df6c9bf7a40b58` |
| 9440 negotiated | `X25519MLKEM768`, `TLS_AES_128_GCM_SHA256`, TLSv1.3 | `negotiated-group` X25519MLKEM768, `negotiated-suite` TLS_AES_128_GCM_SHA256; the X25519MLKEM768 and AES-128-GCM components `negotiated-in` TLSv1.3 |
| 9448 chain | leaf issued by `Demo Corp Issuing CA 1` (sent); root not sent | leaf `issued-by` the intermediate; the intermediate has no `issued-by` (its issuer was not sent) |

### Commands and results

| Command | Result |
|---|---|
| `go test ./...` | 44 of 44 packages pass |
| `golangci-lint run ./...`, and with `GOOS=linux` | 0 issues, 0 issues |
| `cipherhorizon tls scan --cbom` against demo-targets 9440, 9443, 9448, 9458, 9459 | all parse; every test above checks schema validity |
| `testing/e2e/journey.mjs` (CI setup) | 214 passed, 0 failed |

## 8. Phase D: before and after, limits, assessment

**Before (0.1.1, 9443, SSLv3 with 3DES and RC4).** Three components in all (DH, RSA, SSLv3). A suite:

```json
{"name":"TLS_RSA_WITH_3DES_EDE_CBC_SHA","algorithms":["crypto/algorithm/rsa@1.2.840.113549.1.1.1","crypto/algorithm/rsa@1.2.840.113549.1.1.1"],"identifiers":["0x000A"]}
```

**After.** Seven components. The same suite:

```json
{"name":"TLS_RSA_WITH_3DES_EDE_CBC_SHA","algorithms":["crypto/algorithm/3des","crypto/algorithm/rsa@1.2.840.113549.1.1.1","crypto/algorithm/hmac-sha-1@1.2.840.113549.2.7"],"identifiers":["0x000A"]}
```

The 3DES component carries `classical-status` and `classical-basis` (NIST's TDEA deprecation) and
`evidence = derived`.

**Before (0.1.1, 9440).**
- The certificate references `crypto/algorithm/ecdsa`, a family with no OID.
- No serial or fingerprint field.
- secp256r1 is absent, though the server accepts it.
- Nothing says how anything was learned, or what was not tested.

**After.**
- The certificate references `ecdsa-with-SHA256` @ 1.2.840.10045.4.3.2, and carries `serialNumber`, `fingerprint`,
  `subjectAlternativeName`, `seen-in = tls-default, tls1.2-ecdsa` and `evidence = observed`.
- TLS 1.3 lists `accepted-groups = X25519MLKEM768 (0x11EC), x25519 (0x001D), secp256r1 (0x0017)`.
- `ECDH-P256` is a component with `evidence = accepted`.
- The metadata states coverage per stage, for example `coverage:http = not applicable: the service did not answer
  with an HTTP response`.

**Remaining known limits.** Each is stated in docs/cbom-model.md.
- **A-16:** hybrids do not point at their parts. There is no CycloneDX relation for a combiner.
- Ciphers with no catalogue entry (Camellia, ARIA, SEED, IDEA, SM4, GOST) and PSK/SRP key exchange are named by their
  suite (name and IANA code point) only.
- SAN types other than DNS and IP are not recorded.
- An SSLv3-only server's certificate is not fetched (Go's TLS client cannot speak SSLv3). Coverage says
  `certificates` was not reached.
- A remote scan sees what the server offers and one client's handshake. It cannot see what the server uses with
  other clients, or internally, and the CBOM claims neither.
- **Not run:** the FFDHE case of the brief's suite. Go's TLS server has no finite-field DH. The legacy test server
  exercises DHE suites and `Report.DH`; FFDHE groups map to `DH`.

**Compatibility.**
- Consumers that count components or properties will see more of both.
- `negotiated` keeps its value `true`.
- Nothing was renamed or removed. The one changed value is a suite's `algorithms` list, which now also names its MAC or hash.

**Assessment.** The remote TLS CBOM now records three things: what the scanner observed, by the identifiers it read
(OIDs and IANA code points, unknown ones included); how each fact was learned; and what the scan did not cover. Its
remaining gaps are named, with their reasons. Every claim in this section is backed by a test above, or by the
comparison with OpenSSL.
