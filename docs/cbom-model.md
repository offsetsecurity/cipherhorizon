# The CipherHorizon CBOM data model

What a CBOM from `cipherhorizon tls scan --cbom` (and the endpoint export in the UI) contains, what each part
means, and which parts are CycloneDX and which are CipherHorizon's own. A host inventory (`cipherhorizon run`)
uses the same model with a `host` subject and no TLS-specific parts.

## The graph

```
endpoint:host:port                       metadata.component (device)
 ├─ protocol/tls/1.3                     protocol            "the endpoint serves TLS 1.3"
 │    ├─ AES-128-GCM   ✓ negotiated      algorithm           a key-size-and-mode variant, own OID
 │    ├─ AES-256-GCM                     algorithm           accepted, not negotiated
 │    ├─ ChaCha20-Poly1305               algorithm
 │    ├─ X25519MLKEM768 ✓ negotiated     algorithm (combiner) a hybrid post-quantum group
 │    └─ X25519                          algorithm           accepted group, not negotiated
 ├─ protocol/tls/1.2
 │    └─ …
 └─ certificate (leaf)                   certificate         cipherhorizon:chain-role = leaf
      ├─ signature algorithm             algorithm           e.g. ECDSA
      └─ public key                      related-crypto-material (public-key, size)
           └─ ECDSA-P256                 algorithm           curve secp256r1
```

Every component carries CycloneDX identity **evidence** stating how it was observed (a ServerHello, a
HelloRetryRequest naming a group, a certificate presented in the handshake) at confidence 1.0: this builder
never emits an inferred or unobserved fact.

## What an edge means

The single most important rule for reading (or consuming) this document:

- **An edge below a protocol means the endpoint *accepts* it.** It comes from enumerating the server: offer a
  suite or group, see whether it is accepted. It is a capability, not a claim about traffic. That is why a TLS 1.2
  protocol can depend on `X25519` (the server accepts that group for 1.2) without anything having used it.
- **What was actually used is flagged, and only that.** One handshake is made the way a current Go TLS client
  makes it. The components that handshake used carry `cipherhorizon:negotiated = true`: the group, the
  negotiated suite's cipher variant and (up to TLS 1.2) its key exchange and authentication. The protocol
  carries `negotiated-suite` and `negotiated-group`. It is one client's view, not a statement about every
  client.
- The document states this itself in `metadata.properties` (`cipherhorizon:tls-graph`), so a consumer that
  ignores this page still gets it.

If nothing was negotiated (the handshake failed, or `--no-certs` skipped it) nothing is flagged: absence is not
asserted as an error.

## Precision: variants, keys, sizes

| Fact | Modelled as |
|---|---|
| **Host files** (`cipherhorizon run` on Windows) | a `library` or `application` per recognised file: `hashes` (SHA-256), a `pkg:generic` file-identity `purl`, `cipherhorizon:role` (`provider` or `consumer`), and `dependencies[].dependsOn` for links proven from the file's static import table (same directory; "could use"). Only a provider has `provides` edges. See ADR-0012. |
| **Native Windows providers** (`cipherhorizon run` on Windows, sensor `windows-cng`) | a `library` per registered CNG provider, key storage provider or legacy CSP: `cipherhorizon:provider-kind` (`cng`, `ksp`, `cng+ksp`, `csp`), `cipherhorizon:evidence` = `os-enumeration`, `cipherhorizon:native-algorithms`, `cipherhorizon:opened` for key storage providers, and `provides` edges with `cipherhorizon:provides-claim` = `capable-probed` (the system was asked; not use). See ADR-0013. |
| **Certificates a host holds** (sensor `cert-files`, Linux) | a `certificate` asset per distinct certificate (its `hashes` SHA-256 is its identity, and `crypto/certificate/<sha256>` its bom-ref), built by the same code as the TLS inventory so the two are identical for the same certificate: subject, issuer, validity, signature algorithm reference, and `subjectPublicKeyRef` to a public-key component with its `size` (and curve, through the algorithm it references). `evidence.occurrences` lists every place it was found; each occurrence's `additionalContext` is `privateKey=yes|no|unknown` (a key block was seen in the same file, or not, or it cannot be told). Properties: `cipherhorizon:cert:key-algorithm`, `key-bits`, `curve`, `signature-algorithm`, `is-ca`, `self-signed`, `key-usage`, `san`, `serial`, and `cert:private-key` = `yes` if any place has a key beside it. **No key material is ever read into the document**: the sensor decodes CERTIFICATE blocks only. See ADR-0015. |
| **Retired or broken algorithms** | an ordinary algorithm asset with `cipherhorizon:classical-status` and `cipherhorizon:classical-basis` (the source, quoted no further than it says), and `cipherhorizon:pqc:unclassified-reason` instead of a verdict. |
| Bulk cipher of a suite | a variant with key size and mode: `AES-128-GCM`, `AES-256-CBC`, `ChaCha20-Poly1305`; each has its own OID under the NIST AES arc and `parameterSetIdentifier` / `mode`. The whole-family `AES` entry exists only for host inventories that cannot see a key size, and for a suite variant the catalogue has no entry for. |
| A certificate's public key | its own `related-crypto-material` component (`public-key`, `size`), referenced by the certificate's `subjectPublicKeyRef`, pointing at a key-algorithm variant: `RSA-2048`, `ECDSA-P256` (`curve` = `secp256r1`, RFC 5480), or the catalogue entry when there is no size to state (Ed25519, ML-DSA). |
| A certificate's signature | its exact algorithm with its OID, from the certificate: `ecdsa-with-SHA256` (1.2.840.10045.4.3.2, RFC 5758), `sha256WithRSAEncryption` (1.2.840.113549.1.1.11, RFC 8017), `RSASSA-PSS` (1.2.840.113549.1.1.10; its hash is a parameter, not recorded yet). Ed25519 and ML-DSA are already exact. A signature with no variant (DSA with SHA-256) stays at its family. |
| Accepted key-exchange groups | one algorithm per group: `X25519`, `X448` (RFC 8410 OIDs); `ECDH-P256`, `ECDH-P384`, `ECDH-P521` (id-ecDH 1.3.132.1.12 with the curve, RFC 5480: the curve is a parameter of ECDH, carried as `ellipticCurve` secg/secp256r1 in 1.7); the hybrids (`X25519MLKEM768` …, no OID: IANA assigns code points); the RFC 7919 groups as `DH`. Brainpool, binary and GOST curves have no entry yet: named in the suite text only. |
| A suite's bulk cipher | AES and ChaCha20-Poly1305 by variant; 3DES, RC4 (export RC4-40 included), DES and RC2 by family, with their cited classical status. NULL is no cipher and gets no algorithm. |
| A certificate's role | `cipherhorizon:chain-role` = `leaf`, `intermediate` or `root`, from its position in the chain the server sent. |
| Key material itself | **never written.** The model has no field for a key value and the vocabulary layer strips one if a plugin sets it. |

Key *state* (active, compromised, …) is not observable from the wire and is never emitted.

## What is CycloneDX and what is ours

Native CycloneDX 1.6, validated against the vendored schema in tests: `cryptographic-asset` components of type
`algorithm`, `protocol`, `certificate`, `related-crypto-material`; `cryptoProperties` and their sub-objects;
`dependencies`; `evidence`; `metadata.component`.

CipherHorizon extensions, all as namespaced properties (`cipherhorizon:*`) so no consumer's schema is
stretched: 

| Property | On | Meaning |
|---|---|---|
| `pqc:status` | algorithm | `quantum-vulnerable` / `quantum-safe`, with `pqc:rationale`, `pqc:matched-by` (how the rule matched: OID, OID arc, or name) and one `pqc:basis` per citation. A verdict about the algorithm, cited to a primary source; never applied without a matching rule. |
| `negotiated` | algorithm | used by the handshake a current client completed |
| `negotiated-suite`, `negotiated-group` | protocol | the suite and group of that handshake |
| `chain-role` | certificate | `leaf`, `intermediate`, `root` |
| `cert-serial` | certificate | serial number, in 1.6 documents only (1.6 has no field for it; 1.7 writes `serialNumber`) |
| `iana-obsolete` | algorithm | a group IANA marks obsolete, e.g. the pre-standard `X25519Kyber768Draft00` |
| `tls-graph` | document | what the graph's edges mean (above) |
| `evidence` | every component | how it was learned: `observed` (a ServerHello; a certificate and what it states), `accepted` (a probe offering only that group or signature scheme was answered), `derived` (implied by an accepted suite's IANA registry entry: its cipher, key exchange, authentication, MAC or hash), `negotiated` (used by the one handshake a current client completed). Several can apply. Never a probability (AUDIT-TLS-CBOM-001 A-5) |
| `negotiated-in` | algorithm | the version of the handshake that used it (`TLSv1.3`); `negotiated` stays `true` |
| `scan-complete`, `coverage:<stage>` | document | what the scan covered, per stage: `done`, `done; inconclusive: …`, `not tested: …` (switched off), `not applicable: …`, `not reached: …` (an earlier step failed), `not tested (budget)`, `inconclusive: …`. An absent component means "not accepted" only where its stage is `done` (A-6) |
| `mapping` | document | the IANA registries (with retrieval dates) and the catalogue the derived facts were mapped with |
| `accepted-groups` | protocol | every accepted group with its IANA code point, `x25519 (0x001D)`, including groups the catalogue cannot model (brainpool, binary curves, GOST) (A-4) |
| `accepted-signature-schemes-iana` | protocol (TLS 1.3) | the accepted signature schemes with their code points, `ecdsa_secp256r1_sha256 (0x0403)`: what the server can sign a handshake with, not its certificates' algorithms (A-13) |
| `identifier-status` | algorithm | `unrecognised`: an algorithm the catalogue does not know, kept by the OID read from the certificate (name and `oid` are that OID), with no family or verdict guessed (A-1, A-2) |
| `signature-parameters` | certificate | RSASSA-PSS hash, mask generation, salt length and trailer field as the certificate states them, each RFC 8017 default marked `(default)` (A-3) |
| `seen-in`, `no-sni` | certificate | which handshakes returned it (`tls-default`, `tls1.2-ecdsa`, `tls1.2-rsa`, `… (no SNI)`), and `true` when only a client sending no server name gets it (A-9) |
| `issued-by` | certificate | the bom-ref of the next certificate in the chain **as served** when it is this one's issuer; never a certificate the server did not send (A-10) |
| `key-fingerprint-sha256`, `rsa-exponent` | public key | the SubjectPublicKeyInfo SHA-256 (in 1.7 it is `fingerprint` instead) and an RSA key's exponent (A-12) |

Not in the CBOM by design: the readiness level (L0-L4), the TLS hygiene score and findings. Those are the
evaluation's output, derived from the same facts and cited; a CBOM carries facts and per-algorithm verdicts only.

## Known limits (and what they would need)

- **Key exchange is family-level** (`ECDH`, `DH`) rather than the curve or group used in a TLS 1.2 handshake; the
  accepted groups are separate components, and the negotiated one is flagged (TLS 1.3 and hybrid groups).
- **A hybrid group does not point at its parts** (ML-KEM-768 and X25519): CycloneDX has no relation for a combiner,
  and a dependency would claim the server accepts pure ML-KEM-768 (CBOM-REVIEW-002 C-7).
- **A curve or key type with no catalogue entry** is named in the certificate text but gets no algorithm
  component. Omit, don't guess.
- CycloneDX 1.7 adds `ellipticCurve`, `algorithmFamily`, `tlsGroups` on cipher suites and richer relationship
  types; this model targets 1.6 and will move when the SDK and vendored schema do.

## Review history

A review of the first endpoint CBOM raised six points. What was done:

| Point | Outcome |
|---|---|
| Generic `AES` for specific suites | **Fixed.** Key-size-and-mode variants with NIST OIDs; PQC verdict unchanged (same rule, matched by exact OID). |
| Supported vs negotiated mixed | **Clarified and strengthened.** Edges were always capabilities and the negotiated suite/group were always flagged; now the document says so, and the flag also covers the suite's cipher variant, key exchange and authentication. |
| TLS 1.2 depends on X25519 | **Not a defect, now explicit.** The edge records that the server accepts the group for 1.2, observed by enumeration; nothing claimed it was used. The `tls-graph` note and the negotiated flag are what make that unambiguous. |
| Obsolete draft group as a dependency | **Same answer.** It is listed because a server was observed accepting it, and marked `iana-obsolete`; it is not flagged negotiated unless it was. |
| Certificate points at an algorithm, not a key | **Fixed.** `subjectPublicKeyRef` now references a `related-crypto-material` public key with its size and algorithm variant, as the 1.6 schema describes it. |
| No statement of where crypto is used | **Fixed.** The endpoint now depends on its protocols and certificates; certificates on keys; keys on algorithms. |

A second review, of OIDs and completeness (2026-10-18, [CBOM-REVIEW-002](product/CBOM-REVIEW-002-oids-and-completeness.md)):

| Point | Outcome |
|---|---|
| 3DES, RC4, DES in accepted suites left out | **Fixed.** Referenced, with their classical status |
| NIST P-curve and X448 groups left out | **Fixed.** `ECDH-P256/P384/P521`, `X448` |
| Certificate signature at family level, no OID | **Fixed.** The exact algorithm and OID |
| ChaCha20-Poly1305 said to have no OID | **Fixed.** RFC 8103's OID |
| 1.7 `serialNumber` and `fingerprint` unused | **Fixed** (1.7 only) |
| RSA listed twice in a static-RSA suite | **Fixed** |
| Hybrid parts, MAC/HKDF hash, classical security level, SSLv3 certificate | Known limits, above |

A third review, the remote TLS CBOM audit (2026-10-18, [AUDIT-TLS-CBOM-001](audit/AUDIT-TLS-CBOM-001-remote-tls-cbom.md)), added the evidence states, the coverage, unknown OIDs kept, every accepted group and scheme by code point, the RSASSA-PSS parameters, suite MACs and hashes, every certificate extension, the served-chain links and where each certificate was seen.

## Certificate facts in the CBOM (PRD-004 REQ-TNFR-7)

`tls-report/2` records more about each certificate than before. They reach the CBOM only where CycloneDX has a field.

**In 1.7 documents** (`certificateProperties.certificateExtensions`, by `commonExtensionName`):

| 1.7 name | Value written |
|---|---|
| `basicConstraints` | `CA:TRUE` (with `pathlen:N` when set) or `CA:FALSE` |
| `keyUsage` | the RFC 5280 names, comma separated |
| `extendedKeyUsage` | `serverAuth`, `clientAuth`, ... (an unnamed usage as its OID) |
| `certificatePolicies` | the policy OIDs |
| `subjectAlternativeName` | `DNS:name, IP:address`, … (the DNS and IP names; other SAN types are not recorded) |
| `authorityInformationAccess` | `OCSP - URI:…, CA Issuers - URI:…` |
| `crlDistributionPoints` | `URI:…` |
| `authorityKeyIdentifier`, `subjectKeyIdentifier` | the key identifier, hex |
| `signedCertificateTimestamp` | `present (not decoded into the CBOM)` |

Every **other** extension is written as a 1.7 `customExtension`, named by its OID (with the name this program
decodes it by, when it does, as in `nameConstraints (2.5.29.30)` or `tlsFeature (1.3.6.1.5.5.7.1.24)`), valued with
what was decoded (name constraints' permitted and excluded names; `status_request (OCSP must-staple)`) or
`not decoded`, and `; critical` when it is. Nothing is decoded that the parser did not decode (AUDIT-TLS-CBOM-001 A-7, A-8).

1.6 has no such field, so a 1.6 document omits them (`TestCertificateExtensionsOnlyIn17` validates both against the
vendored schemas). A certificate from a `tls-report/1` scan has none of these facts, and none is invented.

**Not in the CBOM** (no field in 1.6 or 1.7); they stay in the report, the evaluation and the estate graph:

| Fact | Why |
|---|---|
| The DV/OV/IV/EV class | derived from the policy OIDs, which are emitted |
| Lifetime and the limit it is held to | derivable from `notValidBefore`/`notValidAfter`; the limit is a judgement |
| Served order, chain problems, per-store trust | properties of an endpoint's configuration and of evaluation, not of the certificate |
| Stapled OCSP response, the SCTs themselves | revocation evidence observed on a connection, not part of the certificate (embedded SCTs are part of it, but are not decoded into the CBOM) |
