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
| Bulk cipher of a suite | a variant with key size and mode: `AES-128-GCM`, `AES-256-CBC`, `ChaCha20-Poly1305`; each has its own OID under the NIST AES arc and `parameterSetIdentifier` / `mode`. The whole-family `AES` entry exists only for host inventories that cannot see a key size, and for a suite variant the catalogue has no entry for. |
| A certificate's public key | its own `related-crypto-material` component (`public-key`, `size`), referenced by the certificate's `subjectPublicKeyRef`, pointing at a key-algorithm variant: `RSA-2048`, `ECDSA-P256` (`curve` = `secp256r1`, RFC 5480), or the catalogue entry when there is no size to state (Ed25519, ML-DSA). |
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
| `cert-serial` | certificate | serial number (CycloneDX 1.6 has no field for it) |
| `iana-obsolete` | algorithm | a group IANA marks obsolete, e.g. the pre-standard `X25519Kyber768Draft00` |
| `tls-graph` | document | what the graph's edges mean (above) |

Not in the CBOM by design: the readiness level (L0-L4), the TLS hygiene score and findings. Those are the
evaluation's output, derived from the same facts and cited; a CBOM carries facts and per-algorithm verdicts only.

## Known limits (and what they would need)

- **Signature algorithms are family-level** (`RSA`, `ECDSA`), not per-hash (`sha256WithRSAEncryption`): the hash
  is in the certificate but the catalogue does not yet carry per-hash signature OIDs.
- **Key exchange is family-level** (`ECDH`, `DH`) rather than the curve or group used in a TLS 1.2 handshake; the
  accepted groups are separate components, and the negotiated one is flagged (TLS 1.3 and hybrid groups).
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
