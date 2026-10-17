# CBOM-REVIEW-002 · OIDs and completeness of the CBOMs we write

Status: review done 2026-10-18; findings C-1 to C-6 go into [PRD-009](PRD-009-interactive-charts-motion-port-cbom.md)
(WP-4), C-7 to C-10 are recorded and deferred. The first review of the endpoint CBOM is in
[docs/cbom-model.md](../cbom-model.md#review-history).

**Question asked (owner, 2026-10-18):** "Is the CBOM missing OIDs, or is it doing it right?"

**Short answer.** Where an OID is present it is correct: every one was checked against its RFC or the NIST
register. But **OIDs are missing in four places where an authoritative one exists**, and two parts of what a TLS
scan sees **never reach the CBOM at all**. The worst gap is the second one: a server that accepts 3DES, RC4 and
NULL cipher suites produced a CBOM that names none of those ciphers as assets.

## 1. Method

1. Built `cipherhorizon` at `f0b62c1` (0.1.1) and ran `demo-targets`.
2. Wrote nine CBOMs (CycloneDX 1.7, the default) from real scans:
   - TLS: 9440 (hybrid), 9443 (SSLv3, RC4, 3DES, export, NULL, anonymous), 9448 (private CA), 9458 (ML-DSA only),
     9459 (ECDSA and ML-DSA);
   - SSH: 9460 (hybrid), 9462 (legacy), 9463 (ML-DSA host key), 9464 (composite host key).
3. Listed every cryptographic asset with its type, name, OID, primitive, parameter set, curve and family, and
   compared that with what the same scan's JSON report holds (`tls scan --json`).
4. Checked each missing OID against its primary source: RFC 8103, RFC 5480, RFC 5758, RFC 8017, RFC 8410.
5. Checked the vendored 1.7 schema for fields the builder could fill and doesn't.

## 2. What is right

- **Every OID written is correct.** That covers the AES variants (NIST AES arc, RFC 3565 and RFC 5084), SHA-2 and
  SHA-3, ML-KEM, ML-DSA, SLH-DSA, RSA, DSA, DH, id-ecDH, X25519, Ed25519, and the SSH HMACs (RFC 8018).
- **OIDs are left out where none exists, and the catalogue says why.** No OID is invented for any of these:
  - the TLS and SSH hybrid groups: IANA assigns code points, not OIDs;
  - AES in CTR mode: NIST registers none;
  - UMAC.
- **The 1.7 output is valid against the vendored schema.** Deprecated fields are mapped (`relatedCryptographicAssets`,
  `ellipticCurve`). `algorithmFamily` is set only where the registry has one.
- **Keys are separate `related-crypto-material` components** with a size and a reference to their algorithm variant
  (`ECDSA-P256`, `secg/secp256r1`). No key value is ever written.
- **Accepted and negotiated are kept apart**, and the document says so in `cipherhorizon:tls-graph`.

## 3. Findings

Severities follow what a CBOM consumer loses. Taken here means this release, PRD-009 WP-4.

### Taken into this release

| # | Sev | Finding | Evidence | Decision |
|---|---|---|---|---|
| **C-1** | High | **Legacy bulk ciphers are dropped.** A suite's cipher is referenced only for AES and ChaCha20. 3DES, RC4 and DES suites reference only their key exchange and authentication, so the CBOM of a server accepting `TLS_RSA_WITH_3DES_EDE_CBC_SHA` and `TLS_RSA_WITH_RC4_128_SHA` has no 3DES or RC4 asset. The code comment says these have "no catalogue entry". That was true at R1; the catalogue has carried 3DES, RC4 and DES (with their cited classical status) since ADR-0013. The builder never caught up. | 9443: components `DH`, `RSA` and `SSLv3` only. Five suites, none naming its cipher. | **Fix.** Reference the catalogue entry for 3DES, RC4 (RC4-40 included) and DES. A NULL cipher has no algorithm and stays unreferenced; the suite name says it. |
| **C-2** | High | **NIST P-curve groups are missing.** TLS groups `secp256r1`, `secp384r1` and `secp521r1` (and `x448`) have no catalogue entry, so a group the server accepts is not in the CBOM. These are quantum-vulnerable key exchanges, which is exactly what a PQC inventory exists to list. | 9440 report: `secp256r1` accepted for TLS 1.2 and 1.3. CBOM: only `X25519` and `X25519MLKEM768`. | **Fix.** Add catalogue variants `ECDH-P256`, `ECDH-P384` and `ECDH-P521` (OID id-ecDH 1.3.132.1.12, RFC 5480 §2.1.2, with `ellipticCurve` secg/secp256r1, secp384r1 and secp521r1). Add `X448` (1.3.101.111, RFC 8410). Map the groups to them. |
| **C-3** | Medium | **Certificate signature algorithms have no OID.** A certificate's signature algorithm is referenced as the family `ECDSA` (no OID) or `RSA` (the key OID, `rsaEncryption`, not a signature OID). The certificate states the exact algorithm, and the scan already records it: `ECDSA-SHA256`, `1.2.840.10045.4.3.2`. | 9440 report vs CBOM. | **Fix.** Add signature variants with their RFC OIDs and reference them from the certificate. Fall back to the family only when the algorithm has no variant. The variants: ECDSA-SHA256/384/512 (1.2.840.10045.4.3.2/3/4, RFC 5758); sha256/384/512WithRSAEncryption (1.2.840.113549.1.1.11/12/13, RFC 8017); RSASSA-PSS (1.2.840.113549.1.1.10, RFC 8017). Ed25519, Ed448 and ML-DSA are already pure-OID signatures. |
| **C-4** | Medium | **ChaCha20-Poly1305 has an OID, and the catalogue says it has none.** RFC 8103 §3 assigns `id-alg-AEADChaCha20Poly1305` 1.2.840.113549.1.9.16.3.18. The comment "no PKIX or CMS registration assigns it one" is wrong. | catalogue.go comment; RFC 8103. | **Fix.** Set the OID and correct the comment. The PQC rule matches by name today; it will match by OID too. |
| **C-5** | Medium | **The 1.7 certificate fields `serialNumber` and `fingerprint` are not used.** The serial goes into the property `cipherhorizon:cert-serial`, and the SHA-256 fingerprint appears only inside the bom-ref. CycloneDX 1.7 has fields for both. | 1.7 schema `certificateProperties`; docs/cbom-model.md says "CycloneDX 1.6 has no field for it". | **Fix (1.7 only).** Write `serialNumber`, and `fingerprint` {alg SHA-256, content}. Keep the property in 1.6 documents, where no field exists. |
| **C-6** | Low | **A suite's algorithm list repeats RSA.** In `TLS_RSA_*` suites the key exchange and the authentication are both RSA, so `algorithms` lists the same reference twice. | 9443 suites: `["rsa@…","rsa@…"]`. | **Fix.** De-duplicate within a suite. |

### Recorded, not taken now

| # | Sev | Finding | Why deferred |
|---|---|---|---|
| C-7 | Low | Hybrid groups (`X25519MLKEM768`, `mlkem768x25519-sha256`) do not point at their parts (ML-KEM-768 and X25519), and carry no `nistQuantumSecurityLevel`. | 1.7 `algorithmProperties` has no relation field. Linking them through `dependencies` would claim the server accepts pure ML-KEM-768, which it may not. Wait for CycloneDX to model combiners. |
| C-8 | Low | The MAC of a TLS 1.2 suite (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-MD5) and the HKDF hash of a TLS 1.3 suite are not referenced. | Needs HMAC-SHA-384 in the catalogue and a rule for the TLS 1.3 PRF hash. A separate, smaller change; the suite name already carries it. |
| C-9 | Low | `classicalSecurityLevel` and `cryptoFunctions` are never filled. | Both are judgements per use (bits of security, which functions are used). They need a cited table, not a guess. |
| C-10 | Info | An SSLv3-only server yields no certificate component. Our Go-based certificate fetch cannot speak SSLv3. | The certificate is visible in the legacy prober's ServerHello flight. A scanner change, tracked with the TLS backlog. |

## 4. Not findings

These were checked and are deliberate. No change.

- **`ECDSA-P256` uses `id-ecPublicKey` (1.2.840.10045.2.1) with `ellipticCurve` = secp256r1.** That is how RFC 5480
  identifies an EC public key. The curve OID (1.2.840.10045.3.1.7) is a parameter of the key, which `ellipticCurve`
  carries by registry name.
- **SSLv3 is written as protocol `tls`, version `3.0`.** CycloneDX has no `ssl` protocol type. The version number
  is the one on the wire.
- **ML-DSA and composite SSH host keys have no `size`.** A lattice key has no bit length in the sense RSA or EC
  keys do. The parameter set is carried by the algorithm it references.

## 5. Done when

- The 9443 CBOM names 3DES and RC4 as algorithm assets, each with its cited classical status.
- The 9440 CBOM names `ECDH-P256` (secp256r1), and its certificate references `ECDSA-SHA256` @ 1.2.840.10045.4.3.2.
- `ChaCha20-Poly1305` carries 1.2.840.113549.1.9.16.3.18.
- Every 1.7 certificate has `serialNumber` and `fingerprint`.
- No suite lists a reference twice.
- All of the above validates against the vendored 1.6 and 1.7 schemas. The golden CBOMs are regenerated and their
  diff reviewed, and docs/cbom-model.md "Known limits" is updated.
