# ENG-HANDOFF-003: TLS scanner T1 — PKI depth and the self-explaining endpoint page

Implements [PRD-004](PRD-004-tls-scanner-t1-pki-depth.md) (baselined 2026-10-02). Read that first; requirements are
referenced by ID. The test plan is [QA-PLAN-004](QA-PLAN-004-tls-t1.md). Status lives in the [RTM](../program/RTM.md)
and [TRACKER](../program/TRACKER.md).

## 1. Design decisions

| # | Decision | Why |
|---|---|---|
| **D-1** | **The scanner records raw observations; trust and every judgement are computed in evaluation.** The report keeps, for every chain, the DER of each certificate *in the order served*, the raw stapled OCSP response and the raw SCTs from the TLS extension. | Trust depends on anchors (bundled stores, the operator's private CA bundle) and on time. With the raw bytes in the stored report, a result can be **re-evaluated** when a bundle or snapshot changes, without rescanning. This is the same observations-then-verdicts line the product already draws. |
| **D-2** | **A new package `internal/pki`** holds chain analysis, path validation per anchor set, and the OCSP-response and SCT-list decoders. It is pure: no network, no clock (time is passed in), no store. | One place for PKI logic. `eval` and, later, the certificate entity both use it. Fuzzed in isolation. |
| **D-3** | **A new package `internal/refdata`** holds generated, dated reference lists with their source URL, retrieval date and source SHA-256. A generator under `internal/refdata/gen` reads downloaded inputs; the generated Go files are committed. Nothing is fetched at run time. | Same pattern as the IANA registries (`internal/tlsprobe/registry`). SR-22. |
| **D-4** | **Roots come from the CCADB** reports `MozillaTLSServerAuthenticationCSV` and `ChromeTLSServerAuthenticationCSV`, governed by the CCADB Data Usage Terms: **CDLA-Permissive-2.0, attribution required**. Each root's PEM is stored once and the store lists reference it by SHA-256. The CSVs also carry Mozilla's *Distrust for TLS After Date* and Chrome's `sct_not_after_sec`; both are kept as per-root constraints. | Resolves OQ-T1 and REQ-TTRS-6 from the same source. The licence is recorded in `docs/reference-data.md` and the attribution is shown on the About page. |
| **D-5** | **The OCSP response is decoded with `encoding/asn1` and our own code**, with no new module. Its signature is checked with `x509.Certificate.CheckSignature` through a small OID → `x509.SignatureAlgorithm` table (RSA PKCS#1 v1.5 with SHA-1/256/384/512, ECDSA with SHA-1/256/384/512, Ed25519). Any other algorithm is reported as *not verified (unsupported algorithm)*, never as valid. | REQ-TNFR-2, SR-14. |
| **D-6** | **Evaluation gains inputs:** `eval.EvaluateWith(rep, eval.Input{Now, Stores, Anchors, SSLv2Keys})`. `eval.Evaluate(rep, now)` stays and uses the bundled stores with no private anchors. | Keeps every existing caller and test working. |
| **D-7** | **Section status, *Fix first*, per-chain PKI views and attack labels are computed in `eval`**, and the UI renders them. | The API, the export and the UI must agree; logic does not live in JavaScript. |
| **D-8** | **Legacy reports (`tls-report/1`)** have no DER, so PKI analysis is impossible. Evaluation marks those sections `not-collected` ("not collected by the version that ran this scan"). `CERT.UNTRUSTED` keeps its old behaviour on them (the stored OS-store verdict). | REQ-TSTG-3, T1-M7. |
| **D-9** | **The HTTP stage defaults on** at the two places a default is chosen: the `serve` flag and the `tls scan` flag (`--http-checks`, now `true`). `tlsprobe.Options.HTTPChecks` remains an explicit input. | REQ-TSTG-4. |
| **D-10** | **Private anchors:** a server-wide PEM file (`--ca-bundle` / config `trust.caBundle`) read at start, plus a per-system set in a new table `trust_anchors`. Upload parses PEM with the same block rules as the host certificate sensor (certificates only; key blocks are refused without being decoded). | REQ-TTRS-2, SR-20. |
| **D-11** | **DROWN across the estate:** the runner passes eval an index *public-key SHA-256 → endpoints where SSLv2 is accepted*, built from the latest completed scan of every endpoint. | REQ-TVLN-2. The index reflects the estate at evaluation time; re-evaluation refreshes it. |
| **D-12** | **Re-evaluation** (`POST /api/v1/scans/{id}/reevaluate`) recomputes from the stored report with the current anchors, snapshots and time. It replaces the stored evaluation and adds a scan event recording the old and new versions. Adding or removing a system's anchor re-evaluates the latest completed scan of each of its endpoints. | REQ-TNFR-4. Trust must change when the person changes the bundle, without a rescan. |

## 2. Data

### 2.1 Report `tls-report/2` (additions only; all optional)

```
Report
  schemaVersion "tls-report/2"
  stages []Stage{ name, outcome(done|skipped|inconclusive), reason, reasonCode, connections, probes[], inconclusive }
  hstsHeader *HSTSResult{ values[] (≤4, each ≤512 bytes, cleaned), maxAge *int64, includeSubDomains, preload, problems[] }
  hsts *bool                      // kept: true when a valid header was present
CertResult
  sni bool                        // false for the no-SNI chain
  sameAsSni *bool                 // only on the no-SNI chain
  ocspStaple string (base64)      // raw stapled response, ≤ 64 KiB
  tlsScts []string (base64)       // raw SCTs from the TLS extension / TLS 1.3 entry, ≤ 32 of ≤ 4 KiB
CertInfo (via certinfo.Facts)
  der string (base64)             // the certificate as served
  spkiSha256, keyUsage[], extKeyUsage[], basicConstraints{ca, maxPathLen}, nameConstraints{critical, permitted[], excluded[]}
  policies[], policyClass (DV|OV|IV|EV|unknown), cnOnly, wildcards[], lifetimeDays, rsaExponent
```

Stage names (fixed; they are the page sections): `protocols`, `suites`, `key-exchange`, `features`,
`certificates`, `revocation`, `http`. `revocation` covers OCSP and CT; it is `done` when `certificates` is, because
its data rides on the same handshakes. Reason codes: `option-off`, `not-applicable`, `not-reached`, `budget`,
`legacy-report`.

### 2.2 Evaluation `eval/3` (additions)

```
Evaluation
  sections []Section{ id, status(problem|attention|good|not-checked|not-collected|inconclusive), reason, findings[] (IDs) }
  fixFirst []string (finding IDs, ≤3)
  pki []ChainView{
      source, sni, served{order, issues[], sizeBytes},
      trust []StoreResult{ store, snapshot, trusted, path[] (SHA-256), error, distrust },
      private *StoreResult, os *StoreResult (only from legacy/opt-in),
      names{ host, checked[], matchedBy },
      lifetime{ days, limitDays, limitSource, public },
      ocsp *OCSPView{ present, status, revokedAt, reason, thisUpdate, nextUpdate, responder, signature(valid|invalid|unsupported|no-issuer), forThisCert, urls[] },
      scts []SCTView{ source(embedded|tls|ocsp), logId, logName, timestamp } }
  referenceData []RefInfo{ name, source, retrieved }
Finding
  section string, labels []string (attack names), availability bool
```

### 2.3 Store

Migration 7 adds `trust_anchors(id, system_id, sha256, subject, not_after, pem, added_at, added_by, UNIQUE(system_id, sha256))`. Bounds:

- at most 50 anchors per system;
- a 64 KiB upload;
- certificates only (D-10);
- audit actions `anchor-add` and `anchor-remove`, with the fingerprint and subject.

### 2.4 API

| Route | Purpose |
|---|---|
| `GET /api/v1/systems/{id}/trust-anchors` | list (fingerprint, subject, notAfter, addedAt, addedBy) |
| `POST /api/v1/systems/{id}/trust-anchors` | body `{"pem": "..."}`; adds every certificate block; refuses keys and non-CA certificates with a reason |
| `DELETE /api/v1/systems/{id}/trust-anchors/{fingerprint}` | remove |
| `GET /api/v1/trust-anchors` | the server-wide bundle, read-only |
| `GET /api/v1/reference-data` | each bundled list's name, source, retrieved date and count |
| `POST /api/v1/scans/{id}/reevaluate` | D-12 |

Every route goes through the guarded mux (SR-12), and the OpenAPI document is updated (parity test).

## 3. Algorithms and rules

### 3.1 Chain analysis (`pki.Served`)

- **Order:** for i>0, `served[i-1]` must be signed by `served[i]` (`CheckSignatureFrom`). A break is an order issue,
  unless the out-of-order certificate is unrelated (then it is *extra*).
- **Extra:** self-signed roots, duplicates (same SHA-256), and certificates on no path from the leaf through served
  certificates.
- **Missing intermediate:** the leaf's issuer (or the topmost certificate on the served path) is neither served nor
  in any anchor set, so no store and no private anchor yields a path. Report the issuer DN and the leaf's AIA
  `caIssuers` URLs.
- **Expires first:** any certificate on the served path with `notAfter` < leaf `notAfter`, or inside the leaf's warning window.
- **Size:** the sum of DER lengths. Note it at > 4 KiB.

### 3.2 Trust per store (`pki.Validate`)

- Run `x509.Verify` with `Roots` = the store's pool and `Intermediates` = the served certificates after the leaf.
  There is no system pool and no AIA. `KeyUsages` is `[ServerAuth]` and `CurrentTime` is `now`.
- For each verified chain, apply the root's constraints:
  - **Mozilla distrust-after:** distrusted if the leaf's `notBefore` > the date.
  - **Chrome `sct_not_after`:** distrusted unless at least one SCT (from any source) has a timestamp ≤ the limit.
    With no SCTs, fall back to `notBefore` ≤ the limit.

  A store trusts the chain if any chain satisfies its constraints.
- Private anchors work the same, with no constraints.
- The OS store is computed only when the opt-in setting is on (REQ-TTRS-3, P1).
- **Public** means: trusted, or distrusted only by a constraint, by at least one bundled store.

### 3.3 Names (REQ-TTRS-5)

The host is matched against the DNS and IP SANs; the CN is never used. The wildcard rule is RFC 9525 §6.3 (left-most
label only, not matching a public suffix boundary beyond one label, as `crypto/x509` implements it). The rule records
which SAN matched.

### 3.4 OCSP (`pki.ParseOCSP`)

The decoding steps:

1. **Bound the input:** at most 64 KiB, and no trailing data.
2. **Decode the outer layers:** `OCSPResponse{status, responseBytes{type=id-pkix-ocsp-basic, BasicOCSPResponse}}`.
3. **Decode the response data:** `tbsResponseData{version, responderID (byName|byKey), producedAt, responses[], extensions}`.
4. **Decode each single response:** `SingleResponse{certID{hashAlg, nameHash, keyHash, serial}, status good|revoked{time, reason}|unknown, thisUpdate, nextUpdate?, singleExtensions}`.

Matching and verification:

- **For this certificate:** the serial is equal, and `nameHash`/`keyHash` match the issuer computed with `hashAlg` (SHA-1 or SHA-256).
- **Signature:** checked by the issuer, or by a delegated responder certificate from `certs` that the issuer signed and that has EKU `OCSPSigning`.
- **SCTs:** the single-extension `1.3.6.1.4.1.11129.2.4.5` carries an SCT list.

### 3.5 SCT list (`pki.ParseSCTList`)

The format is RFC 6962 §3.3:

- A `uint16` total length, followed by SerializedSCTs.
- Each SerializedSCT is a `uint16` length, then an SCT.
- An SCT is: `version(1)`, `logID(32)`, `timestamp(8)`, `exts<uint16>`, `hash(1) sig(1) sig<uint16>`.

Limits: at most 64 SCTs, and every length is checked against what remains. The embedded extension wraps the list in
an OCTET STRING.

### 3.6 Rules (eval/3)

New rule IDs, with severity, section and citations. *A* marks the availability-impact findings (REQ-TUI-2).

| ID | Sev | Section | Fires when | Citation |
|---|---|---|---|---|
| CERT.CHAIN-INCOMPLETE *A* | high | certificates | §3.1 missing intermediate | RFC 8446 §4.4.2, RFC 5246 §7.4.2 |
| CERT.CHAIN-ORDER | medium (TLS ≤1.2 only) / low | certificates | order break | as above |
| CERT.CHAIN-EXTRA | info | certificates | extra certificates | RFC 8446 §4.4.2 |
| CERT.INTERMEDIATE-EXPIRES | medium | certificates | §3.1 expires first | RFC 5280 §6.1 |
| CERT.LIFETIME | medium | certificates | public, and lifetime > the limit on `notBefore` | CA/B BR §6.3.2 as amended by SC-081v3 |
| CERT.NO-SERVERAUTH *A* | high | certificates | the leaf has an EKU without serverAuth/anyEKU | RFC 5280 §4.2.1.12 |
| CERT.CLIENTAUTH-EKU | info | certificates | public, and the leaf or an intermediate has clientAuth | Chrome Root Program Policy v1.8 |
| CERT.PARTIAL-TRUST | medium | certificates | some bundled stores trust it, others do not (names them; distrust constraints named) | RFC 5280 §6 |
| CERT.WEAK-EXPONENT | low | certificates | RSA e < 65537 | CA/B BR §6.1.6 |
| OCSP.REVOKED *A* | critical | revocation | stapled `revoked` for this certificate | RFC 6960 |
| OCSP.MISMATCH | high | revocation | the staple is for another certificate, or its signature is invalid | RFC 6960 §3.2 |
| OCSP.STALE | medium | revocation | `nextUpdate` < now | RFC 6960 §4.2.2.1 |
| OCSP.UNKNOWN | medium | revocation | status `unknown` | RFC 6960 |
| OCSP.MUST-STAPLE-MISSING *A* | high | revocation | the leaf is Must-Staple and nothing was stapled | RFC 7633 |
| OCSP.NO-STAPLE | low | revocation | the leaf names an OCSP URL, nothing was stapled, and it is not Must-Staple | RFC 6066 §8; context: Let's Encrypt ended OCSP 2025-08-06 |
| CT.NO-SCTS | medium | revocation | public, and no SCT from any source | RFC 6962; browser CT policies |
| KX.DH-COMMON-PRIME | medium | key-exchange | the DHE prime is an RFC-published group of ≤ 1024 bits (shared, a precomputation target) | Logjam (CVE-2015-4000), RFC 7919 |
| HTTP.HSTS-DISABLED | medium | http | `max-age=0` | RFC 6797 §6.1.1 |
| HTTP.HSTS-SHORT | low | http | 0 < `max-age` < 31536000 | RFC 6797; hstspreload.org requirements |
| HTTP.HSTS-INVALID | medium | http | syntax problems or duplicate headers | RFC 6797 §6.1, §8.1 |
| HTTP.HSTS-NO-SUBDOMAINS | info | http | valid, and no `includeSubDomains` | RFC 6797 §6.1.2 |
| CIPHER.CBC | info | suites | CBC suites in TLS 1.2 or earlier (label LUCKY13) | RFC 9325 §4.2 |
| VULN.DROWN-SHARED-KEY | high | vulnerabilities | this leaf's SPKI is on an endpoint accepting SSLv2 | CVE-2016-0800 |

Changed rules:

- **CERT.EXPIRING** — the thresholds scale (REQ-TCRT-4).
- **CERT.UNTRUSTED** *A* — fires on `/2` reports only when no bundled store and no private anchor trusts the chain. The detail names the stores and the missing-intermediate cause when that is the reason.
- **CERT.EXPIRED** and **CERT.NAME-MISMATCH** — gain *A*.
- **HTTP.NO-HSTS** — keeps its behaviour, now reading `hstsHeader`.

Attack labels (REQ-TVLN-1):

| Finding | Labels |
|---|---|
| CIPHER.EXPORT | FREAK (RSA_EXPORT), Logjam (DHE_EXPORT) |
| KX.DH-SMALL, KX.DH-COMMON-PRIME | Logjam |
| PROTO.SSL2 | DROWN |
| FEAT.COMPRESSION | CRIME |
| CIPHER.SWEET32 | SWEET32 |
| CIPHER.RC4 | RC4 biases |
| VULN.POODLE | POODLE |
| VULN.BEAST | BEAST |
| CIPHER.CBC | LUCKY13 |

The vulnerabilities section lists every named attack. Each is *exposed* (with its finding), *not exposed* or *not
tested by design* (Heartbleed, CCS injection, ROBOT, Ticketbleed, padding oracles).

### 3.7 Section status and *Fix first*

**Section status:**

- the stage outcome first: `skipped` → `not-checked`, `inconclusive` → `inconclusive`, a legacy report → `not-collected`;
- otherwise the worst finding in the section: critical/high → `problem`, medium/low → `attention`, none or info → `good`.

**Fix first:** order every finding except info by severity rank, then availability, then section order. Take the
first three distinct rule IDs.

## 4. Work packages

| WP | Scope | Requirements | Gate |
|---|---|---|---|
| **T1a** | `internal/refdata` + generator; CCADB Mozilla/Chrome; DH primes from RFC 2409/3526/5114/7919 text; CT log list; lifetime table (transcribed, pinned by test); `docs/reference-data.md` (licences, attribution) | TDAT-1…3, TTRS-6 data | licence recorded per list |
| **T1b** | `tlsprobe`: stages, `tls-report/2`, DER/staple/SCT capture, no-SNI handshake, certinfo extensions, HSTS parser; `internal/pki` decoders + chain + trust | TSTG-1…5, TCRT-1/2, TCHN-1, TREV-1, TCT-1, THTP-1/3, TNFR-1/2 | fuzz targets green; OpenSSL oracle on OCSP fixtures |
| **T1c** | `eval/3` rules, sections, fix-first, labels, inputs; store migration 7 + anchors API; runner wiring (anchors, SSLv2 index), reevaluate; OpenAPI; CBOM gaps doc | TCRT-3…7, TCHN-2…6, TTRS-1…5, TREV-2…5, TCT-2/3, TKX-1/2, THTP-2, TVLN-1…3, TNFR-4…7 | fixture matrix (QA-PLAN-004 §3) green; mutation checks |
| **T1d** | Endpoint page rebuild; anchors UI on the system page; About (reference data + server bundle); Certificates page additions; export | TUI-1…14, TNFR-3 | journey and `security.sh` extended; hostile fixtures in every new section |
| **T1e** | QA-PLAN-004 executed; QA-REPORT-003; RTM; CHANGELOG; docs | all | §5 exit criteria |

## 5. Constraints carried over (do not regress)

These are unchanged from 0.2.0:

- handshakes only, apart from the one HTTP request;
- no exploit traffic;
- no third-party contact (now asserted by test, SR-19);
- `textContent` only in the UI;
- strict CSP;
- own terminology;
- every finding cited;
- PQC findings never counted in the hygiene score;
- the stored report is never rewritten (re-evaluation writes only the evaluation);
- `CGO_ENABLED=0`, no new module.

## 6. Deviations recorded during the build (2026-10-02)

| # | Planned | Built | Why |
|---|---|---|---|
| V-1 | `CertResult.sni` / `sameAsSni` on every chain | `Report.noSni` = `same`, `different` or `failed`; a separate `CertResult` with `noSni: true` only when the certificate differs | A missing field on old reports must not read as "no SNI"; the common case (same certificate) does not duplicate a chain |
| V-2 | `CERT.CHAIN-INCOMPLETE` whenever the top of the served path has an unknown issuer | Fires only when the leaf was served alone. When the served path already ends at a CA certificate, `served.missing.likely = "root"` and `CERT.UNTRUSTED` says "a private or unknown root" | A correctly served private chain (root never sent) was reported as a broken chain (QA-REPORT-003 §5.1) |
| V-3 | Server-wide bundle from `--ca-bundle` / config `trust.caBundle` | `--ca-bundle FILE` only | `serve` has no configuration file |
| V-4 | Stage outcome for a non-HTTP answer: `inconclusive` | `skipped` with `not-applicable` | REQ-THTP-3: not a failure |
| V-5 | — | `tlsprobe.Options.OSTrust` / `tls scan --os-trust`; the OS verifier no longer runs by default | SR-19: some OS verifiers fetch intermediates over the network |
| V-6 | CBOM gains certificate facts only where 1.7 has a field (assumed none) | 1.7 `certificateExtensions`: basicConstraints, keyUsage, extendedKeyUsage, certificatePolicies; stripped from 1.6 | The vendored 1.7 schema defines the field |
| V-7 | `Evaluation` per §2.2 | adds `evaluatedAt`, `vulnerabilities` (attack list), `dhGroup`, `legacyReport`; `MissingView.likely` | Needed by the page; all additive |
| V-8 | Fuzz campaigns in CI's job on any OS | Run on Linux | The Windows fuzz engine stalls on `encoding/asn1` targets (QA-REPORT-003 §2) |
