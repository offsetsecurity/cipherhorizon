# QA-PLAN-004: TLS scanner T1

Verifies [PRD-004](PRD-004-tls-scanner-t1-pki-depth.md) against the design in
[ENG-HANDOFF-003](ENG-HANDOFF-003-tls-t1.md). Written before the code. Evidence goes into the
[RTM](../program/RTM.md); the outcome goes into QA-REPORT-003. The principles of QA-PLAN-002 §1 carry over unchanged:

- requirement-first;
- independent oracles;
- negative controls and mutation checks;
- hostile data everywhere;
- honest reporting.

## 1. Test levels

| Level | Tooling | Scope |
|---|---|---|
| Unit / table | `go test` | `pki` chain, trust per store with constraints, names; lifetime table; HSTS parser; every new and changed rule; section status; fix-first; labels |
| Fuzz | `go test -fuzz` (CI smoke; QA ≥ 1 M execs each) | `FuzzParseOCSP`, `FuzzParseSCTList`, `FuzzParseHSTS`, `FuzzServedChain` (random DER sequences) |
| Oracle | `testing/pki/oracle.sh` (OpenSSL 3.x) | Trust and missing intermediate: `openssl verify -x509_strict -CAfile <store> -untrusted <served>` per fixture. OCSP: `openssl ocsp -respin <der> -resp_text -noverify` fields vs `pki.ParseOCSP` |
| Hermetic scan | `go test` against `testserver` | Every fixture of §3 scanned end to end: report → eval → expected findings, and no others |
| Legacy | stored `tls-report/1` fixtures (from the 0.2.0 golden runs) | Render and evaluate without error; sections `not-collected` (T1-M7) |
| API / contract | Go tests + the OpenAPI parity test | Anchor routes (validation, limits, refusal of keys); reevaluate; reference-data |
| Security script | `testing/e2e/security.sh` | New routes behind the token/Origin/Host checks; anchor upload with a key block refused; hostile PEM |
| Browser journey | `testing/e2e/journey.mjs` | Section index statuses; purpose line in every section; *Not checked* reasons; Fix first; trust row; chain tabs; hostile certificate subjects/SANs in the new sections; ≤ 2 clicks Estate → cause (T1-M5); 390 px and dark mode |
| Traffic | Go test with a recording dialer | A Standard scan dials only the target address (SR-19); connections ≤ 0.2.0 + 5 (T1-M6) |

## 2. Mutation checks (each must make a named test fail)

| Guard | Mutation | Must fail |
|---|---|---|
| Missing intermediate | treat AIA-reachable issuer as present | chain-incomplete fixture |
| Distrust-after | ignore Mozilla constraint | distrusted-root fixture |
| sct_not_after | ignore Chrome constraint | sct-not-after fixture |
| OCSP for this cert | skip serial/issuer-hash match | staple-for-other-cert fixture |
| OCSP signature | skip signature check | tampered-staple fixture |
| Must-staple | drop the rule | must-staple fixture |
| Lifetime public-only | apply to private chains | private-CA fixture raises no lifetime finding |
| Expiry scaling | revert to fixed 30 days | 47-day fixture raises nothing |
| Anchor upload | accept key blocks | decoy-key upload test (SR-20) |
| Target-only traffic | add a lookup to another host | recording-dialer test (SR-19) |
| Parser bounds | remove a length check in the SCT decoder | fuzz seed corpus test |
| Labels not double-counted | make labels separate findings | hygiene test: score unchanged by labels |

## 3. Fixtures

Built by `internal/pki/pkitest`: a deterministic test PKI made at test time (root, intermediate, leaf variants). The
"public" store in tests is a synthetic store holding the test root, so no real CA is involved. OCSP responses are
produced by **OpenSSL** (`testing/pki/make-ocsp.sh`), so the producer is independent of our parser; the DER outputs
and the script are committed.

| Fixture | Expected |
|---|---|
| clean | no finding from the new rules |
| missing-intermediate | CERT.CHAIN-INCOMPLETE (+ UNTRUSTED in no store) |
| wrong-order (TLS 1.2-only server / TLS 1.3 server) | CERT.CHAIN-ORDER medium / low |
| root-included, duplicate, unrelated extra | CERT.CHAIN-EXTRA |
| intermediate-expires-first | CERT.INTERMEDIATE-EXPIRES |
| must-staple-unstapled | OCSP.MUST-STAPLE-MISSING |
| staple-good | none; OCSP view good, signature valid |
| staple-revoked | OCSP.REVOKED |
| staple-good evaluated after nextUpdate | OCSP.STALE |
| staple-for-other-cert | OCSP.MISMATCH |
| staple-tampered | OCSP.MISMATCH (signature invalid) |
| staple-unknown | OCSP.UNKNOWN |
| ocsp-url-no-staple | OCSP.NO-STAPLE (low) |
| crl-only-no-staple | nothing |
| scts-embedded / scts-tls / none-public | none / none / CT.NO-SCTS |
| nosni-expired | CERT.EXPIRED on the no-SNI chain only |
| no-serverauth-eku | CERT.NO-SERVERAUTH |
| public-clientauth | CERT.CLIENTAUTH-EKU |
| lifetime 47 d with 20 d left | nothing |
| lifetime 398 d issued after 2026-03-15 | CERT.LIFETIME |
| private-ca without / with bundle | CERT.UNTRUSTED / trusted by bundle, no lifetime or CT finding |
| trusted by one of two stores | CERT.PARTIAL-TRUST |
| distrusted-after (Mozilla) | partial trust naming the constraint |
| HSTS: absent / max-age=0 / short / duplicate / invalid / full | NO-HSTS / DISABLED / SHORT / INVALID / INVALID / NO-SUBDOMAINS only if missing |
| DH: RFC 7919 prime / RFC 2409 1024-bit prime (report-level) | named, no finding / KX.DH-COMMON-PRIME + Logjam |
| SSLv2 endpoint sharing the leaf key (eval-level, via the index) | VULN.DROWN-SHARED-KEY |
| RSA e=3 | CERT.WEAK-EXPONENT |

## 4. Entry and exit

**Entry:** PRD-004 baselined; handoff and this plan committed with it.

**Exit (T1e):**

- every P0 requirement `done` in the RTM;
- T1-M1…M7 measured and recorded;
- the mutation table recorded;
- `go test ./...`, lint and vet green;
- the journey and `security.sh` green;
- the fuzz runs recorded;
- the legacy fixtures rendered;
- QA-REPORT-003 written with what was not validated.

## 5. Not planned / known limits

- No third-party lookups exist in T1, so OCSP/CRL freshness from the CA, SCT signatures and CT policy counts are not
  validated. They are T2, and the page says so.
- Real-world validation against public servers is not part of automated QA, because hermetic fixtures stand in for
  them. A manual check against a handful of public sites is recorded in the QA report if the owner authorises it.
