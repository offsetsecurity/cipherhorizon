# Methodology: readiness, TLS hygiene and evidence

What the UI and the API report, and exactly how each number is produced. The code is in `internal/eval`
(`readiness.go`, `hygiene.go`, `rules.go`, `citations.go`); this page is the reader's version. Version of the rules:
`eval/2` (shown on every result).

## Evidence tiers

Every fact and finding says how it is known:

| Tier | Meaning |
|---|---|
| `observed` | A server reply demonstrated it (a ServerHello, an alert, a certificate). |
| `inferred` | A consequence of what was observed, not tested directly (for example "POODLE-class" because SSLv3 with CBC suites is accepted). |
| `registry` | Stated by an authoritative registry (the IANA cipher-suite and supported-groups registries, retrieved 2026-09-21). |
| `not-measured` | This product does not measure it. It says so instead of implying it is fine. |

No rule fires without at least one citation; a test (`TestEveryRuleFiresAndIsCited`,
`TestEveryReadinessClaimIsCited`) enforces it.

## PQC readiness (L0 to L4)

**This scale is the project's own. It is not a standard.** Each fact behind a level is cited separately: the
IANA supported-groups registry and RFC 10024 (hybrid key agreement for TLS 1.3), FIPS 203/204 (ML-KEM, ML-DSA),
NIST IR 8547 (draft), and the CISA/NSA/NIST quantum-readiness factsheet for harvest-now-decrypt-later (HNDL).

| Level | Rule | HNDL-exposed |
|---|---|---|
| **?** Undetermined | The scan could not establish whether TLS 1.3 is supported (probes were inconclusive). | no |
| **L0** Not ready | TLS 1.3 is not supported. Post-quantum key exchange in TLS exists only as TLS 1.3 groups. | yes |
| **L1** Exposed | TLS 1.3 works, and no post-quantum group is accepted. | yes |
| **L2** Hybrid available | A standardised hybrid group is accepted, but a current client does not end up using it. | yes |
| **L3** Hybrid negotiated | A current client (Go `crypto/tls`, which offers `X25519MLKEM768` first) negotiates a standardised hybrid group; or the server ranks a hybrid group first. | no |
| **L4** PQ-authenticated | L3, plus a post-quantum certificate (ML-DSA / SLH-DSA). | no |

Notes that matter when reading a result:

- **Obsolete draft groups do not count.** The pre-standard Kyber code points (`0x6399`, `0x639A`) are reported as
  "obsolete" and never raise the level.
- **Only key exchange protects recorded traffic.** Certificates are about future forgery, not about a recording
  made today, so a classical certificate does not stop an endpoint reaching L3; it is shown as a separate
  dimension, and only a post-quantum certificate lifts L3 to L4.
- The overview shows three dimensions (key establishment, authentication, symmetric strength) each with its own
  evidence tier and sources, and an ordered list of next steps.

## TLS hygiene (0 to 100, in five bands)

**This score is the project's own. It is not a standard, and it is not another scanner's rating.** It is deliberately
simple, and it is worked out from nothing but the cited findings on the same result, so every point taken off can be
traced to a finding and every finding carries its sources.

1. Start at **100**.
2. Take off points for each finding, once per distinct problem (two certificates with the same fault are one
   problem), at the finding's worst severity:

   | Severity | Points |
   |---|---|
   | critical | 40 |
   | high | 20 |
   | medium | 10 |
   | low | 4 |
   | info | 0 |

3. Apply a ceiling so a serious problem cannot be averaged away: while any **critical** finding is present the score is
   at most **29**; while any **high** finding is present it is at most **74**.
4. Name the band:

   | Band | Score |
   |---|---|
   | **Strong** | 90 to 100 |
   | **Sound** | 75 to 89 |
   | **Fair** | 55 to 74 |
   | **Weak** | 30 to 54 |
   | **Broken** | 0 to 29 |
   | **Not rated** | no protocol version answered, so there is nothing to rate |

**Post-quantum findings are never counted** (category `pqc`). Readiness answers that question, so a well-configured
endpoint that has not yet adopted post-quantum key exchange scores Strong on hygiene and L1 on readiness, and it is
not marked down twice.

The result lists each deduction (rule ID, title, severity, points), any ceiling that changed the outcome, and what is
**not measured**: live revocation status (the staple is read; the CA is not asked), and active exploit probes
(Heartbleed, ROBOT, CCS injection). HTTP Strict Transport Security is measured by default (the HTTP stage sends one
`GET /`; `--http-checks=false` turns it off, and the HTTP section then says *Not checked* and why). Weaknesses
inferable from what a server offers (POODLE, Sweet32, FREAK, Logjam, CRIME, BEAST, RC4) appear as `inferred`
findings and are scored like any other; an attack name is a label on its finding, so it never counts twice.

The weights are a judgement call made for this project. If your policy weighs things differently, the findings
underneath are unchanged and are the primary output; the score is a summary of them.

`CERT.UNTRUSTED` fires only when **no** bundled root store (Mozilla, Chrome) and **no** private anchor validates the
chain. For internal endpoints, add the private CA to the system's CA bundle (or the server-wide `--ca-bundle`): the
result is re-evaluated at once and reads "trusted by your CA bundle". Private chains are exempt from the public
lifetime limit and the CT requirement. The readiness level is unaffected by trust.

### Rules added in eval/3 (PRD-004)

| Rule | Severity | Fires when | Source |
|---|---|---|---|
| `CERT.CHAIN-INCOMPLETE` | high | only the leaf is served and its issuer is in no store | RFC 8446 §4.4.2, RFC 5246 §7.4.2 |
| `CERT.CHAIN-ORDER` | medium (low if TLS 1.3) | a certificate is not followed by its issuer | RFC 5246 §7.4.2, RFC 8446 §4.4.2 |
| `CERT.CHAIN-EXTRA` | info | a root, duplicate or unrelated certificate is sent | RFC 8446 §4.4.2 |
| `CERT.INTERMEDIATE-EXPIRES` | medium | a served CA expires before the leaf or inside its warning window | RFC 5280 |
| `CERT.LIFETIME` | medium | public, and validity exceeds the limit on its issue date | CA/B Forum BR §6.3.2 (SC-081v3) |
| `CERT.NO-SERVERAUTH` | high | the leaf has an EKU without serverAuth | RFC 5280 §4.2.1.12 |
| `CERT.CLIENTAUTH-EKU` | info | public, and a chain certificate also allows clientAuth | Chrome Root Program Policy |
| `CERT.PARTIAL-TRUST` | medium | some bundled stores trust it and others do not (constraints named) | RFC 5280 §6 |
| `CERT.WEAK-EXPONENT` | low | RSA public exponent below 65537 | CA/B Forum BR §6.1.6 |
| `CERT.NO-SNI-DIFFERENT` | info | without SNI the server presents another certificate (described, never judged as the endpoint's certificate: many sites serve a placeholder there on purpose) | RFC 6066 §3 |
| `OCSP.REVOKED` | critical | the valid stapled response says revoked | RFC 6960 |
| `OCSP.MISMATCH` | high | the staple is for another certificate, unusable, or its signature fails | RFC 6960 §3.2 |
| `OCSP.STALE` | medium | the staple's nextUpdate has passed | RFC 6960 §4.2.2.1 |
| `OCSP.UNKNOWN` | medium | the staple says unknown | RFC 6960 |
| `OCSP.MUST-STAPLE-MISSING` | high | a Must-Staple certificate is served without a staple | RFC 7633 |
| `OCSP.NO-STAPLE` | low | the certificate names an OCSP URL and nothing is stapled (CRL-only raises nothing) | RFC 6066 §8 |
| `CT.NO-SCTS` | medium | public, and no SCT from any of the three sources | RFC 6962, browser CT policies |
| `KX.DH-COMMON-PRIME` | medium | the DHE prime is an RFC-published group of ≤ 1024 bits | Logjam (CVE-2015-4000), RFC 7919 |
| `HTTP.HSTS-DISABLED` / `-SHORT` / `-INVALID` / `-NO-SUBDOMAINS` | medium / low / medium / info | max-age 0 / under one year / syntax or duplicate header / no includeSubDomains | RFC 6797; HSTS preload requirements |
| `CIPHER.CBC` | info | CBC suites in TLS 1.2 or earlier (label LUCKY13) | RFC 9325 §4.2 |
| `VULN.DROWN-SHARED-KEY` | high | the leaf's key is served on an SSLv2 endpoint elsewhere in the estate | CVE-2016-0800 |

`CERT.EXPIRING` now fires at min(30 days, a third of the lifetime) as medium and min(7 days, a tenth) as high, and
names the threshold: a 47-day certificate with 20 days left raises nothing.

### Sections and *Fix first*

Each finding belongs to one section of the endpoint page. A section's status is, first, its scan stage (skipped →
*Not checked*, inconclusive → *Inconclusive*, a report from before `tls-report/2` → *Not collected*), and otherwise
its worst finding: critical or high → *Problem*, medium or low → *Needs attention*, none or info → *Good*. *Fix first*
takes every finding except info, orders it by severity, then by whether it stops clients connecting (expired,
untrusted, name mismatch, missing intermediate, no serverAuth, Must-Staple missing, revoked), then by section order,
and shows the first three distinct rules.

## What a scan sends

A few dozen to a few hundred short TLS handshakes per endpoint (a ClientHello, a read of the server's reply,
close). No application data, no exploit traffic. Concurrency, connection budget and timeouts are bounded
(`--concurrency`, `--timeout`; hard cap of 2000 connections per scan, after which the result is flagged
incomplete). See [tls-scanning.md](tls-scanning.md) for the probe design and known limits.

## Prioritisation: which systems to work on first

`GET /api/v1/estate` ranks systems by four rules applied **in order** (`internal/eval/priority.go`, version `priority/1`; the API returns the rules beside the ranking). There is **no composite score**: each rule decides between two systems only if every earlier rule tied, so any position can be explained in one sentence, and every row lists the facts behind it.

| # | Rule | Reads |
|---|---|---|
| R1 | **Harvest now, decrypt later.** A system with a TLS service whose key exchange a current client negotiates without post-quantum protection ranks first. Among those, systems whose data must stay confidential **past 2030** (the year NIST IR 8547 plans to deprecate classical public-key algorithms) rank above those where the lifetime is unknown or shorter; a longer lifetime ranks higher. No scanned service means exposure is *not known*, which is not the same as safe, and the row says so. | scan readiness (observed); data lifetime (entered) |
| R2 | **Exposure, then criticality.** Internet-facing before internal before restricted; high before moderate before low (the FIPS 199 vocabulary). | entered by a person |
| R3 | **Defects.** The worst severity among the system's current certificate findings (expired, expiring, not yet valid, weak key, broken signature hash, a quantum-vulnerable key outliving 2030 or 2035) and its scans' critical and high findings; then how many. | observed |
| R4 | **How well it is known.** Systems seen by this product's own scanner or collector before systems known only from imported documents; then name. | source classes |

Citations: CISA/NSA/NIST on harvest-now-decrypt-later, NIST IR 8547, RFC 5280, the CA/Browser Forum baseline requirements, NIST SP 800-57. The dates are those documents' dates, used as stated; this product does not predict when a quantum computer will exist.

A system for which nobody has entered exposure, criticality or data lifetime is still ranked, and its row says **"based on evidence only"** and lists what would change its position. Imported evidence ranks a system but is labelled unverified: treat such a position as a lead.
