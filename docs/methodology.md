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
**not measured**: certificate revocation status, and active exploit probes (Heartbleed, ROBOT, CCS injection). HTTP
Strict Transport Security is measured only when `--http-checks` is explicitly enabled (off by default): every other
check in this tool exchanges only TLS handshake messages, and this is the one exception, so it is opt-in and never
silent. Weaknesses inferable from what a server offers (POODLE,
Sweet32, FREAK, Logjam, CRIME, BEAST, RC4) appear as `inferred` findings and are scored like any other.

The weights are a judgement call made for this project. If your policy weighs things differently, the findings
underneath are unchanged and are the primary output; the score is a summary of them.

Private-CA and self-signed certificates produce the high-severity finding `CERT.UNTRUSTED` (the chain does not build
to the operating system's trust store), which is expected for internal endpoints; the readiness level is unaffected.

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
