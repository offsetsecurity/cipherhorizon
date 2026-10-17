# Active TLS/SSL assessment (`cipherhorizon tls scan`)

```sh
cipherhorizon tls scan example.internal:443            # readable report
cipherhorizon tls scan --json host1 host2:8443         # JSON array, one report per target
cipherhorizon tls scan --cbom example.internal:443     # CycloneDX CBOM, one target at a time
```

Scan only systems you own or are authorised to test. A scan makes a few hundred short handshakes.

## What it does

The scanner speaks the protocol itself (`internal/tlsprobe/wire`) instead of linking a TLS library, so it
can offer what `crypto/tls` and OpenSSL never would: SSLv3, SSLv2, export/NULL/anonymous suites, arbitrary
group lists. It works from IANA's registries (`internal/tlsprobe/registry`, generated from the official
CSVs), not from what a library happens to implement.

| Stage | How |
|---|---|
| **Protocol versions** | A hello per version (SSLv2 in its own framing). A server answers with the highest version ≤ the one offered, so "supported" means it answered with exactly that version. |
| **Cipher suites** | Offer every candidate, note the server's pick, remove it, ask again until the server refuses. Yields the full set for each version. |
| **Preference** | Adjacent pairs offered in reverse order. Same pick regardless of order → `server` (and ranks are reported); follows the client → `client`; both → `mixed`. No ranking is ever invented. |
| **TLS 1.3 groups, incl. post-quantum** | A hello with an **empty `key_share`**: a supporting server must answer with a HelloRetryRequest that *names* its chosen group (and cipher suite). No key material is generated. Repeating with the pick removed enumerates every group, including `X25519MLKEM768`, the other ML-KEM hybrids, pure ML-KEM and the obsolete Kyber drafts. |
| **TLS ≤1.2 key exchange** | ECDHE curves the same way, from the ServerKeyExchange; DHE prime size and a fingerprint of the prime. |
| **Signature schemes (TLS 1.3)** | One hello per scheme (ECDSA P-256/384/521, RSA-PSS, Ed25519, Ed448, ML-DSA-44/65/87), each offering only that scheme and carrying real key shares, so the server must pick a certificate before it answers: a ServerHello means it holds a key for that scheme. A control hello offering only a private-use code point must be refused; a server that answers it does not choose by scheme, and the stage is inconclusive. Every TLS 1.3 hello also offers ML-DSA, so a server whose only certificate is ML-DSA is seen. 15 connections. |
| **Server features** | Read from hello extensions: secure renegotiation, extended master secret, tickets, encrypt-then-MAC, OCSP stapling; TLS compression; `TLS_FALLBACK_SCSV` enforcement. |
| **Certificates & "what a real client gets"** | A full handshake with Go's `crypto/tls` (TLS 1.3 encrypts the Certificate message, so raw probes cannot see it), plus ECDSA-only and RSA-only TLS 1.2 handshakes to surface dual certificates, plus one handshake **without SNI** for a named target. Each chain is kept exactly as served (the DER of every certificate, in order), with the stapled OCSP response and the SCTs from the TLS extension. Trust is decided in evaluation, not here (see below). |
| **Revocation & transparency** | No extra connection: the stapled OCSP response and the SCTs ride on the certificate handshakes. No OCSP responder, CRL or CT log is contacted. |
| **HTTP** | One `GET /` over a fresh TLS connection; the `Strict-Transport-Security` header is parsed (RFC 6797 §6.1). On by default; `--http-checks=false` turns it off. |

Each stage is recorded in the report (`stages[]`): `done`, `skipped` (with a reason code: `option-off`,
`not-applicable`, `not-reached`, `budget`) or `inconclusive`, the probes it sent in words, the connections it made,
and what proved nothing. These are the sections of the endpoint page, and its *How we tested* panels.

Every result carries how it was learned: a ServerHello, an alert, a closed connection, or *inconclusive*
(a timeout or network error, which proves nothing). If any probe was inconclusive or hit a limit, the
report says `incomplete` and a missing finding is not evidence of absence.

## PKI depth (`tls-report/2`, evaluation `eval/3`)

Reports are `tls-report/2`, a superset of `/1`. Because the raw certificates, staple and SCTs are stored, the
judgement is made in evaluation and can be redone (`POST /api/v1/scans/{id}/reevaluate`, the **Re-evaluate** button)
when a CA bundle or the reference data changes, without a rescan. The stored report is never rewritten.

| What | How |
|---|---|
| **Chain as served** | Analysed in served order: certificates out of order (TLS 1.2 requires the order, TLS 1.3 tolerates it), a root, duplicate or unrelated certificate sent, size in bytes. A **missing intermediate** is reported when only the leaf was served and its issuer is in no store; the AIA URL the certificate names is shown, never fetched. When the served path already ends at a CA certificate, the unknown issuer is reported as an unknown (often private) root instead. |
| **Trust per store** | Path validation against bundled, dated snapshots of the **Mozilla** and **Chrome** root stores (CCADB), each reported separately, with the stores' own constraints: Mozilla's *distrust for TLS after*, Chrome's `sct_not_after`, program name constraints. Only the served certificates are intermediates: no AIA fetching, no system pool. A **private CA bundle** (server-wide `--ca-bundle FILE`, and per system on the system page) adds a "your CA bundle" row. The machine's own store is an optional extra (`--os-trust` on the CLI), off by default because some OS verifiers fetch missing intermediates from the network. |
| **Names** | The host against the DNS and IP SANs (never the CN, RFC 9525), stating which SAN matched. |
| **Lifetime** | Against the limit in force on the issue date (SC-081v3: 398 days, 200 from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15), for publicly trusted chains only. The expiry warning scales with the lifetime. |
| **OCSP staple** | Decoded by our own bounded parser: response and certificate status, revocation time and reason, this/next update, responder; the signature is checked against the issuer or a delegated responder; the response must be for this certificate (serial and issuer hashes). |
| **CT** | SCTs from all three places (embedded, TLS extension, OCSP), each with its log named from the bundled CT log list. Signatures are not verified in this version. |
| **DH groups** | The DHE prime fingerprint is matched against the RFC 2409, 3526, 5114 and 7919 groups. |
| **Attack names** | Published attacks are labels on the finding that enables them (FREAK, Logjam, DROWN, POODLE, BEAST, SWEET32, CRIME, LUCKY13, RC4), never second findings. A key served on an SSLv2 endpoint anywhere in the estate is reported on every endpoint that serves it (DROWN). Active-only attacks (Heartbleed, CCS injection, ROBOT, Ticketbleed, padding oracles) are listed as *not tested by design*. |

The reference lists, their sources, dates and licences are in [reference-data.md](reference-data.md).

## Observations, not verdicts

The report states facts and the IANA registry's own flags (`Recommended: Y/N/D`), export/anonymous/NULL
properties, block size. It does **not** say "weak" or "vulnerable" or "quantum-safe"; `internal/eval` does
that (readiness level, TLS hygiene score, findings), from the same facts, and cites its sources.

## CBOM export (`--cbom`)

`cipherhorizon tls scan --cbom HOST[:PORT]` turns one scan into a CycloneDX CBOM instead of a text or JSON
report (CycloneDX 1.7 by default; `--spec 1.6` for 1.6). The subject (`metadata.component`, a `device` named `host:port`) depends on one `protocol` component per
supported TLS version, each with its accepted cipher suites, and on one `certificate` component per certificate the
server presented. Below those hang the `algorithm` components they reference: each bulk cipher as a key-size-and-mode
variant (`AES-128-GCM`, not just `AES`) or, for legacy suites, `3DES`, `RC4` and `DES` with their classical status;
each key-exchange group (`ECDH-P256` for secp256r1, `X25519`, `X448`), and the post-quantum hybrids (`X25519MLKEM768` and
the two other RFC 10024 groups get a `combiner`-primitive component and a cited PQC verdict). A certificate points at
its public key, a `related-crypto-material` component with its size, which points at `RSA-2048` or `ECDSA-P256`, and at
its exact signature algorithm with its OID (`ecdsa-with-SHA256`, `sha256WithRSAEncryption`). It
takes exactly one target, since a CBOM has one subject.

An edge below a protocol means the endpoint *accepts* that suite or group; what a current client actually
negotiated is flagged `cipherhorizon:negotiated`. The full model, and which parts are CycloneDX and which are ours,
is in [cbom-model.md](cbom-model.md).

This is the same builder (`internal/cbom.FromTLSReport`) and the same PQC annotation pass
(`internal/pqc.Analyze`/`Annotate`) a host inventory's CBOM gets, so an algorithm's quantum-vulnerable /
quantum-safe verdict is the identical, cited classification either way — it is a fact about the algorithm, not
about which side of the wire found it. What is *not* in the CBOM: the readiness level, the TLS hygiene score,
and findings. Those are the evaluation's job and stay in `internal/eval`'s output (`--json`), the same
CBOM-carries-facts-only line a host inventory already draws. A cipher or curve with no catalogue entry (a
legacy cipher such as RC4, a named curve this program does not carry an OID for, a hybrid group backed only by
an internet-draft) is still named in the suite text or certificate; it simply gets no algorithm reference
rather than an invented one.

## Safety

- Every connection goes through one gate: a concurrency cap (default 4), an optional minimum spacing
  (`--min-interval`), a per-connection timeout, and a **hard connection budget** (`--max-connections`,
  default 2000). When the budget runs out the scan stops and is marked incomplete.
- Only handshake messages are exchanged: no application data, no exploit payloads. The one exception is the
  HTTP stage, **on by default since PRD-004** (`--http-checks=false` turns it off, on `tls scan` and server-wide on
  `serve`): a single plain `GET /` after the handshake, reading at most 8 KiB for the `Strict-Transport-Security`
  header; nothing else acts on the response and no redirect is followed.
- A scan contacts **only the target**: one name lookup and connections to the one address. Nothing is fetched from
  a CA, OCSP responder, CRL or CT log. A test with a recording dialer enforces this (`TestTargetOnlyTraffic`).
- The wire parsers treat the peer as hostile: every length is bounds-checked and capped, and they are fuzzed
  (`go test ./internal/tlsprobe/wire -fuzz FuzzReadFlight`). Oversized fields when *building* a hello are
  errors, never silently truncated lengths.

## Known limits

- One address per name (the first IPv4, else the first); the others are listed in the report.
- Direct TLS only; STARTTLS (SMTP, IMAP, ...) is planned.
- Suites are enumerated as usable **with the server's certificates**: a suite the server enables but cannot
  use (say ECDHE-ECDSA with only an RSA certificate) is not selectable and so is not listed.
- If a server does not answer an empty `key_share` with a HelloRetryRequest, TLS 1.3 groups cannot be
  enumerated; the report says so and the "negotiated" section still shows what a real client gets.
- Post-quantum *certificates* (ML-DSA) cannot be handshaken with by Go's `crypto/tls`. They are identified by
  OID when parseable, but a server presenting only such a chain will not yield a certificate result yet.
- DH: the prime is matched against the RFC-published groups only; widely shipped non-RFC defaults are not
  recognised (no licence-clear list of them exists).
- Revocation and CT are judged from what the server sends: no live OCSP/CRL lookup, no SCT signature check, no
  count against a browser CT policy. These are planned as options, off by default.
- Behavioural vulnerability probes (Heartbleed, ROBOT, CCS injection) are not implemented; when they are,
  they will be off by default.

## Regenerating the registries

The tables in `internal/tlsprobe/registry` are generated, never edited. The generator refuses any cipher-suite
name it cannot decompose, so a new IANA entry forces a decision instead of getting silently wrong properties.

```sh
# fetch tls-parameters-4.csv (Cipher Suites) and tls-parameters-8.csv (Supported Groups) from
# https://www.iana.org/assignments/tls-parameters/ , then:
go run ./internal/tlsprobe/registry/gen -suites tls-parameters-4.csv -groups tls-parameters-8.csv \
    -retrieved YYYY-MM-DD -out internal/tlsprobe/registry
```

`registry_test.go` cross-checks the result against `crypto/tls` (every suite Go implements must appear with
the identical name and code point).
