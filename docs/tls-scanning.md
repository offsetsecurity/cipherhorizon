# Active TLS/SSL assessment (`cbom-scan tls scan`)

```sh
cbom-scan tls scan example.internal:443            # readable report
cbom-scan tls scan --json host1 host2:8443         # JSON array, one report per target
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
| **Server features** | Read from hello extensions: secure renegotiation, extended master secret, tickets, encrypt-then-MAC, OCSP stapling; TLS compression; `TLS_FALLBACK_SCSV` enforcement. |
| **Certificates & "what a real client gets"** | A full handshake with Go's `crypto/tls` (TLS 1.3 encrypts the Certificate message, so raw probes cannot see it), plus ECDSA-only and RSA-only TLS 1.2 handshakes to surface dual certificates. Trust and host-name are checked *after* the handshake, so bad certificates are reported, not refused. |

Every result carries how it was learned: a ServerHello, an alert, a closed connection, or *inconclusive*
(a timeout or network error, which proves nothing). If any probe was inconclusive or hit a limit, the
report says `incomplete` and a missing finding is not evidence of absence.

## Observations, not verdicts

The report states facts and the IANA registry's own flags (`Recommended: Y/N/D`), export/anonymous/NULL
properties, block size. It does **not** say "weak" or "vulnerable" or "quantum-safe"; the evaluation layer
(next milestone) does, and cites its sources.

## Safety

- Every connection goes through one gate: a concurrency cap (default 4), an optional minimum spacing
  (`--min-interval`), a per-connection timeout, and a **hard connection budget** (`--max-connections`,
  default 2000). When the budget runs out the scan stops and is marked incomplete.
- Only handshake messages are exchanged: no application data, no exploit payloads.
- The wire parsers treat the peer as hostile: every length is bounds-checked and capped, and they are fuzzed
  (`go test ./internal/tlsprobe/wire -fuzz FuzzReadFlight`). Oversized fields when *building* a hello are
  errors, never silently truncated lengths.

## Known limits (M1)

- One address per name (the first IPv4, else the first); the others are listed in the report.
- Direct TLS only; STARTTLS (SMTP, IMAP, ...) is planned.
- Suites are enumerated as usable **with the server's certificates**: a suite the server enables but cannot
  use (say ECDHE-ECDSA with only an RSA certificate) is not selectable and so is not listed.
- If a server does not answer an empty `key_share` with a HelloRetryRequest, TLS 1.3 groups cannot be
  enumerated; the report says so and the "negotiated" section still shows what a real client gets.
- Post-quantum *certificates* (ML-DSA) cannot be handshaken with by Go's `crypto/tls`. They are identified by
  OID when parseable, but a server presenting only such a chain will not yield a certificate result yet.
- DH: prime size and fingerprint only; matching against the well-known RFC 7919 groups is not implemented.
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
