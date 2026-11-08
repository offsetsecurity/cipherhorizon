# PRD-018 · Client simulation

| | |
|---|---|
| Date | 2026-11-09 |
| Status | Built with PRD-017 for 0.5.0 |
| Source | STRATEGY-004 §2 item 2 and CRYPTO-REVIEW-005 §7 item 1 (the most-asked operational question; the most visible gap against SSL Labs); RESEARCH-004 §J |
| Where it shows | `docs/clients.md`, the Clients tab, the Summary, the PDF, the CLI, `clients[]` in the evaluation |

## 1. Problem

Every change to a TLS configuration is a compatibility question first: *if we turn off TLS 1.2, drop RSA
certificates, or prefer a hybrid key exchange, which clients stop connecting?* SSL Labs answers it with a
handshake simulation table and it is the most consulted part of its report. CipherHorizon enumerated everything the
server accepts but never said what a given client would get.

## 2. Users and stories

| Who | Story | Done when |
|---|---|---|
| Platform engineer | "Before I remove TLS 1.2 from the gateway, show me which of our clients break." | The Clients tab lists every client that cannot connect, with the reason, and the CLI prints them. |
| PQ programme owner | "Which clients already get post-quantum key exchange from this server, and which only after a retry?" | The post-quantum and retry marks per client; the Summary line counts them. |
| Support engineer | "A customer on Java 8 cannot connect; is it the server?" | The Java 8 row says what it negotiates or why it fails (no x25519, a DH limit, an RSA-only certificate). |

## 3. Requirements

| ID | Requirement |
|---|---|
| REQ-CLI-1 | Every TLS evaluation carries, per named client: connects or not; version, suite, group; forward secrecy; post-quantum; HelloRetry; who decided the suite; default-certificate when the client sends no server name; the failure reason in words. |
| REQ-CLI-2 | Computed from the scan: no connection is made. A scan whose protocol or suite stage did not run yields no simulation, never an invented one. |
| REQ-CLI-3 | Profiles are the vendors' published defaults, each naming its source and release date and noting update-dependent behaviour; every suite and group name is checked against the IANA registry by a test. |
| REQ-CLI-4 | The simulation honours the deciding side (server rank or client order), the client's key-exchange limits (curves, DH size), its certificate constraints (signature algorithms, minimum RSA size, SHA-1), and an ML-DSA-only server. |
| REQ-CLI-5 | Surfaces: a Clients tab (grouped by family, a filter for failing or non-forward-secrecy clients, CSV), a Summary card with a bar and the failing names, a PDF page, a CLI block with `--details`, a Help topic. |
| REQ-CLI-6 | SSH reports have no Clients tab (the SSH negotiation as OpenSSH already answers it). |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | Simulate, do not replay client hellos. | The enumeration already holds every acceptance fact; a replay per client costs 24 handshakes per scan and adds nothing the intersection does not know, except intolerance bugs, which are rare and would be a separate probe. |
| D2 | Two dozen clients across five families, newest first, with the legacy clients people still ask about. | Enough to answer the migration question; small enough to read. More come as profiles. |
| D3 | Profiles are defaults with sources, not captures. | Honest about what they are; a capture library is a later improvement and the doc says so. |
| D4 | Trust is not simulated. | Whether the client's store trusts the chain is the Certificates section's question, already answered per root program. |

## 5. QA

`clients_test.go`: every profile's names exist in the registry; on the modern fixture Chrome gets TLS 1.3 with
X25519MLKEM768, Safari 17 X25519 without retry, Java 8 fails on groups and says so, Java 6 fails on the version; on
a static-RSA-first server a server-order client gets the server's favourite without forward secrecy; Java 7 fails a
2048-bit DHE prime by name; an ML-DSA-only server fails classical clients with the right reason; a client without
SNI is told it gets the default certificate; a scan without a suite enumeration yields no simulation.
