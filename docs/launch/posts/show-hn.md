# Show HN draft

**Title:** Show HN: CipherHorizon, a self-hosted post-quantum readiness scanner for TLS endpoints

**URL:** `<repo>`

**Text:**

Hi HN. We built CipherHorizon at Offset Security because our post-quantum readiness work kept starting with the
same question: which of this organisation's endpoints would leak recorded traffic to a future quantum computer, and
which machines carry quantum-vulnerable crypto? The answer usually lived in spreadsheets and one-off testssl.sh runs.

It's a single Go binary with an embedded web UI and SQLite. You give it addresses; it does a full TLS scan with its
own wire implementation (SSLv2 to TLS 1.3, every suite and group, including the hybrid X25519MLKEM768) and gives
each endpoint:

- a readiness level from L0 (no TLS 1.3, so no PQ key exchange possible) to L4 (PQ key exchange and certificate);
- a TLS hygiene score with the arithmetic shown;
- the checks it ran, each passed or failed with its source.

It also speaks STARTTLS for SMTP, IMAP, POP3, FTP, XMPP, LDAP and Postgres. Two small readable scripts
(PowerShell and sh) inventory a machine, and everything merges into one CycloneDX CBOM.

Things we decided not to do:
- **No exploit traffic.** No Heartbleed or ROBOT probes; use testssl.sh for those.
- **No letter grades.** The score and levels are our own, documented, and not meant to imitate SSL Labs.
- **No network calls** beyond the scans you start, and no telemetry.

The CLI is meant for CI: `cipherhorizon tls scan --fail-on 'level<L3' api.example.com` exits 3 when an endpoint
loses its post-quantum key exchange.

It's Apache 2.0. We'd especially like feedback on the readiness levels and on findings you think are wrong.
