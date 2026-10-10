# RESEARCH-004 — The TLS scanner: what to collect, how to collect it, and how to show it

Status: research and plan, 2026-10-02. **No code is changed by this document.** It is the input to a PRD for the next
round of scanner work. Scope is the remote TLS scanner only; the host collector and CBOM import are separate
reviews to follow.

Earlier work this builds on: [RESEARCH-002](RESEARCH-002-pqc-tls-cbom-landscape.md) (the PQC/TLS/CBOM tool
landscape, and why single-probe scanners under-report hybrid PQC), [PRD-002](PRD-002-evidence-and-coverage.md)
(evidence and coverage, mTLS detection, the HSTS check) and [docs/tls-scanning.md](../tls-scanning.md) (how the
scanner works today).

Constraints carried forward, not reopened here:

- **Our own terminology.** No letter grades, no "A+", no borrowed rating vocabulary. The rating is the
  *TLS hygiene score*; post-quantum posture is the *readiness level* L0–L4.
- **Observations, then verdicts.** The scanner records facts with how each was learned; `internal/eval` judges
  them and cites a source for every judgement.
- **Gentle and bounded by default.** Handshakes only, a connection budget, no exploit traffic unless a person
  explicitly asks for it.
- **Nothing leaves the machine unless asked.** Any check that contacts a third party (a CA's OCSP responder, a CT
  log, DNS) must be visible as such and switchable.

---

## 1. What the scanner does today

### 1.1 Collected

| Area | Collected today | How | Gap |
|---|---|---|---|
| Target | One address per name (first IPv4); the other addresses are listed | DNS lookup | Other addresses are never scanned, so a load-balanced pool with one bad node looks clean |
| Protocols | SSLv2 to TLS 1.3, each with evidence (hello / alert / closed / inconclusive) | Own wire stack, one hello per version | No QUIC/HTTP-3 discovery |
| Cipher suites | Every accepted suite per version, server or client preference, rank | Offer all, remove the pick, repeat; adjacent-pair swaps for order | Only suites usable with the certificates the server has (documented limit) |
| Key exchange | TLS 1.3 groups incl. ML-KEM hybrids and obsolete Kyber drafts; TLS ≤1.2 ECDHE curves; DHE prime size + fingerprint | Empty `key_share` → HelloRetryRequest names the group | DH prime not matched to the RFC 7919 or well-known weak primes; no key-share reuse check |
| Signature algorithms | — | — | Not enumerated: which signature schemes the server will sign with (SHA-1 handshake signatures, RSA-PSS) is unknown |
| Features | Secure renegotiation, EMS, session tickets (offered), encrypt-then-MAC, OCSP stapling (offered), compression, `TLS_FALLBACK_SCSV`, client certificate requested (mTLS) | Hello extensions | Resumption is never actually *tried*; 0-RTT, ALPN list, client-initiated renegotiation, heartbeat extension, ECH, version/extension intolerance are not tested |
| Certificates | Default chain + ECDSA-only and RSA-only chains; subject, SANs, issuer, serial, validity, key, signature, OCSP/CRL/AIA URLs, must-staple flag, "has embedded SCTs" flag | Go `crypto/tls` full handshake (TLS 1.3 encrypts the Certificate message) | No no-SNI certificate; no chain-as-served analysis (order, missing or extra certificates); ML-DSA chains cannot be handshaken with `crypto/tls` |
| Trust | Trusted yes/no + error; name match yes/no + error | `x509.Verify` against the **operating system** store of the machine running the scan | One store, and whichever one the scanning machine happens to have; no custom/private CA bundle; no distrusted-CA knowledge |
| Revocation | "a stapled OCSP response was present" | `ConnectionState.OCSPResponse` non-empty | The stapled response is never parsed (status, freshness, signer); no OCSP or CRL lookup |
| Certificate Transparency | "has embedded SCTs" | Extension present | SCTs in the TLS extension or OCSP are not read; SCTs are not counted, attributed to logs or verified |
| HTTP | HSTS present yes/no | One `GET /` after the handshake, **off by default** (`--http-checks`) | `max-age`, `includeSubDomains`, `preload` not parsed; no preload-list status; no HTTP→HTTPS redirect check |
| DNS PKI controls | — | — | No CAA, TLSA/DANE or HTTPS/SVCB records |
| Vulnerabilities | Inferred only: SSLv2/3, POODLE, BEAST, SWEET32, RC4, export, NULL, anonymous, small DH, compression | From the enumeration | No behavioural probes (by design); DROWN, FREAK, Logjam, LUCKY13, Raccoon not named even where inferable |
| Client view | What one client gets: Go `crypto/tls` (offers X25519MLKEM768 first) | Full handshake | No simulation of other real clients (old Android, Java 8, iOS, Windows) |
| Non-HTTPS services | Direct TLS only | — | No STARTTLS (SMTP, IMAP, POP3, LDAP, Postgres, ...) although `Options.Dial` was designed to take it |

36 findings exist today (`PROTO.*`, `CIPHER.*`, `KX.DH-SMALL`, `FEAT.*`, `CERT.*` ×8, `HTTP.NO-HSTS`, `VULN.BEAST`,
`VULN.POODLE`, `PQC.*` ×7).

### 1.2 How it is shown

The endpoint page has four tabs: **Overview** (readiness card + hygiene card), **TLS details** (one long stack of
cards: protocols, a cipher-suite table per version, groups, DH, server features, certificate chain, negotiated,
notes), **Findings**, **History**.

What makes results feel buried:

1. **Findings are separated from the data they are about.** A problem with a suite lives in the Findings tab;
   the suite table in TLS details shows the suite with no finding next to it. A reader has to cross-reference.
2. **No section says what it checks or why it matters.** "Server features" is a table of RFC numbers; a reader
   who does not already know what encrypt-then-MAC is gets nothing from it.
3. **"Not checked" is invisible.** If HSTS was not checked (the default) or OCSP stapling was not offered, the row
   is simply absent. Absent reads as "fine".
4. **No per-section status.** Nothing tells you *which* of the ten cards is the one with the problem without
   reading all of them.
5. **Certificates are one card among many,** although certificate problems (expiry, trust, name) are the ones
   that take a site down. Trust is a single yes/no with no indication of *which* store.
6. **Everything is equally loud.** Fifteen acceptable cipher suites take as much space as the one RC4 suite.

---

## 2. What other scanners do

### 2.1 The reference tools

**Qualys SSL Labs — SSL Server Test** (hosted, closed engine). The report is laid out as a summary, then
**Certificate** (each certification path, per trust store, with chain issues), then **Configuration** (protocols,
cipher suites per protocol, **handshake simulation** for dozens of real clients), **Protocol details** (renegotiation,
resumption, OCSP stapling, HSTS, the vulnerability checks) and miscellaneous HTTP facts. It scans **every address**
a name resolves to. Its rating guide, currently **2009r (16 May 2025)**, weights protocol support 30 %, key exchange
30 %, cipher strength 40 %, zeroes the score for any certificate problem, and caps results for: no TLS 1.3, no
forward secrecy, no AEAD suites, TLS 1.0/1.1, DH under 2048 bits, and missing or short HSTS; the top result needs
HSTS with `max-age` of at least six months. `TLS_FALLBACK_SCSV` no longer affects it.
*What to take:* the separation of certificate / configuration / protocol details; handshake simulation; per-IP
scanning; which defects the industry treats as disqualifying. *What not to take:* its vocabulary and grade bands.

**sslyze** (Python library + CLI; handshakes through **nassl**, its own OpenSSL bindings built in a modern and a
legacy flavour). Organised as independent **scan commands**: certificate info, one per protocol version's cipher
suites (SSL 2.0 to TLS 1.3), elliptic curves, ROBOT, Heartbleed, OpenSSL CCS injection, TLS compression, session
resumption (session IDs and tickets), session renegotiation (secure and client-initiated), TLS 1.3 early data,
`TLS_FALLBACK_SCSV`, extended master secret, HTTP headers. **Certificate info** validates against several trust
stores (Mozilla, Apple, Android, Java, Windows), reads the **stapled OCSP response**, checks **must-staple**,
**SCTs** and EV. STARTTLS for SMTP, XMPP, LDAP, POP3, IMAP, RDP, PostgreSQL, FTP. JSON output, usable as a library.
*What to take:* the scan-command decomposition (each check independently runnable and reportable), multi-store trust,
OCSP response parsing, resumption actually attempted.

**testssl.sh** (bash; handshakes via OpenSSL **and** its own bash-socket implementation so it is not limited by the
OpenSSL it finds; 3.2 stable, 3.3 in development). The most exhaustive open checklist:

- protocols incl. QUIC detection, NPN, ALPN;
- cipher categories (NULL, anonymous, export, LOW, 3DES/IDEA, obsolete CBC, AEAD without forward secrecy, forward-secret AEAD), server preference;
- server defaults: TLS extensions, ticket lifetime, session ID, resumption, 0-RTT, **clock skew**;
- certificate: signature, key, KU/EKU, serial, fingerprints, CN/SAN, issuer, validity, EV, chain of trust against **five stores**, custom CA, CRL/OCSP URIs, stapling, must-staple, revocation status (only with `--phone-out`), **CAA**, CT, **SNI vs no-SNI** certificate;
- HTTP headers: HSTS incl. **preload status**, HPKP, banners, cookies' Secure/HttpOnly, security headers;
- vulnerabilities: Heartbleed, CCS injection, Ticketbleed, ROBOT, STARTTLS injection, secure and client-initiated renegotiation, CRIME, BREACH, POODLE, fallback SCSV, SWEET32, FREAK, DROWN, Logjam, BEAST, LUCKY13, Winshock, RC4, Opossum, GREASE tolerance;
- **client simulation** (~126 clients, ~25 by default);
- STARTTLS for 14 protocols;
- output as text, CSV, JSON, HTML.

*What to take:* the checklist itself (it is the most complete public statement of "what a TLS assessment means"),
SNI vs no-SNI, clock skew, the explicit `--phone-out` gate for third-party lookups.

**Also relevant** (from prior knowledge; not re-verified in this session):

- **nmap `ssl-enum-ciphers`** has its own Lua TLS implementation and enumerates per version.
- **ZGrab2/zcrypto** (Go) is Internet-scale: one handshake per target, very rich certificate parsing.
- **zlint** lints certificates against the CA/Browser Forum Baseline Requirements and RFC 5280.
- **CryptoLyzer** (Python) uses its own implementation and also covers SSH and DNS records.
- **Mozilla's server-side TLS guidelines** and config generator define Modern and Intermediate *profiles*; their v6 refresh lists X25519MLKEM768 among recommended groups (verify the exact profile contents before relying on them).
- **Internet.nl** is the Dutch government test, built on the NCSC-NL TLS guidelines. It is the best precedent for the UI goal here: every sub-test has a plain explanation of what it checks, the levels it can come out at (good / sufficient / phase out / insufficient), and technical details underneath.
- **Hardenize** is commercial: continuous monitoring of TLS, PKI, CT and DNS together.

### 2.2 How they scan, and what that means for us

| Approach | Who | Strength | Weakness |
|---|---|---|---|
| Linked TLS library | sslyze (nassl), testssl.sh (openssl) | Real-world handshake behaviour; full TLS 1.3 handshake for free | Limited to what the library can offer; needs a "legacy" build for SSLv2/export |
| Own wire implementation | **CipherHorizon**, SSL Labs, nmap, testssl.sh's sockets | Can offer anything (SSLv2, export, arbitrary groups, empty key_share) | Must implement each new protocol feature itself |
| Mixed | **CipherHorizon** (own wire for enumeration, Go `crypto/tls` for full handshakes) | Best of both for common cases | `crypto/tls` decides what the full handshake can see: no ML-DSA certificate chains, no stapled-OCSP-per-certificate in TLS 1.3, no control over sigalgs |

Our approach is right. The plan below keeps it and adds **one** capability to the own stack: a complete TLS 1.3
handshake (key schedule + decrypting EncryptedExtensions, Certificate, CertificateVerify). That removes the
dependence on `crypto/tls` for seeing certificates, lets us read per-certificate TLS 1.3 extensions (stapled OCSP, SCTs),
handshake with ML-DSA chains, and enumerate signature algorithms.

The PQ lesson of RESEARCH-002 §3.1 still holds and generalises: **a capability is only observed if a probe offers
it**. Every new check below states which probe offers what.

### 2.3 Capability matrix

✅ yes · ◐ partial · — no. "Ours" is today.

| Capability | SSL Labs | sslyze | testssl.sh | Ours |
|---|---|---|---|---|
| Every IP of a name | ✅ | — | ◐ (opt) | — |
| Protocols / suites / preference | ✅ | ✅ | ✅ | ✅ |
| TLS 1.3 groups incl. PQ hybrids, reliably | ◐ | ◐ | ◐ | ✅ |
| Signature algorithms | ◐ | — | ◐ | — |
| Multi-store trust | ✅ | ✅ | ✅ | — |
| Custom/private CA | — | ✅ | ✅ | — |
| Served-chain issues | ✅ | ◐ | ◐ | — |
| Stapled OCSP parsed | ✅ | ✅ | ✅ | — |
| OCSP/CRL lookup | ✅ | — | ◐ (opt-in) | — |
| SCTs | ✅ | ✅ | ✅ | ◐ |
| CAA | ◐ | — | ✅ | — |
| SNI vs no-SNI | ✅ | — | ✅ | — |
| Resumption / 0-RTT tried | ✅ | ✅ | ✅ | — |
| HSTS parsed + preload | ✅ | ✅ | ✅ | ◐ |
| Client simulation | ✅ | — | ✅ | ◐ (one client) |
| STARTTLS | — | ✅ | ✅ | — |
| Behavioural vuln probes | ✅ | ✅ | ✅ | — (by design) |
| Profile compliance | — | ✅ (Mozilla) | — | — |
| Evidence per fact, cited verdicts | — | — | — | ✅ |
| Fleet, history, diff, CBOM | — | — | — | ✅ |

The last two rows are what nobody else does; the rest is catching up on the PKI side.

---

## 3. The 2025–2026 PKI context the checks must reflect

These change what "good" means, and a scanner that checks 2020's rules will raise wrong findings:

- **OCSP is being retired by the largest CA.** Let's Encrypt stopped putting OCSP URLs in certificates on
  7 May 2025 and turned its responders off on **6 August 2025**; it publishes CRLs instead, and Must-Staple requests
  now fail. So "no OCSP stapling" is no longer a defect by itself. It matters only when the certificate *names* an
  OCSP responder, and a Must-Staple certificate without a staple is a hard failure.
- **Certificate lifetimes are shrinking** (CA/Browser Forum ballot SC-081v3). The maximum is 398 days before
  15 Mar 2026, 200 days from then, **100 days from 15 Mar 2027** and **47 days from 15 Mar 2029**. A lifetime check
  must use the limit in force on the certificate's issue date. Expiry warnings should scale to lifetime (a 47-day
  certificate with 25 days left is normal).
- **Public TLS hierarchies are becoming serverAuth-only** (Chrome Root Program Policy v1.8). New intermediates
  must be serverAuth-only from 15 Jun 2026, and new leaves from 15 Mar 2027. A public certificate used for **mTLS
  client auth** will stop being obtainable; that is worth telling people who use `clientAuth` EKUs today.
- **Encrypted Client Hello is a standard**: RFC 9849 (March 2026). Its presence (via the DNS HTTPS record and the
  server's `encrypted_client_hello` handling) is a modern-posture fact worth reporting.
- **Distrust events happen.** Browsers remove CAs (e.g. the 2024 Entrust distrust). Trust must be judged against
  *dated* root-store snapshots, with "trusted by the OS of the scanning machine" never presented as the answer.
- **PQ.** Hybrid key exchange (X25519MLKEM768) is mainstream in browsers; ML-DSA certificates are not yet issued by
  public CAs. Both stay covered by the readiness level.

---

## 4. The complete catalogue: what to collect

Each item: **what**, **why it matters**, **how** (and whether it costs extra connections or contacts a third party),
**priority** (P0 next round, P1 after, P2 later), **status** today.

Traffic classes:

- **H**: handshakes only, to the target.
- **A**: application data to the target (one HTTP request).
- **X**: contacts a third party (a CA, a CT log, DNS beyond the A/AAAA lookup).
- **E**: exploit-like traffic.

### A. Reachability and identity of the target

| Item | Why | How | Pri | Now |
|---|---|---|---|---|
| All A/AAAA addresses, scan each (option) | Pools behind one name are often inconsistent; IPv6 is often forgotten | H, per address; "first address only" stays the default for speed | P1 | ◐ |
| Consistency sampling | Different backends behind one IP | Repeat the negotiated handshake *n* times; compare cert and suite | P2 | — |
| No-SNI certificate | Clients without SNI, scanners, misrouted vhosts get a different (often expired/default) cert | H, one handshake without SNI | P0 | — |
| Clock skew | Bad server time breaks tickets/OCSP freshness | `gmt_unix_time` in ServerHello (TLS ≤1.2), HTTP `Date` | P2 | — |
| STARTTLS | Mail, directory and database TLS is where weak configs live | H after a protocol-specific preamble (SMTP, IMAP, POP3, FTP, XMPP, LDAP, PostgreSQL, MySQL, RDP); `Options.Dial` is the hook | P1 | — |
| QUIC/HTTP-3 advertised | Shows a TLS-1.3-only path exists | `Alt-Svc` header (A) or HTTPS DNS record (X); no QUIC probing | P2 | — |
| Middlebox/interception hint | A corporate TLS proxy in the path makes the whole result about the proxy | Issuer is a known inspection CA, or the cert differs from a second vantage | P2 | — |

### B. Protocol versions

SSLv2 to TLS 1.3 per version (have). Add **version intolerance** (a hello offering a future version or a large one
must still be answered), **GREASE tolerance** (RFC 8701 values must be ignored) — both are compatibility facts that
break real clients. P1, H.

### C. Cipher suites

Have: full enumeration, preference, rank. Add the **categories** a person reasons in (forward secrecy, AEAD,
CBC, 64-bit block, export, anonymous, NULL), as a summary above the table rather than a column readers must scan.
Add a **ChaCha20 preference** check (server prioritises ChaCha20 when the client prefers it, RFC 7905 practice for
mobile). P0 summary / P2 ChaCha. H.

### D. Key exchange

| Item | Why | How | Pri | Now |
|---|---|---|---|---|
| TLS 1.3 groups incl. PQ hybrids, pure ML-KEM, obsolete drafts | Readiness level | Empty key_share → HRR | — | ✅ |
| ECDHE curves for TLS ≤1.2 | | ServerKeyExchange | — | ✅ |
| FFDHE: named groups (RFC 7919) and well-known primes | Logjam: shared 1024-bit primes; known-weak primes | Match `primeSha256` against RFC 7919, RFC 3526 and the published weak-prime list | P0 | ◐ |
| HRR behaviour | Some servers fail on HRR (a real interop bug) | Already observed during enumeration; report it | P1 | ◐ |
| Ephemeral key reuse | Same (EC)DHE public value across handshakes defeats forward secrecy (Raccoon class) | Compare server key shares across handshakes already made | P1 | — |

### E. Signature algorithms (new)

| Item | Why | How | Pri |
|---|---|---|---|
| Schemes the server will sign with | SHA-1/MD5 handshake signatures; RSA-PKCS1 vs PSS; the ML-DSA readiness path | Offer one scheme at a time in `signature_algorithms`; record accept/alert (TLS 1.2 via ServerKeyExchange; TLS 1.3 needs our own full handshake) | P1 |
| Certificate selected per scheme | Dual-cert servers pick by sigalgs | Same probes | P1 |

### F. Extensions, session behaviour, features

| Item | Why | How | Pri | Now |
|---|---|---|---|---|
| Secure renegotiation | | | — | ✅ |
| **Client-initiated renegotiation** | DoS amplification; legacy attack surface | H: request a renegotiation on an established TLS 1.2 session; no app data | P1 | — |
| EMS, encrypt-then-MAC | | | — | ✅ |
| **Session resumption actually works** (IDs, tickets, TLS 1.3 PSK) | Offered ≠ works; performance; ticket key rotation | H: resume with what the first handshake gave | P1 | ◐ (offered only) |
| Ticket lifetime hint | Very long lifetimes weaken forward secrecy | NewSessionTicket | P1 | — |
| **0-RTT** accepted | Replay risk for non-idempotent requests | `max_early_data_size` in the ticket; optionally offer early data with no payload | P1 | — |
| ALPN list | h2/http1.1 support; HTTP/2 readiness | Offer one protocol at a time | P1 | ◐ (one) |
| Compression | CRIME | | — | ✅ |
| Heartbeat extension advertised | Presence only (no Heartbleed probe) | Hello extension | P2 | — |
| `TLS_FALLBACK_SCSV` | Informational now (SSL Labs dropped it) | | — | ✅ |
| **ECH** support | Privacy posture (RFC 9849) | DNS HTTPS record `ech` (X) + server's retry_configs behaviour (H) | P2 | — |
| mTLS requested + **acceptable CA list** | Who may connect; detect `clientAuth` PKI dependence | CertificateRequest `certificate_authorities` | P1 | ◐ |
| Record size limit, post-handshake auth | Completeness | Extensions | P2 | — |

### G. Certificates and PKI (the largest gap)

**G1. Per certificate** (for each chain seen: default, ECDSA, RSA, no-SNI, and ML-DSA once the own TLS 1.3
handshake exists)

- Already collected: subject, SANs (DNS/IP), issuer, serial, validity, key type/size/curve, signature algorithm, SHA-256.
- **Lifetime vs the limit in force on the issue date** (398/200/100/47). P0
- **Days left, relative to lifetime** (warning thresholds scale). P0
- **Key Usage / Extended Key Usage**: serverAuth present; `clientAuth` on a public leaf (phase-out notice); `anyEKU`. P0
- **Basic constraints, name constraints, certificate policies → DV/OV/EV**. P1
- **Weak key fingerprints**: ROCA (Infineon), Debian weak keys, RSA exponent 3, small or shared moduli. These are passive tests on the public key. P1
- **Wildcard scope; CN-only certificates (no SAN)**. P1
- **zlint-class lint** against the Baseline Requirements and RFC 5280 (encoding errors, forbidden extensions). P2

**G2. The chain as served** (not as a client rebuilds it)

| Item | Why | Pri |
|---|---|---|
| Order (leaf first, each issued by the next) | Strict clients fail | P0 |
| **Missing intermediate** (only buildable via AIA) | Works in Chrome, fails in curl/Java/Android/IoT | P0 |
| Extra certificates (root sent, unrelated certs, duplicates) | Handshake bloat; confusion | P0 |
| Chain size in bytes | Large chains cost an extra round-trip (and grow with PQ signatures) | P1 |
| Intermediate expiry before leaf expiry | Silent future outage | P0 |
| Cross-signed alternatives (several valid paths) | Old clients may take a path through an expired root | P1 |

**G3. Trust**

- Path validation against **bundled, dated snapshots** of the major root programs: Mozilla (via CCADB), Chrome Root Store, Apple, Microsoft (and Java as an old-client proxy). Show **per store** whether a path exists. The OS store of the scanning machine becomes one optional column, never the headline. P0 (Mozilla + Chrome), P1 (rest).
- **Private/internal CA bundle** supplied by the person, per system or per endpoint: most enterprise endpoints are internal, and "untrusted" is a false finding for them. P0
- **Distrust list**: CAs a root program has removed or partially distrusted, with effective dates, so a certificate issued after the cut-off is reported even if the root is still present. P1
- Name matching per **RFC 9525**: SAN DNS/IP, wildcard rules, no CN fallback. P0 (have yes/no; add *which* names were checked)

**G4. Revocation**

| Item | Traffic | Pri |
|---|---|---|
| **Parse the stapled OCSP response**: status (good/revoked/unknown), `thisUpdate`/`nextUpdate` freshness, responder and signature validity | H | P0 |
| Must-Staple without a staple → hard failure | H | P0 |
| "Stapling not offered" judged only if the certificate names an OCSP responder (§3) | — | P0 |
| OCSP responder query | X (CA) | P1, opt-in |
| CRL download and check | X (CA) | P1, opt-in |
| AIA fetch to complete a broken chain *for analysis* (still reported as missing) | X (CA) | P1, opt-in |

**G5. Certificate Transparency**

| Item | Traffic | Pri |
|---|---|---|
| SCTs from all three sources (embedded, TLS extension, OCSP), counted and attributed to logs | H | P0 |
| SCT signatures verified against a bundled log list (Chrome/Apple) | — | P1 |
| CT policy compliance (enough distinct logs for the lifetime) | — | P1 |
| Other certificates for this name in CT (unexpected or forgotten ones) via a CT search service | X | P2, opt-in |

**G6. DNS PKI controls** (X, opt-in, one resolver lookup each)

| Item | Pri |
|---|---|
| **CAA** (`issue`, `issuewild`, `iodef`), and whether the actual issuer is permitted | P1 |
| **TLSA/DANE**, only meaningful with DNSSEC; important for mail (SMTP) | P2 |
| **HTTPS/SVCB** records (ALPN, ECH config) | P2 |

### H. HTTP layer (A: one request, already gated by `--http-checks`)

| Item | Why | Pri | Now |
|---|---|---|---|
| **HSTS parsed**: `max-age` (days; vs 6 months / 1 year), `includeSubDomains`, `preload`, duplicate or invalid headers | Presence alone says little | P0 | ◐ |
| **HSTS preload list status** from a bundled, dated snapshot of the Chromium list | Whether browsers enforce it before first visit | P1 | — |
| **HTTP→HTTPS redirect** on port 80 (one plain HTTP request; follow only same-host redirects) | Users typing the name land on HTTP | P1 | — |
| HPKP / Expect-CT present | Deprecated; report as informational "remove it" | P2 | — |
| `Alt-Svc` (HTTP/3) | §A | P2 | — |
| Cookies without `Secure` | Borderline TLS scope. Recommend **out of scope** (web-app scanners do this) | — | — |

### I. Known vulnerabilities

Name every attack that is **inferable from facts already collected** (no extra traffic), so people searching for
"FREAK" find it. These are additions to `eval`, not to the scanner:

- **FREAK**: RSA_EXPORT suites.
- **Logjam**: DHE_EXPORT, ≤1024-bit or common DH primes.
- **DROWN**: SSLv2 here, *or* this certificate's key seen on any SSLv2 endpoint in the estate. The estate graph makes the cross-host case possible, which other scanners only do with external data.
- **LUCKY13**: CBC suites, informational.
- **CRIME**: compression; have.
- **Insecure renegotiation**; have.
- **3SHAKE**: no EMS + resumption.
- **Raccoon class**: DH reuse; needs D.

**Behavioural probes** (E: Heartbleed, CCS injection, ROBOT, Ticketbleed, padding oracles) send malformed or
exploit-shaped traffic. Options in §8: keep them out, or add them behind an explicit per-scan "active checks"
switch that is never on by default and never scheduled.

### J. Client compatibility (handshake simulation)

Replay **real client hellos** (current Chrome, Firefox, Safari/iOS, Edge; Android 7/10/14; Java 8/11/21; Windows 7/10;
OpenSSL 1.0.2/1.1.1/3.x; curl; Go; Python) and record, per client, protocol, suite, group (PQ?) and certificate, or
the failure.

This answers the migration question people actually have: *"if I turn off TLS 1.2 / remove RSA / require hybrid PQ,
who breaks?"* The client-hello library is our own data, captured from the clients themselves, not copied from
another tool. Cost: one handshake per client (H). **P1.**

### K. Profile checks (compliance, in our own terms)

Evaluate a scan against a selected **profile** and show a checklist: requirement → pass/fail → cited source. The
profiles are:

- Mozilla Intermediate / Modern
- NIST SP 800-52 Rev. 2
- RFC 9325 (BCP 195)
- BSI TR-02102-2
- NCSC-NL
- PCI DSS 4.0's TLS requirements
- CNSA 2.0 for the PQ timeline

This is a *view over findings*, not a new score, and fits the auditor persona. **P2.**

### L. About the scan itself

Already: evidence per fact, connection count, duration, incomplete flag, notes. Add:

- per-section "**how this was tested**" (which probes, how many connections, inconclusive count);
- the trust-store snapshot dates;
- whether external lookups were on;
- the address actually scanned.

**P0.**

---

## 5. How the engine should change (plan only)

1. **Own TLS 1.3 full handshake.** Implement the key schedule plus decryption of EncryptedExtensions, Certificate
   (with per-entry extensions) and CertificateVerify. Use it for sigalg enumeration (E), ML-DSA chains, TLS 1.3
   stapled OCSP and SCTs per certificate, and client simulation (J). Keep `crypto/tls` as an independent oracle in
   tests. This is the one large engineering item; everything else is additive.
2. **Probe plan as named stages.** Each catalogue section becomes a stage with:
   - its traffic class (H/A/X/E);
   - a connection estimate;
   - an on/off switch;
   - its own evidence record.

   The report gains a per-stage `status: done | skipped(reason) | inconclusive`, which is what makes "not checked"
   visible in the UI.
3. **Scan depth presets**, shown with their budget before starting:

   | Preset | Covers | About |
   |---|---|---|
   | **Quick** | Versions, negotiated, certificates | ~20 connections |
   | **Standard** (default) | All H and A stages | ~300 connections |
   | **Thorough** | Adds every address, client simulation, consistency sampling | ~1000 connections |

   **External lookups (X)** and **active checks (E)** are separate switches on top of any preset.
4. **Bundled, dated reference data**, generated like the IANA registries are today. Each item carries its snapshot
   date and a refresh tool:
   - root-store snapshots;
   - the distrust list;
   - the CT log list;
   - the HSTS preload list;
   - the known-DH-prime list;
   - client hellos.
5. **STARTTLS adapters** as `Dial` wrappers, one per protocol, each tested against a hermetic server.
6. **Estate integration.** New PKI facts attach to the **certificate entity**, so OCSP status, SCTs and trust per
   store appear wherever the certificate appears (Certificates page, system page, host inventory), not only on the
   endpoint that presented it. Map them into the CBOM only where CycloneDX has a field; never invent one.
7. **Test fixtures** (extend `demo-targets` and the hermetic `testserver`):
   - missing intermediate;
   - wrong order;
   - root included;
   - expired intermediate;
   - Must-Staple without a staple;
   - stapled `revoked` and stale responses;
   - no-SNI default certificate;
   - HSTS variants (short, `includeSubDomains`, `preload`, duplicate);
   - HTTP→HTTPS redirect and non-redirect;
   - an SMTP STARTTLS server;
   - a DH server with an RFC 7919 prime and with a known weak prime;
   - a resumption-broken server.

---

## 6. How to show it: the endpoint page

### 6.1 Principles

1. **Answer first.** The top of the page says, in words, the three things that matter most, each linked to its
   section.
2. **Every section has the same shape:**
   - a one-sentence *what this checks and why it matters*;
   - a **status in words** (*Good*, *Needs attention*, *Problem*, *Not checked*, *Inconclusive*); colour never stands alone;
   - the key facts in plain language;
   - **the findings for this section, right there**, each with its fix and citation;
   - "Show all data" (the full tables);
   - "How we tested".
3. **Findings live next to their data.** The Findings tab stays as a cross-section index (sortable, triage), but a
   reader never has to go there to learn what is wrong with a suite or a certificate.
4. **"Not checked" is always shown, with the reason and how to turn it on.** Absence must never read as "fine".
5. **Problems loud, the acceptable quiet.** Tables show problem rows first and collapse "12 more acceptable suites".
6. **Same words everywhere.** TLS hygiene score, readiness level, profile check; no grades.

### 6.2 Layout

```
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│ shop.example.com:443   203.0.113.10 (1 of 3 addresses)            [Scan now] [Export]     │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────────────┐ ┌──────────────────────┐ │
│ │ Readiness L1 │ │ Hygiene 60   │ │ Certificate: expires in 12d  │ │ Not checked: 2       │ │
│ │ Exposed      │ │ Fair         │ │ trusted by 4 of 5 stores     │ │ (external lookups    │ │
│ └──────────────┘ └──────────────┘ └──────────────────────────────┘ │  off) →              │ │
│                                                                    └──────────────────────┘ │
│ Fix first:  1. Renew the certificate (12 days left)          → Certificates                  │
│             2. Send the intermediate certificate               → Certificates · chain         │
│             3. Turn off TLS 1.0 and 1.1                        → Protocols                    │
├───────────────────┬───────────────────────────────────────────────────────────────────────┤
│ ● Certificates    │  Certificates and trust                         Problem                │
│ ● Revocation & CT │  Who this server says it is, and whether clients will believe it.      │
│ ○ Protocols       │  ┌ chain: leaf ── intermediate (missing!) ── root ┐                     │
│ ○ Cipher suites   │  │ validity bar: issued ──────── today ── expiry  │  lifetime 90/200 d  │
│ ◐ Key exchange&PQ │  └────────────────────────────────────────────────┘                     │
│ ○ Signatures      │  Trust:  Mozilla ✗  Chrome ✓  Apple ✓  Microsoft ✓  Your CA bundle —   │
│ ◐ Features        │  ▲ high  Intermediate not sent (curl, Java and Android fail) — fix…    │
│ ○ HTTP security   │  [Show all data]  [How we tested]                                      │
│ – Compatibility   │                                                                        │
│ – Vulnerabilities │                                                                        │
│ – Profile checks  │                                                                        │
│   Scan details    │                                                                        │
│   History         │                                                                        │
└───────────────────┴───────────────────────────────────────────────────────────────────────┘
 ● problem  ◐ needs attention  ○ good  – not checked (says why)
```

- The left **section index** carries each section's status, so problems are visible without opening anything. On a
  phone it becomes a horizontal chip row.
- The **"Fix first"** list is the top findings across sections, ranked by severity, then by a "takes the site down"
  weight (certificate expiry, trust, name), with the action in plain words.

### 6.3 Sections, in order

| Section | One-line purpose (shown on the page) | Key visual |
|---|---|---|
| **Certificates & trust** | Who the server claims to be, and whether clients will believe it | Chain diagram (served vs built, problems marked on the link); validity bar with the lifetime limit marker; **trust-per-store row**; tabs per chain (ECDSA, RSA, no-SNI, ML-DSA) |
| **Revocation & transparency** | Whether a revoked certificate would be noticed, and whether it was publicly logged | Sentences: "Stapled OCSP: good, valid until 14:00 tomorrow"; "CRL: not checked, external lookups are off [turn on]"; SCT list with log names |
| **Protocols** | Which TLS versions are on, and which should not be | A row of version pills SSLv2 → TLS 1.3 (+ HTTP/3 advertised), each labelled |
| **Cipher suites** | How data is encrypted once connected | Category summary ("all forward-secret · 3 CBC · 1 RC4"); per-version table, problems first |
| **Key exchange & post-quantum** | Whether recorded traffic stays secret, today and against a future quantum computer | Group list with PQ hybrids highlighted; what a current client gets; the readiness ladder |
| **Signatures** | How the server proves its identity during the handshake | Accepted schemes, SHA-1 flagged, ML-DSA readiness |
| **Features & sessions** | Behaviours that affect security and performance | Plain-language rows: "Resumption works (tickets, 24 h lifetime)"; "0-RTT: accepted, replay risk for non-idempotent requests" |
| **HTTP security** | Whether browsers are told to always use HTTPS | HSTS fields as sentences (max-age 2 days, recommended ≥ 1 year); preload status; HTTP→HTTPS redirect |
| **Compatibility** | Which real clients can connect, and what they get | Client × (protocol, suite, PQ, cert) matrix; "would break if TLS 1.2 were turned off: Java 8, Android 7" |
| **Vulnerabilities** | Named attacks, and whether this server is exposed | One line per attack: exposed / not exposed / not tested (and why: active checks off) |
| **Profile checks** | How the configuration measures against a published baseline | Choose a profile → checklist with pass/fail and citations |
| **Scan details** | How the scan was done | Address, presets, connections, duration, inconclusive stages, reference-data dates |
| **History** | What changed | Change markers per section since the last scan (exists today as a tab) |

### 6.4 Fleet level (TLS overview)

The fleet page should answer:

- **Which certificates expire next?** An expiry calendar across all endpoints and host-held certificates.
- **Where are TLS 1.0/1.1, RC4 and small DH still on?** A protocol and suite heatmap with drill-down.
- **Which endpoints fail which trust store?**
- **What is our PQ adoption?** % of endpoints negotiating hybrid key exchange.
- **What does the chosen profile say across the fleet?**
- **Who would break if we raised the floor?** From compatibility simulation.

The same section vocabulary is used as on the endpoint page, so a fleet tile links straight to the matching section.

---

## 7. Proposed phasing

| Phase | Content | Why first |
|---|---|---|
| **T1 — PKI depth and page structure** | No-SNI cert; served-chain analysis; multi-store trust (Mozilla + Chrome snapshots) + private CA bundle; lifetime vs SC-081; KU/EKU incl. clientAuth notice; stapled OCSP parsed + must-staple; SCTs from all sources; HSTS parsed; DH prime matching; per-stage status; **endpoint page rebuilt on the section shape of §6** | Certificates are what take sites down and are our biggest gap; the page structure fixes "buried" for everything that follows |
| **T2 — Reach** | Own TLS 1.3 full handshake (sigalgs, ML-DSA, TLS 1.3 OCSP/SCT); resumption/0-RTT/tickets; ALPN list; client-initiated renegotiation; STARTTLS adapters; every-address mode; external lookups switch (OCSP, CRL, AIA, CAA, CT log list, HSTS preload, redirect) | Broadens what can be scanned and verified |
| **T3 — Comparison** | Client simulation; profile checks; fleet views of §6.4; ECH; distrust list; remaining stores | Turns data into migration decisions |
| **T4 — Decision-dependent** | Active vulnerability checks (if chosen); consistency sampling; CT search; zlint-class linting | Needs the decisions in §8 |

Each phase ends the way WP-1…9 did: a PRD with acceptance criteria, hermetic fixtures, mutation-checked tests, the
browser journey extended to the new sections, and a QA report.

---

## 8. Decisions needed from the owner

**Decided 2026-10-02:** the owner accepted every recommendation below. They are recorded with their effect on T1
in [PRD-004 §9](PRD-004-tls-scanner-t1-pki-depth.md#9-decisions-owner-2026-10-02).

1. **External lookups (OCSP, CRL, AIA, CT, DNS CAA/TLSA/HTTPS).** Recommendation: available but **off by default**
   (the air-gapped stance), switchable per scan and server-wide, with every unchecked item saying so on the page.
   Alternative: on by default with a privacy notice.
2. **Active vulnerability checks (Heartbleed, ROBOT, CCS, Ticketbleed).** Recommendation: **keep them out** for now
   and name them in the Vulnerabilities section as "not tested by design". Dedicated vulnerability scanners do
   this, and it keeps the "handshakes only" promise. Alternative: implement behind an explicit per-scan switch,
   never scheduled.
3. **Which root stores to bundle**, given licence and redistribution terms of each snapshot. Recommendation:
   Mozilla (via CCADB) and the Chrome Root Store in T1; Apple, Microsoft, Java later. Each needs its licence
   checked before inclusion.
4. **STARTTLS priority.** Recommendation: SMTP (25/587), IMAP, LDAP, PostgreSQL first.
5. **Client simulation data.** Recommendation: build our own client-hello library from captures of each client
   (reproducible, clear provenance) rather than importing another tool's list.
6. **HTTP scope.** Recommendation: TLS-relevant only (HSTS, preload, redirect, Alt-Svc). Cookies and general
   security headers are web-application scanning, out of scope.
7. **Scan every address by default?** Recommendation: no (cost), but show "1 of 3 addresses scanned" prominently
   with a one-click "scan all".

---

## Sources

- Qualys SSL Labs, [SSL Server Rating Guide 2009r](https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide), 16 May 2025.
- sslyze, [available scan commands](https://blog.adqt.fr/sslyze/documentation/available-scan-commands.html).
- testssl.sh, [repository](https://github.com/testssl/testssl.sh) and [man page (3.3dev)](https://raw.githubusercontent.com/testssl/testssl.sh/3.3dev/doc/testssl.1.md).
- Let's Encrypt OCSP end: [LWN](https://lwn.net/Articles/1000941/), [Heise](https://www.heise.de/en/news/Schedule-published-Let-s-Encrypt-abolishes-OCSP-certificate-verification-10195214.html), [Let's Encrypt community announcement](https://community.letsencrypt.org/t/removing-ocsp-urls-from-certificates/236699).
- CA/B Forum SC-081v3 schedule: [CA/B Forum server-cert WG](https://groups.google.com/a/groups.cabforum.org/g/servercert-wg/c/a6A2Wmu0gUw/m/eDGxwthmBQAJ), [summary](https://www.encryptionconsulting.com/education-center/47-day-certificate-validity/).
- Chrome Root Program Policy v1.8, serverAuth-only hierarchies: [summary](https://www.encryptionconsulting.com/chromes-root-program-policy-v1-8/).
- [RFC 9849](https://www.rfc-editor.org/info/rfc9849/), TLS Encrypted Client Hello (March 2026).
- Mozilla [Server Side TLS](https://wiki.mozilla.org/index.php?title=Security/Server_Side_TLS) guidelines (profile contents to be verified against the source before use).
- [Internet.nl](https://internet.nl/faqs/report/), report structure.
- Standards named for checks: RFC 5746, 7366, 7507, 7627, 7905, 7919, 8446, 8701, 9325, 9525; NIST SP 800-52r2; CA/B Forum Baseline Requirements.
