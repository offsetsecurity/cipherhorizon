# Published standards, clause by clause

Every TLS endpoint and SSH server is judged against the published standards this program carries, from the same
facts the findings rest on. The verdicts sit on a report's **Standards** tab, in the endpoint lists, on the
Overview, in the PDF reports, in the CSV export and on the command line (`cipherhorizon tls standards`,
`ssh standards`, and the `Standards` block of every scan). The code is `internal/eval/standards*.go`; this page is
the reader's version, and names the edition of each document the clauses were read from.

## The user story

Three people ask the same kind of question and get the same kind of answer:

- **An auditor** asks "does this payment endpoint meet PCI DSS 4.2.1?" They need the requirement in the
  assessor's words, a yes or a no per clause, and the evidence for each, in a document they can file.
- **A platform engineer at a German federal supplier** must show TR-02102 conformance for a procurement. They need
  the exact table the server fails and which cipher suite or group is outside it, so the change is one line.
- **A security architect** has to answer "where do we stand against NIST SP 800-52 and against Mozilla
  Intermediate across all 300 endpoints?" and get a list of the ones that do not, to hand to owners.

The answer is a **checklist**: each clause of the document, with the document's own section number, whether the
endpoint meets it, and what the scan saw on that endpoint. On the report it is the Standards tab and a CSV per
standard; across the fleet it is the Overview's Standards panel, whose bars open the endpoints that do or do not
meet each standard; in a pipeline it is `--fail-on standard=ID`.

## How a verdict is reached

A clause is one of:

| Status | Meaning |
|---|---|
| **met** | The scan showed the clause holds. |
| **not met** | The scan showed it does not; the detail names what was seen (the suite, the group, the key). |
| **not assessed** | The scan holds no evidence either way: the stage did not run, the handshake read no certificate, or the document asks for something a network scan cannot see. Never counted as met. |
| **does not apply** | There is nothing to judge: a CBC rule on a server with no CBC suite, a renegotiation rule on a TLS 1.3-only server. |

A clause is **binding** (`must`: the document's *shall*, *MUST*, or a thing it says it does not recommend) or a
**recommendation** (`should`). An endpoint **meets** a standard when no binding clause is *not met*; recommendations
not followed are counted beside the verdict ("Meets · 2 recommendations not followed"). A standard is **not
assessed** when nothing could be judged at all.

Where a document gives a period of use (BSI's "use up to" years), the year is applied on the day of evaluation:
a TLS 1.2 suite BSI recommends until 2029 is *met* in 2028 and *not met* in 2030, without a new release. A
re-evaluation (the **Re-evaluate** button, or the server's launch) applies the current date to a stored scan.

The verdict is the document's, not this product's. The readiness level (L0 to L4) and the TLS hygiene score are
unchanged by it and do not feed it. Because every clause reads the same report the findings read, a standard and a
finding can never disagree about what the server offered.

## What a network scan cannot assess

Each standard lists, under *Not assessed by a network scan*, the clauses a scan cannot see: session-ticket key
rotation, FIPS 140 validation of the module, key storage, client-side duties, operational controls, and whether the
system is in the standard's scope at all (a cardholder-data environment, a national security system). A **meets**
means "every clause this program can see holds", and the page says so.

## The standards

Transcribed on 2026-11-08 from the documents named. When a document changes, the edition changes with it and the
clause table is re-read; nothing is taken from another scanner's rendering of a standard.

### TLS

| ID | Document | Edition read | Binding clauses | Recommendations |
|---|---|---|---|---|
| `bcp195` | RFC 9325, *Recommendations for Secure Use of TLS and DTLS* (BCP 195), IETF | November 2022 | versions (§3.1.1), TLS 1.2 (§3.1.1), renegotiation_info and extended_master_secret for TLS 1.2 (§3.5), no NULL/RC4/export/sub-112-bit suites (§4.1), forward secrecy supported and preferred (§4.1), DH ≥ 2048 and curves ≥ 224 (§4.5), RSA ≥ 2048 and no SHA-1/MD5 signatures (§4.5) | TLS 1.3 (§3.1.1), no compression (§3.3), no 3DES-class suites, no static RSA or static DH, no finite-field DHE (§4.1), CBC only with encrypt_then_mac and a RECOMMENDED suite (§4.2), HSTS (§3.2), OCSP stapling (§7.5) |
| `nist-sp800-52r2` | NIST SP 800-52 Rev. 2, *Guidelines for the Selection, Configuration, and Use of TLS Implementations* | August 2019 | TLS 1.2 and TLS 1.3 (§3.1), no SSL (§3.1), only the suites of §3.3.1, Appendix C and D, ephemeral keys ≥ 112 bits (§3.3.1), an RSA or ECDSA certificate (§3.2) with key and signature ≥ 112 bits (§3.2.1) from a CA that publishes OCSP (§3.2), renegotiation indication (§3.4.1.1), extended master secret (§3.4.1.3), stapling when the CA supports OCSP (§3.4.1.5), TLS_FALLBACK_SCSV with several versions (§3.4.2.1), P-256 or P-384 (§3.4.2.2), encrypt-then-MAC with CBC (§3.4.2.7), null compression only (§3.7) | TLS 1.0 and 1.1 not used (§3.1; binding for government-only servers), no RSA key transport (Appendix D), P-256/P-384 certificates (§3.2), EKU serverAuth and a SAN (§3.2.1) |
| `bsi-tr-02102-2` | BSI TR-02102-2, *Cryptographic Mechanisms: Recommendations and Key Lengths, Part 2 – Use of TLS* | Version 2026-01 | only TLS 1.2 (until 2031) and 1.3 (§3.2, Table 2); TLS 1.2 suites only from Tables 3 to 5 within their period of use (§3.3.1); TLS 1.3 suites from Table 13 (§3.4.4); CBC only with Encrypt-then-MAC (§3.3.1); groups from Tables 6 and 10, plus the ML-KEM hybrids BSI's 2026 note allows (§3.3.2, §3.4.2); TLS 1.3 signature schemes from Table 11 (§3.4.3); certificate signed RSA-PSS or ECDSA with SHA-2, PKCS #1 v1.5 only until 2025 (Tables 7 and 12); RSA ≥ 3000 bits, curves ≥ 250 bits, DH ≥ 3000 bits (§3.6.1, Table 14) | TLS 1.3 preferred (§3.2), a quantum-safe hybrid (§3.1.3), renegotiation per RFC 5746 (§3.3.4.1), no compression (§3.3.4.3), Encrypt-then-MAC (§3.3.4.5), no Heartbeat (§3.3.4.6), Extended Master Secret (§3.3.4.7) |
| `anssi-tls-v1.2` | ANSSI, *Recommandations de sécurité relatives à TLS* | Version 1.2, 26 March 2020 | R3 TLS 1.3, R4 no SSL/TLS 1.0/1.1, R6 forward secrecy always, R7 curves, R7- DHE ≥ 2048, R9 AES or ChaCha20 (Camellia, ARIA tolerated), R10 AEAD (CBC only with encrypt_then_mac; no CCM_8), R11 SHA-2, R13 server order, R19 no compression, R24 SHA-2 signature, R25 ≤ 825 days, R26 key sizes and RSA exponent, R29 SAN, R33 revocation source, R34 ordered and complete chain | R7- DHE ≥ 3072, R22 secure renegotiation, R28 EKU, R35 OCSP stapling, R38 Certificate Transparency |
| `mozilla-modern-6.0` | Mozilla Server Side TLS, Modern profile | Guideline 6.0 (`ssl-config.mozilla.org/guidelines/6.0.json`) | TLS 1.3 only; the three TLS 1.3 suites; groups X25519MLKEM768, X25519, prime256v1, secp384r1 only; an ECDSA P-256/P-384 certificate signed ecdsa-with-SHA*; ≤ 90 days | X25519MLKEM768 offered, OCSP stapling, HSTS ≥ 63072000 |
| `mozilla-intermediate-6.0` | Mozilla Server Side TLS, Intermediate profile | Guideline 6.0 | TLS 1.2 and 1.3 only, TLS 1.3 present; the three TLS 1.3 suites and six ECDHE AES-GCM/ChaCha20 suites; the same four groups; DH 2048; ECDSA or RSA ≥ 2048 signed ecdsa-with-SHA* or sha256WithRSAEncryption; ≤ 366 days | X25519MLKEM768 offered, ≤ 90 days, OCSP stapling, HSTS ≥ 63072000 |
| `pci-dss-4` | PCI DSS v4.0.1, Requirement 4.2.1, and the PCI SSC glossary entry *Strong Cryptography* | v4.0.1, June 2024 | no SSL or early TLS (SSLv2, SSLv3, TLS 1.0); every suite ≥ 112 bits of effective strength (no NULL, export, anonymous, RC4, DES, MD5); public keys ≥ 112 bits (RSA 2048, ECC 224, DH 2048); the certificate chain trusted and within its validity | TLS 1.1 not used; 128 bits for new implementations (no 3DES, RSA 3072, ECC 256); the certificate confirmed as not revoked; TLS_FALLBACK_SCSV where several versions are enabled |
| `cnsa-2.0-tls` | NSA CNSA 2.0 for TLS: `draft-becker-cnsa2-tls-profile-06` (IETF individual draft), with RFC 9151 for the CNSA 1.0 transition | October 2026 | nothing below TLS 1.2 and TLS 1.3 present; TLS 1.3 suite TLS_AES_256_GCM_SHA384 only; TLS 1.2 suites only the RFC 9151 §6 list; groups ML-KEM-1024 or (transition) secp384r1, ffdhe3072, ffdhe4096 only; certificate key ML-DSA-87, or P-384 / RSA 3072 or 4096; certificate signed with ML-DSA-87 or over SHA-384 | TLS 1.3 only; ML-KEM-1024 offered; ML-DSA-87 authentication available |

### SSH

| ID | Document | Edition read | Binding clauses | Recommendations |
|---|---|---|---|---|
| `bsi-tr-02102-4` | BSI TR-02102-4, *Part 4 – Use of Secure Shell (SSH)* | Version 2026-01 | SSH-2 only (§3.2); key exchange only from Table 2 (group exchange SHA-256, group 15/16 SHA-512, ECDH nistp256/384/521, and the ML-KEM hybrids on NIST curves BSI names in §3.3); ciphers only from Table 3 (AES-GCM, AES-CTR); MACs only from Table 4 (hmac-sha2-256/512, accepted in OpenSSH's encrypt-then-MAC spelling too); host-key algorithms only from Table 5 (ECDSA nistp*, X.509 ECDSA, pgp-sign-dss until 2029) | a quantum-safe hybrid key exchange (§3.1.3) |
| `cnsa-2.0-ssh` | NSA CNSA 2.0 for SSH: `draft-becker-cnsa2-ssh-profile-07` (IETF individual draft), with RFC 9212 for the CNSA 1.0 transition | October 2026 | key exchange mlkem1024-sha384 or (transition) ecdh-sha2-nistp384, group 15/16 SHA-512 only; host keys ssh-mldsa-87 or (transition) ECDSA nistp384, RSA with SHA-2 ≥ 3072; AES-256-GCM only; integrity from AES-256-GCM (or hmac-sha2-512 beside it) | mlkem1024-sha384 first; ML-DSA-87 first |

Notes a reader should know before quoting a verdict:

- **BSI lists neither X25519 nor ChaCha20 nor Ed25519.** A server that offers them is outside Tables 6, 10, 13 and
  (for SSH) Tables 2, 3 and 5, and the report says which names. That is BSI's recommendation, faithfully applied;
  OpenSSH's defaults do not meet TR-02102-4 as written.
- **BSI recommends PKCS #1 v1.5 certificate signatures only until the end of 2025** (Table 12). From 2026 an RSA
  certificate signed `sha256WithRSAEncryption` is *not met*; an ECDSA or RSA-PSS signature is met.
- **PCI DSS 4.2.1 is about cardholder data in transit.** Whether an endpoint is in scope is the assessor's call; the
  program judges the cryptography. Requirement 4.2.1.1 (an inventory of trusted keys and certificates) is what
  the Inventory and certificate pages provide, not a per-endpoint clause.
- **CNSA 2.0 defines no hybrid groups.** A server offering X25519MLKEM768 does not meet its key-exchange clause;
  ML-KEM-1024 alone, or the CNSA 1.0 transition groups, do.
- **Mozilla 6.0 has no Old profile.** Guideline 5.7's Old profile is not carried.
- **The CNSA 2.0 profiles are IETF individual drafts**, named as such with their revision; the NSA algorithm suite
  itself (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87) is what they implement.

## Reading the result elsewhere

- **API:** `GET /api/v1/standards` is the catalogue; every evaluation carries `standards[]` (verdict, counts, one
  result per requirement with clause, level, status and detail); `GET /api/v1/standards/summary` counts the fleet.
- **CSV export** (`/api/v1/export/assets.csv`): `standards_met` and `standards_not_met`, ids separated by `;`.
- **PDF:** the full security report and the SSH report end with a Standards page per standard.
- **CLI:** `tls scan` and `ssh scan` print a `Standards` block; `--details` prints every clause with its status;
  `--fail-on standard=bcp195` (or any id) exits 3 when a target does not meet it, and `tls standards` /
  `ssh standards` print the catalogue.

## Adding a standard

A standard is a Go value in `internal/eval/standards_tls.go` or `standards_ssh.go`: id, title, publisher, the
edition read, URL, scope, the clauses (each with the document's section number, a level and a check over the
scan's facts) and the list of what a scan cannot assess. `standards_test.go` pins one endpoint that meets each
standard and one that fails named clauses, so a transcription error fails the build. Read the document itself;
never transcribe another tool's rendering of it.
