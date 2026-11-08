# CRYPTO-REVIEW-005 · The cryptographic analysis: what the product measures, what the standards ask, where it stands

| | |
|---|---|
| Date | 2026-11-08 |
| Role | Cryptographer, with the product manager beside |
| Scope | The TLS and SSH evaluation as of 0.4.1 (`eval/13`), judged against what the published standards require and what the competing scanners measure; the standards layer built from it (PRD-017, `eval/14`) |
| Sources read in session | NIST SP 800-52 Rev. 2 (PDF, Aug 2019); BSI TR-02102-2 and -4 (PDF, version 2026-01); NIST IR 8547 final (PDF, Oct 2026); ANSSI *Recommandations de sécurité relatives à TLS* v1.2 (PDF, 2020); RFC 9325; Mozilla Server Side TLS 6.0 and 5.7 (JSON); PCI SSC glossary *Strong Cryptography*; RFC 9151; draft-becker-cnsa2-tls-profile-06; draft-becker-cnsa2-ssh-profile-07. The NSA CNSA 2.0 PDFs and the PCI DSS v4.0.1 PDF refused automated reads; their content is used only where another source states it, and is marked |

## 0. Verdict, first

The scanner is better than its competitors at the cryptography it measures: a wire-level TLS implementation that
reaches SSLv2 and export suites, group enumeration without key material, signature-scheme probing, a PKI view with
two root programs, OneCRL and a hand-curated distrust list, DH primality, SSH with every host key verified and a
cited baseline, post-quantum on both protocols. Its judgements are cited, and its "unknown" is honest.

What it lacked was not measurement but **consumption**. The product produced facts and its own two scales; the
people who pay for a scanner are asked for conformance to named documents. That gap is now closed for ten standards
(§5), from the facts already collected, with each clause carrying the document's section number. Three measurement
gaps remain real and are ranked in §7; none of them blocks the standards work, and two are cheap.

## 1. What the product measures today

| Area | What is observed | Depth, compared with testssl.sh / SSLyze / SSL Labs |
|---|---|---|
| Protocol versions | SSLv2 (own framing) to TLS 1.3, each with its evidence (ServerHello, alert, closed, inconclusive) | Equal to testssl.sh; SSL Labs equal; SSLyze lacks SSLv2 on some builds |
| Cipher suites | Every suite per version by elimination, server/client/mixed preference, rank | Equal; our registry is IANA-generated and refuses unknown names |
| Key exchange | TLS 1.3 groups by HelloRetryRequest (no key share), including ML-KEM hybrids, pure ML-KEM, obsolete drafts; TLS ≤1.2 curves and the DHE prime with primality and safe-prime tests and RFC group matching | Ahead: no competitor enumerates PQ groups this way or tests the prime |
| Signatures | One hello per TLS 1.3 scheme with a refused control, ML-DSA included | Ahead; nobody else proves scheme acceptance with a control |
| Hello features | renegotiation_info, EMS, tickets, EtM, heartbeat echo, OCSP stapling, compression, FALLBACK_SCSV, client-cert request | Equal |
| Certificates | Served chain as sent (order, extras, missing issuer with AIA named not fetched), path validation against Mozilla and Chrome snapshots with program constraints, private anchors, names per RFC 9525, lifetime against SC-081, OCSP staple parsed and verified, SCTs from three places, CRL lookups opt-in with scope rules, OneCRL, distrust list, weak-exponent | Ahead of testssl.sh and SSLyze on trust (two programs, constraints, OneCRL); SSL Labs has more stores (Apple, Java, Windows) and live revocation |
| Classical strength | Bits per part by NIST's methods; suite as weak as its weakest part | Ahead; others show only key sizes |
| Post-quantum | L0–L4 per protocol, HNDL exposure, three dimensions | Ahead; competitors list groups at most |
| SSH | Lists, negotiation as OpenSSH 10.6, every host key fetched and verified, 18 rules, baseline with sshd_config lines | Equal to ssh-audit on lists and policies; ahead on host-key verification and PQ |
| Not measured, by design | Active exploits (Heartbleed, ROBOT, CCS, Ticketbleed, padding oracles), live OCSP, client simulation | testssl.sh and SSL Labs do these |

## 2. What the standards ask, and whether a scan can see it

Reading the ten documents end to end gives four kinds of clause:

1. **Configuration a handshake reveals** (versions, suites, groups, extensions, the certificate's fields): the great
   majority of every document. All observable; all now judged.
2. **Properties of the server's own operation** (ticket-key rotation, DH exponent reuse, 0-RTT acceptance,
   re-keying): a scan sees some only with dedicated probes (0-RTT, DH reuse across two handshakes). Not judged;
   listed per standard as *not assessed*.
3. **Properties of the trust and revocation infrastructure** (revoked, CT logged, OCSP available): observable from
   the staple, the SCTs and, with lookups on, the CRL. Judged with *not assessed* where the evidence is absent.
4. **Scope and policy** (is it a cardholder-data endpoint; is it a national security system; the CNSA 2033 date):
   not a server property. Stated as such.

Two findings from the reading matter beyond this product:

- **BSI TR-02102 (2026-01) and OpenSSH defaults disagree.** TR-02102-4 Table 2 lists neither `curve25519-sha256`
  nor the ML-KEM/X25519 hybrid, Table 3 omits ChaCha20-Poly1305, Table 5 lists no Ed25519 or RSA host key. A stock
  OpenSSH 10 does not meet TR-02102-4; a BSI-conformant `sshd_config` is NIST-curve ECDH, AES-GCM/CTR, ECDSA host
  keys. The same holds for TLS: Table 10 has no X25519, Table 13 no ChaCha20, and Table 12 ends PKCS #1 v1.5
  certificate signatures at 2025. The product reports this faithfully and names the table; a reader who finds it
  surprising is reading BSI correctly.
- **NIST IR 8547 is final (October 2026).** Tables 2 and 4 keep the draft's dates: quantum-vulnerable signatures
  and key establishment *deprecated after 2030, disallowed after 2035*; 112-bit symmetric standards disallowed in
  2030; SHA-1 disallowed in validated modules after 2030; and, new in the final, federal high-value systems must
  adopt PQ key establishment by 31 December 2030 and PQ signatures by 31 December 2031 (EO 14412, OMB M-26-15), with
  TLS 1.3 required by 2 January 2030. The readiness scale already encodes the first two; the citation in
  `internal/eval` still points at the initial public draft and should move to the final.

## 3. Correctness review of the existing rules against the documents

Checked while transcribing; nothing found that contradicts a document. Three notes:

- `CIPHER.SWEET32` treats 3DES as 112-bit and 64-bit-block; SP 800-52r2 §3.3.1.1 says 3DES suites "are no longer
  allowed", and SP 800-131A disallows TDEA after 2023. The classical-strength table already labels it so; the
  standards layer makes the consequence visible (NIST's suite list excludes it; PCI's glossary still names
  triple-length TDES as an example, so the PCI 112-bit clause accepts it while the 128-bit recommendation does not).
- The hygiene score's `FEAT.NO-FALLBACK-SCSV` is Low; RFC 9325 §3.1.3 no longer asks servers for the SCSV at all
  (it is a client duty); SP 800-52r2 §3.4.2.1 still does when several versions are enabled. Both readings are now
  separate clauses; the finding stays Low, which is right.
- `CERT.LIFETIME` follows SC-081 for public chains; ANSSI R25 (825 days from 2018) and Mozilla's 90/366 are
  stricter or looser per document and are judged per document, not folded into the finding.

## 4. The competitive position, in crypto terms

| Capability a buyer asks for | Qualys SSL Labs | testssl.sh | CipherHorizon |
|---|---|---|---|
| Named-standard conformance checklist | No (its own grade) | Hints only | **Ten standards, clause by clause, with section numbers** |
| Post-quantum key exchange and authentication per endpoint | Lists groups | Lists groups | Readiness level, dimensions, SSH too |
| Evidence tiers and "not assessed" honesty | Partly | No | Yes, per clause and per check |
| Self-hosted, internal endpoints, STARTTLS, SSH | No / no / no / no | Yes / yes / yes / no | Yes on all four |
| Client simulation | Yes | Yes | No (§7) |
| Active vulnerability probes | Yes | Yes | No, by design (§7) |
| More root stores and live revocation | Yes | Partly | Two programs plus OneCRL and opt-in CRL (§7) |

The standards checklist is the differentiator nobody else offers, and it rests on the measurement depth nobody else
has for PQ. The two capabilities SSL Labs has and we do not are both about *clients* (simulation, which browsers
connect) and *attacks*; neither is a standards question, and both are listed below with their real cost.

## 5. What was built (PRD-017)

Ten standards, 139 clauses, judged on every scan from the existing report; the catalogue and the clause texts are
in `docs/standards.md`. The engineering is a thin layer: `internal/eval/standards.go` (types, verdict rules, 25
shared fact-readers over the evaluation context), `standards_tls.go` and `standards_ssh.go` (the transcriptions),
storage of the verdict map beside each scan, two API routes, a report tab, list column and filter, an Overview
panel, a PDF page, CSV columns, three CLI additions and a Help topic. Every clause in the tables of §2 of
`docs/standards.md` was read from the document in this session; the agents that fetched the documents returned
PDFs that were converted to text locally (`pdftotext`) and grepped by section, so the section numbers are the
documents' own.

## 6. Validation on live targets

The 23 demo targets were re-evaluated with `eval/14` on a running server and read by hand. Spot checks:

- The modern hybrid demo (Go's TLS server, ECDSA P-256, self-signed) **meets BCP 195** with two recommendations
  not followed (CBC without EtM, which Go does not implement; no staple); **does not meet NIST SP 800-52**
  because it offers ChaCha20-Poly1305, which §3.3.1 does not list, and its certificate names no OCSP responder;
  **does not meet PCI 4.2.1** on the trusted-chain clause only (self-signed), which is the right single reason;
  **does not meet BSI** on X25519 and the suite tables; **does not meet Mozilla Intermediate** on one clause (the
  CBC suites Go's server also enables). Every "does not meet" names the exact suite, group or field.
- The SSLv3 legacy demo fails every TLS standard on versions and suites, with the forbidden names listed.
- The hardened OpenSSH demo meets the product's own baseline and **does not meet TR-02102-4**, naming
  `curve25519-sha256`, `chacha20-poly1305@openssh.com` and `ssh-ed25519` as the names outside BSI's tables, and
  meets neither CNSA 2.0 clause set, as expected.
- The SSH-1 demo yields *not assessed* for CNSA 2.0 and *not met* for BSI's SSH-2 clause.

## 7. Measurement gaps that remain, ranked

| # | Gap | What a standard or buyer loses without it | Cost | Recommendation |
|---|---|---|---|---|
| 1 | **Client (handshake) simulation**: which of ~25 named clients negotiate, and with what | The question operations teams ask first ("will Android 9 still connect?"); SSL Labs' most used table | Medium: a client-hello library (versions, suites, groups, sig algs per client) and an offline intersection with the enumerated server data; no new probes for most clients | Build next; it reuses the enumeration and needs no new wire code |
| 2 | **Session resumption and 0-RTT**: whether tickets resume, whether a ticket is accepted after N minutes, whether early data is accepted | BCP 195 §3.4, SP 800-52 §3.6, ANSSI R20–R23, BSI 0-RTT: today all *not assessed* | Medium: a second handshake with the ticket; early-data offer with a known request | Build; it turns eight *not assessed* clauses into verdicts |
| 3 | **Active probes** (Heartbleed, ROBOT, CCS injection, Ticketbleed, renegotiation attempt) | Audit scopes often require them; today "not tested by design" | Medium to high; each must stay safe and opt-in | Opt-in, behind `--probes`, after 1 and 2 |
| 4 | **More root programs** (Apple, Microsoft, Java) and SCT signature verification | Trust per platform; CT clauses become verdicts rather than presence | Low (CCADB has Apple and Microsoft) / medium (SCT keys) | Add Apple and Microsoft from CCADB; defer SCT verification |
| 5 | **Live OCSP (opt-in)** | PCI's "not revoked" clause for Let's Encrypt-free estates; SP 800-52's OCSP expectation | Low, with the same guard as CRL | Add behind `--revocation`, with the privacy note |
| 6 | **DH exponent reuse** across two handshakes (RFC 9325 §7.4) | One clause | Low | Add to the key-exchange stage |
| 7 | **TLS 1.2 signature_algorithms enumeration** | BSI Table 7 clause; today *not assessed* | Low to medium | Add after client simulation, which needs the same data |

Weak-key tests (ROCA, Fermat, small scalars, batch GCD) from CRYPTO-REVIEW-004 P1 remain on the 0.5.0 plan and are
not duplicated here.

## 8. What not to do

- Do not fold standards into the hygiene score or the readiness level. Each answers a different question; the
  product's clarity came from separating them (STRATEGY-003).
- Do not "soften" BSI or CNSA to match common practice. The value is fidelity; the detail text explains the gap.
- Do not transcribe a standard from another scanner's rendering of it. Several exist and several are wrong (Mozilla
  5.7 Intermediate still carried DHE and CBC; 6.0 does not).
- Do not present the CNSA 2.0 drafts as RFCs or the NSA PDFs as read; the product names the draft revision.

## 9. Follow-ups recorded

- Move the IR 8547 citation to the final (October 2026) and quote the EO 14412 / M-26-15 dates in Help.
- Standards view on the Findings page (one row per failing clause across the fleet) and a per-system choice of
  which standards apply (REQ-STD-13).
- Mozilla Old 5.7, NCSC-NL, CIS SSH benchmarks as further profiles, each after a read of the document.
