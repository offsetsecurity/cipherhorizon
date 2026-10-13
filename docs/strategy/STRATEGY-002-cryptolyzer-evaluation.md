# STRATEGY-002: CipherHorizon against CryptoLyzer, and what to build next

| | |
|---|---|
| Date | 2026-10-12 |
| Role | Product management |
| Compared | CipherHorizon `main` at 5abee48 · CryptoLyzer 1.6.0 (2026-08-25), CryptoParser 1.6.0, CryptoDataHub 1.6.0 |
| Evidence | **[src]** read in CryptoLyzer's published 1.6.0 source, CHANGELOG or `llms.txt`. **[pypi]** PyPI metadata. **[repo]** read in this repository. **[inf]** my inference: check it before acting on it. |
| Status | Draft for the owner. Nothing here is built. |

## 1. Verdict

**CryptoLyzer is the strongest open-source protocol analyzer for breadth. It is not a competitor for what CipherHorizon
sells.** It answers "what does this one server accept, across TLS, SSH, IKE, DNS and HTTP?" CipherHorizon answers
"where does my estate stand on post-quantum, what do I fix first, and what can I hand to an auditor?" CryptoLyzer has
no readiness verdict, no CBOM, no history, no inventory, no web interface and no notion of an estate. **[src]**

**We should not build on its code.** It is Python and MPL-2.0. Embedding it would break the one-static-binary,
no-runtime promise that is one of our differentiators, and we would inherit a single maintainer's release cadence.
**We should build on its map of the problem.** It shows clearly which cryptographic attack surfaces a serious scanner
covers and we don't. Three of those matter directly to post-quantum readiness, and we have none of them:

1. **SSH.** HNDL applies to SSH as much as to TLS, and OpenSSH already ships post-quantum key exchange by default.
2. **Post-quantum signature negotiation in TLS.** We never offer ML-DSA in our ClientHello, so we can't reliably see a
   post-quantum certificate. L4 is the top of our own scale. **[repo]**
3. **IKE / IPsec VPNs.** Site-to-site VPN traffic is the clearest example of harvest-now-decrypt-later, and CryptoLyzer
   is the only open-source tool that enumerates IKEv1 and IKEv2 properly. **[src]**

The recommendation (§8) is to **close gap 2 now (small), build SSH next (medium), and plan IKE as a later program**.
Most of CryptoLyzer's other surfaces (HTTP headers, JA3, GOST, DMARC/SPF) are off our strategy and should stay out.

## 2. What CryptoLyzer is

| | |
|---|---|
| Purpose | A multi-protocol server crypto analyzer and fingerprint generator, with a CLI and a Python API. **[src]** |
| Architecture | Three packages: **CryptoParser** (its own wire implementation, independent of OpenSSL), **CryptoDataHub** (an algorithm and identifier database stored as JSON), and **CryptoLyzer** (the analyzers). **[src]** |
| Language, licence | Python 3.9+ (CPython and PyPy), MPL-2.0, all three packages. **[pypi]** |
| Funding | NLnet / NGI Zero Core. The 2026 grant is for IKE ("CryptoLyzer-IKE"). **[src]** |
| Activity | First release 2019-03. 43 releases. Since 1.1.0 (2026-02) it has shipped about one release a month, mostly IKE work. **[pypi]** |
| Adoption | About 48 GitHub stars and 3 forks. GitHub is a mirror; GitLab is the primary repository. Effectively one maintainer. **[src, inf]** |
| Packaging | uv/pip, Docker, deb, rpm, Arch. **[src]** |
| Output | Colourised text with a traffic-light rating per algorithm, Markdown (for Pandoc), JSON. No overall score, no CBOM. **[src]** |

### Coverage, protocol by protocol **[src]**

- **TLS/SSL (SSL 2.0 to TLS 1.3)**
  - Versions, including TLS 1.3 drafts 0 to 28.
  - More than 400 cipher suites, including GOST, ShangMi and non-standard ones.
  - More than 50 groups, including the hybrid ML-KEM and Kyber groups.
  - Signature algorithms, enumerated. Since 1.6.0 the ClientHello also offers standalone PQ signature algorithms.
  - DH parameters: safe-prime check, well-known group identification, key-reuse detection.
  - Extensions.
  - Client simulations (Chromium, Firefox, Opera).
  - Certificate chain validated against Apple, Google, Microsoft and Mozilla stores; CRL, OCSP and stapling; CT log
    identification; must-staple.
  - **STARTTLS for 13 protocols:** FTP, IMAP, LDAP, LMTP, MySQL, NNTP, OpenVPN, POP3, PostgreSQL, RDP, Sieve, SMTP,
    XMPP.
- **SSH 2.0**
  - Key-exchange, cipher and MAC algorithms in each direction.
  - Group-exchange DH parameters.
  - Host keys, including OpenSSH certificates and X.509.
  - SSHFP verification.
  - Vendor and version.
  - Terrapin.
- **IKE (v1 and v2)**
  - Versions, transforms, DH groups and curves, extensions and vendor IDs.
  - Server public keys and chains (aggressive mode, EAP mode).
  - Accepted CA hashes.
  - "Would this initiator's proposal be accepted?" simulation, with strongSwan and Libreswan names.
- **DNS**
  - DNSSEC keys (DNSKEY, DS, RRSIG), with type and size.
  - DMARC, SPF, MTA-STS, TLSRPT.
  - SSHFP.
- **HTTP**
  - 10 security headers (CSP, HSTS, HPKP and others).
  - Subresource integrity and mixed content.
- **Vulnerabilities**
  - D(HE)at, DROWN, FREAK, Logjam, Lucky Thirteen, Sweet32, Terrapin.
  - RC4, anonymous, NULL, export, non-forward-secret, fallback and early-version findings.
- **Fingerprinting**
  - Acts as a TLS or SSH *server* and records connecting clients as JA3, JA4 or HASSH, over 11 STARTTLS protocols too.
  - Decodes existing tags.

**Post-quantum depth.** CryptoDataHub models KEMs and hybrid groups well. It records security category, key and
ciphertext sizes, and Open Quantum Safe (OQS) names, and it lists many historical candidates (BIKE, NTRU-HRSS, CECPQ2)
alongside ML-KEM. **[src]** It turns none of this into a judgement. A hybrid group is reported as an accepted curve.
There is nothing about HNDL, migration or the deadlines.

## 3. Head to head

✓ = has it · ◐ = partly · ✗ = no

| Capability | CipherHorizon | CryptoLyzer | Matters for our buyer? |
|---|:-:|:-:|---|
| **Post-quantum readiness verdict (L0 to L4) with HNDL exposure** | ✓ | ✗ | Core. |
| **CycloneDX 1.6 and 1.7 CBOM** (endpoint, machine, merged) | ✓ | ✗ | Core. |
| **Web app: history, schedules, accounts, roles, audit log** | ✓ | ✗ | Core. |
| **Machine inventory** (PowerShell and sh engines, Windows CNG, signatures) | ✓ | ✗ | Core. |
| **Systems and migration order** | ✓ | ✗ | Core. |
| PDF reports, OMB M-23-02 export | ✓ | ◐ (Markdown, then Pandoc) | High. |
| Every finding cited (RFC, NIST, IANA) with a pass text | ✓ | ✗ | High (audit evidence). |
| Coverage statement (what was not checked) | ✓ | ✗ | High. |
| CI gate (`--fail-on`) | ✓ | ✗ (JSON only) | Medium. |
| One static binary, no runtime | ✓ | ✗ (Python) | Medium (air-gapped sites). |
| TLS versions SSLv2 to 1.3 | ✓ | ✓ (plus 1.3 drafts) | Parity. |
| Cipher suites | ◐ ~356 IANA | ✓ 400+ (GOST, SM, non-IANA) | Low: the extras are niche. |
| Hybrid and pure ML-KEM groups | ✓ | ✓ | Parity. |
| **PQ signature algorithms offered and enumerated** | ✗ | ✓ | **High: L4 depends on it.** |
| DH parameter analysis | ◐ (small, common prime) | ✓ (safe prime, key reuse) | Low to medium. |
| Client simulations | ✗ | ✓ | **Medium to high: "is real traffic PQ?"** |
| Certificate trust, revocation, CT, chain order | ✓ | ✓ | Parity. |
| STARTTLS protocols | 7 | 13 | Medium: RDP and MySQL are the useful extras. |
| HSTS | ✓ (opt-in) | ✓ | Parity. |
| Other HTTP security headers | ✗ | ✓ | Off-strategy. |
| Named attacks we can show without exploit traffic | ◐ (BEAST, POODLE, DROWN shared key, Sweet32) | ✓ (+FREAK, Logjam, Lucky13, D(HE)at) | Medium: cheap mapping. |
| **SSH** | ✗ | ✓ | **High.** |
| **IKE / IPsec** | ✗ | ✓ | **High, but expensive.** |
| DNSSEC key inventory | ✗ | ✓ | Medium: these are quantum-vulnerable signatures. |
| DANE / MTA-STS / TLSRPT | ✗ | ◐ (MTA-STS, TLSRPT, no DANE) | Low to medium (mail estates). |
| DMARC / SPF | ✗ | ✓ | Off-strategy. |
| JA3 / JA4 / HASSH capture | ✗ | ✓ | Medium if reframed (§5, C7). |
| Library API | REST + OpenAPI | Python API | Different but equivalent. |

**How to read it.** Everything in bold in the first five rows is ours alone. CryptoLyzer has no answer to them, and
they are what an organisation buys. Where CryptoLyzer leads, the gaps that touch PQC are SSH, IKE, PQ signatures and
client simulation. The rest is breadth for penetration testers, who are not our primary persona.

## 4. Gaps confirmed in our code

**G1. The scanner can't see an ML-DSA certificate.**
- `internal/tlsprobe/hellos.go:14` offers ECDSA, RSA-PSS, EdDSA and RSA-PKCS1 signature schemes, and nothing
  post-quantum. **[repo]**
- A server that holds both a classical and an ML-DSA certificate will always present the classical one to us.
- A server with only an ML-DSA certificate will fail our handshake.
- Certificates come from a `crypto/tls` handshake (`certs.go`), which needs the same treatment. **[repo]**
- So L4 ("post-quantum certificate") is effectively unreachable from a live scan. The readiness code knows how to judge
  ML-DSA and SLH-DSA (`internal/eval/readiness.go:212`, `:321`), but the probe never collects it.
- CryptoLyzer fixed this exact problem in 1.6.0 (#190). **[src]**
- This is a correctness bug in our headline feature, not a nice-to-have.

**G2. We have no signature-algorithm stage.** The scan stages are protocols, suites, key exchange, features, certs,
revocation and HTTP. **[repo]** We can't say which signature schemes a server accepts, so we can't produce the CBOM
`signatureAlgorithm` evidence an auditor asks for when the question is "do you still accept SHA-1 or RSA-PKCS1?"

**G3. No SSH, no IKE.** STRATEGY-001 already lists "STARTTLS and SSH" as gaps. STARTTLS is done; SSH isn't.
**[repo]** Our CBOM vocabulary already allows `ssh` and `ike` protocol types (`internal/cbom/vocab.go:33`), so the
output side is ready. **[repo]**

## 5. Capabilities to build, ranked

Value is judged against our positioning: post-quantum readiness, an evidence-graded inventory, and a CBOM for the
estate. Effort is my estimate in engineer-weeks, assuming the current codebase and conventions. **[inf]**

| # | Capability | Value | Effort | Fit | Recommendation |
|---|---|---|---|---|---|
| **C1** | **PQ signature schemes in the ClientHello, plus a signature-algorithm stage.** Offer ML-DSA-44/65/87 (0x0904 to 0x0906) and SLH-DSA, enumerate accepted schemes per version, capture a PQ leaf even when a classical one also exists. | Very high (fixes L4) | 1 to 2 | Exact | **Build now (P0).** |
| **C2** | **SSH scanner** (`cipherhorizon ssh scan`, and SSH targets in the web app). The server's KEXINIT arrives in plain text on connect, so one connection lists all KEX, host-key, cipher and MAC algorithms. Then complete one key exchange per host-key type to collect the keys. Readiness per endpoint: `mlkem768x25519-sha256` or `sntrup761x25519-sha512` offered or not; host keys (all quantum-vulnerable today). CBOM protocol `ssh`. Terrapin as a finding. | Very high | 3 to 5 | Exact: same L0–L4 story, same CBOM | **Build next (P0).** Use `golang.org/x/crypto/ssh` for the key exchange; write our own KEXINIT reader, as we did for TLS. |
| **C3** | **Client simulation:** "Chrome 13x, Firefox, Safari, Java 21, .NET 8, curl/OpenSSL 3.5 would negotiate X with this server." It turns "the server offers ML-KEM" into "your actual clients get ML-KEM", which is the HNDL question. Profiles are built from published ClientHellos. | High | 2 to 3, plus upkeep | Strong | **P1.** Build our own profile table with sources. Don't import CryptoDataHub's `client.json` (§6). |
| **C4** | **Named attacks, mapped not probed.** FREAK (export RSA accepted), Logjam (export DHE or DH ≤ 1024), Lucky Thirteen (CBC with HMAC), D(HE)at (FFDHE accepted, informational). We already have the facts (`CIPHER.EXPORT`, `KX.DH-SMALL`, `CIPHER.CBC`). This is wording and rule mapping only, with no exploit traffic. | Medium | < 1 | Strong | **P1.** It cheaply closes "testssl finds Logjam and you don't". |
| **C5** | **More STARTTLS:** RDP (X.224 negotiation), MySQL, plus LMTP, NNTP, Sieve. RDP and MySQL are common internal services that hold long-lived secrets. | Medium | 1 to 2 | Strong | **P1:** RDP and MySQL first. |
| **C6** | **IKE / IPsec scanner.** IKEv2 versions, transforms and groups, including RFC 9370 additional key exchanges and ML-KEM for IKEv2, plus the server certificate. A VPN gateway is the textbook HNDL target. | Very high | 6 to 10 | Exact | **P2, as its own program.** UDP 500/4500, two protocol versions and NAT-T make it bigger than SSH. CryptoLyzer spent most of a funded year on it. Check the status of the IKEv2 ML-KEM draft at planning time. |
| **C7** | **Client readiness listener.** Run a short-lived TLS (and later SSH) listener inside the estate, or point clients at it. Record what each client *offers*, and report which clients support PQ key exchange. It's the client half of the migration picture, which nobody in our open-source peer set shows. | Medium to high (differentiator) | 2 to 3 | Strong | **P2.** Store raw offered values, not just a hash. If we show JA4, check FoxIO's licence first: JA4 is BSD, other JA4+ methods are not. |
| **C8** | **DNSSEC key inventory:** zone signing algorithms and sizes as CBOM assets. RSA and ECDSA zones are quantum-vulnerable signatures with long migration lead times. | Medium | 1 to 2 | Good (inventory) | **P2.** Needs a DNS resolver path and an SSRF review. |
| **C9** | **Mail transport posture:** DANE TLSA and MTA-STS beside the SMTP STARTTLS scan. | Low to medium | 1 to 2 | Partial | P3, only if mail operators become a target persona. |
| **C10** | **DH depth:** safe-prime check and server key reuse. | Low | 1 | Good | P3. |

### What not to build

| CryptoLyzer feature | Why not |
|---|---|
| HTTP security headers beyond HSTS (CSP, X-Frame-Options, SRI, mixed content) | Web-application security, not cryptographic posture. It would dilute the product and invite comparison with header scanners. |
| DMARC / SPF | Email authentication policy, not cryptography. |
| GOST, ShangMi and non-IANA suites (400+) | Niche markets. Our registry is generated from IANA, which is the defensible source. Revisit only for a customer in those jurisdictions. |
| TLS 1.3 draft versions | Very rare in practice; legacy embedded devices. |
| A Python API | Our REST API and OpenAPI serve the same need without a second language. |
| Traffic-light per-algorithm rating | We have our own vocabulary (readiness level, TLS hygiene). Keep it. |

## 6. "Building on" CryptoLyzer: integrate, borrow or learn?

| Option | What it means | Verdict |
|---|---|---|
| **A. Embed or bundle CryptoLyzer** | Ship Python with it, call it for SSH and IKE. | **No.** It breaks the single static binary, air-gapped installs and our "what it sends" guarantees. We'd also depend on one maintainer's schedule. |
| **B. Import its JSON** | Treat `cryptolyze --output-format=json` as another import source, like third-party CBOMs today. The importer maps SSH and IKE findings into the inventory and a CBOM, marked "observed by CryptoLyzer". | **Yes, as a cheap bridge (P1, about 1 to 2 weeks).** Users get IKE coverage now without us building C6. It fits STRATEGY-001's "ingest, don't compete". Risk: its JSON schema isn't versioned as a contract, so pin to a version and test against fixtures. |
| **C. Reuse CryptoDataHub data** | Generate Go tables from its JSON (KEM sizes, hybrid groups, well-known DH and EC parameters, client profiles, CT logs). | **Only with care.** MPL-2.0 is file-level copyleft. Generated files derived from it would probably need to stay MPL-licensed and ship in source form. That works inside an Apache-2.0 project, but it needs a licence decision and per-file headers. Prefer primary sources (IANA, NIST, RFCs, CCADB), which we already use. Use CryptoDataHub as a **cross-check in tests**: "what does it know that our registry doesn't?" **[inf; owner or legal to confirm]** |
| **D. Learn from its design** | Copy no code. Use its feature map, its changelog of real-world server quirks, and its test ideas. | **Yes.** Its fix list is a free bug backlog for any custom TLS stack. Examples: servers without `supported_versions` (#186), resets during ClientHello (#187), SM2-only servers (#198), TLS 1.3-only groups offered in 1.2 (#191). We should check each against `tlsprobe`. |
| **E. Collaborate** | Ask the maintainer about a stable JSON schema or a CBOM output. Report anything we find. | **Worth one email**, if the owner wants it. It's outward-facing, so it's the owner's call. |

## 7. Competitive risk

- **Will CryptoLyzer move into our space?** Low in the next 12 months. **[inf]** Its funding and changelog point at
  protocol breadth (IKE), not posture management. A CBOM output is the most plausible step. If it adds one, B becomes
  more valuable to us, not less.
- **Does it weaken our CLI story?** For a penetration tester comparing CLIs, yes: it covers five protocols to our one.
  Our README comparison table (testssl.sh, SSLyze, SSL Labs, new PQC CLIs) leaves it out. Add it, and say plainly that
  it's broader on protocols and that we're the posture and evidence product.
- **The real competitive threat remains** what STRATEGY-001 found: CBOM-Lens, CipherIQ, cbomscope, and the commercial
  posture platforms. Of those, CipherIQ and CBOM-Lens already scan SSH. **C2 closes that gap.**

## 8. Recommendation and sequence

| When | What | Why |
|---|---|---|
| **Now** | **C1** PQ signatures and the signature stage. Add a demo-target with an ML-DSA certificate to prove L4 end to end. | Correctness of our headline scale. Small. |
| **Now** | **C4** named-attack mapping. README: add CryptoLyzer to "How it compares". | Cheap, closes an obvious comparison gap. |
| **Next (one program)** | **C2** SSH scanner, all the way through: CLI, web app, readiness, CBOM, PDF. | Biggest PQC-relevant gap. It's what peers already have. |
| **Then** | **C3** client simulation, **C5** RDP and MySQL STARTTLS, **B** CryptoLyzer JSON import. | Strengthens the HNDL claim. Fills IKE coverage cheaply until C6. |
| **Later** | **C6** IKE scanner, **C7** client readiness listener, **C8** DNSSEC inventory. | High value, larger, each a program of its own. |
| **Not** | HTTP headers, DMARC/SPF, GOST/SM, TLS 1.3 drafts. | Off strategy. |

## 9. Decisions for the owner

1. Agree that C1 is a bug fix and goes in before the public 0.1.0 tag. (Recommended: yes. L4 is advertised in the
   README.)
2. SSH next, or IKE first? (Recommended: SSH. It's half the effort, peers already have it, and OpenSSH defaults make it
   immediately measurable.)
3. Is the CryptoLyzer JSON import (B) acceptable as a stop-gap for IKE, given that it depends on a Python tool?
4. A licence position on CryptoDataHub data (C): use it as a test cross-check only (recommended), or generate MPL-2.0
   files from it.
5. Contact the CryptoLyzer maintainer (E): yes or no.

## Sources

- CryptoLyzer: <https://gitlab.com/coroner/cryptolyzer> (mirror <https://github.com/c0r0n3r/cryptolyzer>); 1.6.0 source
  distribution from PyPI, files `README.md`, `CHANGELOG.rst`, `llms.txt`, `cryptolyzer/**`; CryptoDataHub 1.6.0
  `cryptodatahub/common/{pqc.py,hybrid-named-group.json,key-encapsulation-mechanism.json}`, `cryptodatahub/tls/*`.
- PyPI JSON API for cryptolyzer, cryptoparser and cryptodatahub (release dates, licence, dependencies).
- Documentation: <https://cryptolyzer.readthedocs.io>.
- This repository: `internal/tlsprobe/hellos.go`, `scan.go`, `starttls.go`, `registry/groups_gen.go`;
  `internal/eval/*`; `internal/cbom/vocab.go`; `docs/strategy/STRATEGY-001-product-review.md`.
