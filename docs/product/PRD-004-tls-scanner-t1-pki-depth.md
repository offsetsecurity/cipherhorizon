# PRD-004: TLS scanner T1 — PKI depth and an endpoint page that explains itself

| | |
|---|---|
| **Status** | **Baselined 2026-10-02** by the owner ("looks good, go ahead"). Changes go through the change log in §12. Design: [ENG-HANDOFF-003](ENG-HANDOFF-003-tls-t1.md); tests: [QA-PLAN-004](QA-PLAN-004-tls-t1.md). |
| **Authors** | Product Manager and Security Architect, jointly (role-played, as for PRD-003; owner approval pending) |
| **Builds on** | PRD-001 (workbench), PRD-002 (evidence and coverage, mTLS, HSTS), PRD-003 (estate model: certificate entity, systems) |
| **Inputs** | [RESEARCH-004](RESEARCH-004-tls-scanner-and-pki.md) §1–§7. Its **§8 decisions were accepted by the owner on 2026-10-02**, recorded in §9 below. |
| **Phase** | T1 of T1–T4 (RESEARCH-004 §7). T2 (reach), T3 (comparison) and T4 are separate PRDs. |
| **Traceability** | Requirement IDs use new prefixes (`REQ-TSTG`, `REQ-TCRT`, `REQ-TCHN`, `REQ-TTRS`, `REQ-TREV`, `REQ-TCT`, `REQ-TKX`, `REQ-THTP`, `REQ-TVLN`, `REQ-TDAT`, `REQ-TUI`, `REQ-TNFR`) so they cannot collide with PRD-003. On baseline the RTM gains their rows and `internal/archtest` is extended to read this PRD too. |

## 1. Problem

The scanner is strong at enumeration (protocols, suites, preference, post-quantum key exchange) and weak on the
public-key infrastructure that actually takes sites down:

- **Trust** is one yes/no against whatever store the scanning machine has. Internal endpoints signed by a
  private CA are reported "untrusted" with no way to say otherwise.
- **The chain as served is never examined.** A missing intermediate (works in Chrome, fails in curl, Java and
  Android) is invisible.
- **The certificate a client gets without SNI is never fetched.**
- **Revocation is "a stapled response was present".** The response is never read, and Must-Staple without a staple
  is not caught.
- **Certificate Transparency is "has embedded SCTs".**
- **HSTS is a presence check, off by default.**
- **Rules predate 2025–26 changes.**
  - Lifetime limits are shrinking to 47 days, so a fixed 30-day "expiring" window raises false alarms.
  - Let's Encrypt switched OCSP off.
  - Public hierarchies are becoming serverAuth-only.

And the page buries what it does find. Findings live in a separate tab from the data they concern. No section
says what it checks. "Not checked" disappears instead of being shown. Nothing marks which of ten cards holds
the problem.

## 2. Outcome

A person opening an endpoint learns, without scrolling or cross-referencing:

- **whether the certificate will work** for real clients: chain, trust per browser store and their own CA, name,
  lifetime, revocation, transparency;
- **what is wrong, in order of how badly it hurts**, with the fix;
- **what each part of the scan checked, what it found, and what it did not check, and why.**

## 3. Personas and jobs

| Persona | Job | What T1 gives them |
|---|---|---|
| **Marcus — platform / web-ops engineer** | "Will this certificate and chain break any client, and when?" | Served-chain problems named; trust per store; lifetime-aware expiry; no-SNI certificate; Fix first |
| **Priya — PQC migration lead** | "What is this endpoint's posture and what do I change first?" | Same readiness and hygiene, now with every section stating its status |
| **Dana — auditor** | "Show me how each fact is known." | Per-section *How we tested*; snapshot dates of every reference list; evidence on every fact |
| **Internal-PKI owner** | "Stop telling me my internal CA is untrusted." | A private CA bundle, server-wide and per system |

## 4. Goals, non-goals, success measures

**Goals.**

- **G1** — Certificate and PKI facts at the depth of the reference tools, for everything learnable from the target itself.
- **G2** — Rules current with the 2025–26 PKI changes.
- **G3** — An endpoint page where every section explains itself and states its status, and findings sit next to their data.
- **G4** — "Not checked" always visible with its reason.

**Non-goals (T1).** These move to later phases, per RESEARCH-004 §7:

- Anything that contacts a third party: OCSP or CRL queries, AIA fetching, CT log verification, CAA/TLSA/HTTPS DNS
  records, CT search (T2, behind the external-lookups switch).
- STARTTLS; scanning every address of a name (T2).
- Our own TLS 1.3 full handshake, signature-algorithm enumeration, ML-DSA chains (T2).
- Session resumption, 0-RTT and ALPN-list tests (T2).
- HSTS preload-list status and the HTTP→HTTPS redirect check (T2).
- Client simulation and profile checks (T3).

**Never in this program:** active vulnerability probes (decision D2). Also out of scope: cookies and general
web-security headers (decision D6).

**Success measures** (verified in QA; a QA-PLAN-004 follows baseline):

| # | Measure | Target |
|---|---|---|
| T1-M1 | Each PKI condition in the fixture matrix (§8.2) is detected | 100 % detected; 0 findings on the clean fixture |
| T1-M2 | Served-chain and trust results agree with an independent oracle (OpenSSL `verify` with the same bundles) on every fixture | 0 disagreements |
| T1-M3 | Stapled-OCSP, SCT-list and HSTS parsers under fuzzing | ≥ 1 M executions each, 0 crashes or hangs; decoded fields agree with OpenSSL on fixture inputs |
| T1-M4 | Every section on the endpoint page shows a purpose line and a status word; every *Not checked* shows a reason | 100 % of sections, asserted by the browser journey |
| T1-M5 | From the Estate page to the cause of a certificate problem | ≤ 2 clicks, measured by the journey script |
| T1-M6 | Extra connections for a Standard scan on the demo targets | ≤ 5 more than 0.2.0 |
| T1-M7 | Stored `tls-report/1` scans render on the new page | 100 % of legacy fixtures; absent data says *Not collected by the version that ran this scan* |

## 5. Requirements

Priorities: **P0** must ship in T1; **P1** should ship in T1 and may slip with PM sign-off; **P2** only if time
allows. Traffic class per RESEARCH-004: **H** handshakes with the target, **A** one HTTP request to the target. T1
introduces no **X** (third-party) or **E** (exploit-like) traffic.

### Epic A — Scan stages and report (REQ-TSTG)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TSTG-1** | The scan is a fixed list of **named stages** matching the page sections: certificates, revocation & transparency, protocols, cipher suites, key exchange, features, HTTP. The report records each stage's outcome: `done`, `skipped` (with a reason code and text, e.g. *option off*, *not applicable: not an HTTP service*), or `inconclusive` (with the probe errors). | P0 | R-004 §5.2 |
| **REQ-TSTG-2** | Each stage records **how it tested**: probes used, connections made, inconclusive count, and the reference-data snapshots it consulted (name and date). | P0 | R-004 §4.L |
| **REQ-TSTG-3** | The report schema becomes **`tls-report/2`**, a strict superset of `/1`. Every reader (API, eval, UI, CBOM builder, graph projection) accepts both. A `/1` report is never rewritten. | P0 | PRD-003 REQ-MOD-1 |
| **REQ-TSTG-4** | The **HTTP stage is on by default** (decision D6/D1). It still sends exactly one `GET /`, reads at most 8 KiB, follows no redirect, and runs only when the service answers as HTTP. The server-wide switch (`--http-checks=false`, config key) turns it off, and a skipped stage says so. The About page, `docs/tls-scanning.md` and the CHANGELOG state the new default. | P0 | R-004 §8 D6 |
| **REQ-TSTG-5** | T1 contacts **no host other than the target**. A test asserts the dialer sees only the target address during a full Standard scan. | P0 | R-004 §8 D1 |

### Epic B — Certificate facts (REQ-TCRT)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TCRT-1** | Every certificate records, in addition to today's fields:<br>• Key Usage and Extended Key Usage (named);<br>• basic constraints including path length;<br>• name constraints (present: yes/no plus the permitted/excluded names);<br>• certificate-policy OIDs mapped to **DV / OV / EV / unknown**;<br>• whether the subject has only a CN and no SAN;<br>• the wildcard names;<br>• validity lifetime in days. | P0 | R-004 §4.G1 |
| **REQ-TCRT-2** | A **no-SNI handshake** (one extra connection) records the certificate a client gets without SNI. The report says whether it is the same certificate as with SNI. A different one is analysed like any other chain and shown as its own tab. | P0 | R-004 §4.A; testssl.sh |
| **REQ-TCRT-3** | **Lifetime vs the limit in force on the issue date** (CA/Browser Forum ballot SC-081v3: 398 days before 2026-03-15, 200 from then, 100 from 2027-03-15, 47 from 2029-03-15). The limit table is reference data with its source, not code. Applied **only to publicly trusted certificates** (a path to a bundled public root); private-CA certificates are exempt and the page says why. | P0 | R-004 §3 |
| **REQ-TCRT-4** | **Expiry warning scales to lifetime.** Today it fires at ≤ 30 days (medium) and ≤ 7 days (high). It becomes ≤ min(30 days, ⅓ of the lifetime) (medium) and ≤ min(7 days, ⅒ of the lifetime) (high). The rule's text names the threshold it used. A 47-day certificate with 20 days left raises nothing. | P0 | R-004 §3 |
| **REQ-TCRT-5** | **EKU checks:**<br>• a leaf without `serverAuth` (and without `anyExtendedKeyUsage`) → high finding;<br>• a **publicly trusted** leaf or intermediate that also carries `clientAuth` → info finding. The info finding explains the Chrome Root Program serverAuth-only dates (intermediates 2026-06-15, leaves 2027-03-15) and what that means for mTLS use. | P0 | R-004 §3 |
| **REQ-TCRT-6** | **Passive weak-key checks** on every RSA key: ROCA fingerprint, Debian weak-key blocklist, public exponent < 65537, modulus shared with another certificate in the estate. Each check is its own cited finding. | P1 | R-004 §4.G1 |
| **REQ-TCRT-7** | Certificate facts attach to the **certificate entity** of the estate graph (PRD-003 REQ-CERT-6), so they appear on the Certificates page and on every system that holds the certificate. The certificate entity's page and API show them. | P1 | R-004 §5.6 |

### Epic C — The chain as served (REQ-TCHN)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TCHN-1** | The **chain as served** (the certificates in the order the server sent them, from the existing handshakes) is analysed separately from any path a client builds. | P0 | R-004 §4.G2 |
| **REQ-TCHN-2** | **Missing intermediate:** no path from the served certificates to a bundled or private anchor, while the leaf names an issuer that is neither served nor an anchor → high finding. The finding names the issuer and the AIA URL the certificate gives, and does not fetch it (T1 makes no third-party contact). | P0 | RFC 8446 §4.4.2; RFC 5246 §7.4.2 |
| **REQ-TCHN-3** | **Order:** a certificate that is not issued by the one after it. TLS 1.2 requires the order (RFC 5246 §7.4.2: *MUST*); TLS 1.3 tolerates it (RFC 8446 §4.4.2). The severity follows the highest version the server negotiates. | P0 | as cited |
| **REQ-TCHN-4** | **Extra certificates:** a root sent (allowed but wasteful), duplicates, or certificates not on any path → low/info finding listing them. | P0 | RFC 8446 §4.4.2 |
| **REQ-TCHN-5** | **Intermediate expires first:** any certificate on the served path that expires before the leaf, or inside the leaf's warning window → medium finding naming it and the date. | P0 | R-004 §4.G2 |
| **REQ-TCHN-6** | **Chain size** in bytes, with a note when it exceeds what fits a typical initial congestion window. Informational; relevant to PQ signatures. | P1 | R-004 §4.G2 |

### Epic D — Trust (REQ-TTRS)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TTRS-1** | Path validation runs against **bundled, dated snapshots** of the **Mozilla** (via CCADB) and **Chrome Root Store** programs (decision D3), each reported separately: path found / not found / error, with the path. | P0 | R-004 §4.G3 |
| **REQ-TTRS-2** | A **private CA bundle**: one server-wide (config file) and one per **system** (API and system page). PEM **certificates only**: key blocks are refused undecoded, like the host certificate sensor. Size and count are limited. Every change is audited. A path to a private anchor is reported as *trusted by your CA bundle*. | P0 | R-004 §4.G3 |
| **REQ-TTRS-3** | The **operating-system store** of the scanning machine becomes an optional, clearly labelled column, off by default, never the headline result. | P1 | R-004 §4.G3 |
| **REQ-TTRS-4** | `CERT.UNTRUSTED` fires only when **no** bundled public store and **no** private anchor yields a path. When some stores do and others do not → new medium finding naming the stores that fail. | P0 | R-004 §6.3 |
| **REQ-TTRS-5** | Name matching reports **which names were checked against which SANs** (RFC 9525: no CN fallback; wildcard only in the left-most label), not only yes/no. | P0 | RFC 9525 |
| **REQ-TTRS-6** | A **distrust list** (CAs removed or partially distrusted by Mozilla or Chrome, with effective dates) as reference data. A certificate from a distrusted CA issued after the cut-off is reported even when its root is still in a snapshot. | P1 | R-004 §3 |

### Epic E — Revocation (REQ-TREV)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TREV-1** | The **stapled OCSP response** is parsed by our own bounded, fuzzed parser (no new dependency; see REQ-TNFR-2). Recorded: response status, cert status (good / revoked + reason and time / unknown), `thisUpdate`, `nextUpdate`, responder ID, whether its signature verifies against the issuer or a delegated responder certificate, and whether it is for this certificate. | P0 | RFC 6960; R-004 §4.G4 |
| **REQ-TREV-2** | Findings:<br>• stapled **revoked** → critical;<br>• stapled for another certificate, or signature invalid → high;<br>• `nextUpdate` passed (**stale**) → medium;<br>• **unknown** → medium. | P0 | RFC 6960 |
| **REQ-TREV-3** | **Must-Staple** (RFC 7633) certificate served without a staple → high finding. | P0 | RFC 7633 |
| **REQ-TREV-4** | "Stapling not offered" is a finding **only** when the certificate names an OCSP responder, and then at low severity with the context that the largest public CA stopped OCSP on 2025-08-06. A certificate with only CRL distribution points raises nothing. | P0 | R-004 §3 |
| **REQ-TREV-5** | The page states plainly that OCSP and CRL **lookups were not made** (external lookups arrive in T2, off by default) and lists the URLs the certificate gives. | P0 | R-004 §8 D1 |

### Epic F — Certificate Transparency (REQ-TCT)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TCT-1** | SCTs are collected from **all three sources**: embedded in the certificate, the TLS `signed_certificate_timestamp` extension, and the stapled OCSP response. Each SCT records its source, log ID, timestamp and signature algorithm. Parsing is our own bounded, fuzzed decoder (RFC 6962 §3.3). | P0 | RFC 6962 |
| **REQ-TCT-2** | Log IDs are named from a **bundled, dated CT log list** (reference data); an unknown log ID is shown as such. | P1 | R-004 §4.G5 |
| **REQ-TCT-3** | A **publicly trusted** leaf with **no SCT from any source** → medium finding (major browsers require CT for publicly trusted certificates). Private-CA certificates are exempt and the page says why. Counting against a browser policy and verifying SCT signatures is T2. | P0 | R-004 §4.G5 |

### Epic G — Key exchange (REQ-TKX)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TKX-1** | The DHE prime fingerprint already collected is matched against **reference data** generated from the RFC texts: RFC 7919 FFDHE groups (named, positive), RFC 3526 and RFC 2409 MODP groups, RFC 5114 groups. | P0 | R-004 §4.D |
| **REQ-TKX-2** | An **RFC-published prime of ≤ 1024 bits** (shared by every server that uses it, so a precomputation target) → new medium finding, labelled Logjam (see REQ-TVLN-1). Any named group is reported by its name. | P0 | CVE-2015-4000; Adrian et al., CCS 2015 |

### Epic H — HTTP security (REQ-THTP)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-THTP-1** | The `Strict-Transport-Security` header is **parsed** (RFC 6797 §6.1) into `max-age` (seconds and days), `includeSubDomains` and `preload`, plus a list of syntax problems. Multiple headers are recorded; per RFC 6797 §8.1 only the first is processed, and the rest are a finding. | P0 | RFC 6797 |
| **REQ-THTP-2** | Findings:<br>• no HSTS on an HTTP service → today's `HTTP.NO-HSTS`;<br>• `max-age` = 0 (HSTS switched off) → medium;<br>• `max-age` under one year → low, with the threshold cited from the HSTS preload requirements;<br>• invalid syntax or duplicate headers → medium;<br>• no `includeSubDomains` → info. | P0 | RFC 6797; hstspreload.org requirements |
| **REQ-THTP-3** | The HTTP stage is reported *not applicable* (not a failure) when the service does not answer as HTTP. | P0 | existing behaviour |

### Epic I — Named attacks (REQ-TVLN)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TVLN-1** | Every attack inferable from collected facts is **named as a label on the existing finding**, not as a second finding. A fact still counts once in the TLS hygiene score. The labels and the findings they attach to:<br>• **FREAK** → RSA_EXPORT suites;<br>• **Logjam** → DHE_EXPORT, DH ≤ 1024 bits, or a common prime;<br>• **DROWN** → SSLv2;<br>• **POODLE**, **BEAST** → existing;<br>• **SWEET32** → existing;<br>• **CRIME** → compression;<br>• **LUCKY13** → CBC suites, info;<br>• **RC4** → existing. | P0 | R-004 §4.I |
| **REQ-TVLN-2** | **DROWN across the estate:** this certificate's public key seen on **any** endpoint in the estate that supports SSLv2 → new high finding naming that endpoint. This uses the estate graph and is a capability other scanners lack. | P1 | R-004 §4.I |
| **REQ-TVLN-3** | Active-only attacks (Heartbleed, CCS injection, ROBOT, Ticketbleed, padding oracles) are listed in the Vulnerabilities section as ***Not tested by design***, with one sentence on why (no exploit traffic, decision D2), never omitted. | P0 | R-004 §8 D2 |

### Epic J — Reference data (REQ-TDAT)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TDAT-1** | Each reference list is **generated, never hand-edited**, by a committed generator, the way the IANA registries are. It carries its **source URL, retrieval date and checksum**, and is compiled into the binary. The lists are:<br>• the Mozilla roots (CCADB);<br>• the Chrome Root Store;<br>• the certificate-lifetime limits;<br>• the DH primes;<br>• the CT log list;<br>• the distrust list. | P0 | R-004 §5.4 |
| **REQ-TDAT-2** | **Licence gate:** a list is bundled only after its redistribution terms are recorded in `docs/` and found compatible with Apache-2.0. A list that fails the gate is not shipped, and its stage says so. | P0 | R-004 §8 D3 |
| **REQ-TDAT-3** | Each list's age is shown on *How we tested* and on the About page. A list older than 180 days is flagged there (not as a finding against the endpoint). | P1 | R-004 §5.4 |

### Epic K — The endpoint page (REQ-TUI)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TUI-1** | **Summary strip** at the top: readiness level, TLS hygiene score, a certificate headline (days left, trusted by *n* of *m* stores) and the count of *Not checked* sections. Each is a link to its section. | P0 | R-004 §6.2 |
| **REQ-TUI-2** | **Fix first:** the three most important findings across all sections, ordered by severity and then by a documented **availability-impact** property set on the findings that make clients fail. That property is set on:<br>• expired;<br>• untrusted;<br>• name mismatch;<br>• missing intermediate;<br>• must-staple missing;<br>• stapled revoked.<br>Each item gives the action in plain words and links to its section. | P0 | R-004 §6.2 |
| **REQ-TUI-3** | A **section index** (sticky left column; a chip row on narrow screens). It lists every section with its status as **word and symbol, never colour alone**: *Problem* (a critical or high finding), *Needs attention* (medium or low), *Good*, *Not checked*, *Inconclusive*. | P0 | R-004 §6.1 |
| **REQ-TUI-4** | **Every section has the same anatomy:**<br>• a one-sentence purpose (*what this checks and why it matters*);<br>• the status;<br>• the key facts as plain sentences;<br>• **this section's findings inline**, each with fix and citation;<br>• *Show all data* (the full tables);<br>• *How we tested* (REQ-TSTG-2).<br>A test fails any section without a purpose line. | P0 | R-004 §6.1 |
| **REQ-TUI-5** | *Not checked* and *Not collected by the version that ran this scan* are always rendered, with the reason and, where a setting controls it, how to turn it on. | P0 | R-004 §6.1 |
| **REQ-TUI-6** | **Certificates & trust** section:<br>• a chain diagram of the chain **as served**, problems marked on the link where they occur;<br>• a validity bar (issued → today → expiry) with the lifetime-limit marker;<br>• a **trust row per store** (Mozilla, Chrome, your CA bundle, optional OS);<br>• the names checked;<br>• one tab per chain: default, ECDSA, RSA, no-SNI. | P0 | R-004 §6.3 |
| **REQ-TUI-7** | **Revocation & transparency** section in sentences. For example: *Stapled OCSP response: good, valid until …, signed by the issuer*. Then the OCSP/CRL URLs the certificate gives, with *not looked up* and the reason. Then the SCT list (source, log, time). | P0 | R-004 §6.3 |
| **REQ-TUI-8** | The remaining sections are restructured to the anatomy of REQ-TUI-4, in the order of RESEARCH-004 §6.3:<br>• Protocols, as a pill row;<br>• Cipher suites, with a category summary first, problem rows first and acceptable rows collapsed;<br>• Key exchange & post-quantum;<br>• Features & sessions;<br>• HTTP security, with HSTS fields as sentences;<br>• Vulnerabilities, one line per named attack: *exposed / not exposed / not tested by design*;<br>• Scan details;<br>• History.<br>Signatures, Compatibility and Profile checks are **not shown** until their phase delivers data. | P0 | R-004 §6.3 |
| **REQ-TUI-9** | The **Findings tab** remains as a cross-section index with triage. Every finding links to its section anchor, and every inline finding links to the index. | P0 | R-004 §6.1 |
| **REQ-TUI-10** | **History** marks which sections changed since the previous scan. A change of evaluation version is shown as such, not as a change in the endpoint. | P1 | R-004 §6.3 |
| **REQ-TUI-11** | The **report export** (existing *Export report*) follows the same sections and order. | P1 | — |
| **REQ-TUI-12** | **Private CA bundle UI** on the system page (add, list with subject/expiry/fingerprint, remove) and the server-wide bundle shown read-only on the About page. Upload goes through the same PEM rules as REQ-TTRS-2. | P0 | R-004 §4.G3 |
| **REQ-TUI-13** | The **Certificates page** (estate-wide) gains columns and filters for trust-per-store, OCSP staple status, SCT presence and chain problems (via REQ-TCRT-7). | P1 | — |
| **REQ-TUI-14** | Terminology unchanged: TLS hygiene score, readiness level, profile check (later). No grades. The UI vocabulary guard test is extended to the new copy. | P0 | feedback-own-terminology |

### Epic L — Quality and non-functional (REQ-TNFR)

| ID | Requirement | Pri | Source |
|---|---|---|---|
| **REQ-TNFR-1** | New parsers (stapled OCSP, SCT list, HSTS header, certificate extensions beyond what `crypto/x509` decodes) treat input as hostile. Every length is bounded, there is no unbounded allocation, and each parser has a **fuzz target** in CI's fuzz job. | P0 | SECARCH-001 |
| **REQ-TNFR-2** | **No new Go module dependency** (OCSP and SCT are decoded with `encoding/asn1` and our own code). If that proves unsound, an ADR is required before adding one. | P0 | PRD-003 REQ-NFR-2 |
| **REQ-TNFR-3** | Every text that comes from the target or a certificate (subjects, SANs, policy strings, HSTS header, OCSP responder names) reaches the DOM via `textContent` only. Hostile-string fixtures cover every new section in the browser journey and `security.sh`. | P0 | SECARCH-001 |
| **REQ-TNFR-4** | **Evaluation version** moves to `eval/3`. Stored results keep their evaluation. The page says when a result was evaluated by an earlier version and offers *re-evaluate* (from the stored report, no new scan). | P0 | existing behaviour |
| **REQ-TNFR-5** | **Connection budget:** a Standard scan adds no more than 5 connections over 0.2.0 on the demo targets (T1-M6). | P0 | R-004 §5.3 |
| **REQ-TNFR-6** | **API and OpenAPI** carry the new fields; the route-parity test stays green; `docs/tls-scanning.md` and `docs/methodology.md` describe every new check and rule with its citation. | P0 | PRD-003 REQ-EXP-5 |
| **REQ-TNFR-7** | The **CBOM** gains new certificate facts only where CycloneDX 1.7 has a field for them. Nothing is invented; the gaps are listed in `docs/cbom-model.md`. | P1 | PRD-003 REQ-EXP-2 |

## 6. Security requirements (merged into SECARCH-001 §3 on baseline)

| ID | Requirement | Verified by |
|---|---|---|
| **SR-19** | T1 traffic goes only to the target (REQ-TSTG-5). | A dialer-recording test over a full Standard scan; mutation check: add a lookup → the test fails |
| **SR-20** | The private CA bundle accepts public certificates only. Key blocks are refused undecoded; there are size/count limits; changes are audited. | Decoy-key fixture as in PRD-003 M4: 0 key bytes stored, logged or returned |
| **SR-21** | The HTTP stage's limits are unchanged by turning it on by default: one request, 8 KiB, no redirects, the SSRF guard on the same dialer. | Existing HSTS tests plus a test that a `Location` header is not followed |
| **SR-22** | Reference data is compiled in and checksummed; it is never downloaded at run time. | Build-time generator check; a test that no HTTP client is constructed by the scan path |
| **SR-23** | All new parsers are fuzzed (REQ-TNFR-1). | CI fuzz job targets listed in the RTM |
| **SR-24** | All new UI text from untrusted sources is inert (REQ-TNFR-3). | Hostile fixtures in the journey and `security.sh` |

## 7. Data and interfaces (summary)

- **Report** `tls-report/2` adds, all optional:
  - `stages[]` (name, outcome, reason, connections, probes, inconclusive, reference snapshots);
  - per-certificate `kuEku`, `basicConstraints`, `nameConstraints`, `policyClass`, `lifetimeDays`;
  - per chain:
    - `served` (order, issues);
    - `trust[]` per store;
    - `namesChecked`;
    - `noSni` comparison;
    - `ocspStaple{...}`;
    - `scts[]`;
  - `hsts{ maxAge, includeSubDomains, preload, problems[] }`;
  - `dh.namedGroup`.
- **Graph:** the new facts are attributes of the certificate entity, with the observation that produced them.
- **API:** existing scan/report routes return the new fields. New routes for the private CA bundle per system (list, add, remove), all under the token and the anti-forgery guard. OpenAPI is updated.
- **Config:** a `trust.caBundle` path for the server-wide bundle; the existing `--http-checks` flag now defaults to on.

## 8. Delivery

### 8.1 Increments

| Increment | Contents | Depends on |
|---|---|---|
| **T1a — Data** | Reference-data generators, licence gate, snapshots (Epic J) | — |
| **T1b — Scanner** | Stages, `tls-report/2`, no-SNI handshake, served chain, certificate extensions, OCSP and SCT decoders, HSTS parser (Epics A–C, E–H scanner parts) | T1a for trust |
| **T1c — Evaluation** | New and changed rules, attack labels, availability impact, `eval/3`, DROWN across the estate (rule side of Epics B–I) | T1b |
| **T1d — UI** | Endpoint page rebuild, private CA bundle UI, Certificates page additions (Epic K) | T1c |
| **T1e — QA** | QA-PLAN-004 executed, QA report, RTM | all |

### 8.2 Fixtures (new hermetic servers / demo targets)

Each fixture is paired with the finding it must raise:

| Fixture | Finding |
|---|---|
| Clean (publicly-shaped chain under a test root bundled for tests only) | none |
| Missing intermediate | high |
| Wrong order | per REQ-TCHN-3 |
| Root included | info |
| Intermediate expiring before the leaf | medium |
| Must-Staple without a staple | high |
| Stapled `good`, fresh | none |
| Stapled `revoked` | critical |
| Stapled stale | medium |
| Stapled for another certificate | high |
| No-SNI default certificate, expired | finding on the no-SNI tab only |
| Leaf without serverAuth | high |
| Public leaf with clientAuth | info |
| 47-day certificate with 20 days left | none |
| 398-day certificate issued after 2026-03-15 | lifetime finding |
| Private-CA chain, without bundle | untrusted |
| Private-CA chain, with bundle | trusted, lifetime/CT exempt |
| Trusted by one bundled store only | partial-trust finding |
| No SCTs, publicly-shaped | medium |
| SCTs via TLS extension only | none |
| HSTS absent / `max-age=0` / short / duplicate / invalid / complete | per REQ-THTP-2 |
| DHE with an RFC 7919 prime | named, no finding |
| DHE with a common 1024-bit prime | medium + Logjam label |
| A second endpoint with SSLv2 and the same key | DROWN across the estate |

### 8.3 Definition of done

As PRD-003 §10. Each requirement is done when all of these hold:

- the design is recorded;
- tests that trace to its ID are merged;
- its security requirements are verified (with a mutation check where listed);
- its QA evidence is in the RTM;
- the docs are updated.

The RTM is the only place "done" is asserted.

## 9. Decisions (owner, 2026-10-02)

Recorded from RESEARCH-004 §8 ("go with your recommendations"):

| # | Decision | Effect on T1 |
|---|---|---|
| D1 | Third-party lookups exist from T2, **off by default**, and every unchecked item says so | T1 makes none (REQ-TSTG-5); the page lists the URLs as *not looked up* (REQ-TREV-5) |
| D2 | **No active vulnerability probes** | Listed as *not tested by design* (REQ-TVLN-3) |
| D3 | Bundle **Mozilla and Chrome** root stores first; Apple, Microsoft, Java later; each after a licence check | REQ-TTRS-1, REQ-TDAT-2 |
| D4 | STARTTLS order: SMTP, IMAP, LDAP, PostgreSQL | T2 |
| D5 | Client-hello library captured by us | T3 |
| D6 | HTTP scope **TLS-related only** (HSTS, preload, redirect, Alt-Svc); the HTTP stage on by default within those limits | REQ-TSTG-4, Epic H; preload and redirect in T2 |
| D7 | Scan the first address by default; show "1 of n addresses" with one-click *scan all* | *Scan all* is T2; T1 shows the count (REQ-TUI-1) |

## 10. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| RT-1 | A root-store snapshot cannot be redistributed under its terms | Medium | High | Licence gate before bundling (REQ-TDAT-2); the stage reports *not available* instead of silently falling back to the OS store |
| RT-2 | Snapshots go stale between releases | High | Medium | Dates shown everywhere they are used; 180-day flag; generator in the release checklist |
| RT-3 | New findings move hygiene scores, and history looks like the endpoints changed | High | Medium | `eval/3` marked in history; re-evaluate from the stored report; CHANGELOG |
| RT-4 | HTTP stage on by default surprises users who relied on handshake-only scans | Low | Medium | Unchanged limits, a server-wide off switch, About page and CHANGELOG wording |
| RT-5 | Hand-written OCSP/SCT decoding is subtly wrong | Medium | High | OpenSSL oracle on fixtures (T1-M3), fuzzing, mutation checks on each finding |
| RT-6 | The page rebuild regresses accessibility or the hostile-input guarantees | Low | High | The existing journey and `security.sh` extended to every new section before merge |
| RT-7 | Scope: Epic K alone is large | Medium | Medium | Increments with gates; P1 items slip first, with PM sign-off |

## 11. Open questions

All three were resolved at baseline:

| # | Question | Resolution |
|---|---|---|
| OQ-T1 | Redistribution terms of the root lists | **Resolved.** Both root stores are taken from the CCADB reports (`MozillaTLSServerAuthenticationCSV`, `ChromeTLSServerAuthenticationCSV`), governed by the CCADB Data Usage Terms: **CDLA-Permissive-2.0**, attribution to the CCADB required, no endorsement. Compatible with Apache-2.0; the attribution is recorded in `docs/reference-data.md` and shown on the About page. |
| OQ-T2 | Private CA bundle per endpoint as well? | **Per system plus server-wide**, as drafted. Per endpoint can be added later if asked for. |
| OQ-T3 | Expiry thresholds of REQ-TCRT-4 | **Accepted as drafted.** |

## 12. Change log

| Date | Change | By |
|---|---|---|
| 2026-10-02 | Draft from RESEARCH-004 and the owner's §8 decisions | PM, Security Architect (role-played) |
| 2026-10-02 | **Baseline** (owner). Security requirements renumbered SR-19…SR-24 and merged into SECARCH-001 so the existing traceability check covers them. | Owner |
| 2026-10-02 | REQ-TKX-1/2: the "widely shipped defaults from the Logjam study" are dropped from the reference data. No machine-readable, licence-clear list of them exists; the RFC-published groups (which include the 1024-bit Oakley groups) are generated from the RFC texts instead. | PM, Security Architect |
| 2026-10-02 | REQ-TDAT-1: a short table transcribed from a document (the SC-081v3 lifetime schedule) is hand-written with its source and date and pinned by a test. Lists with a machine-readable source are generated. | PM, Security Architect |
| 2026-10-02 | REQ-TVLN-1: LUCKY13 attaches to a new info finding `CIPHER.CBC` (CBC suites in TLS ≤ 1.2), since no existing finding covers CBC suites as such. Info findings take no points. | PM, Security Architect |
| 2026-10-02 | REQ-TCRT-6: the Debian weak-key blocklist is deferred (data volume; no licence-clear machine-readable source located). ROCA, small exponent and shared modulus remain. | PM, Security Architect |
