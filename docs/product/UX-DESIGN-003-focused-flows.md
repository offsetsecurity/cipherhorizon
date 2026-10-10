# UX-DESIGN-003: Focused flows — Scan, Reports, Inventory, Systems

Design for [PRD-005](PRD-005-product-focus-and-flows.md). Keeps the 0.2.0 visual identity (violet primary, amber accent,
dark sidebar); changes the structure and the amount of text.

## 1. Principles

1. **The first screen answers the question.** Scan: "what do I type". Report: "is it OK, what do I fix". Inventory:
   "what do we have, what is vulnerable".
2. **One line per thing by default.** A section, a finding, a source is one line until it is opened.
3. **Explanation is opt-in.** Every *why*, *source*, *method* is behind a disclosure with a consistent label.
4. **One noun per thing.** Report, endpoint, machine, inventory, source, system.

## 2. Menu

```
┌──────────────────────────┐
│ ◆ CipherHorizon           │
│ TLS scanner and CBOM      │  ← product sentence, short form
│ inventory                 │
│                           │
│ ⌕  Scan            (home) │
│ ▤  Reports                │
│ ◫  Inventory              │
│ ⚑  Systems          (3)   │  ← pending decisions
│ ⋯                         │
│ ⓘ  About                  │  ← footer
└──────────────────────────┘
```

## 3. Scan (home)

```
Scan a TLS endpoint
Check its configuration, certificate and post-quantum readiness.

┌────────────────────────────────────────────┐ ┌────────┐
│ example.com or host:port                     │ │  Scan  │
└────────────────────────────────────────────┘ └────────┘
Only scan systems you own or are authorised to test.
Scan many endpoints · Add a CBOM or machine inventory

Recent reports                                   All reports →
┌──────────────────────────────────────────────────────────────┐
│ modern-hybrid   127.0.0.1:9440   L3 Hybrid · Fair 60 · 62 d · 2 findings · 8 min ago │
│ legacy-tls12    127.0.0.1:9442   L0 Not ready · Fair 56 · …                         │
└──────────────────────────────────────────────────────────────┘

Inventory   34 algorithms · 9 quantum-vulnerable · 7 certificates     Open inventory →
```

Errors (refused target, invalid input) appear in red under the input.

## 4. Reports

```
Reports                                            [Scan many] [Export CSV]
┌─ Fleet ───────────────────────────────────────────────────────┐
│ PQC readiness  ■■■ L3 4  ■■ L1 2  ■ L0 2      TLS hygiene  Strong 1 · Sound 0 · Fair 4 · Weak 2 · Broken 1 │
│ Certificates expiring ≤ 30 days: 5                                                                   │
└───────────────────────────────────────────────────────────────┘
[Endpoints] [Findings] [Activity]
  (the current endpoints table)
```

## 5. The report

```
← Reports
legacy-tls12                                  [Scan now] [Rescan ▾] [Download ▾] [Copy link] [⋯]
127.0.0.1:9442 · scanned 8 min ago

┌ L0 Not ready ┐ ┌ 56 Fair ┐ ┌ 0 days left ┐ ┌ 0 not checked ┐     ← summary strip (unchanged)
Fix first
 1 ▲ high  Certificate chain is not trusted — Install a certificate from a CA your clients trust…   Certificates →
 2 ◆ medium TLS 1.0 is enabled — Disable TLS 1.0.                                                  Protocols →

[Report] [Findings 7] [History 3]                               Expand all · Collapse all
▸ Certificates & trust      ✖ Problem          Not trusted by Mozilla or Chrome; valid 79 days
▾ Protocols                 ▲ Needs attention  Accepts TLS 1.2, 1.1, 1.0
    Which SSL and TLS versions the server accepts.
    ◆ medium  TLS 1.0 is enabled.  Fix: Disable TLS 1.0.            Why and sources ▸
    ✔TLS1.3 ✔TLS1.2 ✖TLS1.1 ✖TLS1.0 — SSLv3 — SSLv2
    Show data ▸
▸ Cipher suites             ✔ Good             11 suites, all AEAD
▸ Key exchange & PQ         ✔ Good             X25519MLKEM768 negotiated
▸ Revocation & CT           ✔ Good             OCSP stapled, 2 CT proofs
▸ Features & sessions       ✔ Good             Secure renegotiation, no compression
▸ HTTP security             ▲ Needs attention  No HSTS header
▸ Vulnerabilities           ✔ Good             Not exposed to any inferable attack
▸ About this report         scan, methodology, reference data, TLS hygiene breakdown
```

Section line verdicts come from the same facts the section body uses (first fact sentence). Open/closed state of each
section is remembered per session.

## 6. Inventory

```
Inventory                                   [Add data] [Download CBOM ▾ 1.7 / 1.6]
Every algorithm, certificate and protocol seen by your scans, your machines and imported CBOMs.
┌ Algorithms 34 ┐ ┌ Quantum-vulnerable 9 ┐ ┌ Certificates 7 · 5 expire ≤30 d ┐ ┌ Sources 14 ┐
[Algorithms] [Certificates] [TLS] [Software] [Sources]
Filter [________]  ☐ only quantum-vulnerable   Source: [any ▾]
┌──────────────────────────────────────────────────────────────────────────┐
│ RSA-2048        ✖ quantum-vulnerable   seen in 3 systems · 4 places   scan, collector   2 h ago  ▸ │
│   └ legacy-tls12 (endpoint, scan) · db-02 (machine, collector) · …                                 │
│ AES-256-GCM     ✔ quantum-safe         seen in 6 systems …                                         │
└──────────────────────────────────────────────────────────────────────────┘
```

Add data dialog: three tiles (Scan an endpoint · Upload a machine inventory (+ collector download) · Import a CBOM),
each opening the existing flow.

## 7. Systems

```
Systems                                              [Export details (CSV)]
Group endpoints and machines, set owners, and see which to move to post-quantum first.
[Migration order] [Decisions 3]
 (the current ranked table; "no owner details yet" instead of "based on evidence only")
```

## 8. Responsive and states

390 px: menu collapses to the top bar (existing behaviour); summary tiles 2×2; section lines wrap the verdict under the
name. Empty states are one sentence and one button. Loading: skeleton rows.
