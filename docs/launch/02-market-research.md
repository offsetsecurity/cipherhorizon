# 02 · Market research: who else does this, what people like, how tools like this get adopted

2026-10-08. Sources are listed at the end. GitHub figures come from third-party snapshots and are approximate.

## 1. The field

### Classic TLS scanners (configuration hygiene)

| Tool | Form | Strengths people cite | Limits |
|---|---|---|---|
| testssl.sh (~9k stars, GPLv2) | One Bash script | Zero install, broad named-vulnerability checks, STARTTLS, HTML/JSON/CSV out | One endpoint at a time, no history, no fleet view, letter grades, no PQC focus |
| SSLyze (~3.7k, AGPL) | Python library + CLI | Scriptable, fast, Mozilla profile checks | AGPL blocks embedding; no UI; no PQC focus |
| sslscan, nmap `ssl-enum-ciphers` | CLI | Everywhere already | Raw lists, no judgement |
| Qualys SSL Labs, Hardenize | Web service | The reference report everyone knows | Public internet only, letter grades, no internal endpoints, no CBOM |

### New open-source PQC-readiness scanners (TLS + CBOM), mostly 2025–2026

| Tool | Form | Claims |
|---|---|---|
| QuReddy (BreachSAFE, Apache-2.0) | Python CLI, Docker | PQC readiness at TLS, SSH, IKE; JSON/CBOM out |
| AC-Scanner (qubitac) | Pipeline | TLS + SSH surface, CBOM aligned to NIST IR 8547 |
| QRAMM TLS Analyzer (CSNP, MIT) | Go CLI | Detects hybrid ML-KEM, CNSA 2.0 tracking, CycloneDX CBOM, bulk scan |
| oqs-scanner / open-quantum-secure | Go CLI | 0–100 "Quantum Readiness Score", CycloneDX 1.7 CBOM, 7 compliance frameworks, code scanning in 14 languages |
| cryptosweep | CLI, CI gate, MCP server | TLS + source + dependencies; CBOM, SARIF, HTML report |

### CBOM tooling and enterprise suites

| Tool | Form | Notes |
|---|---|---|
| PQCA CBOMkit (from IBM, Linux Foundation) | SonarQube plugin, service, GitHub Action, container scanner | Source-code CBOM (Java, Python), the reference for the CBOM format; no network scanning |
| IBM Guardium Quantum Safe, SandboxAQ AQtive Guard, Keyfactor and others | Commercial platforms | Continuous discovery, policy, enterprise integrations; sales-led, priced for large estates |

## 2. Where CipherHorizon stands

The space is no longer empty: "PQC TLS scanner with CBOM output" is now a crowded one-liner, so it cannot be the
headline on its own. CipherHorizon is unusual in what it combines:

| Differentiator | Others |
|---|---|
| **A self-hosted application, not a CLI:** history, fleet view, accounts and roles, scheduled rescans, PDF reports | The new PQC tools are CLIs; SSL Labs is a public web service |
| **Its own TLS wire implementation:** SSLv2/v3, export and anonymous suites, arbitrary groups, the server's group preference, a direct L0–L4 readiness level | Go `crypto/tls` or OpenSSL based tools cannot offer what those libraries refuse |
| **Endpoints and machines in one inventory:** TLS scans plus a PowerShell or shell script for servers, merged into one CBOM | Network-only or code-only |
| **Every finding is explained and cited:** "why it matters", "what to do", sources (RFCs, NIST, IANA), passed checks stated too | Bare lists or opaque scores |
| **Migration order:** systems ranked by harvest-now-decrypt-later exposure, data lifetime and criticality; OMB M-23-02 export | Only the commercial suites |
| **Air-gap friendly:** one binary, no external calls, no telemetry, signed releases | SaaS tools need the internet |

**Positioning.** The open-source *self-hosted* PQC readiness workbench: scan every TLS endpoint you run, inventory
the machines behind them, get one CBOM and a migration order, and hand auditors a report. It is the product form
of Offset Security's PQC Readiness practice (discovery and inventory, then quantum risk prioritisation).

**Who it is for.**
1. Security and PKI engineers starting a PQC programme, who need an inventory and evidence.
2. Platform teams that must fix TLS hygiene before they can talk about post-quantum.
3. Consultants and MSSPs, including Offset's own practice, who need a repeatable engagement tool.
4. Regulated organisations with an air-gapped or internal estate, which SaaS scanners cannot reach.

## 3. What people like after seeing a tool (first ten minutes)

From launch threads, tool comparisons and README patterns of successful security projects:

1. **Instant proof.** A GIF or screenshot above the fold showing the result, then a one-command start:
   `docker run …` or a single binary. Setup friction is the first question on every launch thread.
2. **Value without sign-up or cloud.** "Runs locally, sends nothing anywhere" is a feature for security buyers. Say
   it in the first screen.
3. **A result they can show their boss.** A clean report (PDF), a single readiness level, a clear list of what to fix.
4. **Honesty.** What it checks, what it does not, how false positives are handled, what data it touches. Security
   readers trust candour more than claims.
5. **Standards they already cite.** NIST IR 8547 dates, FIPS 203/204/205, CNSA 2.0, CycloneDX CBOM, OMB M-23-02.
6. **A clear "why now".** Harvest now, decrypt later, and the 2030/2035 deprecation dates.
7. **It fits their pipeline.** Repeated use comes from automation: a CLI with exit codes, JSON, and a CI example.
   Stars follow repeated use.
8. **Comparison is expected.** "How is this different from testssl.sh / SSL Labs?" will be asked; answer it in the
   README.
9. **Hygiene signals.** A license, SECURITY.md, CONTRIBUTING, signed releases, an SBOM, recent commits, a live demo.

## 4. How tools like this get adopted (channels)

| Channel | Fit | Notes |
|---|---|---|
| GitHub (README, topics, releases) | Primary | Topics: `post-quantum`, `pqc`, `tls`, `cbom`, `cyclonedx`, `ml-kem`, `security-tools`. A pinned "Quick start" |
| Show HN | High | Something people can try immediately; the first comment says why it exists and its limits |
| Reddit r/netsec, r/cybersecurity, r/sysadmin, r/selfhosted | High | r/selfhosted loves one-command Docker apps with screenshots |
| LinkedIn (Offset Security and the founders) | High for buyers | The CISO and regulated-industry audience Offset already addresses |
| PQC community: PQCA, CycloneDX CBOM working group, NIST NCCoE migration project, OpenSSF | High credibility | List it in the CycloneDX tool center; offer CBOM samples |
| Awesome lists (awesome-pqc, awesome-selfhosted, awesome-security) | Steady discovery | Needs a docs site and a stable release |
| Conference talks and blog posts | Long tail | "We scanned N public sites for post-quantum readiness" data posts travel well |
| Product Hunt | Low to medium | Better for UI tools; possible with the web app |

**A public demo instance** (read-only viewer account, demo targets) removes the last bit of friction. It needs the
scan scope (L-01) and a viewer-only account so it cannot be abused.

## Sources

- [QuReddy (BreachSAFE)](https://github.com/BreachSAFE/qureddy), [AC-Scanner](https://github.com/qubitac/AC-Scanner),
  [QRAMM open-source tools](https://qramm.org/open-source-tools.html), [cryptosweep](https://github.com/maximilliangrand/cryptosweep),
  [open-quantum-secure](https://github.com/jimbo111/open-quantum-secure)
- [CryptoLyzer vs testssl.sh vs SSLyze](https://dev.to/coroner/cryptolyzer-vs-sslyze-vs-testsslsh-a-practical-comparison-eo9),
  [testssl vs sslyze vs sslscan guide](https://www.pistack.xyz/posts/2026-04-22-testssl-vs-sslyze-vs-sslscan-self-hosted-ssl-tls-scanning-guide-2026/),
  [HN thread on testssl.sh vs sslyze](https://hn.svelte.dev/item/43552514)
- [IBM: CBOM toolset to the Linux Foundation](https://researcher.ibm.com/blog/cryptographic-cbom-linux-foundation),
  [Managing cryptography with CBOMkit](https://researcher.ibm.com/blog/quantum-safe-cbomkit),
  [Cryptographic inventory vendors](https://postquantum.com/post-quantum/cryptographic-inventory-vendors/),
  [AQtive Guard](https://carahsoft.com/sandboxaq/solutions/AQtive-Guard)
- [Opengrep launch](https://hunted.space/product/opengrep), [OpenHack launch](https://www.linkedin.com/company/openhackai)
- [Offset Security](https://offsetsecurity.net/), [Offset PQC Readiness](https://offsetsecurity.net/post-quantum-cryptography-readiness.html)
