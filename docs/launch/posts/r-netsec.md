# r/netsec draft

**Title:** CipherHorizon: open-source TLS scanner that rates post-quantum readiness (L0 to L4), with STARTTLS and a CycloneDX CBOM

**Body:**

We've released CipherHorizon (Apache 2.0, Go), a self-hosted scanner for working out where an estate stands on
post-quantum TLS. Some technical notes:

- **Own TLS wire implementation.** It can offer what `crypto/tls` and OpenSSL refuse: SSLv2/v3, export, anonymous,
  NULL suites, and arbitrary groups. It enumerates each version's suites, the server's preference, and the
  supported groups, including ML-KEM hybrids. Go's `crypto/tls` is used only to fetch chains and show what a current
  client actually negotiates.
- **Readiness level.** L2 means a hybrid group is accepted but a current client doesn't get it. L3 means it does.
  Pre-standard Kyber draft code points are reported but don't count.
- **No active vulnerability probes.** Attack exposure (POODLE, Sweet32, FREAK, Logjam...) is inferred from the
  configuration and labelled as such. If you need Heartbleed or ROBOT confirmed, testssl.sh does that.
- **55 checks,** each citing RFC 8446/9325/8996, NIST SP 800-52, FIPS 203/204, IANA.
- **Scope controls:**
  - the SSRF guard checks the real remote address on every connection (no DNS rebinding);
  - `--scan-allow` limits targets to your own networks or domains;
  - every change is in an append-only activity log.
- **It passes its own scan:** TLS 1.2 ECDHE-AEAD only, TLS 1.3 with X25519MLKEM768, and HSTS. CI scans it with itself.

Repo: `<repo>` · Methodology: `<repo>/blob/main/docs/methodology.md`

Corrections to findings or citations are very welcome; the evidence rule is in CONTRIBUTING.md.
