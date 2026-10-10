# REVIEW-002: PM final review — PRD-002 (evidence, capability-vs-negotiation, mTLS surface, HSTS)

| | |
|---|---|
| **Covers** | [RESEARCH-002](RESEARCH-002-pqc-tls-cbom-landscape.md) (Phases 1–7) → [PRD-002](PRD-002-evidence-and-coverage.md) (Phase 8) → implementation (Phase 9) → dev testing (Phase 10) → QA (Phase 11) |
| **Result** | All 4 PRD-002 features (2×P0, 2×P1) shipped, tested, and QA'd. `go build`, `go vet`, `gofmt -l`, `go test ./...`, `golangci-lint run ./...` all clean. |

## Executive summary

The brief asked five questions the industry's own literature (not vendor marketing) says general-purpose TLS/PQC
scanners get wrong: whether a meaningful CBOM can come from a remote scan alone, whether "the server can" is being
conflated with "the server did," whether client-certificate (mTLS) posture is visible, whether the product's own
stated methodology gaps are real, and whether transfer/deployment model matters for this class of tool. All five
were researched from primary sources first (RESEARCH-002), turned into four scoped, cited feature specs
(PRD-002), then implemented, tested, and QA'd end to end — CLI, JSON, and web UI all verified against a live
server, not just unit tests.

**What shipped this round is CBOM evidence + capability-vs-negotiation labelling + mTLS detection + opt-in HSTS.**
What deliberately did **not** ship (STARTTLS, fleet CBOM merge, full named-curve/DH-group catalogues, composite
ML-DSA certs, JARM/JA3, agent/binary transfer redesign) is unchanged from RESEARCH-002 §9's original scoping —
this round closed the four highest-value, most tractable gaps rather than attempting all of them shallowly, per
the explicit instruction to implement fully rather than survey broadly.

## Industry problems (grounded findings, not assumptions)

From RESEARCH-002 (every claim there tagged `[verified]`/`[reported]`/`[my inference]`):

1. **Capability vs. negotiation conflation.** The literature's own stated reason general-purpose PQC scanners
   under-report: a single default probe often never *offers* a hybrid group, so it never sees a server accept one,
   and "accepted in enumeration" gets reported as equivalent to "a real client would get this." This project's
   *readiness* levels already separated these; its *CBOM* did not until Feature 2.
2. **CBOMs asserting more than a remote scan can know.** CBOMkit and CycloneDX 1.6 both provide
   `evidence.identity.confidence` for exactly this reason; this project's own CBOM export carried no evidence
   marker at all before Feature 1 — a consumer of the raw JSON could not tell "observed on the wire" from anything
   else.
3. **mTLS is a real, currently blind, TLS-observable surface.** A `CertificateRequest` (RFC 8446 §4.3.2) is
   something a scanner already completing full handshakes can see for free, but wasn't looking for. Reported
   real-world mTLS adoption is low (~6.2%) but concentrated exactly where PQC-readiness stakes are highest
   (service mesh, high-value internal APIs).
4. **HSTS was this project's own single largest named "not measured" gap.** Every general-purpose competitor that
   publishes a grade treats it as part of "fully checked"; this project's own `docs/methodology.md` already
   admitted the gap by name before this round.
5. **Can a meaningful CBOM be built from a remote scan alone?** Yes, for the TLS surface specifically (protocol,
   negotiated suite/group, certificate chain, mTLS request) — not a complete cryptographic inventory of the host.
   RESEARCH-002 §5 draws the observable/not-observable line explicitly; nothing implemented this round crosses it.

## Competitive gaps addressed vs. still open

| Gap | Status after this round |
|---|---|
| Evidence-tiered CBOM facts | **Closed** (Feature 1) |
| Capability vs. negotiation distinction, in the CBOM specifically | **Closed** (Feature 2) |
| mTLS / client-cert-requested detection | **Closed** (Feature 3) |
| HSTS / HTTP-layer check | **Closed, opt-in** (Feature 4) |
| STARTTLS | Still open — P1 backlog, unchanged from RESEARCH-002 |
| Fleet CBOM merge, named-curve/DH-group catalogue completion, composite ML-DSA cert recognition, JARM/JA3 | Still open — P1/P2 backlog, unchanged |

## Features added

**Feature 1 — Evidence-aware CBOM.** Every component `FromTLSReport` emits now carries a CycloneDX 1.6
`evidence.identity` block (`confidence: 1.0`, a `methods` entry naming exactly what observed the fact — ServerHello,
HelloRetryRequest, or certificate chain). Validated against the vendored 1.6 schema, not just "compiles."

**Feature 2 — Capability vs. negotiation in the CBOM.** The protocol component matching `rep.Negotiated.Version`
carries `cipherhorizon:negotiated-suite` / `cipherhorizon:negotiated-group` properties; the negotiated group's own
algorithm component (when independently enumerated too) carries `cipherhorizon:negotiated = "true"`. Shared
primitive components (AES, ECDH, RSA, ...) are never marked — marking a shared component would itself be the kind
of overclaim this feature exists to prevent. Two real implementation bugs were caught and fixed during development
(matching by name instead of catalogue-resolved bom-ref; passing a catalogue ID where a bom-ref was required) —
both caught by the test suite before being called done, not by later QA.

**Feature 3 — Client-certificate-requested (mTLS) detection.** `Features.ClientCertRequested *bool`, set via a
`tls.Config.GetClientCertificate` callback on the handshake already made by default (no new connection). Semantics
are stricter than the PRD's original two-state description: `true` the instant the server asks (even if the
handshake then fails for lack of a real certificate — that failure is itself the observation), `false` **only**
when a full handshake succeeded with no request, and `nil` — unknown, not "no" — for everything in between (e.g. a
handshake that failed for an unrelated reason before reaching that point). New `Info`-severity, cited eval finding
`FEAT.CLIENT-CERT-REQUESTED`; new CLI text-report line; new "Server features" UI table row (nil-means-omit,
matching every existing row).

**Feature 4 — Optional HTTP-layer check (HSTS).** Off by default, opt-in via `--http-checks` (both `tls scan` and
`serve`). When enabled, sends exactly one `GET /` (no body, no redirect followed, 8 KiB read cap) over a dedicated
connection after the handshake and reads only the `Strict-Transport-Security` header. `Report.HSTS *bool`: `nil`
when not attempted or the connection didn't speak HTTP at all, `true`/`false` only from a genuine HTTP response.
New `Low`-severity finding `HTTP.NO-HSTS`, firing only when the check actually ran. Documented as the one named
exception to the project's "only handshake messages are exchanged" safety invariant, in the CLI help text, the
web UI's About page, `docs/tls-scanning.md`, and `docs/methodology.md`.

**One documented design deviation:** the PRD's technical design for Feature 4 specified reusing the TLS connection
already open for certificate fetching, to avoid a second connection. Implemented instead as one dedicated
connection, opened only when `--http-checks` is set. Reason: reusing the live connection across `certs.go`'s
lifecycle would have meant closely coupling connection-lifetime management between two otherwise-independent
probe stages — a bigger, riskier change than the AC actually required (AC-4.1 only constrains *default*
behavior: zero extra connections when the flag is off). Verified live: `--http-checks` adds exactly one connection
to `rep.Connections`, never more, and the default-off path adds none — both hermetic-tested and confirmed against
a real running server.

## Features deliberately not implemented (and why)

Unchanged from RESEARCH-002 §9's scoping, carried into PRD-002's backlog table, none silently dropped:
- **STARTTLS** (SMTP/IMAP/etc.) — real gap, but a different protocol-detection surface than anything touched this
  round; P1 for next.
- **Fleet-level CBOM merge** — a server/aggregation feature, out of scope for a single-scan CBOM builder change.
- **Named curve catalogue completion, composite ML-DSA certificate recognition, DH group registry matching,
  JARM/JA3** — each is its own research-and-verify cycle (rule 3: do not invent capabilities); none were
  short-changed to hit a deadline, they were never started.
- **File/script/binary/agent transfer model changes** — Phase 4's research question was answered (RESEARCH-002),
  but no code in this round touches deployment/transfer; the existing single static binary was not judged to need
  a redesign to ship these four features.

## CBOM assessment (the brief's central question)

**Yes, a meaningful CBOM can be generated from a remote TLS scan alone** — for the TLS surface specifically:
negotiated and offered protocol versions, cipher suites, key-exchange groups (including hybrid PQC), and the
certificate chain, each now evidence-tagged with exactly what observed it and, where applicable, whether it was
negotiated or merely accepted in enumeration. **It is not, and cannot be, a complete cryptographic inventory of a
host or application** — that requires source, binary, agent, or config-file visibility this scanner does not have
and does not claim to have (unchanged from RESEARCH-002 §5's observable/not-observable table; nothing this round
narrowed that line).

## PQC assessment

No change to the project's PQC verdict logic this round (readiness levels, ML-KEM/ML-DSA algorithm classification
untouched). What changed is *evidentiary honesty around* PQC facts already reported: the CBOM now states its
confidence and method per fact (Feature 1) and distinguishes "this hybrid group was offered and accepted" from
"a real client actually got it" (Feature 2) — directly addressing the specific literature finding that this
distinction is where PQC-readiness tools most often mislead.

## QA results

- `go build ./...`, `go vet ./...`, `gofmt -l .` (clean, zero output), `golangci-lint run ./...` (0 issues) — all
  passing on the full module, not just touched packages.
- `go test ./...` — all packages pass, including new hermetic tests: `TestClientCertRequested`,
  `TestClientCertNotRequested`, `TestHSTSNotCheckedByDefault` (asserts zero extra connections by default and
  exactly one with the flag), `TestHSTSPresent`, `TestHSTSAbsent`, `TestHSTSNilWhenNotSpeakingHTTP`, plus the
  extended `terrible()`/`modern()` eval fixtures and `TestEveryRuleFiresAndIsCited`/
  `TestEveryDeductionTracesToAFinding` machinery, which fail the build if any rule is ever dead or uncited.
- **Live verification, not just unit tests**: both servers (`cipherhorizon serve`, `demo-targets`) were run
  together; the About page was confirmed to render the new HSTS section and the corrected "not measured" list;
  an endpoint was rescanned end-to-end and its "Server features" table confirmed to show the new
  "Client certificate requested" row; the CLI's `tls scan --http-checks` was run against a real (non-hermetic)
  demo server and correctly reported `HSTS check: the connection did not answer with an HTTP response` (the demo
  server doesn't speak HTTP) — the exact "unknown, not no" behavior AC-4.3 requires, observed against a live
  process, not a mock.
- One test bug was caught and fixed during this QA pass itself: an early version of
  `TestHSTSNotCheckedByDefault` mistakenly flagged the plain handshake-then-close (which still reaches the test
  server's callback with an empty read) as if an HTTP request had been sent. Caught by the test failing, not
  assumed correct.

## Known limitations

- mTLS detection only covers the default (`tls-default`) handshake attempt; the two TLS 1.2-specific
  ECDSA/RSA-forcing attempts do not separately check for a `CertificateRequest` (a server that only asks for a
  client cert on those specific cipher-restricted handshakes would not be caught). Judged low-value to add: those
  attempts exist purely to coax out a specific server certificate, not to characterize general server behavior.
- The HSTS check's minimal parser only recognizes HTTP/1.1 responses; a server that only speaks HTTP/2 without
  ALPN fallback to `http/1.1` will correctly report `nil` (unknown), not `false` — this is the intended
  "unknown, not no" behavior, not a bug, but worth naming so it isn't mistaken for broader HTTP/2 support later.
- No load/performance testing was run against the two new features beyond what the existing hermetic
  connection-budget/concurrency tests already cover; HSTS is opt-in and adds at most one connection per scan, so
  its performance profile is bounded by the same limits as certificate fetching.

## Recommended next steps

**P0:** none — the two P0 features from PRD-002 (evidence-aware CBOM, capability-vs-negotiation) are both closed
and QA'd.

**P1:** STARTTLS support (the next-largest named coverage gap after HSTS, now closed); fleet-level CBOM merge (a
server-side aggregation feature enabling org-wide crypto inventory, the platform-level ask behind the original
brief); extend mTLS detection to the TLS 1.2-specific handshake attempts if real-world testing shows it matters.

**P2:** named curve/DH group catalogue completion, composite ML-DSA certificate recognition, JARM/JA3
fingerprinting — each still requires its own primary-source research pass before implementation, per rule 3
(do not invent capabilities).

---

## What changed / Why / Evidence / Remaining gaps

**What changed.** Four features shipped: (1) every CBOM component now carries evidence of exactly how it was
observed, (2) the CBOM now distinguishes a negotiated suite/group from merely-accepted ones, (3) client-certificate
requests (mTLS) are now detected and reported, (4) an opt-in HSTS check closes this project's own largest named
methodology gap. All four are P0/P1 items traced directly to primary-source research (RESEARCH-002), not
speculative additions.

**Why.** Each answers a documented, cited industry problem — CBOMs overclaiming certainty, scanners conflating
capability with negotiation, mTLS being an invisible surface, and this project's own docs admitting the HSTS gap
by name — rather than adding features because they sounded interesting.

**Evidence.** Full module builds clean (`go build`, `go vet`, `gofmt -l`, `golangci-lint run ./...` all zero
issues); the full test suite passes including new hermetic tests for every new behavior; two real implementation
bugs and one test-authoring bug were caught by tests failing during development, not assumed away; the UI and CLI
changes were verified live against a running server, not just asserted from unit tests.

**Remaining gaps.** STARTTLS and fleet CBOM merge are the two largest still-open items, both already identified
and prioritized in RESEARCH-002/PRD-002's backlog rather than newly discovered here. The CBOM remains, by design,
a TLS-surface inventory — not a complete cryptographic inventory of a host or application — and every UI/CLI
surface says so explicitly.
