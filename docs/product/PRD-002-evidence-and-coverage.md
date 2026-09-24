# PRD-002: Evidence-aware CBOM, capability-vs-negotiation, mTLS surface, HTTP-layer check

| | |
|---|---|
| **Status** | Approved for build (self-directed PM → Dev → QA cycle, see [RESEARCH-002](RESEARCH-002-pqc-tls-cbom-landscape.md)) |
| **Builds on** | PRD-001 (Posture Workbench), the CBOM-export work added after PRD-001's QA (RELEASE-REPORT-001 deviation 7b) |
| **Research** | [RESEARCH-002-pqc-tls-cbom-landscape.md](RESEARCH-002-pqc-tls-cbom-landscape.md) — every feature below traces to a specific finding there |

## Objective

Close the gap the research identified as the field's actual headline problem — tools that conflate "the server can" with "the server did," and CBOMs that assert things a remote scan cannot know — rather than add features because they sound interesting (brief rule 12... the brief's own rule, restated: every feature here answers a demonstrated problem).

## Feature 1 — Evidence-aware CBOM (Observed / Inferred / Not-observable / Not-applicable)

**Problem.** The CBOM this tool exports (`tls scan --cbom`) states facts as flat truth with no per-fact confidence, unlike what the research found CBOMkit does for its own identity claims (`evidence.identity.confidence`, 0-1) and unlike what the primary research source (RESEARCH-002 §3.2) recommends for PQC-TLS measurement specifically: keep "observed" separate from "inferred," and never assert something a remote scan cannot see.

**User.** Dana (the auditor persona from PRD-001): needs to know, per fact in the CBOM, whether it was directly observed on the wire or derived — for evidentiary/audit purposes, not just for this UI to display nicely.

**Current behavior.** Every `algorithm`/`protocol`/`certificate` component `FromTLSReport` emits carries no evidence marker at all; a consumer of the raw CBOM JSON cannot tell "this cipher suite was accepted by the server" from anything else.

**Proposed behavior.** Every component `FromTLSReport` emits gets a CycloneDX `evidence.identity` block:
- `field: "name"`, `confidence: 1.0`, `methods: [{technique: "other", value: "<what observed it>"}]` for anything directly read off a ServerHello, HelloRetryRequest, or certificate (i.e. everything this scanner currently emits *is* Observed — see "Technical design" for why Inferred doesn't apply to the current fact set, and why that's the honest answer, not a shortcut).
- Nothing is emitted with confidence 0 or omitted-but-implied; a fact this scanner cannot observe is not in the document at all (already this project's convention — "omit, don't guess" — this feature makes the *reason* machine-readable for what *is* in the document, it does not change what's included).

**UX/CLI.** No new flag; `--cbom` output changes shape (additive: a new `evidence` object per component). Documented in `docs/tls-scanning.md`'s CBOM section.

**Technical design.** `internal/cbom/tlsbuild.go`'s component builders (`protocolAsset`, `certificateAsset`, `hybridComponent`) each set `Component.Evidence = &cdx.Evidence{Identity: &cdx.EvidenceIdentity{...}}`. A helper `observedEvidence(method string) *cdx.Evidence` in tlsbuild.go, so every call site states *what* observed the fact (e.g. `"ServerHello (protocol version negotiation)"`, `"HelloRetryRequest (empty key_share probe)"`, `"certificate chain"`) — this text is what makes the confidence number auditable rather than decorative. Must first confirm (against the vendored 1.6 schema, not the Go SDK) that `Component.Evidence` and `EvidenceIdentity.{Field,Confidence,Methods}` are 1.6-valid before using them (same discipline as the certificate/protocol work: check the schema file directly).

**Data model.** No new Go types beyond what `cyclonedx-go` already provides (confirm exact 1.6-valid shape from the schema first, same as previous session's `CertificateProperties` discovery that `serialNumber` was NOT 1.6-valid despite being in the Go struct).

**Output.** CBOM JSON only; no UI change this round (the web UI does not render raw CBOM JSON today — that's out of scope here).

**Security considerations.** None; this is descriptive metadata.

**Error cases.** None new.

**Acceptance criteria.**
- AC-1.1 Every component `FromTLSReport` emits has a non-nil `evidence.identity` with confidence `1.0` and a `methods` entry naming what produced it.
- AC-1.2 The evidence shape is validated against the vendored 1.6 schema (not just "compiles"): a schema-invalid evidence block must be caught by `schematest.Validate`, the same gate every other CBOM test already goes through.
- AC-1.3 No component ever carries confidence `0` or a fabricated method string for something not actually observed (there is nothing to omit-with-evidence in the current fact set — the test proves the *positive* claim, that everything present says how it's known).

**Test cases.** Unit: every existing `tlsbuild_test.go` assertion extended to also check `Component.Evidence != nil`; schema validation (already run) extended implicitly by the new field. New: a table test asserting each component *kind* (protocol, algorithm, hybrid combiner, certificate) has the right method string.

**Priority: P0.**

---

## Feature 2 — Capability vs. negotiation, made explicit in the CBOM

**Problem.** RESEARCH-002 §3.1: the field's own literature names this the primary reason general-purpose scanners under-report PQC support — conflating "the server accepted this in enumeration" with "a real client got this." This project's *readiness* model already separates these (L2 "hybrid available" vs. L3 "hybrid negotiated" — see `internal/eval/readiness.go`), but the **CBOM** does not: `FromTLSReport` lists every accepted suite/group as an equal-weight `algorithm` reference with no marker for the one `rep.Negotiated` actually reports a standard client received.

**User.** Priya (PQC migration lead, PRD-001): scanning a CBOM (or feeding it to another CycloneDX-aware tool) needs to answer "is this *actually being used* by a normal connection" without cross-referencing the separate JSON report.

**Current behavior.** `protocolAsset` builds `CipherSuite.Algorithms` from every accepted suite/group uniformly; nothing in the CBOM marks `rep.Negotiated`'s specific suite/group as different from the other N-1 the enumeration found.

**Proposed behavior.** `CipherSuite` has no `properties` field in the CycloneDX 1.6 schema (checked directly against the vendored schema, not assumed from the Go SDK — the same discipline the certificate work already established), so an individual suite entry cannot itself carry a marker. Instead: the **protocol** component whose version matches `rep.Negotiated.Version` gets two custom properties naming the exact suite and group text a real client got (`cipherhorizon:negotiated-suite`, `cipherhorizon:negotiated-group`) — answerable with one look at the protocol component, no cross-referencing the separate JSON report. Additionally, if the negotiated group was *also* found by enumeration (the common case) and so already has its own algorithm component, that component gets `cipherhorizon:negotiated = "true"`. Cipher/key-exchange/auth algorithm components (AES, ECDH, RSA, ...) are deliberately **not** marked this way even when they're part of the negotiated suite: they're shared across every suite that uses that primitive, so marking one "negotiated" would itself be the kind of overclaim this feature exists to prevent — only the protocol-level property states the specific suite.

**UX/CLI.** No new flag. Documented alongside feature 1 in `docs/tls-scanning.md`.

**Technical design.** `protocolAsset` already receives `rep`, which carries `Negotiated`. After building the normal suite/group components for a version, if `rep.Negotiated != nil`, `rep.Negotiated.Error == ""`, and `rep.Negotiated.Version == version`, add the two protocol-level properties; separately, if `rep.Negotiated.GroupID` matches an already-emitted group's ID, add the `negotiated` property to that group's own component (found via the same `emit`/`emitHybrid` resolvers already in scope, keyed by ID not just name since a hybrid and a pure form can share a similar name). If `rep.Negotiated` is nil or carries an error, no property is added anywhere and nothing is asserted about negotiation — consistent with feature 1's "don't assert what wasn't observed."

**Data model.** No new stored fields; a CBOM-only marker.

**Output.** CBOM JSON: two custom properties on at most one protocol component, and one custom property on at most one algorithm component (the negotiated group, when it was independently enumerated too).

**Security considerations.** None.

**Error cases.** Negotiation failed / `rep.Negotiated == nil`: no marker added (not an error, a correctly-represented absence).

**Acceptance criteria.**
- AC-2.1 When a scan has a successful `Negotiated` result, the protocol component whose version matches it carries `cipherhorizon:negotiated-suite` equal to `Negotiated.Suite`, and `cipherhorizon:negotiated-group` equal to `Negotiated.Group` when non-empty.
- AC-2.2 When the negotiated key exchange is a group this scanner also found via enumeration (the common case), that group's `algorithm` component carries `cipherhorizon:negotiated = "true"`.
- AC-2.3 When negotiation failed, no component in the document carries either marker, and this is not reported as a build warning (an absent negotiation is not an error).
- AC-2.4 A group present in the enumerated (capability) set but *not* the negotiated one is unmarked, and no cipher/key-exchange/auth algorithm component is ever marked `negotiated` (only the group can be, and only the protocol carries the specific suite name) — this is the actual regression test for the capability-vs-negotiation conflation the research names, and for not overclaiming onto a shared component.

**Test cases.** Extend `tlsbuild_test.go`'s `sampleReport()` fixture with a `Negotiated` field matching one of its suites/groups; assert the two protocol properties and the one group-component property land, and nowhere else (in particular: not on AES). A second fixture with `Negotiated: nil` (or an error) asserts no marker anywhere.

**Priority: P0.**

---

## Feature 3 — Client-certificate-requested detection (mTLS surface)

**Problem.** RESEARCH-002 §5: whether a server will ask for a client certificate is a real, TLS-observable fact (a `CertificateRequest` message, RFC 8446 §4.3.2) this scanner does not currently probe for at all, despite completing full handshakes already (`certs.go`). Low real-world prevalence (6.2% per the research) doesn't make it unimportant when present — mTLS-protected services are disproportionately the ones organizations most need to get PQC-readiness right for (internal service mesh, high-value APIs), and client-side certificate signatures are a second, currently entirely blind, authentication-PQC surface alongside the server certificate this scanner already covers.

**User.** Priya and Marcus (SRE): need to know an endpoint requires mTLS *before* assuming a routine scan's "certificate not verified" result means what it usually means (a scan without a client cert will typically fail differently against an mTLS-required endpoint, and that failure reason is currently unlabelled).

**Current behavior.** `certificates()` never learns whether the server sent a `CertificateRequest`; if it did and strictly requires a cert, the handshake simply fails and is reported the same as any other handshake failure.

**Proposed behavior.** The default handshake attempt in `certificates()` sets `tls.Config.GetClientCertificate`; if Go's `crypto/tls` invokes it, the server asked for a client certificate. The probe returns an empty certificate (so the handshake proceeds as far as the server allows — it may still fail if the server *requires* one, which is fine: the request was already observed before that failure). This becomes `Features.ClientCertRequested *bool`, and a new `Info`-severity finding, `FEAT.CLIENT-CERT-REQUESTED`.

**UX/CLI.** No new flag — this uses the handshake attempt already made by default. Surfaced in the existing TLS-details "Server features" table (web UI) alongside secure renegotiation etc., and in the CLI text report.

**Technical design.** In `internal/tlsprobe/certs.go`'s `base()`/`certificates()`: add a `requested *bool` captured by a closure passed as `GetClientCertificate`. Set `Features.ClientCertRequested` in `scan.go` from this result. New rule in `internal/eval/rules.go`, `category: "feature"`, `severity: Info`, `evidence: Observed`, citing `citRFC8446` (§4.3.2 defines `CertificateRequest`).

**Data model.** `tlsprobe.Features.ClientCertRequested *bool` (nil = not tested — this only happens if the endpoint had no protocol at all to attempt a handshake on, matching the nil-means-untested convention every other `Features` field already uses).

**Output.** JSON report (`Features.ClientCertRequested`); eval finding; UI "Server features" table row; CLI text report line. Not added to the CBOM (feature 1/2's evidence model is about cryptographic *assets*; "the server wants mTLS" is a protocol-behavior fact, same category as the existing `Features` block, which the CBOM already doesn't carry — no change to that boundary).

**Security considerations.** The probe never presents a real certificate (the callback returns an empty one), so this cannot be mistaken for an authentication attempt or leak anything; it's a passive observation of the server's own request.

**Error cases.** If the handshake fails before the server would have sent `CertificateRequest` (e.g. no shared cipher suite), the fact is correctly unknown (`nil`), not `false` — `false` must mean "we completed enough of the handshake to be sure it wasn't requested," not "we don't know."

**Acceptance criteria.**
- AC-3.1 A hermetic TLS 1.2 server configured with `ClientAuth: tls.RequireAnyClientCert` (or TLS 1.3 equivalent) is detected: `Features.ClientCertRequested == true`, without the scan otherwise failing to complete.
- AC-3.2 A hermetic server with `ClientAuth: tls.NoClientCert` (the default) yields `Features.ClientCertRequested == false`.
- AC-3.3 The finding `FEAT.CLIENT-CERT-REQUESTED` fires only when the flag is `true`, at `Info` severity (this is not a vulnerability), cites RFC 8446, and its `Detail` says plainly that this is informational.
- AC-3.4 UI: the TLS-details "Server features" table shows the row only when the field is non-nil (matching every other feature row's existing nil-means-omit convention already in `web/static/js/views/asset.js`).

**Test cases.** `internal/tlsprobe/scan_test.go`: two new hermetic-server cases (`tls.RequireAnyClientCert`, `tls.NoClientCert`) asserting the flag. `internal/eval/eval_test.go`: the new rule fires/doesn't fire correctly and is cited (covered automatically by the existing `TestEveryRuleFiresAndIsCited`/`TestEveryRuleIsCited` machinery once the rule is registered).

**Priority: P1.**

---

## Feature 4 — Optional HTTP-layer check (HSTS)

**Problem.** RESEARCH-002 §2.1/§7: every general-purpose competitor that publishes a grade (SSL Labs directly, and this project's own TLS hygiene score by its own stated methodology, `docs/methodology.md`) treats HSTS as part of "fully checked" — this project's own docs already list it under "not measured" as the *only* named reason A+-equivalent status is capped. It is real, well-understood, and currently the single biggest named gap in this project's own methodology page.

**User.** Priya/Marcus: want the one HTTP-layer fact that materially affects a TLS posture assessment (does the server tell browsers to always use HTTPS) without switching to a separate HTTP scanner.

**Current behavior.** Not checked; `docs/methodology.md` explicitly says so.

**Proposed behavior.** An **opt-in, default-off** check (`--http-checks` on `tls scan`; a per-scan or server-wide toggle for `serve`, off by default) that, only when enabled, sends one `GET /` over the already-established TLS connection and reads the `Strict-Transport-Security` response header (and nothing else — no body, no redirect following, no other headers acted on). This is the one feature in this round that changes this project's own stated safety invariant ("only handshake messages are exchanged: no application data is sent," `docs/tls-scanning.md`) — which is exactly why it must be opt-in, loudly documented as the exception, and never default-on, matching the precedent already set by `--intrusive` for behavioural vulnerability probes (a different kind of exception, same principle: extra network behavior beyond the handshake is never silent).

**UX/CLI.** `cipherhorizon tls scan --http-checks HOST[:PORT]`; `serve`'s `--http-checks` flag (server-wide; PRD-001's existing per-scan-options precedent, e.g. `--concurrency`, is server-wide too, so this matches). The UI's About page and the CLI's `--http-checks` help text both state plainly that turning this on sends an HTTP request to the target, beyond the TLS handshake.

**Technical design.** New `internal/tlsprobe/http.go`: `checkHSTS(ctx, conn *tls.Conn, host string) (*bool, error)` — writes a minimal `GET / HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n` over the connection already used for the `tls-default` negotiated handshake (no new connection), reads up to a capped byte budget (e.g. 8 KiB) with the existing per-connection timeout, parses only status line + headers (no HTTP library needed — this is deliberately minimal, matching the project's existing preference for hand-rolled parsers over pulling in `net/http` client machinery for one header). Wired into `Options.HTTPChecks bool` (default false) and `Scan()`; only attempted when the option is set *and* the default handshake succeeded *and* ALPN/protocol suggests HTTP is plausible (skip entirely if `Negotiated` failed).

**Data model.** `tlsprobe.Report.HSTS *bool` (top-level, not nested in `Features`, since it's not a TLS-protocol feature — matches how `Negotiated` and `DH` are already top-level, protocol/HTTP-layer-appropriate fields rather than forced into `Features`). `nil` when not attempted (the default) or inconclusive; `true`/`false` when observed.

**Output.** JSON report; a new `eval` rule (`HTTP.NO-HSTS`, `Low` severity, `category: "feature"`, cites the browser HSTS spec, RFC 6797) that only fires when `Report.HSTS != nil && *Report.HSTS == false` — i.e. it only ever fires when the check actually ran, never implied by its absence. UI/CLI show it only when present, same nil-means-omit convention as feature 3.

**Security considerations.** This is the feature that needs the most explicit warning: it makes a real HTTP request. No body is parsed, no redirect is followed (redirects could point off-target — SSRF-guard already only governs the *initial* connection, so definitely do not follow a `Location` header), no cookies/auth are ever sent, the byte budget is capped so a malicious server cannot use this to exhaust memory.

**Error cases.** Target doesn't speak HTTP on that connection (a non-web TLS service, e.g. an IMAP STARTTLS-adjacent port never reachable via this project until STARTTLS itself ships): the read comes back as garbage/times out → `Report.HSTS` stays `nil` with a note, never `false` (false must mean "we got an HTTP response and it lacked the header," not "this wasn't a web server").

**Acceptance criteria.**
- AC-4.1 Default behavior (`--http-checks` absent) makes zero additional connections and sends zero bytes beyond the existing handshakes — a hermetic-server test asserts connection count is unchanged from before this feature existed.
- AC-4.2 With `--http-checks`, a hermetic HTTPS server that returns `Strict-Transport-Security: max-age=...` yields `Report.HSTS == true`; one that omits it yields `false`.
- AC-4.3 A hermetic server that isn't speaking HTTP at all over that TLS connection yields `Report.HSTS == nil`, not `false`, and the scan does not fail or hang (bounded by the existing per-connection timeout).
- AC-4.4 The finding only fires when `HSTS != nil`.
- AC-4.5 CLI `--help` and the web UI's About page both state, in plain language, that this option sends an HTTP request to the target.

**Test cases.** New hermetic test server variant that, after the TLS handshake, speaks a minimal HTTP response (with and without the header, and a third case returning garbage/non-HTTP bytes to test the "stays nil" path). CLI test asserting `--http-checks` is required for the field to ever be non-nil.

**Priority: P1.**

---

## Backlog (researched, not built this round — see RESEARCH-002 §9 for why)

| Item | Priority | One-line reason |
|---|---|---|
| STARTTLS (SMTP first, then IMAP/POP3) | P1 | Real, well-evidenced gap; large enough to need its own PRD and hermetic-server test matrix rather than being squeezed into this round. |
| Fleet-wide CBOM merge (multiple endpoints, one document) | P1 | Real enterprise want; secondary to first fixing what a single endpoint's CBOM says (this PRD). |
| Named curve catalogue completion (secp256r1/384r1/521r1) | P2 | Small, mechanical, not blocking anything; tracked already before this research round. |
| Composite ML-DSA certificate recognition | P2 | Real per IETF standards-track adoption; 0% observed real-world adoption today (RESEARCH-002 §4) makes it low urgency. |
| DH group registry matching (RFC 7919) | P2 | Already a known, documented gap (`docs/tls-scanning.md`); unrelated to this round's findings. |
| JARM/JA3 fingerprinting | P2 | Useful for asset clustering at internet scale, not for PQC/CBOM depth; different product shape. |
