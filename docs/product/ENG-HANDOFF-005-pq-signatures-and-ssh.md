# ENG-HANDOFF-005 · Post-quantum signatures and SSH endpoints (architecture)

Implements [PRD-008](PRD-008-pq-signatures-and-ssh.md). Design record: [ADR-0019](../decisions/ADR-0019-ssh-endpoints.md).
Screens: [UX-DESIGN-006](UX-DESIGN-006-ssh-endpoints.md), agreed **before** any UI code. Tests:
[QA-PLAN-006](QA-PLAN-006-pq-signatures-and-ssh.md).

## 1. Design decisions

| # | Decision | Why |
|---|---|---|
| **D-1** | **ML-DSA joins the TLS 1.3 hellos only.** `signatureSchemes13 = signatureSchemes + {0x0904, 0x0905, 0x0906}`, used when a hello's `supported_versions` includes TLS 1.3. The values are pinned to `tls.MLDSA44/65/87`. | RFC 8446 says to ignore unknown schemes, and Go's own client already offers them. ML-DSA isn't defined for TLS 1.2, so 1.2 hellos stay as they are. |
| **D-2** | **The signature stage is acceptance-by-ServerHello.** There's one hello per candidate scheme. Each offers every TLS 1.3 suite, the full groups list (with key shares as the protocol stage sends them), and only that one scheme. A ServerHello or HelloRetryRequest means accepted; an alert or close means refused; a timeout is inconclusive. | In TLS 1.3 the certificate and CertificateVerify are encrypted. A server picks a certificate whose key can sign with an offered scheme *before* it sends the ServerHello (RFC 8446 §4.4.2.2), so a ServerHello answering one scheme shows it has a usable key for it. |
| **D-3** | **The control probe.** A hello whose only scheme is `0xFE01` (private use, RFC 8446 §11). If it gets a ServerHello, the server doesn't select by scheme: the stage is inconclusive and no scheme is reported. | The ServerHello test proves nothing for a server that answers regardless. This makes that visible instead of a false "accepts everything". |
| **D-4** | **The signature stage runs after the protocol stage, only when TLS 1.3 is supported** (skipped: "TLS 1.3 is not supported"). It's 14 schemes + 1 control = 15 connections. | Cheap, and bounded by the existing budget. |
| **D-5** | **Readiness L4** = L3 and (a leaf whose key is ML-DSA/SLH-DSA, *or* an accepted `mldsa*` scheme with the control passed). The `Authentication` dimension says which. | PRD-008 REQ-PQS-5. |
| **D-6** | **SSH prober** `internal/sshprobe` with subpackages: `wire` (packets, name-lists, KEXINIT, KEX messages, key blobs, certificates; pure and fuzzed), `registry` (the algorithm table: kind, family, PQ, hybrid, FIPS, key and block size, mode, ETM, status and source), and `testserver` (x/crypto servers and scripted servers; test-only). | Mirrors `tlsprobe`, so the code reads the same. |
| **D-7** | **SSH scan flow** (each step is a stage). All steps share the `Options` of `tlsprobe` (Dial, LookupIP, Timeout, MaxConnections, MinInterval, Progress, Tick, Now). | One connection gives the whole algorithm surface; the rest prove what's used and collect keys. |
| | 1. *identification*: connect, read up to 20 lines / 8 KiB until `SSH-`, send our identification, read the server KEXINIT, close. | |
| | 2. *negotiation*: send OpenSSH 10.6's default lists, compute the choice (RFC 4253 §7.1). If we implement the chosen KEX, complete it to the reply and verify the signature. | |
| | 3. *host-keys*: for each advertised host key algorithm, one KEX (the best one we implement that the server offers) restricted to that algorithm. Read and verify the key, then close. | |
| **D-8** | **Packet framing before NEWKEYS:** `uint32 packet_length ‖ byte padding_length ‖ payload ‖ padding` (RFC 4253 §6). No MAC. `packet_length ≤ 35000`, padding 4–255. We send padding of random bytes (aligned to 8) and treat any oversize field as a protocol error. | Bounded parsing of hostile input. |
| **D-9** | **The exchange hash H** is computed per method: `string V_C, V_S, I_C, I_S, K_S`, then `string Q_C, Q_S` (ECDH and hybrid) or `mpint e, f` (MODP), then `K`. The hash is SHA-256, SHA-384 or SHA-512 as the method says. `K` is an mpint for ECDH and MODP, and a **string** for `mlkem768x25519-sha256` (`K = SHA-256(K_PQ ‖ K_CL)`, per draft-kampanakis-curdle-ssh-pq-ke). | Verifying the server's signature over H proves the key exchange completed and the server holds the host key it showed. |
| **D-10** | **The SSH evaluation** is `eval.EvaluateSSH(rep *sshprobe.Report, in Input) Evaluation` in `internal/eval/ssh*.go`. It reuses `Finding`, `Check`, `Section`, hygiene, `fixFirst` and `attacks`. Sections in page order: `ssh-version`, `key-exchange`, `host-keys`, `encryption`, `integrity`, `vulnerabilities`. `Evaluation.Protocol` is a new field, `"ssh"` (empty means TLS). | A UI or PDF chooses its section set from `protocol`. |
| **D-11** | **Asset kind and target parsing.** `store.KindSSH = "ssh-endpoint"`. `normalizeTarget` returns a `protocol` of `tls` or `ssh`. `ssh://host[:port]` gives SSH (default 22). With `protocol: "auto"`, port 22 gives SSH. `createReq.Protocol` takes `auto`, `tls` or `ssh`, and `starttls` applies to TLS only. | PRD-008 REQ-SHW-1. |
| **D-12** | **Scan rows** gain `service` and `host_key` (migration 13). For SSH they hold the software version and the default host key type; for TLS they stay empty. `ListAssets(kind)` gains the pseudo-kind `endpoint`, meaning both. | The Endpoints list needs them without opening every report. |
| **D-13** | **Every consumer dispatches on kind** (see §3). | ADR-0019 decision 5. |
| **D-14** | **SSH CBOM** `internal/sshcbom.FromSSHReport`:
- a protocol component (`cryptoProperties.protocolProperties.type = ssh`, version `2.0`, the cipher and MAC lists as `cipherSuites` with algorithm refs);
- algorithm components from the catalogue;
- host keys as `related-crypto-material` (`public-key`, size, fingerprint in a property);
- `cipherhorizon:negotiated` on the chosen ones.

It goes through `cbom.Build`, so the vocabulary is re-checked. | Same rules as `tlscbom`: an algorithm the catalogue doesn't know is listed by name only (a property), never minted with a guessed OID. |
| **D-15** | **Catalogue additions:** AES-128/192/256-CTR (no OID: NIST registers none for CTR), AES-192-CBC and -GCM where an OID exists, HMAC-SHA-1/256/512 (RFC 8018 OIDs), UMAC (no OID), `mlkem768x25519-sha256` and `sntrup761x25519-sha512` as Combiner (no OID), sntrup761 as KEM (no OID), and Blowfish and CAST-128 (with RFC/IETF OIDs where they exist). Each gets a PQC rule with citations (`TestEveryCatalogueAlgorithmIsClassified`). | The catalogue is total and every algorithm is classified. |
| **D-16** | **The current SSH client** is pinned in `sshprobe/clients.go` as OpenSSH 10.6's defaults for `KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers` and `MACs` (source: `ssh_config(5)` of OpenSSH 10.6 and the 10.0 to 10.6 release notes; 10.6 adds `ssh-mldsa44-ed25519` host keys). A test pins the list. | PD-4. |
| **D-17** | **The CLI** `internal/app/ssh.go` shares `parsePolicy`, `--fail-on` evaluation, the verdict printer and the exit codes with `tls scan`. The printer takes the hygiene label as a parameter. | Same behaviour, no second policy engine. |
| **D-18** | **The UI** dispatches on `asset.protocol`:
- `report.js` keeps the shared parts (verdict, coverage line, action items, weaknesses list, CBOM table, history);
- the per-protocol pieces (section definitions, fact builders, configuration tab, summary tiles) move behind a `protocolViews(protocol)` registry;
- SSH's are in `views/report-ssh.js`. | No `if (ssh)` scattered through TLS code. |

## 2. Data

### 2.1 `tls-report/2` additions

```
Report.signatures *SignatureResult   // nil when the stage did not run
SignatureResult {
  version   "TLSv1.3"
  control   string                    // "refused" | "accepted" | "inconclusive"
  accepted  []SigScheme               // empty when control != "refused"
  refused   []SigScheme
  inconclusive []SigScheme
}
SigScheme { id uint16, name string ("mldsa65", "ecdsa_secp256r1_sha256", ...), algorithm string ("ML-DSA-65", "ECDSA", "RSASSA-PSS", "Ed25519"), pq bool }
Stage name "signatures" added to the fixed list (between key-exchange and features).
```

### 2.2 `ssh-report/1`

```
Report {
  schemaVersion "ssh-report/1"
  target { host, port }
  addresses[], address, started, durationMs, connections
  identification { raw (cleaned, ≤255), protoVersion "2.0"|"1.99"|"1.5", software, comment, ssh1Only bool, preamble int (lines before) }
  algorithms {                       // the server's own KEXINIT: advertised
    kex[], hostKey[], cipherC2S[], cipherS2C[], macC2S[], macS2C[], compC2S[], compS2C[],
    strictKex bool, extInfo bool, firstKexFollows bool
  }
  negotiated {                       // as OpenSSH 10.6 would
    client "OpenSSH 10.6 defaults", kex, hostKey, cipher, mac, compression,
    completed bool, verified bool, error string, evidence "observed"|"computed"
  }
  hostKeys []HostKey {
    type ("ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa", "ssh-mldsa-65", "ssh-dss", ...),
    algorithm ("Ed25519", "ECDSA", "RSA", "ML-DSA-65", "DSA"), bits, curve,
    fingerprint "SHA256:base64", blob (base64, ≤ 8 KiB),
    servedBy []string (host key algorithms answered with this key),
    verified bool, verifyNote string,
    certificate *{ keyType, caType, caFingerprint, serial, principals[], validAfter, validBefore, critical[] }
  }
  hostKeyAttempts []{ algorithm, outcome "key"|"refused"|"no-common-kex"|"inconclusive", detail }
  stages []Stage (same type as tlsprobe.Stage)
  notes[], incomplete bool
}
```

### 2.3 Evaluation

`Evaluation.Protocol string` (`"ssh"` for SSH, omitted for TLS), so stored TLS evaluations are byte-identical.
Rule set version `eval/7`: it adds the TLS signature view and the SSH rules. TLS findings are unchanged for a
report without a signature stage.

## 3. Dispatch points (every place that reads a stored report)

| Where | Today | Change |
|---|---|---|
| `server/runner.go` `execute` | `tlsprobe.Scan` | switch on `asset.Kind`: `sshprobe.Scan`, then `EvaluateSSH`, then `resultOfSSH` (service, host key) |
| `server/evaluate.go` `Reevaluate` | unmarshal TLS | by kind |
| `server/api.go` `loadScan`, `report`, `diff`, `scanCBOM`, `createAsset`, `scanAsset`, `scanMany`, `exportCSV` | TLS only | by kind; `scanMany` all/tag covers both kinds |
| `server/pdfreports.go` | TLS | by kind (`reportpdf.SSH`) |
| `server/inventory.go` | `a.Kind != KindTLS` skip | include SSH via `sshcbom` |
| `server/findings.go` | `case KindTLS` | add `KindSSH` |
| `store/scans.go` `DueAssets` | `kind = 'tls-endpoint'` | both kinds |
| `store/fleet.go`, `store/priority.go` | `KindTLS` | both kinds |
| `store/graph.go` `projectScanTx` | TLS | by `schemaVersion` prefix (it has no asset row in hand cheaply; `ssh-report/` gives `estate.FromSSHReport`) |
| `estate/correlate.go` | `tls-endpoint` only | unchanged (no SSH correlation in this release) |
| `store` SSLv2 key index | reads all scans | filter `kind = 'tls-endpoint'` |
| `app` | `tls scan` | `ssh scan` |
| `web/static/js/api.js` and views | `assets('tls-endpoint')` | `assets('endpoint')` |

## 4. Work packages and order

| WP | Content | Depends on |
|---|---|---|
| **A** | TLS signatures: hellos, stage, report, eval L4 rule, UI list, PDF, CBOM, demo targets, Go 1.27 | none |
| **B** | `sshprobe` (wire, registry, kex, host keys, scan), x/crypto test servers, fuzz | none |
| **C** | `eval` SSH rules, readiness and hygiene, plus catalogue and PQC rules | B |
| **D** | store kind + migration 13, runner and every dispatch point, API, OpenAPI | B, C |
| **E** | `sshcbom`, inventory, graph projection, PDF, CLI | C, D |
| **F** | UI per UX-DESIGN-006 | D, E |
| **G** | demo-targets SSH, the OpenSSH oracle, docs, QA run, screen walk | all |

## 5. Risks

| Risk | Mitigation |
|---|---|
| A server may treat our KEX_ECDH_INIT oddly, or drop us before the reply | Every failure is recorded per attempt with the reason; the oracle runs against two real OpenSSH versions |
| A misreading of the hybrid KEX encoding | x/crypto implements the same draft independently; the signature verifies only if both sides computed the same H |
| SSH scans of a whole estate add load | ≤ 24 connections per scan, the same rate limit and budget |
| Bigger hellos break TLS servers that dislike unknown schemes | Go clients already send them. The full test suite and the demo matrix run against them. A server that breaks shows as an inconclusive protocol probe, not a silent change. |
