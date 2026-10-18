# ENH-001 · Classical strength for every detected algorithm, from one cited model

Status: proposed 2026-10-18, for owner approval. Raised by the owner: "why is strength not shown for the detected
ciphers? Is this not a miss by the PM and cryptography engineers?" Reviewed against 0.3.0 (`7da548a`).

## 1. Short answer

**Partly shown, and yes, it is a miss.** The TLS report and its PDF give each cipher suite one of four words: Strong,
Acceptable, Weak, Insecure. But:

- **Every other surface shows none:**
  - the CLI (`tls scan --details` lists every suite with no strength);
  - the Inventory (3DES and RC4 appear as "? not classified");
  - the SSH report's algorithm lists;
  - the key-exchange groups;
  - the certificate keys;
  - the API;
  - the CBOM.
- **The four words come from a heuristic, not a model.** It is written twice: `suiteStrength` in
  `web/static/js/views/report.js` and again in `internal/reportpdf/matrix.go`. It has no source, no test, and no
  security-strength number behind it, and it gets single DES wrong.
- **No algorithm in the catalogue has a classical security strength in bits.** The catalogue records post-quantum
  status (cited) and legacy status (cited), but not how strong an algorithm is today. NIST SP 800-57 Part 1 Rev. 5
  Table 2 gives that number for every algorithm we detect.

**How it was missed.**
- PRD-006 REQ-RV-3 specified the *presentation*: "the number of suites by strength (strong, acceptable, weak,
  insecure) drawn as a bar". It never asked for the *model*: the rules, their sources, and where else strength must
  appear.
- The cryptography work went into post-quantum readiness and the cited findings, which do flag RC4, export,
  64-bit blocks and so on. Strength per algorithm fell between the two.
- The CBOM review deferred `classicalSecurityLevel` for the same reason: there was no cited table to fill it from
  (CBOM-REVIEW-002 C-9).
- No QA case asked "does every place that lists an algorithm say how strong it is?"

## 2. Evidence (0.3.0)

| # | Where | What a user sees | Why it matters |
|---|---|---|---|
| S-1 | TLS report, protocol matrix | Strong / Acceptable / Weak / Insecure per suite, with no reason and no source | A reader cannot tell why AES-128-CBC is "Acceptable", or check it |
| S-2 | `report.js` and `reportpdf/matrix.go` | Two hand-kept copies of the same rules, untested | They can drift; nothing proves the PDF matches the page |
| S-3 | Same rules | `TLS_RSA_WITH_DES_CBC_SHA` (DES, 56-bit key) is rated **Weak**: the 64-bit-block rule fires before anything looks at the key size. | **Defect.** A 56-bit key is brute-forceable. RFC 9325 §4.1 says MUST NOT negotiate ciphers under 112 bits, so this is **Insecure** |
| S-4 | Same rules | AES-128 and AES-256 suites get the same word, and key exchange and authentication strength (ffdhe2048, RSA-1024 certificate) are ignored | "Strong" hides that a suite's security is the weakest of its parts |
| S-5 | `tls scan --details` | `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA  AES-128 CBC kx:ECDHE  iana:N` | The CLI, which CI pipelines read, has no strength at all |
| S-6 | Inventory → Algorithms | 3DES, RC4, DES, MD5 and SHA-1 show **"? not classified"** in the only status column (post-quantum). Their cited classical status is in the CBOM but never shown | Reads as "unknown" for the algorithms most clearly broken today |
| S-7 | SSH report | Ciphers, MACs, key exchanges and host keys are judged against the baseline (allowed or not), with no strength | `3des-cbc` and `hmac-sha1` read only as "not in the baseline" |
| S-8 | Key-exchange groups, certificate keys | Group tables say classical or post-quantum; keys say "RSA 1024-bit" | No statement that ffdhe2048 or RSA-2048 is 112-bit, secp256r1 or X25519 128-bit, RSA-1024 about 80-bit |
| S-9 | API `/api/v1/assets/{id}/report`, CSV | Raw registry fields only (cipher, keyBits, mode) | Integrations recompute strength their own way, or not at all |
| S-10 | CBOM | `classicalSecurityLevel` never set (1.6 and 1.7 both define it) | Consumers that rank by security level get nothing |

## 3. The enhancement

### 3.1 One model, cited, in Go

- **Catalogue (`internal/algo`):** every entry gets `SecurityBits` (classical security strength) and its source,
  using these sources only:
  - **NIST SP 800-57 Part 1 Rev. 5, Table 2** (symmetric, FFC, IFC, ECC):
    - 3TDEA 112; AES-128/192/256 128/192/256;
    - RSA and DH 1024 ≤80, 2048 112, 3072 128, 7680 192, 15360 256;
    - ECC 224–255 112, 256–383 128, 384–511 192, 512+ 256.
  - **SP 800-57 Part 1 Table 3 and SP 800-107** (hash functions and HMAC).
  - **RFC 7748 / RFC 8032** (X25519 ≈128, X448 ≈224, Ed25519 ≈128, Ed448 ≈224).
  - **The broken algorithms** have no strength number; their cited status stands in its place: DES (56-bit key),
    RC4 (RFC 7465), MD5 (RFC 6151), SHA-1 collisions (RFC 6194), export ciphers.
- **Variants:** key-size variants (RSA-2048, ECDSA-P256, ECDH-P384, ffdhe groups) take the strength of their size.
- **Suite strength (`internal/eval`)** is the weakest part of:
  - the cipher's strength;
  - the key exchange (the group or DH prime actually accepted);
  - the authentication (the certificate key);
  - the MAC or hash.
- **Mapped to the four words** by a table, each threshold cited:
  - **Insecure:** below 80 bits, or a cited break (NULL, export, RC4, single DES, anonymous).
  - **Weak:** 80 to 111 bits, or 64-bit block (Sweet32, RFC 9325 §4.2), or no forward secrecy (RFC 9325 §4.1).
  - **Acceptable:** at least 112 bits, but below 128 or not AEAD (RFC 9325 §4.2 prefers AEAD).
  - **Strong:** at least 128 bits in every part, AEAD, forward secrecy.
- **Owner decision (OD-1).** Under this rule an RSA-2048 certificate (112 bits, SP 800-57) makes every suite it
  authenticates *Acceptable*, not *Strong*. That is most of the web today. The alternative: judge the certificate
  key on its own (it already has its own finding when it is under 2048 bits), and leave it out of the suite's word.
  Recommendation: keep the weakest-part rule, and say so in the suite's reason ("Acceptable: RSA-2048 certificate,
  112 bits"). It is the honest reading of SP 800-57.
- **Every suite carries its reasons**, for example "weakest part: ffdhe2048 key exchange, 112 bits". The words stay
  the product's own, and docs/methodology.md documents them. No third-party grade vocabulary
  (feedback-own-terminology).

### 3.2 Shown everywhere an algorithm is listed

| Surface | Change |
|---|---|
| TLS report, matrix and suite tables | The word comes from the API, not the page; a "Strength" cell shows bits and the weakest part on hover and in the expanded row |
| PDF | Same field; the Go copy of the heuristic is deleted |
| CLI `tls scan --details` (and `--json`) | A strength column: `strong 128`, `weak 112 (3DES 64-bit block)` |
| SSH report | Each offered cipher, MAC, key exchange and host key shows its strength next to the baseline verdict |
| Key-exchange groups, certificate keys | Bits beside each group and key |
| Inventory → Algorithms and Keys | A **Classical strength** column next to Post-quantum. Broken algorithms show their cited status ("broken: RFC 7465"), never "? not classified" |
| API and CSV | `strength`, `securityBits`, `weakestPart` on every suite; `securityBits` on every inventory row |
| CBOM | `algorithmProperties.classicalSecurityLevel` from the catalogue (1.6 and 1.7); broken algorithms keep `classical-status` and get no number |

### 3.3 Acceptance

| ID | Check | Test |
|---|---|---|
| AC-1 | Every catalogue entry has `SecurityBits` with a source, or a cited broken status; none has neither | `TestEveryAlgorithmHasACitedStrength` |
| AC-2 | DES-56 is Insecure; 3DES is Weak (112 bits, 64-bit block); AES-128-GCM with ECDHE-P256 and an RSA-2048 certificate is Acceptable (112 bits from the certificate key), not Strong | `TestSuiteStrengthIsTheWeakestPart` (table test over the IANA registry) |
| AC-3 | The page, the PDF and the CLI show the same word for every suite of every demo target | journey `E2E-STR-1`; `TestPDFAndAPIAgreeOnStrength` |
| AC-4 | The Inventory shows a classical strength for every row; no legacy algorithm reads "not classified" without its cited status | journey `E2E-STR-2` |
| AC-5 | The CBOM's `classicalSecurityLevel` equals the catalogue's bits and validates against 1.6 and 1.7 | `TestCBOMCarriesClassicalSecurityLevel` |
| AC-6 | docs/methodology.md has the table and its sources; Help explains the four words | `report:` |

### 3.4 Out of scope

- A numeric score per suite.
- Rating the server as a whole by strength (the TLS hygiene score already does that from findings).
- Re-weighting findings: the existing cited findings stay as they are, and strength is shown beside them, not
  instead of them.
- Post-quantum strength. NIST categories stay where they are (`nistQuantumSecurityLevel`, readiness level).

## 4. Process change

The PRD template gets one line: "Every algorithm the feature lists states its classical strength and its
post-quantum status." The QA plan template gets the matching check. The screen walk (UX-REVIEW) checks it on
every screen that lists an algorithm.
