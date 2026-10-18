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

## 5. How the strength is calculated: NIST's method, reproduced

Every number below is computed by `internal/algo/strength.go`. The tests in `strength_test.go` fail unless the
results equal NIST's own published tables, to the precision NIST prints them. The source text was read in the
documents themselves.

### 5.1 RSA and finite-field DH: the General Number Field Sieve

The best known classical attack on RSA (factoring the modulus N) and on finite-field DH (discrete logarithms modulo
the prime p) is the General Number Field Sieve. Its heuristic running time is

  L_N[⅓, (64/9)^⅓] = exp( (64/9)^⅓ · (ln N)^⅓ · (ln ln N)^⅔ ),  with (64/9)^⅓ ≈ 1.923.

NIST turns it into bits of security for an L-bit modulus. This is the FIPS 140-3 Implementation Guidance §D.B
(formerly FIPS 140-2 IG 7.5), as written in **SP 800-56B Rev. 2, Appendix D**:

  **E(L) = ( 1.923 · ∛(L·ln 2) · ∛( (ln(L·ln 2))² ) − 4.69 ) / ln 2**

- ln N = L·ln 2, because an L-bit number is about 2^L.
- Dividing by ln 2 converts natural-log work into bits.
- The constant **4.69** calibrates the curve so that **L = 1024 gives exactly 80.00 bits**, the strength SP 800-57
  assigns to 1024-bit RSA. It absorbs the o(1) term of the asymptotic formula.

**Rounding.** *"The value of E will be rounded to the nearest integer multiple of eight"* (SP 800-56B Rev. 2,
Appendix D). We also hold the result to 256, the highest strength SP 800-57 assigns.

| Modulus or prime (bits) | E(L) | Strength | NIST's published value |
|---|---|---|---|
| 1024 | 80.00 | 80 | 80 (SP 800-57 Pt 1 Table 2) |
| 1536 | 96.60 | 96 | (not tabulated; MODP group 5) |
| 2048 | 110.12 | **112** | 110.1 → 112 (SP 800-56B Table 4); ffdhe2048 = 112 (SP 800-56A Table 26) |
| 3072 | 131.97 | **128** | 131.97 → 128 (both) |
| 4096 | 149.73 | **152** | 149.73 → 152 (both) |
| 6144 | 178.42 | **176** | 178.42 → 176 (both) |
| 8192 | 201.71 | **200** | 201.7 → 200 (both) |
| 15360 | 262.62 | **256** (held) | 256 (SP 800-57 Pt 1 Table 2) |

**SP 800-57 Table 2 lists 7680 bits as 192, while the formula gives 196.25, rounded to 200.** Both are right
about different questions. Table 2 gives the *smallest key that reaches* each strength category (80, 112, 128,
192, 256). The 56B method *estimates the strength of a given key*. A scanner holds a given key, so it reports the
estimate; a 7680-bit key comfortably meets the 192 category. For the thresholds that matter in practice (112 and
128), the two methods never disagree.

### 5.2 Elliptic curves: half the order

The best known classical attack on the elliptic-curve discrete logarithm problem is Pollard's rho, about
√(πn/4) ≈ 2^(f/2) operations for a base point of order n with f bits. **SP 800-186 §3**: *"if an elliptic curve has a
basepoint of order n, then the security strength will be approximately one half of the bit length of n"*. We take
f/2, rounded to a multiple of eight, held to 256.

| Curve (as TLS or SSH names it) | Order f (bits) | f/2 | Strength | SP 800-186 Table 1 |
|---|---|---|---|---|
| secp224r1 (P-224) | 224 | 112 | 112 | 112 |
| secp256r1 (P-256) | 256 | 128 | 128 | 128 |
| x25519, Ed25519 (Curve25519) | 253 | 126.5 | 128 | 128 |
| secp384r1 (P-384) | 384 | 192 | 192 | 192 |
| x448, Ed448 (Curve448) | 446 | 223 | 224 | 224 |
| secp521r1 (P-521) | 521 | 260.5 | 256 (held) | 256 |

### 5.3 Symmetric ciphers, hashes, MACs: SP 800-57 Part 1 Tables 2 and 3

| Algorithm | Strength | Why |
|---|---|---|
| AES-128 / 192 / 256 | 128 / 192 / 256 | Exhaustive key search (Table 2) |
| 3DES (3TDEA, 168-bit key) | 112 | Meet-in-the-middle halves the work of the three-key cascade (Table 2). Deprecated through 2023 and disallowed after (SP 800-131A Rev. 2); 64-bit block, so Sweet32 also applies |
| 2TDEA | 80 | Table 2 |
| DES | 56: **broken** | 56-bit key, exhaustive search is practical |
| RC4 | **broken** | RFC 7465, whatever its key length |
| ChaCha20 | 256 | Key length (RFC 8439). NIST does not list it, so this is stated as key length, not a NIST strength |
| SHA-256 / 384 / 512 (signatures, collision resistance) | 128 / 192 / 256 | Birthday bound, half the output (Table 3) |
| SHA-1 (signatures) | under 80: **broken** | Table 3 footnote 74 |
| HMAC-SHA-1 / HMAC-SHA-256 and longer | 128 / 256 | Table 3 (keyed: collisions do not apply) |

### 5.4 Worked examples: a suite is as strong as its weakest part

| What the scan saw | Parts | Weakest | Strength word |
|---|---|---|---|
| TLS 1.3, `TLS_AES_128_GCM_SHA256`, X25519, ECDSA P-256 certificate | AES-128 128 · X25519 128 · P-256 128 · HKDF-SHA-256 256 | 128 | **Strong** (≥128, AEAD, forward secret) |
| The same suite, with an RSA-2048 certificate | … · RSA-2048 **112** | 112 | **Acceptable** under OD-1's weakest-part rule |
| TLS 1.2, `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`, secp384r1, RSA-3072 | AES-256 256 · P-384 192 · RSA-3072 128 · HMAC-SHA-384 256 | 128 | **Acceptable** (not AEAD) |
| TLS 1.2, `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`, 1024-bit DH prime | DH-1024 **80** | 80 | **Weak** (80 to 111 bits) |
| `TLS_RSA_WITH_3DES_EDE_CBC_SHA`, RSA-2048 | 3DES 112, 64-bit block · RSA key transport (no forward secrecy) | 112 | **Weak** (64-bit block; no forward secrecy) |
| `TLS_RSA_WITH_DES_CBC_SHA` | DES **broken** | broken | **Insecure** (today's code says Weak: #18) |

The calculator is in place and tested. Wiring it into the suite rating, the API, the CLI, the Inventory, the SSH
report and the CBOM is the rest of this enhancement, after the owner approves it (OD-1).
