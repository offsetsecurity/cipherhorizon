# ENH-002 · Every algorithm by class (asymmetric, symmetric, hash), with its strength

Status: decisions taken by the owner 2026-10-21 (§5: OD-1 and OD-2 as recommended); to be baselined as PRD-011. Raised by the owner: "the cipher, its strength and its
classification (asymmetric, hashing, symmetric) would be needed, so that you can show it." Reviewed against
`feat/classical-strength` (PR #19, PRD-010).

## 1. Short answer

**The model has the parts, but no screen shows them.** PRD-010 rates every cipher suite by its weakest part, and
the evaluation already stores each part: cipher, key exchange, authentication and MAC, each with its bits. The
report shows one word and the weakest part only ("Strong · 128 bits · x25519"). No surface answers the questions a
cryptography reviewer asks first:
- which **asymmetric** algorithms does this endpoint use (key exchange, signatures), and how strong is each?
- which **symmetric** ciphers, and how strong is each?
- which **hashes**, and for what?

Hashes are missing from the model too:
- a TLS 1.3 suite's hash (SHA-384 in `TLS_AES_256_GCM_SHA384`, used by HKDF) is not a part;
- a TLS 1.2 AEAD suite's PRF hash is not a part;
- the certificate's signature hash (SHA-256 in ECDSA-SHA256) is not rated anywhere: the Inventory shows
  `SHA256withRSA` as *not rated*.

## 2. Evidence

| # | Where | Today | Gap |
|---|---|---|---|
| C-1 | Report › Configuration › suite table | Strength word, bits and the weakest part | The other parts, each part's class, and its strength are in the API (`suiteStrength[].parts`) but are never drawn |
| C-2 | Report, any tab | There is no "algorithms this endpoint uses" view | A reviewer has to read the suite names to find out that the endpoint uses RSA, ECDHE, AES-GCM and SHA-384 |
| C-3 | Model (`internal/eval/strength.go`) | Parts: cipher, key exchange, authentication, MAC | No PRF/HKDF hash part; no signature hash on the certificate |
| C-4 | Inventory › Algorithms | A *Kind* column (block cipher, signature, hash…) | No class grouping or filter: the list cannot show "every symmetric cipher" or "every hash" |
| C-5 | Inventory | `SHA256withRSA`, `ecdsa-with-SHA256` | A composite signature algorithm is rated only when the CBOM names its key; it is never split into hash and key |
| C-6 | CBOM tab | Name, Type, Detail, Post-quantum | No classical strength (the CBOM file has `classicalSecurityLevel`, the table does not show it) |
| C-7 | PDF and CLI | Suite word and weakest part | Same gap as C-1 |

## 3. Proposal

### 3.1 One class vocabulary
Each primitive gets one of three classes, and a role within it:

| Class | Roles | Examples |
|---|---|---|
| **Asymmetric** | key exchange (KEM, key agreement, key transport), signature | ECDHE secp256r1, X25519, ML-KEM-768, RSA key transport, ECDSA P-256, RSA-2048, ML-DSA-65 |
| **Symmetric** | bulk cipher (AEAD, block, stream), MAC | AES-256-GCM, ChaCha20-Poly1305, 3DES, RC4, HMAC-SHA-256 |
| **Hash** | PRF or KDF, signature hash, MAC hash, fingerprint | SHA-384 (HKDF), SHA-256 (in ECDSA-SHA256), SHA-1 |

The class comes from the CycloneDX `primitive` already in the catalogue (`ae`, `block-cipher`, `kem`,
`signature`…), so nothing is classified twice. "Fingerprint" hashes are shown but never rated: we compute them
ourselves.

### 3.2 The model
- Add a **hash part** to every suite:
  - the PRF hash in TLS 1.2;
  - the HKDF hash in TLS 1.3;
  - SP 800-57 Table 3 rates a hash in HMAC, KDF and RBG use separately from its collision strength: SHA-1 ≥128,
    SHA-256 and SHA-384 ≥256.

  This part never lowers a suite today: NIST rates SHA-1 at ≥128 for HMAC and KDF use. It is shown because a reviewer
  needs to see it, and so that one later rule change touches the model only.
- **Signature algorithm = hash + key.** `ECDSA-SHA256` is rated as the weaker of its hash's collision strength
  (Table 3) and the key's strength. A certificate whose key we know (any TLS scan) is always rated. An imported
  `SHA256withRSA` with no key size is rated by its hash, and says that the key was not given.
- `algo.ClassOf(name)` returns class and role. Every catalogue entry gets one, and a test enforces it.

### 3.3 Surfaces
1. **Report › Configuration › a new "Algorithms in use" card**, above the suites:
   - three groups (Asymmetric, Symmetric, Hash);
   - each row gives: the algorithm, its role, its classical strength, its post-quantum status, and where it is used
     (which versions or suites, or the certificate);
   - the weakest row in each group is marked.

   This is the view a reviewer reads first.
2. **The suite row expands** to its parts: one line per part with class, name and strength, the weakest marked. It
   replaces the single "weakest" hint, which stays as the collapsed summary.
3. **Inventory › Algorithms:** a *Class* filter (Asymmetric, Symmetric, Hash) next to *Only quantum-vulnerable*,
   with the class shown in the *Kind* column ("Asymmetric · signature").
4. **CBOM tab:** a *Classical strength* column, from `classicalSecurityLevel`.
5. **PDF and `tls scan --details`:** the same "Algorithms in use" table, and each suite's parts.
6. **SSH report:** the existing tables are already one per role; each gets its class in the heading
   ("Key exchange methods · asymmetric").
7. **API:** the evaluation gains `algorithms[]` ({name, class, role, strength, pqc, usedBy[]}), and each suite part
   gains `class`.

## 4. Requirements (draft for PRD-011)

| ID | Requirement | Test |
|---|---|---|
| REQ-CLS-1 | `algo.ClassOf` gives every catalogue entry a class and a role; none is left unclassified | `TestEveryAlgorithmHasAClass` |
| REQ-CLS-2 | Each suite gains its hash part (PRF or HKDF), rated by SP 800-57 Table 3 for that use | `TestSuiteHasItsHashPart` |
| REQ-CLS-3 | A signature algorithm is rated as the weaker of its hash (collision strength) and its key; a known key is always used | `TestSignatureAlgorithmIsHashAndKey` |
| REQ-CLS-4 | The evaluation carries `algorithms[]`, one per distinct algorithm, with class, role, strength, post-quantum status and the suites or certificate that use it | `TestEvaluationListsAlgorithmsByClass` |
| REQ-CLS-5 | The report's *Algorithms in use* card, grouped by class, agrees row for row with the API | e2e `E2E-CLS-1` |
| REQ-CLS-6 | A suite row expands to its parts, the weakest marked | e2e `E2E-CLS-2` |
| REQ-CLS-7 | The Inventory's *Class* filter; the CBOM tab's *Classical strength* column | e2e `E2E-CLS-3`, `TestInventoryFiltersByClass` |
| REQ-CLS-8 | The PDF and the CLI show the same table and parts | `TestPDFListsAlgorithmsByClass`, `TestDetailsShowSuiteParts` |
| REQ-CLS-9 | Help and the methodology explain the three classes and the hash rule | `report:docs/methodology.md` |

## 5. Decisions (owner, 2026-10-21)

- **OD-1: does the hash part count toward a suite's word? Decided: yes, as a part.** It never decides a word with
  today's NIST numbers, but one rule is easier to explain than an exception.
- **OD-2: where does the card sit? Decided: Configuration, first card.** The Summary stays the short answer (what
  to fix), and gains one line naming the weakest suite and its bits, which links to the card (UX-REVIEW-010 U-3).

## 6. Size

Medium: one model change (a hash part, and the signature split), one new evaluation list, and four surfaces. It
builds on PRD-010's model and tests; no new standard is needed.
