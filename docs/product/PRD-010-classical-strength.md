# PRD-010 · Classical strength for every detected algorithm

Status: baselined 2026-10-18. The owner approved [ENH-001](ENH-001-cipher-strength.md) with **OD-1 as recommended**:
a suite is as strong as its weakest part, so an RSA-2048 certificate makes its suites *Acceptable*. The scope
includes the suite rating, the API, the CLI, the Inventory, SSH and the CBOM `classicalSecurityLevel`, and fixes
issue #18.

Problem, evidence and the NIST method: ENH-001 §1, §2 and §5. Status per requirement: [RTM](../program/RTM.md).
Results: QA-REPORT-010.

## 1. Goals

| # | Goal | Measure |
|---|---|---|
| G-1 | Every place that lists an algorithm says how strong it is classically, from one cited model | No surface lists an algorithm without a strength, or a cited reason it has none |
| G-2 | The strength is NIST's, computed the way NIST computes it | Tests reproduce SP 800-56B Table 4, SP 800-56A Table 26, SP 800-186 Table 1 and SP 800-57 Tables 2 and 3 |
| G-3 | A suite's word explains itself | Each suite names its weakest part and its bits |

**Non-goals:**
- a score;
- re-weighting findings or the TLS hygiene score;
- post-quantum strength, which stays in the readiness level and `nistQuantumSecurityLevel`.

## 2. The rating (ENH-001 §3.1, OD-1)

A suite's parts:
- **cipher:** the bulk cipher;
- **key exchange:**
  - ECDHE: the weakest group the server accepts for that version;
  - DHE: the prime it sent;
  - RSA key transport: the certificate key;
- **authentication:** the weakest end-entity key the server presented whose type the suite can use (RSA or ECDSA
  in TLS 1.2; any in TLS 1.3);
- **MAC:** for non-AEAD suites.

Its **bits** are the minimum over the parts. Each part is broken or has a strength (`internal/algo/strength.go`).

| Word | When |
|---|---|
| **Insecure** | any part broken (NULL, export, RC4, DES, anonymous, so no authentication), or fewer than 80 bits |
| **Weak** | 80 to 111 bits, or a 64-bit block cipher (Sweet32), or no forward secrecy (RSA key transport, static DH or ECDH) |
| **Acceptable** | at least 112 bits, but below 128 or not AEAD |
| **Strong** | at least 128 bits in every part, AEAD, forward secrecy |

The reason names the weakest part, for example "RSA-2048 certificate key, 112 bits", or the rule that decided the
word ("64-bit block cipher").

## 3. Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-STR-1** | **The model.** `algo.StrengthOf` gives every catalogue algorithm, and every variant this program derives (RSA-n, ECDSA-curve, ECDH-curve, DSA-n, the signature variants), its classical strength in bits, or a cited broken status, or "not rated" with a reason. Never a guess. | Every catalogue entry is one of the three; the post-quantum ones carry their NIST category's classical equivalent (FIPS 203, 204, 205); a hybrid is as strong as its stronger part (RFC 10024) | `TestEveryAlgorithmHasACitedStrength` | P0 |
| **REQ-STR-2** | **Suite rating** as §2, in `internal/eval`, with the parts, the bits and the reason. Single DES is **Insecure** (#18). | A table test over the IANA registry; the demo targets' suites rate as expected | `TestSuiteStrengthIsTheWeakestPart`, `TestSingleDESIsInsecure` | P0 |
| **REQ-STR-3** | **API.** The evaluation carries `suiteStrength`: per suite, version, ID, word, bits, the weakest part and the reason. It also carries `keyStrength` for every certificate key and accepted group. `eval.Version` becomes `eval/9`, so stored scans are re-evaluated. | `GET /api/v1/scans/{id}/evaluation` shows them | `TestEvaluationCarriesStrength` | P0 |
| **REQ-STR-4** | **Report and PDF read the evaluation.** The two heuristic copies are deleted. The suite table shows the word with bits and the weakest part; the group and certificate-key tables show bits. | Page, PDF and API agree for every suite of every demo target | `TestPDFAndEvaluationAgreeOnStrength`, `script:testing/e2e/strength-phase.mjs#E2E-STR-1` | P0 |
| **REQ-STR-5** | **CLI.** `tls scan --details` shows each suite's word, bits and weakest part, and each group's bits. `--json` includes the evaluation fields. | | `TestDetailsShowSuiteStrength` | P1 |
| **REQ-STR-6** | **Inventory.** Algorithm and key rows carry `classicalStrength`: `bits`, `status` (rated, disallowed, broken, not-rated) and the cited `basis`. The lists show a *Classical strength* column, and no broken algorithm reads only "not classified". | 3DES shows "112 bits, disallowed" (SP 800-131A Rev. 2); RC4 "broken" (RFC 7465); RSA-2048 112; AES-256-GCM 256 | `TestInventoryRowsCarryClassicalStrength`, `script:testing/e2e/strength-phase.mjs#E2E-STR-2` | P0 |
| **REQ-STR-7** | **SSH.** Each advertised algorithm in the evaluation (key exchange, host key, cipher, MAC) carries its strength; host keys use the size of the key fetched. The report shows it. | `diffie-hellman-group14-sha256` 112; `curve25519-sha256` 128; `3des-cbc` 112 disallowed; `hmac-md5` not rated (MD5 is not an approved hash, so SP 800-57 gives it no strength; RFC 6151 does not call HMAC-MD5 broken); an RSA-1024 host key 80 | `TestSSHAlgorithmsCarryStrength` | P1 |
| **REQ-STR-8** | **CBOM.** `algorithmProperties.classicalSecurityLevel` is set from the model for every algorithm component that has a strength (1.6 and 1.7). A broken one keeps `classical-status` and gets no number. | Validates against both schemas | `TestCBOMCarriesClassicalSecurityLevel` | P0 |
| **REQ-STR-9** | **Documentation.** docs/methodology.md has the method, the table and its sources; Help explains the four words; docs/cbom-model.md the field; the CHANGELOG notes the change in words. | | `report:docs/methodology.md` | P1 |

## 4. Release

A minor release (0.4.0), when the owner asks. Visible changes:
- some suites change word (RSA-2048 suites become *Acceptable*; single DES becomes *Insecure*);
- new API fields;
- the CBOM's `classicalSecurityLevel`.
