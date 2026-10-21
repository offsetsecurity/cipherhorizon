# PRD-011 · Every algorithm by class, and a flow that explains itself

Status: baselined 2026-10-21. The owner approved [ENH-002](ENH-002-algorithm-classes.md) and
[UX-REVIEW-010](UX-REVIEW-010-flow-and-self-explanation.md) with every open decision as recommended:
- the hash part counts in the weakest-part rule;
- the *Algorithms in use* card goes first on Configuration;
- the TLS hygiene bands are renamed, so no word belongs to two scales.

Issues #20 and #22. Status per requirement: [RTM](../program/RTM.md). Results: QA-REPORT-011.

## 1. Goals

| # | Goal | Measure |
|---|---|---|
| G-1 | A reviewer sees every algorithm an endpoint uses, grouped as asymmetric, symmetric and hash, each with its strength | One card answers "what crypto does this endpoint use, and how strong is each piece?" |
| G-2 | A suite's rating can be checked part by part | Every part is shown, with its class, strength and source |
| G-3 | No word means two things | The hygiene bands and the suite words share no word |

Non-goals: new findings, or a change to the TLS hygiene score's numbers.

## 2. Classes

| Class | CycloneDX primitives | Roles |
|---|---|---|
| asymmetric | `pke`, `signature`, `key-agree`, `kem`, `combiner` | key exchange, signature |
| symmetric | `ae`, `block-cipher`, `stream-cipher`, `mac` | cipher, MAC |
| hash | `hash` | hash (PRF, HKDF or signature) |

## 3. Requirements

| ID | Requirement | Acceptance | Test | Pri |
|---|---|---|---|---|
| **REQ-CLS-1** | **The class model.** `algo.ClassOf` gives every catalogue entry, and every name this program derives (RSA-2048, ECDSA-P256, the group names, the signature spellings), a class and a role from §2. | No catalogue entry is unclassified | `TestEveryAlgorithmHasAClass` | P0 |
| **REQ-CLS-2** | **Hash part.** Every suite gains its hash part: HKDF in TLS 1.3, the PRF in TLS 1.2 (SHA-256 unless the suite names SHA-384), MD5 and SHA-1 combined in TLS 1.0 and 1.1. It is rated in its KDF use (SP 800-57 Table 3), and it counts in the weakest-part rule (OD-1). | Every registry suite has a hash part; no word changes on today's demo targets | `TestSuiteHasItsHashPart`, `TestEverySuiteInTheRegistryIsRated` | P0 |
| **REQ-CLS-3** | **Signature algorithms.** A signature algorithm is split into its hash and its key: `ECDSA-SHA256`, `SHA256-RSA`, `sha256WithRSAEncryption` and `SHA256withRSA` are one algorithm. It is rated as the weaker of the hash's collision strength and the key's strength; with no key size, the hash's strength and a basis saying the key was not given. | `SHA256withRSA` is no longer *not rated* | `TestSignatureAlgorithmIsHashAndKey` | P0 |
| **REQ-CLS-4** | **API.** The evaluation carries `algorithms[]`, one per distinct algorithm, with its class, role, strength, post-quantum status and what uses it (versions, suites, the certificate). Each suite part gains `class`. `eval.Version` becomes `eval/10`. | | `TestEvaluationListsAlgorithmsByClass` | P0 |
| **REQ-CLS-5** | **Algorithms in use.** The first card on Configuration groups the endpoint's algorithms by class, each row with its role, strength, post-quantum status and uses, the weakest per class marked. It agrees row for row with the API. | | `script:testing/e2e/classes-phase.mjs#E2E-CLS-1` | P0 |
| **REQ-CLS-6** | **Suite parts.** A suite's strength cell opens its parts: class, name and strength, the weakest marked. | | `script:testing/e2e/classes-phase.mjs#E2E-CLS-2` | P0 |
| **REQ-CLS-7** | **Inventory and CBOM tab.** The Inventory's algorithm list has a *Class* filter and says the class in *Kind*; the report's CBOM tab has a *Classical strength* column. | | `TestInventoryFiltersByClass`, `script:testing/e2e/classes-phase.mjs#E2E-CLS-3` | P1 |
| **REQ-CLS-8** | **PDF and CLI.** The PDF has the *Algorithms in use* table; `tls scan --details` lists it and each suite's parts. | | `TestPDFListsAlgorithmsByClass`, `TestDetailsShowAlgorithmsByClass` | P1 |
| **REQ-UXF-1** | **Hygiene bands renamed** (UX-REVIEW-010 U-1): Excellent (90+), Good (75+), Fair (55+), Poor (30+), Failing. A stored scan's old band (Strong, Sound, Weak, Broken) is migrated in the database and mapped when an old evaluation is read. | No screen, API answer or PDF shows an old band name | `TestBandsHaveTheirOwnWords`, `TestOldBandsAreMigrated` | P0 |
| **REQ-UXF-2** | **Summary headline** (U-2): the line under "N things to fix" names the first thing to fix; the post-quantum sentence stays in its tile. | | `script:testing/e2e/classes-phase.mjs#E2E-UXF-1` | P1 |
| **REQ-UXF-3** | **Summary strength** (U-3): the *Cipher suites* row names the weakest suite, its word and bits, and links to *Algorithms in use*. | | `script:testing/e2e/classes-phase.mjs#E2E-UXF-1` | P1 |
| **REQ-UXF-4** | **Reasons and links** (U-6, U-7): a *not rated* Inventory cell says why; the hygiene tile links to Help › TLS hygiene. | | `script:testing/e2e/classes-phase.mjs#E2E-UXF-2` | P2 |
| **REQ-UXF-5** | **Overview tile** (U-8): the TLS endpoints tile shows the count and the exposed figure only. | | `script:testing/e2e/classes-phase.mjs#E2E-UXF-2` | P2 |
| **REQ-CLS-9** | **Documentation.** The methodology gives the classes and the hash rule; Help explains the card and the new band words; the CHANGELOG names the rename. | | `report:docs/methodology.md` | P1 |
