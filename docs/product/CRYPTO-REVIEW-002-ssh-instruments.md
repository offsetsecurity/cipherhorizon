# CRYPTO-REVIEW-002 · Every number and claim on the rebuilt SSH report (PRD-014)

Date: 2026-10-21. Reviewer role: cryptographer (PRD-014 REQ-SSV-9). Build: branch `feat/ssh-instruments`, stacked
on `feat/classes-and-x509` (PRD-013). Scope: what the SSH Summary and Configuration *show*: each number, word,
glyph, tooltip and sentence, checked against the report and evaluation it is drawn from and against the source
cited. The SSH rules and strengths themselves were reviewed for PRD-008 and PRD-010 (CRYPTO-REVIEW-001 covers the
shared scale); they are re-read here only where a screen states them.

Data: the CI journey's SSH demo servers: 9460 (hybrid key exchange, OpenSSH-style MACs), 9461 (classical), 9462
(legacy: SHA-1 groups, a 1024-bit RSA host key, CBC, 3DES, truncated MACs), 9463 (ML-DSA-65 host key), 9465
(SSH-1 only), 9467 (hardened to meet the baseline). Agreement between screen and API is checked by the journey
(E2E-H.2, E2E-VIS-6, E2E-VIS-8, E2E-VIS-9, E2E-VIS-10); this review checks that what is said is right.

## Verdict

**Signed off**, with the five defects below fixed in this branch (3 to 5 from a second evaluation the owner asked for) and two notes left as they are, each with its
reason. No number on the SSH screens disagrees with its cited source.

## Numbers checked

| Shown | Value | Source | Holds |
|---|---|---|---|
| Hybrid key exchange | mlkem768x25519-sha256 → 192 | the stronger part (RFC 10042; ML-KEM-768 is category 3, FIPS 203) | yes |
| Elliptic-curve key exchange and host keys | curve25519-sha256, ssh-ed25519, ecdsa-sha2-nistp256 → 128 | SP 800-186 Table 1 (half the base-point order) | yes |
| Finite-field groups | group14 (2048-bit MODP) → 112; group1 (1024-bit, Oakley 2) → 80 | SP 800-57 Part 1 Rev. 5, Table 2 | yes |
| RSA host-key algorithms | rsa-sha2-256 on a 1024-bit key → 80; ssh-rsa (SHA-1) → broken | SP 800-57 Table 2; SP 800-131A Rev. 2 (SHA-1 disallowed for signature generation) | yes |
| ML-DSA host key | ssh-mldsa-65 → 192 | FIPS 204, category 3 | yes |
| Ciphers | AES-128/192/256 (CTR, GCM, CBC) by key; 3DES → 112, disallowed; chacha20-poly1305 → 256 by its key | SP 800-57 Table 2; SP 800-131A; RFC 8439 | yes |
| MACs | HMAC-SHA-1 → 128; HMAC-SHA-256 and -512 → 256 | SP 800-57 Table 3, HMAC column | yes (see note 1) |
| Host-key card | the strongest signature the key answers to: RSA 1024 → 80 (rsa-sha2-256, not ssh-rsa); Ed25519 → 128; ML-DSA-65 → 192 | as above | yes |
| Weakest classical strength (Summary) | the weakest rated algorithm offered: on 9462 ssh-rsa, broken; on 9460 128 bits | the evaluation's strengths | yes (E2E-VIS-10) |
| Readiness L0 to L4 | stepper filled to the evaluation's level: 9460 L3, 9461 L1, 9463 L4, 9465 L0 | PRD-008 SSH readiness | yes (E2E-H.1b, E2E-VIS-9) |
| Fingerprints | `SHA256:` base64 of the host-key blob, as `ssh-keygen -l` prints it | RFC 4253 §6.6 blob; OpenSSH fingerprint format | yes |

## Claims checked

- **"Every list here is in the server's order; in each, the client's order decides (RFC 4253 §7.1)."** RFC 4253
  §7.1: the chosen algorithm is the first on the client's name-list that is also on the server's, for key exchange,
  host keys, ciphers, MACs and compression alike. So the rows carry no rank numbers, unlike TLS's suites (where the
  server may pick). Correct after fix 2.
- **"A current client gets" + four chips, "signature verified".** The scan's own negotiation with OpenSSH 10.6's
  default lists, carried out to the host-key signature over the exchange hash, which verified. The banner names
  the client in its tooltip. Correct.
- **"no MAC" with an AEAD cipher.** With chacha20-poly1305@openssh.com or aes-gcm@openssh.com the negotiated MAC is
  ignored (OpenSSH PROTOCOL §1.6 for aes-gcm@openssh.com; PROTOCOL.chacha20poly1305). Correct.
- **Post-quantum glyphs.** Shield with a check on mlkem768x25519-sha256 and ssh-mldsa-65; shield with a cross on
  curve25519, ECDH, finite-field DH, Ed25519, ECDSA and RSA; a dot on ciphers and MACs ("no post-quantum verdict").
  See note 3.
- **Strict key exchange: "On: the countermeasure to Terrapin".** kex-strict-s-v00@openssh.com, OpenSSH 9.6
  (CVE-2023-48795). *Not offered* is the problem tone only when the scan infers Terrapin is possible
  (chacha20-poly1305, or CBC with encrypt-then-MAC, without strict key exchange); otherwise it needs attention.
  Correct.
- **Compression: "zlib@openssh.com, after login" and "zlib, before login".** zlib@openssh.com starts after user
  authentication; plain zlib starts with the first NEWKEYS, before authentication. Correct.
- **Protocol tile.** "SSH-2 only" for 2.0; "SSH-2, and SSH-1 accepted" for 1.99 (RFC 4253 §5.1); "SSH-1 only" for
  1.x. The identification string is shown as sent. Correct.
- **"Lines before the identification".** RFC 4253 §4.2 allows them; shown as a count, in no tone. Correct.
- **Software.** "As the server announces it. Its version is not matched against vendor advisories." True: the
  scanner reads the banner only; *Server software flaws* stays *Not tested* under Weaknesses.
- **Baseline requirements.** Each tile links to its cited source (RFC 10042; OpenSSH 9.6 release notes;
  SP 800-57 Table 2 for 3072-bit RSA, i.e. 128-bit strength). The *Met / Not met* states equal the evaluation's.
- **The changes.** − remove, + add, ↑ upgrade, ⟲ replace a key; each chip's tooltip is the evaluation's own reason
  and source. The `sshd_config` hint ("sshd keeps the first value of each keyword") is sshd_config(5)'s rule.
  Correct.

## Defects found and fixed in this branch

1. **The Summary's Host key tile drew a 1024-bit RSA key in the good tone.** It was toned by post-quantum status
   alone (classical → green). It now follows the key's strength: weak or broken in the problem tone, acceptable in
   the attention tone, strong green, post-quantum the L4 colour.
2. **"Listed in the server's order; the client's order decides" stood on Key exchange alone**, which could read as
   if the other lists were preferences. RFC 4253 §7.1 applies the rule to every list; the aside now says so.

3. **Truncated MACs were rated by their HMAC** (the first review's note 1, now fixed). hmac-sha1-96 showed 128 bits,
   but a 96-bit tag lets a forger guess right with probability 2⁻⁹⁶ per attempt: SP 800-107 Rev. 1 §5.3.5 bounds a
   truncated MAC by its tag. The strength is now the smaller of the HMAC's and the tag's (hmac-sha1-96 → 96,
   umac-64 → 64), with the reason in its basis. `TestTruncatedMACIsBoundedByItsTag`. eval/11.
4. **The next steps told every server to "Upgrade to OpenSSH 9.9"**, including the demo servers that identify as Go.
   OpenSSH releases are now named only to a server that identifies as OpenSSH; any other is told what to offer
   (mlkem768x25519-sha256 first; strict key exchange), with OpenSSH as the reference point.
   `TestSSHNextStepsNameOpenSSHOnlyForOpenSSH`.
5. **"RSA host keys are at least 3072 bits: Met" on servers with no RSA key.** Nothing was judged, so *Met* claimed a
   check that never ran. The requirement now carries `notApplicable` and the tile says *Does not apply: the server has
   no RSA host key*; the verdict is unchanged. `TestRSASizeRuleWithoutAnRSAKeyDoesNotApply`.

## Notes left as they are

1. **SHA-1 key exchanges are rated by their group.** diffie-hellman-group14-sha1 shows 112 bits (the 2048-bit
   group); its SHA-1 exchange hash is what puts it on *should be off* (SSH.KEX-SHA1, RFC 9142), and the row now says so
   beside the mark (*a SHA-1 key exchange*). The bar stays the group's strength and the mark carries the SHA-1 risk;
   kept.
2. **Ciphers and MACs carry a dot, not a shield.** The TLS class map and the Inventory mark AES as quantum-safe
   (NIST IR 8547; Grover gives no practical break), while the SSH rows give ciphers and MACs no post-quantum
   verdict, as PRD-013 drew them. Both are true statements; the dot's tooltip says *no post-quantum verdict*, not
   *safe* or *vulnerable*. Kept, so the SSH page does not imply that its ciphers were classified by a source they
   were not.

## Sign-off

The numbers and claims on the SSH Summary and Configuration are correct against their sources, with fixes 1 to 5
in this branch. Signed off for PRD-014 REQ-SSV-9, cryptography.
