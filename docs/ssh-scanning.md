# SSH scanning

CipherHorizon audits SSH servers the way it scans TLS endpoints: its own wire implementation
(`internal/sshprobe`, Go standard library only). It shows what the server offers, what a current client would
actually use, and every host key. It judges two things:
- the server's **post-quantum readiness** (L0 to L4);
- whether it **meets an SSH baseline**, a cited list of what an SSH server may and must offer.

**It never logs in**, and it sends no password, key or user name. SSH servers get no 0 to 100 score.

```sh
cipherhorizon ssh scan bastion.example.com                    # port 22 unless given
cipherhorizon ssh scan --details git.example.com:2222         # also the algorithm lists and host keys
cipherhorizon ssh scan --fail-on baseline bastion.example.com # exit 3 when it does not meet the baseline
cipherhorizon ssh baselines                                   # the baselines, entry by entry, with sources
```

In the web app, SSH servers have their own page: **SSH servers**. Add one with `ssh://host[:port]`, with port 22 and
Protocol *Automatic*, or by choosing *SSH*.

Scan only systems you own or are authorised to test.

## What is sent

| Stage | What happens | Connections |
|---|---|---|
| **Identification** | Connect, read the server's identification line (RFC 4253 §4.2), and send `SSH-2.0-CipherHorizon_<version>`. Up to 20 lines before it are allowed. A server that offers only SSH-1 is recorded as such, and the scan stops there. | 1 |
| **Algorithms** | Read the server's KEXINIT (RFC 4253 §7.1): its key exchange, host key, cipher, MAC and compression lists, in its order. `ext-info-s` and `kex-strict-s-v00@openssh.com` are recorded as signals, not as key exchanges. | same |
| **Negotiation** | Offer the default lists of the OpenSSH 10.6 client and apply RFC 4253 §7.1 to find what a current client would use. If that key exchange is one the scanner implements, complete it up to the server's reply and verify the server's signature over the exchange hash. | 1 |
| **Host keys** | For each host key algorithm the server offers, run one key exchange restricted to it and read the key. Verify the signature where possible: Ed25519, ECDSA, RSA (SHA-2 and SHA-1), ML-DSA and the composite `ssh-mldsa44-ed25519`. Keys are grouped by their SHA-256 fingerprint (OpenSSH format). | one per algorithm |

**Limits:**
- **Connections:** a scan makes at most 2 plus the number of host key algorithms, and never more than 24.
- **Guards:** the same scan scope, address guard (no loopback, link-local or cloud-metadata addresses unless
  allowed), timeouts and rate limit as TLS apply.
- **Untrusted input:** nothing the server sends is trusted. Packets are bounded to 35,000 bytes, names and banners are
  cleaned of control characters and capped, and the parsers are fuzzed.

**Key exchanges the scanner can complete:**
- `mlkem768x25519-sha256` (RFC 10042);
- `curve25519-sha256` (and the `@libssh.org` name);
- ECDH on P-256, P-384 and P-521;
- `diffie-hellman-group14-sha256`, `group16-sha512`, `group14-sha1` and `group1-sha1`.

A server that offers none of these, for example only `sntrup761x25519-sha512` or group exchange, still has its lists
read and judged. Its host keys are then reported as *not fetched*, with the reason, never as absent.

The prober is checked against real OpenSSH 9.2 (Debian 12) and 10.0 (Debian 13): `testing/ssh/oracle.sh` compares
every list, negotiated choice and host key fingerprint with what `ssh -vv` reports.

## Readiness, SSH rules

The scale is the same as for TLS ([methodology](methodology.md)); the SSH rules are:

| Level | SSH rule |
|---|---|
| **L0** | The server speaks only SSH-1. |
| **L1** | No post-quantum hybrid key exchange is offered. Recorded sessions are exposed to harvest-now-decrypt-later. |
| **L2** | A hybrid is offered, but a current client (OpenSSH 10.6) doesn't end up using it. |
| **L3** | A current client negotiates a post-quantum hybrid: `mlkem768x25519-sha256`, or `sntrup761x25519-sha512`. sntrup also gets a Low note recommending ML-KEM for FIPS 203 alignment. |
| **L4** | L3, plus a post-quantum host key: `ssh-mldsa44-ed25519` (enabled in OpenSSH 10.6), `ssh-mldsa87-p384` or `ssh-mldsa-44/65/87`. |

## The SSH baseline

SSH practice judges a server against a policy, not a score. A **baseline** is a named, versioned list:
- **allowed algorithms**, per kind (key exchange, host key, cipher, MAC, compression), in preference order;
- **requirements**: things a server must do.

Every entry cites its source and names the OpenSSH version that first offers it. `cipherhorizon ssh baselines`
prints them all; `GET /api/v1/ssh/baselines` returns them as JSON.

A server **meets** the baseline when nothing it offers should be off and every requirement holds. Unknown names are
not on the list, so they should be off. A server whose lists couldn't be read is **not judged**, never "meets".

### CipherHorizon SSH baseline 2026 (`cipherhorizon-ssh-2026`, the default)

| Kind | Allowed, in order |
|---|---|
| Key exchange | `mlkem768x25519-sha256`, `sntrup761x25519-sha512` (and its `@openssh.com` name), `curve25519-sha256` (and its `@libssh.org` name), `curve448-sha512`, ECDH P-256/384/521, `diffie-hellman-group-exchange-sha256`, `group16-sha512`, `group18-sha512`, `group14-sha256`, `group15-sha512`, `group17-sha512`, `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384` |
| Host keys | `ssh-mldsa44-ed25519` (and its certificate), `ssh-mldsa87-p384`, `ssh-mldsa-44/65/87`, `ssh-ed25519` (and certificate), `ssh-ed448`, ECDSA P-256/384/521 (and certificates), `rsa-sha2-512`, `rsa-sha2-256` (and certificates) |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`, `aes128-ctr`, `aes192-ctr`, `aes256-ctr`, `AEAD_AES_128_GCM`, `AEAD_AES_256_GCM` |
| MACs | `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com`, `umac-128-etm@openssh.com` |
| Compression | `none`, `zlib@openssh.com` (after authentication only) |

**Requirements:**
1. **A post-quantum hybrid key exchange is offered** (RFC 10042, RFC 9941).
2. **Strict key exchange is offered.** This is OpenSSH's countermeasure to Terrapin (CVE-2023-48795), in OpenSSH 9.6
   and later.
3. **RSA host keys are at least 3072 bits** (NIST SP 800-57 Part 1: 128-bit security). On a server with no RSA host
   key this rule *does not apply*, rather than reading as met.

A truncated MAC is rated by its tag: `hmac-sha1-96` is 96 bits, not HMAC-SHA-1's 128 (NIST SP 800-107 Rev. 1). The
next steps and the changes name OpenSSH releases only to a server that identifies as OpenSSH; any other server is told
what to offer.

**What it leaves out, and why:**

| Left out | Why |
|---|---|
| SHA-1 key exchange and `ssh-rsa` signatures | RFC 9142, RFC 8332 |
| DSA | FIPS 186-5 |
| CBC modes | CVE-2008-5161 |
| RC4 | RFC 8758 |
| 64-bit-tag and SHA-1 MACs | |
| MACs computed over the plaintext (the non-ETM forms) | |
| Compression before authentication | |

A stock OpenSSH 10 server doesn't meet it, only because of its default MACs: `umac-64`, `hmac-sha1` and the non-ETM
forms. That is also what common hardening guides remove.

**BSI TR-02102-4** is planned as a second baseline. It will be added once its 2026-01 tables are verified, because the
BSI publishes them only as image PDFs.

### The `sshd_config` lines

When a server doesn't meet the baseline, the report (web, PDF, CLI) gives the lines that would make it meet it:
- **One line per directive that needs changing** (`KexAlgorithms`, `HostKeyAlgorithms`, `Ciphers`, `MACs`). Each line
  keeps the allowed algorithms the server already offers, in the baseline's order.
- **A required algorithm the server lacks** is added, with a comment naming the OpenSSH version it needs.
- **`Compression no`** when compression before authentication is offered.
- **Comments for what configuration can't fix:** upgrading for strict key exchange, or replacing a small RSA host
  key (with the `ssh-keygen` command).

**Where the lines go.** sshd uses the **first** value it reads for each keyword. Put the lines at the top of
`/etc/ssh/sshd_config`, or in a file under `/etc/ssh/sshd_config.d/` that is included first. Then check them with
`sshd -t`, reload sshd, and scan again. The oracle applies the lines to a real OpenSSH 10 server and confirms that
`sshd -t` accepts them and that the rescan meets the baseline.

## The checks

Each check is cited and says what it found or that it passed. They are listed, with their sources, in
[methodology.md](methodology.md#ssh-checks). The post-quantum findings use the same IDs as TLS, so Findings groups
harvest-now-decrypt-later exposure across protocols.

## Not covered

- **Auditing SSH clients.** ssh-audit's `-c` listens for clients; CipherHorizon audits servers only.
- **Stress tests** such as DHEat. They are denial-of-service tests, excluded by design.
- **The modulus sizes of `diffie-hellman-group-exchange-*`.** Judged by name only.
- **Authentication methods, user keys, SSHFP and HASSH.**
