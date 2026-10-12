# UX-DESIGN-006 · SSH endpoints and post-quantum signatures, screen by screen

For [PRD-008](PRD-008-pq-signatures-and-ssh.md). Agreed before UI code (ENG-HANDOFF-005 §4, WP-F). The bar is
the one the owner set: every capability reachable from a button, every state says what happened and whether
that is right, no TLS words on an SSH page, a written screen walk before "done" (UX-REVIEW-008 method).
Design tokens, type and components are DESIGN.md v2; nothing new is introduced except where stated.

## 1. Principles for this release

1. **One list of endpoints, two services.** People think "the bastion" and "the API", not "my SSH assets" and "my
   TLS assets". SSH endpoints live in **Endpoints** beside TLS ones. The service is said under the address, exactly as
   STARTTLS endpoints say `SMTP · STARTTLS` today. No new menu item.
2. **Same report, protocol's own words.** The tabs, header and verdict are identical, so a reader who learned one
   report reads the other. The areas, facts and remediation are SSH's own: *Host keys* not *Certificates*,
   `sshd_config` lines, not cipher-suite names.
3. **Advertised is not used.** SSH servers advertise lists; a client picks. Every algorithm row says which:
   *Offered*, and, for the one a current client lands on, *Used by OpenSSH 10.6*.
4. **The scale is one scale.** L0 to L4 keep their names; the descriptions name both protocols in one line each.

## 2. Screens and changes

### 2.1 Overview (`#/`)

- Scan box placeholder: `example.com, https://example.com, host:port or ssh://host`. A 22 port or `ssh://` scans SSH.
- Help line under the box: "Only scan systems you own or are authorised to test. A TLS scan makes a few hundred
  short handshakes; an SSH scan a handful of key exchanges, never a login."
- Readiness scale descriptions (both protocols, one sentence each):

| Level | Description |
|---|---|
| L4 PQ-authenticated | Post-quantum key exchange and a post-quantum certificate or host key. |
| L3 Hybrid negotiated | A current client gets a post-quantum hybrid key exchange. |
| L2 Hybrid available | Offered, but a current client does not get it by default. |
| L1 Exposed | Only classical key exchange: recorded traffic is exposed. |
| L0 Not ready | The protocol in use can't carry it: no TLS 1.3, or SSH-1 only. |

- Endpoint counts and the "where you stand" panel include SSH endpoints.

### 2.2 Add endpoints dialog (Endpoints → *Add endpoints*)

```
Host or URL      [ bastion.example.com:22                        ]
                 A hostname or IP, optionally with a port. ssh://host scans SSH.
Service          [ Automatic (by port)                         ▾ ]
                   Automatic (by port)            ← default
                   TLS from the first byte
                   SSH
                   STARTTLS: SMTP / IMAP / POP3 / FTP / XMPP / LDAP / PostgreSQL
                 Automatic: port 22 is SSH; mail, directory and database ports use
                 STARTTLS; everything else is TLS from the first byte.
Name / Tags      (unchanged)
```

The label changes from *How it starts TLS* to **Service**, because it now chooses the protocol. *Paste a list*
accepts `ssh://` lines.

### 2.3 Endpoints list (`#/endpoints`)

```
☐  Endpoint                        PQC readiness   Hygiene        Findings   Certificate / key     Last scan
☐  api.example.com                 L3 Hybrid neg.  Sound 82       1 medium   ECDSA · 64 days left   2 min ago
☐  bastion.example.com:22          L3 Hybrid neg.  Strong 96      none       Ed25519 host key       2 min ago
   SSH · OpenSSH_10.0
☐  old-jump:22                     L1 Exposed      Weak 44        2 high     RSA 2048 host key      2 min ago
   SSH · OpenSSH_8.4p1
```

- The column header *TLS hygiene* becomes **Hygiene**; the band word plus score stays.
- The certificate column is titled **Certificate / key**. For SSH it shows the default host key type, never a
  day count. SSH host keys don't expire.
- A **Service** filter beside the search: *All services* · *TLS* · *SSH*.

### 2.4 SSH endpoint report (`#/endpoints/N`)

Header: breadcrumb *Endpoints / bastion.example.com:22*, title, the subtitle **SSH · OpenSSH_10.0 · scanned 2 min
ago**, and the actions *Scan again*, *Download* (PDF report, CBOM), *More*. The tabs are the same: **Summary,
Configuration, Weaknesses, CBOM, History**.

**Summary.** It keeps the verdict card ("N things to fix", the post-quantum line, the coverage line). Three tiles:

| Tile | Shows |
|---|---|
| Post-quantum readiness | Level, label, bar (as TLS) |
| SSH hygiene | Score, band |
| Host key | `Ed25519` · `SHA256:AbC…` (shortened, full value on hover and in Configuration); "post-quantum" or "classical" |

Then *Action items* (same component) and *What was evaluated*. Each area is one line with its status chip,
expandable:

| Area | One-line verdict example |
|---|---|
| SSH version & software | "SSH-2.0, OpenSSH_10.0. SSH-1 is not offered." |
| Key exchange & post-quantum | "A current client gets mlkem768x25519-sha256 (post-quantum hybrid). 2 SHA-1 methods offered." |
| Host keys | "3 host keys: Ed25519, ECDSA P-256, RSA 3072. Signatures verified." |
| Encryption ciphers | "4 ciphers, all AEAD or CTR. No CBC." |
| Integrity (MACs) | "SHA-2 MACs with encrypt-then-MAC. hmac-sha1 still offered." |
| Vulnerabilities | "Terrapin: not exposed (strict key exchange is on)." |

**Configuration.** One card per category, each a table:

```
Key exchange                                             What a current client uses: mlkem768x25519-sha256
 Method                          Status                           Kind
 mlkem768x25519-sha256           ✓ Offered · post-quantum hybrid   ML-KEM-768 + X25519   ● Used by OpenSSH 10.6
 sntrup761x25519-sha512          ✓ Offered · post-quantum hybrid   NTRU Prime + X25519
 curve25519-sha256               ✓ Offered · fine                  X25519
 diffie-hellman-group14-sha1     ✖ Offered · should be off         2048-bit MODP, SHA-1
 kex-strict-s-v00@openssh.com    ✓ Strict key exchange on           (protects against Terrapin)
```

- **Host keys**: one row per key. Type, size or curve, fingerprint (monospace, copyable), the algorithms it
  answers, and "Signature verified" or the reason not. A certificate host key adds its CA, principals and
  validity.
- **Encryption ciphers** and **Integrity (MACs)**: same table form. Client-to-server and server-to-client are shown
  once when they're equal (almost always). When they differ, there are two columns.
- **Compression**: one line.

The status word follows the 2026-10-04 rule: what happened, then whether that's right. *Offered · should be off*,
*Offered · fine*, *Not offered · good*, and never a tick next to a weak algorithm.

**Weaknesses.** Same component as TLS: every check found, passed or not run, with filter and evidence.

**CBOM.** Same table: protocol `ssh`, algorithms, host keys. *Download CBOM*.

**History.** Same timeline. Changes read "Key exchange: mlkem768x25519-sha256 added", "Host key changed
(Ed25519 SHA256:… → SHA256:…)".

### 2.5 TLS report: signature schemes (WP-A)

In **Configuration**, inside *Key exchange & post-quantum*, a new sub-table under the groups:

```
Signature schemes the server can authenticate with (TLS 1.3)
 mldsa65                    ✓ Accepted · post-quantum (ML-DSA-65)
 ecdsa_secp256r1_sha256     ✓ Accepted · fine
 rsa_pss_rsae_sha256        Not accepted
 ...
 Tested by offering one scheme per handshake; the server answered only for keys it holds.
```

- If the control probe failed, it shows the inconclusive callout instead of the table: "This server answers
  whatever scheme is offered, so which keys it holds can't be told from a handshake."
- Summary, *Post-quantum* line at L4: "…and the server can authenticate with ML-DSA-65 (post-quantum)."
- Readiness tile at L4: unchanged component, label *PQ-authenticated*.

### 2.6 Findings (`#/findings`), Systems, Reports, Inventory

- **Findings** groups by problem across protocols. *Traffic is exposed to harvest-now-decrypt-later* lists TLS and
  SSH endpoints together, with the service tag on each SSH row. The kind filter keeps its three choices, and SSH
  counts as an endpoint.
- **Systems** ranks SSH endpoints with the rest, no change in the UI.
- **Reports**: an SSH endpoint's PDF is named *SSH security report*.
- **Inventory**: the merged CBOM includes the SSH components. The *Protocols* breakdown shows `SSH 2.0` beside the
  TLS versions.

### 2.7 Help and About

- **Help** gets a section *Scanning SSH servers*: what is sent (identification, the algorithm lists, a key
  exchange per host key type, never a login), how readiness is decided, how to fix the common findings in
  `sshd_config`.
- **About**, under *What it does*, adds "SSH servers: key exchange, host keys, ciphers and MACs, with post-quantum
  readiness."

### 2.8 PDF: SSH security report

The cover and verdict page are the same. The sections follow the areas in §2.4, then *Every check run*. The title
is **SSH security report**.

## 3. Copy rules checked

- No em-dash or en-dash (`TestUICopyRules`).
- No TLS words on an SSH report: `cipher suite`, `certificate chain`, `TLS hygiene`, `handshake` (except in
  "never a login" help text) (`TestSSHReportCopyHasNoTLSWords`).
- Every status names its state *and* the judgement.

## 4. States to design for (and to capture in the walk)

| State | What the user sees |
|---|---|
| SSH scan queued or running | The same progress bar; stages named "Reading the server's identification", "Reading the algorithm lists", "Negotiating as a current client", "Fetching host keys" |
| Not an SSH server on that port | Failed-scan card: "The service did not send an SSH identification line (it sent: `HTTP/1.1 400…`). Check the port, or choose TLS." |
| SSH-1 only | L0, critical finding, the other areas *not applicable* |
| Host keys inconclusive (no common key exchange we implement) | The Host keys area says *Not checked*, with the reason naming the methods |
| Hostile banner (markup, control characters) | Rendered as text, cleaned |
| Phone width (390 px) | Tables scroll inside their card; tiles stack |

## 5. Screen walk (done after the build, recorded in QA-REPORT-008 §screens)

Overview; add dialog (Service select); Endpoints with mixed services and the filter; SSH report: all five tabs
for L3, L1 (legacy), L4 (ML-DSA host key), SSH-1 and a failed scan; TLS report Configuration with signature
schemes (L4 dual-certificate and the inconclusive control); Findings with mixed services; Inventory; Help; and the
PDF. Each at 1440×900 and 860×700, and the report at 390 px.
