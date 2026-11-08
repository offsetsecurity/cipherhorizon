# Client simulation

A TLS report's **Clients** tab says what each of two dozen named clients would negotiate with the server, or why it
cannot connect. It is the answer to the question operations teams ask before any change: *if we turn off TLS 1.2,
drop RSA, or require a hybrid key exchange, who breaks?* The code is `internal/eval/clients.go`.

## How it works

Nothing is sent. A scan has already enumerated every protocol version, cipher suite and key-exchange group the
server accepts, and found out who decides the order (the server's ranking, or the client's). Each client has a
**profile**: the versions, suites and groups it offers in its own order, how many key shares its first TLS 1.3
flight carries, the signature algorithms it accepts, and its limits (the largest DH prime, the smallest RSA key,
whether it refuses SHA-1 signatures, whether it sends a server name).

For each client, in order:

1. **Version:** the highest the client offers that the server supports. None in common: *cannot connect*.
2. **Certificate:** the server must present a certificate the client can verify: a key type its signature
   algorithms cover, an RSA key of at least its minimum, no SHA-1 signature if it refuses them. A server presenting
   only an ML-DSA certificate fails every classical client.
3. **Suite:** the first suite, in the deciding side's order, that both support and whose key exchange the client can
   complete (a common curve for ECDHE, a DH prime within its limit for DHE, a common group for TLS 1.3).
4. **Group:** for TLS 1.3, the server's favourite among the client's offers when the server ranks groups, else the
   client's first common group, with a *retry* mark when it was not in the client's first key shares (one extra
   round trip); for ECDHE, the first common curve; for DHE, the prime's size.
5. **Properties:** forward secrecy (ECDHE, DHE or TLS 1.3), post-quantum (a standardised hybrid or ML-KEM group),
   and *default certificate* for a client that sends no server name.

The simulation runs on every TLS scan and is stored with its evaluation, so it is recomputed by a re-evaluation
and never needs a new connection.

## The clients

Profiles are the clients' **published defaults** for the named version, transcribed on 2026-11-09 from the vendors'
own sources (the Chromium and Mozilla source trees, Apple's and Oracle's release notes, OpenSSL's and Go's
defaults, Microsoft's Schannel documentation). They are defaults, not a capture of a particular device: an
application can enable or disable versions and suites, and the profile's note says where a default depends on an
update. `GET /api/v1/scans/{id}/evaluation` carries each client's outcome under `clients[]`.

| Client | Family | Versions | Post-quantum group | Notes |
|---|---|---|---|---|
| Chrome 131+, Edge 131+ | browser | 1.3, 1.2 | X25519MLKEM768 | Two key shares (the hybrid and X25519); no DHE suites; refuses SHA-1 |
| Firefox 132+ | browser | 1.3, 1.2 | X25519MLKEM768 | Also offers ffdhe2048 and ffdhe3072 as groups |
| Safari 26 / iOS 26 | browser | 1.3, 1.2 | X25519MLKEM768 | Requires RSA keys of 2048 bits and SHA-2 signatures |
| Safari 17 / iOS 17 | browser | 1.3, 1.2 | none | |
| Safari 12 / iOS 12.1 | legacy | 1.2, 1.1, 1.0 | none | TLS 1.3 arrived in 12.2 |
| Android 14, Android 10 | mobile | 1.3, 1.2 | none | The platform (Conscrypt) stack; apps using their own stack differ |
| Android 7.0 | mobile | 1.2, 1.1, 1.0 | none | |
| Android 4.4 | legacy | 1.0 | none | TLS 1.1 and 1.2 present but not enabled by default before 5.0 |
| Java 21 | runtime | 1.3, 1.2 | none | ChaCha20 suites; ffdhe groups; x25519 and x448 |
| Java 11 | runtime | 1.3, 1.2 | none | No ChaCha20 suites (JDK 12) |
| Java 8u261+ | runtime | 1.3, 1.2 | none | TLS 1.3 backported in 8u261; earlier updates stop at 1.2; no x25519 |
| Java 7 | legacy | 1.0 | none | DH primes over 1024 bits refused; TLS 1.2 only when the application enables it |
| Java 6 | legacy | 1.0, SSL 3.0 | none | No elliptic curves, no server name |
| OpenSSL 3.5+ | library | 1.3, 1.2 | X25519MLKEM768, SecP256r1MLKEM768 | The 3.5 default group list |
| OpenSSL 3.0 to 3.4 | library | 1.3, 1.2 | none | curl, Python and most distributions link against it |
| OpenSSL 1.1.1 | library | 1.3, 1.2 | none | Ubuntu 20.04, RHEL 8 |
| OpenSSL 1.0.2 | legacy | 1.2, 1.1, 1.0 | none | RHEL 7; no x25519 |
| Go 1.24+ | library | 1.3, 1.2 | X25519MLKEM768 | This scanner's own certificate client |
| Windows 11 / Server 2022 (Schannel) | runtime | 1.3, 1.2 | none | .NET, PowerShell, IIS clients |
| Windows 10 (Schannel) | runtime | 1.2, 1.1, 1.0 | none | x25519 from version 1903 |
| IE 11 on Windows 7 | legacy | 1.2, 1.1, 1.0 | none | No AES-GCM with ECDHE_RSA |
| IE 8 on Windows XP | legacy | 1.0, SSL 3.0 | none | RSA key exchange, RC4 and 3DES, no server name |

## Reading the result

- A client that **cannot connect** says which step failed: no common version (naming both sides' versions), a
  certificate it cannot verify (and why), no common suite, no common curve or group, or a DH prime over its limit.
- **client order** on a suite means the server follows the client's preference, so the suite shown is the client's
  first common one; the server would give a differently ordered client a different suite.
- **retry** on a TLS 1.3 group means the server chose a group outside the client's first key shares: the handshake
  works but costs a round trip. A server that prefers X25519MLKEM768 while a client shares only X25519 shows it.
- **default certificate** marks a client without a server name; the certificate it gets is named in the note.

## Limits

- Profiles are defaults; an operator who tuned a client's configuration should read their own capture.
- TLS 1.2 signature-algorithm negotiation for the ServerKeyExchange signature is not simulated.
- Session resumption, renegotiation and 0-RTT are not simulated.
- Certificate trust is the client's own store and is not simulated: a client "connects" when the handshake would
  complete; whether its root store trusts the chain is the Certificates section's question.

## Adding or updating a client

A client is a `ClientProfile` in `internal/eval/clients.go`: read the vendor's source or release notes for the
version, transcribe its default lists in order, name the source and the release date, and note anything that
depends on an update. `clients_test.go` checks every name against the IANA registry and pins the outcomes on known
servers.
