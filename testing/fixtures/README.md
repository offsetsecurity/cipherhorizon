# Fixtures

Each directory is a **synthetic** host root filesystem: just the files the collectors read.
Package names and versions are modeled on Ubuntu 24.04 and Debian 13, but these are hand-written
test inputs, not dumps of real machines.

| Fixture | Exercises |
|---|---|
| `ubuntu-24.04` | classical OpenSSL 3.0.x, GnuPG 2.4 (ECC), inventory-only families (libgcrypt, gnutls, openssh), a removed package, a `-dev` package (must be ignored), `etc/os-release` |
| `debian-13` | OpenSSL 3.5.x (ML-KEM / ML-DSA / SLH-DSA capability), `os-release` found only under `usr/lib` (the fallback path) |

Golden CBOMs for each live in `../golden/`.
