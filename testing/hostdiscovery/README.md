# Host discovery ground truth

`cipherhorizon run` is validated by comparing what it reports with what an **independent oracle** finds on a
known host: `EXPECTED / DETECTED / MISSING / FALSE POSITIVE / EVIDENCE`. The oracle uses a broader, different
net than the collector, so a shared mistake cannot hide.

| Script | Platform | Status |
|---|---|---|
| `compare-windows.ps1` | Windows | **Run** on the development machine as a standard user (results in test-report-level-1 (internal)). Run it again from an *elevated* PowerShell to see what elevation reveals. |
| `compare-hashes.ps1` | Windows | **Run**: SHA-256 of every hashed component against `Get-FileHash` (22 of 22 agree). |
| `compare-cng.ps1` | Windows | **Run**: the native inventory against C# P/Invoke and `certutil -csplist`, with negative controls for the post-quantum probe. |
| `authenticode-probe/` | Windows | An investigation tool, not shipped; results in authenticode-investigation (internal). |
| `lab-debian.sh` | Debian, Ubuntu, Kali (WSL, VM or container) | **Written, not yet run**: no Linux host was available. |

## The inventory scripts (PRD-019)

The scripts handed out on the Inventory page are validated the same way: by running the real engine and reading the
facts file. Done 2026-11-09: `cipherhorizon-inventory.ps1` on Windows 11 as a standard user (42 s, 517 lines, 139
listener records, 0 key-material lines); `cipherhorizon-inventory.sh` on Ubuntu 26.04 (WSL) as root (12 s, 666 lines,
`sshd -T` effective policy, nginx configuration, loaded libraries per listener) and as `nobody` (the same sockets, no
process owners). Trimmed copies shaped on those runs are the fixtures in `internal/machinefacts/interpret_v3_test.go`.
To repeat: `DUMP_SCRIPTS_DIR=<dir> go test ./internal/machinefacts -run TestDumpScripts`, run the dumped script, grep the
facts file for `PRIVATE KEY` (must be 0), upload it.

## Linux via WSL (what has to happen first)

WSL is not installed on the development machine, and installing it enables Windows features, so it needs an
Administrator once:

```powershell
# elevated PowerShell, once, then reboot
wsl --install -d Debian        # or Ubuntu
```

Then, from the repo root:

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -o dist/cipherhorizon-collector-linux ./cmd/cipherhorizon-collector
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
wsl -d Debian -- bash testing/hostdiscovery/lab-debian.sh /mnt/d/code/pqc/dist/cipherhorizon-collector-linux
wsl -d Debian -u root -- bash testing/hostdiscovery/lab-debian.sh /mnt/d/code/pqc/dist/cipherhorizon-collector-linux   # root tier
```

To make the Linux host a *known-crypto* lab (so the oracle has something to find), install a few packages first
inside the distro, for example `sudo apt install openssl gnupg libgnutls30 openssh-client libsodium23`, and
include one older and one newer OpenSSL if you can (Debian 13 ships 3.5, Debian 12 ships 3.0). Kali is
deliberately weakened for legacy TLS (its `openssl.cnf`): a useful *legacy* host, but **not representative** of
Linux; treat a Kali result as "Kali", not "Linux".

A WSL distro shares the Windows kernel's WSL2 VM, not a real machine's boot and `/proc/sys/crypto/fips_enabled`
state, so nothing about FIPS or runtime evidence is validated by it. CI containers have the same limit.

## What "validated" means here

A platform/level is **validated** only when its script has run on a real host of that kind, its output is
recorded, every MISSING entry has been adjudicated (real gap / correct exclusion / listed blind spot), and there
are no false positives. Fixture tests and synthetic PE files show the code does what it was written to do; only
a real host shows the written thing is right.
