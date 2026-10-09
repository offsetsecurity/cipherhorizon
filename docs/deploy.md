# Deploying CipherHorizon

CipherHorizon is one static binary with an embedded web interface and a SQLite database. It runs
on a laptop, as a container, or as a service.

**Sign-in** is off by default, so one person can scan straight away. Turn it on in **Settings** (which
creates the first administrator), or start with `--sign-in on`: the log then prints a one-time setup
code (valid for 24 hours). A server listening beyond loopback must require sign-in, or be started with
`--open-network` to say it is meant to be open.

| You want | Use |
|---|---|
| To try it on your machine | [The binary](#the-binary) or `docker compose up -d` |
| A team server with HTTPS | [Compose with Caddy](#compose-with-caddy-automatic-https) |
| A Linux service without containers | [systemd](#systemd) |
| Windows | [A Windows service](#windows) |
| Scans in CI | [docs/CI.md](CI.md) |

Every option below is exercised by a script: `testing/deploy/smoke.sh` (the container),
`testing/deploy/linux-script.sh` (the inventory script on Debian, RHEL and Alpine), and the unit
test `TestSystemdUnitIsSandboxed`.

## The binary

```sh
cipherhorizon serve                 # http://127.0.0.1:8080, data in ./cipherhorizon.db
```

Open the address and scan. Add
`--allow-loopback` to scan services on the same machine, `--scan-allow 10.0.0.0/8` (repeatable;
networks, addresses or domains) to limit what may be scanned at all.

## Docker or Podman

```sh
docker compose up -d
docker compose logs cipherhorizon    # the start-up log
```

`docker-compose.yml` publishes the port on loopback only and runs the container hardened:
read-only filesystem, no Linux capabilities, no privilege escalation, bounded processes and memory.
The data lives in the `data` volume.

## Compose with Caddy (automatic HTTPS)

```sh
CIPHERHORIZON_HOST=cipherhorizon.example.com docker compose -f deploy/compose-caddy.yml up -d
```

Caddy obtains and renews a certificate for the name and is the only published service. The server
trusts Caddy's network for client addresses (`--trusted-proxy`), so sign-in limits and the
activity log see real clients, and the session cookie becomes `__Host-ch_session`.

To serve HTTPS without a proxy, mount a certificate and run
`serve --addr 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem`. The server then speaks TLS 1.2
(forward-secret AEAD suites only) and TLS 1.3 with the hybrid post-quantum key exchange, sends
HSTS, and passes its own scan.

## systemd

```sh
sudo install -m 0755 cipherhorizon /usr/local/bin/
sudo install -m 0644 deploy/cipherhorizon.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cipherhorizon
sudo journalctl -u cipherhorizon     # the log (and the setup code, with --sign-in on)
```

The unit runs under a dynamic unprivileged user with its own state directory
(`/var/lib/cipherhorizon`, mode 0700), a read-only view of the system, no capabilities and a
system-call filter (`systemd-analyze security` rates it 1.5, "OK"). It listens on loopback; put a
proxy in front or add `--tls-cert/--tls-key` with `systemctl edit cipherhorizon`.

## Windows

Run `cipherhorizon.exe serve` from a folder only administrators can write. To run it as a service,
use a service wrapper you already trust (for example WinSW or NSSM), with:

- the arguments `serve --addr 127.0.0.1:8080 --db C:\ProgramData\CipherHorizon\cipherhorizon.db`;
- a dedicated low-privilege service account;
- `C:\ProgramData\CipherHorizon` readable by that account and Administrators only.

With `--sign-in on`, the setup code appears in the wrapper's log.

## Backups and restore

```sh
cipherhorizon db backup --db /var/lib/cipherhorizon/cipherhorizon.db /backup/ch-$(date +%F).db
docker compose exec cipherhorizon /cipherhorizon db backup --db /data/cipherhorizon.db /data/backup.db
```

A backup is a consistent copy taken while the server runs, readable by its owner only. It holds
password and session hashes: protect it like the database. To restore, stop the server, put the copy
in place of the database file and start it again (`serve --db` also opens a copy directly).

Upgrades migrate the database on start, after keeping a copy next to it; the newest three such
copies are kept.

## Checking the inventory scripts

The scripts a server hands out are plain text. Before running one, compare its SHA-256 with
`cipherhorizon scripts list` from the same version, or with `inventory-scripts.sha256` in the
release (covered by the signed `checksums.txt`).
