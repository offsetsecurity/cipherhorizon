# Installing, running and keeping your data

How to install CipherHorizon on each platform, where it keeps its data, and how to back up, upgrade and
remove it. Downloads are on the [Releases page](https://github.com/offsetsecurity/cipherhorizon/releases);
check them first ([DISTRIBUTION.md](DISTRIBUTION.md#verifying-a-download)).

| Platform | Recommended | Runs as | Data |
|---|---|---|---|
| Debian, Ubuntu | `.deb` package | systemd service, throwaway unprivileged user | `/var/lib/cipherhorizon/` |
| RHEL, Fedora, Rocky, Alma, SUSE | `.rpm` package | systemd service, throwaway unprivileged user | `/var/lib/cipherhorizon/` |
| Windows 10/11, Server 2019+ | zip + `cipherhorizon service install` | Windows service, `LocalService` | `C:\ProgramData\CipherHorizon\` |
| macOS 12+ | tar.gz + launchd agent | your user, at login | `~/Library/Application Support/CipherHorizon/` |
| Any OS with Docker or Podman | container image | non-root (uid 65532), read-only filesystem | the `data` volume |
| Linux with Podman | Quadlet unit | systemd-managed container | the `cipherhorizon-data` volume |
| Just trying it | the binary, `cipherhorizon serve` | you, in a terminal | your per-user folder (below) |

Every option listens on `127.0.0.1:8080` and has sign-in off until you turn it on, so only the machine
itself can reach it. To share it, turn sign-in on and serve HTTPS (or put it behind a TLS proxy): see
[Sharing it](#sharing-it-with-other-machines).

### Choosing the port

8080 is only the default. Pick another port with `--port`, or with `CIPHERHORIZON_PORT` where editing the command
line is awkward (containers, services). A flag wins over the variable. `--addr` sets the interface; it can be a host
alone (`--addr 0.0.0.0 --port 9000`).

| How you run it | Another port |
|---|---|
| In a terminal | `cipherhorizon serve --port 9000` (`--port 0` takes any free port and prints it) |
| Linux package (systemd) | `CIPHERHORIZON_OPTS="--port 9000"` in `/etc/cipherhorizon/env`, then `sudo systemctl restart cipherhorizon` |
| Windows service | `cipherhorizon service install --port 9000` (as administrator) |
| Docker / Podman | `-e CIPHERHORIZON_PORT=9000 -p 127.0.0.1:9000:9000` (the health check follows the variable) |
| Compose | `CIPHERHORIZON_PORT` under `environment`, and both sides of `ports` |
| Quadlet | `Environment=CIPHERHORIZON_PORT=9000` and `PublishPort=127.0.0.1:9000:9000` |

If the port is taken, `serve` says so and suggests the next one, for example
`port 8080 is already in use on 127.0.0.1 … Start on another port with --port 8081`.

## Linux: .deb and .rpm

```sh
# Debian / Ubuntu
sudo apt install ./cipherhorizon_0.1.0_amd64.deb
# RHEL / Fedora / Rocky / Alma
sudo dnf install ./cipherhorizon-0.1.0-1.x86_64.rpm

sudo systemctl enable --now cipherhorizon      # start now and at every boot
```

Then open http://127.0.0.1:8080 (from another machine: `ssh -L 8080:127.0.0.1:8080 server`).

| What | Where |
|---|---|
| program | `/usr/bin/cipherhorizon` |
| service | `/usr/lib/systemd/system/cipherhorizon.service` |
| settings | `/etc/cipherhorizon/env` (mode 0600; kept on upgrade) |
| database | `/var/lib/cipherhorizon/cipherhorizon.db` (really `/var/lib/private/cipherhorizon/`) |
| log | `journalctl -u cipherhorizon` |

Change options in `/etc/cipherhorizon/env`, then `sudo systemctl restart cipherhorizon`:

```sh
CIPHERHORIZON_OPTS="--sign-in on"          # the journal prints a one-time setup code for the administrator
CIPHERHORIZON_TOKEN="…"                     # an automation token for scripts (openssl rand -hex 24)
```

The package installs the service but does not start it: a scanner should run because someone chose to
run it. The service runs as a throwaway user created by systemd (`DynamicUser`). It sees the rest of the
filesystem read-only and holds no capabilities. `systemd-analyze security cipherhorizon` rates it 1.5,
"OK".

Other distributions (Arch, Alpine, …): use the container image, or the tar.gz with
[deploy/cipherhorizon.service](../../deploy/cipherhorizon.service) (its header lists the commands).

## Windows

1. Unzip `cipherhorizon_0.1.0_windows_amd64.zip`.
2. Open **PowerShell as administrator** in that folder and run:

```powershell
.\cipherhorizon.exe service install
```

That copies the program to `C:\Program Files\CipherHorizon\`. (The service account cannot read your
Downloads folder, so it cannot run from there.) It then creates `C:\ProgramData\CipherHorizon\`, readable
only by SYSTEM, Administrators and the service. It registers the **CipherHorizon** service: automatic
start at boot (delayed), the low-privilege `LocalService` account, restart after a failure. Then it
starts the service and checks that it stayed up.

| What | Where |
|---|---|
| program | `C:\Program Files\CipherHorizon\cipherhorizon.exe` |
| database | `C:\ProgramData\CipherHorizon\cipherhorizon.db` |
| log | `C:\ProgramData\CipherHorizon\logs\cipherhorizon.log` (rolls over at 10 MB) |

```powershell
cipherhorizon service status                 # no administrator needed
cipherhorizon service stop | start           # administrator
cipherhorizon service uninstall              # administrator; keeps the database
```

Options for the server go after `install`, for example
`.\cipherhorizon.exe service install --sign-in on`. To change them, uninstall and install again; the
data stays. Without the service, `cipherhorizon.exe serve` runs it in that window until you close it.

## macOS

```sh
tar -xzf cipherhorizon_0.1.0_darwin_arm64.tar.gz      # darwin_amd64 on Intel
sudo install -m 0755 cipherhorizon /usr/local/bin/cipherhorizon
xattr -d com.apple.quarantine /usr/local/bin/cipherhorizon 2>/dev/null   # downloaded with a browser
```

Run it at login with the launchd agent in
[deploy/net.offsetsecurity.cipherhorizon.plist](../../deploy/net.offsetsecurity.cipherhorizon.plist) (its
header lists the commands). The log goes to `~/Library/Logs/CipherHorizon/cipherhorizon.log`.

## Containers: Docker and Podman

```sh
docker run -d --name cipherhorizon --restart unless-stopped \
  -p 127.0.0.1:8080:8080 -v cipherhorizon-data:/data \
  ghcr.io/offsetsecurity/cipherhorizon:0.2.0
```

Or, from a checkout, `docker compose up -d` ([docker-compose.yml](../../docker-compose.yml): read-only
filesystem, no capabilities, bounded memory and processes). `podman` and `podman compose` take the same
commands.

On Linux servers with Podman, run it under systemd with the Quadlet unit
[deploy/cipherhorizon.container](../../deploy/cipherhorizon.container) (its header lists the commands).

**Podman on Windows and macOS: keep the machine rootless** (Podman's default). The containers run inside
a Linux VM. A *rootful* machine publishes ports with firewall rules inside the VM, which the Windows
(WSL) port relay never sees, so `http://127.0.0.1:8080` does not open even though the container is
healthy. Check and fix it like this:

```sh
podman machine inspect --format '{{.Rootful}}'       # must print false
podman machine stop
podman machine set --rootful=false
podman machine start
```

Images and volumes belong to one mode, so pull or build the image again after switching.

## Where the data lives

Everything the server knows is one SQLite file (plus its `-wal` and `-shm` companions):
- every endpoint and machine;
- every scan result and its history;
- uploaded inventories, systems and accounts.

When `--db` is not given, the server looks in this order:

1. the `CIPHERHORIZON_DB` environment variable;
2. `cipherhorizon.db` in the current folder, if one is there (where versions before 0.1.0 put it, so an
   upgrade finds your history);
3. the per-user data folder:
   - Windows: `%LOCALAPPDATA%\CipherHorizon\`
   - macOS: `~/Library/Application Support/CipherHorizon/`
   - Linux: `~/.local/share/cipherhorizon/`

Services and containers always name the file: `/var/lib/cipherhorizon/`, `C:\ProgramData\CipherHorizon\`
or `/data`. The server prints the path it uses when it starts.

**What is kept.**
- **Scans:** the last 200 per endpoint.
- **Uploaded inventories:** the last 50 per machine, at most 256 MB per machine and 8 GB across all
  machines. An upload past the total is refused rather than deleting another machine's history.
- **Accounts, systems and settings:** until you delete them.

The database runs in WAL mode, so a crash or power cut loses at most the scan in progress, never the
file.

## Backup and restore

Back up while it runs (a consistent copy, readable by its owner only):

```sh
cipherhorizon db backup --db /var/lib/cipherhorizon/cipherhorizon.db /root/cipherhorizon-$(date +%F).db
docker exec cipherhorizon /cipherhorizon db backup --db /data/cipherhorizon.db /data/backup.db
```

On Windows (administrator): `cipherhorizon db backup --db C:\ProgramData\CipherHorizon\cipherhorizon.db D:\backup\ch.db`.

To restore:
1. Stop the server.
2. Put the backup in place of `cipherhorizon.db`.
3. Delete the stale `cipherhorizon.db-wal` and `cipherhorizon.db-shm` files next to it.
4. Start the server.

A backup opens like any database (`cipherhorizon serve --db backup.db`), so you can check it first.

## Upgrading

| Installed with | Upgrade by |
|---|---|
| `.deb` / `.rpm` | installing the new package; a running service restarts on the new version |
| Windows service | `service stop`, then copy the new `cipherhorizon.exe` over `C:\Program Files\CipherHorizon\cipherhorizon.exe`, then `service start` |
| container | pulling the new tag, then recreating the container; the volume keeps the data |
| binary | replacing the file |

On start, the server migrates the database forward. Before each migration it saves a consistent copy
next to the file, `cipherhorizon.db.bak-v<schema>-<time>`, and keeps the newest three. 0.x releases do
not promise a downgrade path: to go back, restore that copy (as above) and run the older version.

## Removing it

| Installed with | Remove with | The database |
|---|---|---|
| `.deb` | `sudo apt remove cipherhorizon` (`purge` also removes `/etc/cipherhorizon`) | kept in `/var/lib/private/cipherhorizon/` |
| `.rpm` | `sudo dnf remove cipherhorizon` | kept in `/var/lib/private/cipherhorizon/` |
| Windows service | `cipherhorizon service uninstall` | kept in `C:\ProgramData\CipherHorizon\` |
| container | `docker rm -f cipherhorizon` | kept in the volume until `docker volume rm cipherhorizon-data` |

The scan history is never deleted for you. Delete the folder or volume yourself when you no longer want
it.

## Sharing it with other machines

1. Turn sign-in on, either in Settings or with `--sign-in on`. On the first start the server prints a
   one-time setup code for the administrator.
2. Serve HTTPS, either with `--addr 0.0.0.0:8443 --tls-cert … --tls-key …`, or behind a reverse proxy
   with `--plain-http --trusted-proxy <proxy address>`.
   [deploy/compose-caddy.yml](../../deploy/compose-caddy.yml) does this with automatic certificates.

The server refuses to listen beyond loopback over plain HTTP, or without sign-in, unless you say why
(`--plain-http`, `--open-network`).
