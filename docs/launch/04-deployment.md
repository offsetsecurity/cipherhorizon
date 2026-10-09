# 04 · Deployment: how people will run it

2026-10-08.

## What exists today

| Path | State |
|---|---|
| Single static binary (Linux, macOS, Windows; amd64, arm64) | Built by GoReleaser; **never released** |
| Container image (distroless, non-root, pinned) | Dockerfile exists; **never built in CI or pushed**; never run here |
| `docker compose up` | Builds locally; binds to host loopback; documented |
| HTTPS | `--tls-cert/--tls-key`, or a TLS proxy with `--plain-http` |
| Health | `cipherhorizon healthcheck` (image `HEALTHCHECK`) |
| Backups | Pre-migration copies only; no documented backup of a running server |
| Upgrades | Migrations run on start with a backup first |

## What people expect (by audience)

| Audience | Expected path | Gap |
|---|---|---|
| Evaluator | `docker run -p 127.0.0.1:8080:8080 ghcr.io/<org>/cipherhorizon` | No published image |
| Self-hoster | Compose with a reverse proxy (Caddy or Traefik) and automatic HTTPS | No example with a proxy |
| Linux admin | A `.deb`/`.rpm` or a binary with a systemd unit | No package; no unit file |
| Windows admin | A binary, run as a service | No service install instructions |
| Kubernetes platform team | A Helm chart or plain manifests | None |
| Air-gapped | A signed binary and the offline signature DB | Binary is fine; needs the verification steps in the docs |
| Demo | A hosted, read-only instance | None |

## Recommendation (in order)

1. **Publish** signed binaries, SBOMs and a multi-arch image to GHCR (the existing release workflow, run once on a
   fork first; see audit L-05).
2. **Quick start in the README:** one `docker run` line and one binary line, both verified on a clean machine.
3. **Production compose example** with Caddy for automatic HTTPS, the hardening from audit L-13, a volume, and a
   backup command.
4. **systemd unit** and a Windows service note, in `docs/deploy/`.
5. **Kubernetes:** plain manifests first (Deployment, Service, PVC, NetworkPolicy); a Helm chart only if asked.
6. **Backups:** `cipherhorizon db backup FILE` (SQLite online backup, `0600`), with a restore section.
7. **Public demo** behind the scan scope (audit L-01), with demo targets, a viewer account and a nightly reset.

## Validation needed before launch

- Build the image with Podman on this machine. This pulls the pinned `golang` and `distroless` base images.
- Run the compose stack, complete first-run setup and scan a target from inside the container.
- Run the Linux inventory script on Debian, RHEL (UBI) and Alpine containers. This pulls those images. It closes
  the one platform gap from earlier programs.
- Dry-run the release on a fork with a pre-release tag, then verify cosign signatures, SBOMs and provenance.
