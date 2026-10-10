# Release checklist for 1.0 (PRD-007 REQ-DP-6)

For the owner. Each step names how to check it. The general procedure is in
[RELEASING.md](RELEASING.md); this list is what 1.0 adds on top, in order.

## 1. Decide and rename (blockers B-01, B-02, B-03)

- [ ] Choose the GitHub organisation and repository. Run `scripts/set-owner.sh <owner>` (module path
      `github.com/offsetsecurity/cipherhorizon` in every Go file) and check `go build ./... && go test ./...`.
- [ ] Decide whether the name stays (ADR-0014). If not: [RENAME.md](RENAME.md).
- [ ] Put the security contact in `SECURITY.md` (the placeholder `<maintainer-security-contact ...>`).
- [ ] `grep -rn "example/cipherhorizon\|<owner>\|OWNER/" --include=*.go --include=*.md --include=*.yml .`
      finds nothing that should have changed.

## 2. Rehearse on a fork

- [ ] Push to a fork, enable Actions, tag `v1.0.0-rc.1`.
- [ ] The release workflow finishes and leaves a draft release with:
  - every archive;
  - `checksums.txt` and its `.sigstore.json` bundle;
  - an SBOM per archive;
  - `cipherhorizon-inventory.sh`, `cipherhorizon-inventory.ps1` and `inventory-scripts.sha256`;
  - the multi-arch image in GHCR.
- [ ] Note what failed in [RELEASING.md](RELEASING.md) "If the workflow fails", fix, re-run.

## 3. Verify from a clean machine

On a machine that has never built the project:

- [ ] `cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json --certificate-identity-regexp ... --certificate-oidc-issuer https://token.actions.githubusercontent.com`
- [ ] `sha256sum --check --ignore-missing checksums.txt`
- [ ] `gh attestation verify <archive> --repo <owner>/cipherhorizon` (build provenance)
- [ ] `cosign verify ghcr.io/<owner>/cipherhorizon:1.0.0-rc.1 ...` and `docker run --rm ... version`
- [ ] `./cipherhorizon scripts list` equals `inventory-scripts.sha256`
- [ ] The SBOM opens in a CycloneDX tool and lists the Go modules.

## 4. Run what users will run

- [ ] The README quick start, copied line by line, on Linux, macOS and Windows.
- [ ] `testing/deploy/smoke.sh` against the released image (`SKIP_BUILD=1 IMAGE=ghcr.io/...`).
- [ ] `deploy/compose-caddy.yml` on a host with a real DNS name: HTTPS works, the certificate renews
      (`caddy` log), sign-in from another machine works, the activity log shows real client addresses.
- [ ] `deploy/cipherhorizon.service` on a systemd host: starts, `journalctl` shows the setup code.

## 5. Publish

- [ ] CHANGELOG: move *Unreleased* to `1.0.0` with the date; mention the breaking changes (the
      `tls scan --json` shape, the text output's new order).
- [ ] Tag `v1.0.0` on `main`, let the workflow publish, check the release page.
- [ ] Docs site deployed (GitHub Pages workflow) and its links checked.
- [ ] Launch posts from `docs/launch/posts/` reviewed by Offset and scheduled.
