# CipherHorizon in CI

`cipherhorizon tls scan --fail-on` turns a scan into a pass or fail step: a pipeline can stop a
release when an endpoint loses its post-quantum key exchange, drops below a TLS hygiene score you
choose, or brings back a finding you fixed.

## The command

```sh
cipherhorizon tls scan --fail-on 'level<L3,severity>=high' api.example.com:443 www.example.com
```

It prints the verdict for each target (readiness level, TLS hygiene score, what was checked, what
to do), says on stderr which condition each failing target met, and exits:

| Exit | Meaning |
|---|---|
| 0 | Every target was scanned and none met a condition. |
| 1 | Nothing could be done: bad usage, a bad condition, interrupted. |
| 2 | A result was produced, but a target could not be scanned fully (only without `--fail-on`). |
| 3 | At least one target met a `--fail-on` condition, or could not be scanned at all. |

Quote the conditions: `<` and `>` mean redirection to a shell.

### Conditions

| Condition | Fails when |
|---|---|
| `level<L3` | Post-quantum readiness is below level 3: a current client does not negotiate a hybrid post-quantum key exchange (L1 to L4; `level<3` works too). |
| `score<70` | The TLS hygiene score is below 70 (1 to 100). An endpoint that could not be rated fails. |
| `severity>=high` | Any finding of this severity or worse: `critical`, `high`, `medium`, `low` or `info`. |
| `finding=PROTO.TLS10` | This finding is present. The IDs are listed in [methodology.md](methodology.md). |

Give several conditions with commas or by repeating `--fail-on`; a target fails if it meets any.

### Machine-readable output

`--json` prints one object per target:

```json
[{ "target": "api.example.com:443", "report": { "...": "what was observed" }, "evaluation": { "readiness": { "level": 3 }, "hygiene": { "score": 92 }, "findings": [] } }]
```

`report` is what the scanner saw; `evaluation` is the judgement (readiness, TLS hygiene score,
findings with remediation, every check run). The schema is the same one the server stores.

## GitHub Actions

This job downloads a release, checks its signature, and scans the endpoints a deployment
changed. Replace `OWNER` with the repository that publishes CipherHorizon and pin `VERSION`.

```yaml
name: tls-posture
on:
  workflow_dispatch:
  schedule:
    - cron: "17 6 * * 1"   # every Monday
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    env:
      VERSION: "1.0.0"
      REPO: OWNER/cipherhorizon
    steps:
      - name: Download CipherHorizon and its checksums
        run: |
          base="https://github.com/${REPO}/releases/download/v${VERSION}"
          curl -fsSLO "${base}/cipherhorizon_${VERSION}_linux_amd64.tar.gz"
          curl -fsSLO "${base}/checksums.txt"
          curl -fsSLO "${base}/checksums.txt.sigstore.json"
      - uses: sigstore/cosign-installer@v3
      - name: Verify the signature and the archive
        run: |
          cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
            --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@refs/tags/v" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf "cipherhorizon_${VERSION}_linux_amd64.tar.gz" cipherhorizon
      - name: Scan
        run: |
          ./cipherhorizon tls scan --fail-on 'level<L3,severity>=high' \
            api.example.com:443 www.example.com:443
```

Pin actions to a commit SHA in your own workflows, as this repository does.

Scan only endpoints you own or are authorised to test. A scan makes a few hundred short TLS
handshakes and one HTTP request (`--http-checks=false` turns that off); it contacts nothing but
the target.

## GitLab CI and others

Any runner that can download a file works the same way: fetch the release, verify it, run
`tls scan --fail-on`, and let the exit code fail the job. For results over time (history, trends,
a dashboard), run `cipherhorizon serve` and point the pipeline's scans at it instead.
