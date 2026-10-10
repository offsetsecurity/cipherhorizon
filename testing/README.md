# Test assets

| Path | What |
|---|---|
| `fixtures/` | synthetic host root filesystems the collectors read (see its README) |
| `golden/` | the committed baseline CBOMs; end-to-end output is compared byte-for-byte and validated against the schema |
| `schema/` | vendored CycloneDX 1.6 JSON schemas, so validation works offline (see its README) |

Regenerate the golden files after an intentional output change, and **read the diff** before committing:

```sh
go test ./internal/app -update
```

Golden output is reproducible because the tests inject the clock, serial number and hostname; the JSON is
LF-terminated on every OS (`.gitattributes`).

## End-to-end in a real browser (`e2e/`)

`e2e/journey.mjs` drives the shipped UI in Chrome/Edge over the DevTools protocol (no dependencies, Node 22+)
through the whole workflow in [PRD-001](../docs/product/PRD-001-posture-workbench.md): add endpoints (single and
bulk), scan, watch progress, cancel, read readiness, change a target and compare history, upload a host CBOM,
hostile-input, dark mode and phone-width layout. It asserts as it goes and saves screenshots and `results.json`.

```sh
go build -o dist/cipherhorizon ./cmd/cipherhorizon && go build -o dist/demo-targets ./cmd/demo-targets
./dist/demo-targets &                                                          # servers of known posture
./dist/cipherhorizon serve --allow-loopback --db e2e.db --addr 127.0.0.1:8090 &    # a FRESH database
node testing/e2e/journey.mjs --base http://127.0.0.1:8090 --out artifacts/screenshots
```

`e2e/security.sh` checks the built binary from outside: refusing a network bind without a token, bearer-token
handling, forged-request protection, the SSRF guard, response headers and DNS-rebinding defence. It needs a
token-less server on `127.0.0.1:8080` for the last group.

Both run in CI (`e2e` job). The journey needs a fresh database and a fresh `demo-targets` process because it
asserts the first-run empty state and the toggle target's starting posture.
