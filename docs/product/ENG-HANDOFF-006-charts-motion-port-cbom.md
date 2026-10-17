# ENG-HANDOFF-006 · Charts, motion, port, CBOM: how to build PRD-009

For [PRD-009](PRD-009-interactive-charts-motion-port-cbom.md). Screens: [UX-DESIGN-008](UX-DESIGN-008-interactive-charts-and-motion.md).
Tests: [QA-PLAN-007](QA-PLAN-007-charts-motion-port-cbom.md). One branch, `feat/interactive-charts`, one PR; four work
packages that touch disjoint files except the CHANGELOG.

## WP-1 · Charts you can act on (web/static/js)

- **`charts.js`**:
  - `markAttrs(href, label)` returns the attributes of an interactive mark: `role=link`, `tabindex=0`,
    `aria-label`, `data-href`, `data-tip`.
  - `wireMarks(root)` is one delegated listener set per page root: pointerover/out, focusin/out, click and keydown
    (Enter, Space). It handles sibling dimming (`.chart-hot` on the chart, `.is-hot` on the mark) and one shared
    tooltip element appended to `body`.
  - `filterChip(label, onClear)`.
  - `setQuery(params)`: `history.replaceState` of the hash query, with no `hashchange` and so no re-route.
- **The inventory dashboard** (`views/inventory.js`):
  - `ring`, `hbar` and `legend` take an optional `href` per segment or item;
  - each card passes its links;
  - **`itemsList`** reads `quantum` and `purpose` and shows chips for them.
- **The server** (`internal/server/inventory.go`): `GET /api/v1/inventory` adds two filters.
  - `quantum=vulnerable|safe|unknown`; `vulnerable=1` stays as an alias.
  - `purpose=<dashboard purpose name>`, using the same `purposeOf(detail)` as the dashboard, so the counts agree by
    construction.
  - Unknown values are a 400.
- **The certificates list** (`views/certificates.js`): reads `expires`, `key` and `origin` from the query (`later` is
  new: more than 90 days). The window values match the dashboard buckets exactly; check `inventory_dashboard.go`'s
  `within30`/`within90`/`later` boundaries and use the same ones.
- **The TLS and SSH lists** (`views/assets.js`): read `level` (0 to 4, `u`) and `exposed=1`; a chip for `level`.
  The control changes call `setQuery`.
- **Findings** (`views/findings.js`): seeds `severity`, `status` and `kind` from the query; changes call
  `setQuery`.
- **The Overview** (`views/overview.js`):
  - `countLevels` turns each level row into links per protocol;
  - the severity chips become links;
  - the exposed notes become links.
  - Nested `<a>` is not allowed: the band's stat is an `<a>`, so the chips inside it are `<span role=link>`
    handled by `wireMarks`, with `stopPropagation`.
- **The history chart** (`charts.js historyChart`): takes `hrefFor(point)`; points become marks; `asset.js` passes
  `#/…/ID?scan=…`.

## WP-2 · Motion (style.css, ui.js, charts.js)

- **CSS** (DESIGN.md §9 table replaced by UX-DESIGN-008 §4):
  - `.enter .ring-seg` animates `stroke-dashoffset` from the segment length to its offset. Because the offset differs
    per segment, the segment carries `--len` and `--off` as CSS custom properties set through CSSOM
    (`style.setProperty`, which the CSP allows), and the keyframe goes `from { stroke-dasharray: 0 var(--C) }`.
    Simpler and equivalent: animate `stroke-dasharray` from `0 C` to `len C-len`, which is a paint property. Keep it
    within the "SVG stroke" exception and say so in DESIGN.md.
  - `.enter .hbar .seg` grows (scaleX, `transform-box: fill-box`, origin left).
  - `.enter .dot` fades in after the line.
  - `.chart-hot .mark:not(.is-hot) { opacity: .35 }`; the tooltip keyframe; `.btn-primary:active`; the `a.stat`,
    `.sumtile`, `.recent-row` and `.rowlink` accent edge (`::before` scaleY); the nav indicator `::before`
    keyframe `grow-y`.
  - Every new keyframe goes into the reduced-motion and print resets (they use `*`, so they are covered; the
    test checks it).
- **`ui.js`**:
  - `countUp` exists but nothing calls it; wire it to the stat figures, the level counts and the sumtiles (key per
    figure);
  - add `crossFade(el, paint)` for filter changes (opacity out, paint, in), used by the lists in place of
    `playEnter(body, 700)`.
- **`TestMotionRulesAreRespected`** (web/design_test.go) parses style.css and checks three things:
  - every `@keyframes` body sets only `opacity`, `transform`, `stroke-dashoffset`, `stroke-dasharray` or
    `background-position` (the existing shimmer);
  - no `transition` lists a layout property;
  - the reduced-motion block exists with `animation: none` and `transition: none` on `*`.

## WP-3 · Port (internal/app)

- **`serve.go`**:
  - `--port` (int, default -1 meaning unset);
  - `resolveListenAddr(addr, port string, addrSet, portSet bool, getenv)` returns the final `host:port` or an error;
  - it is a pure function, table-tested;
  - the defaults come from `CIPHERHORIZON_ADDR`, then `CIPHERHORIZON_PORT`, then `127.0.0.1:8080`.
  - `fl.Visit` tells whether a flag was set.
- **Busy port**: `isAddrInUse(err)`, with `errors.Is(err, syscall.EADDRINUSE)` on Unix and the WSAEADDRINUSE
  (10048) errno on Windows in `serve_windows.go`. The message is
  `port N is already in use on HOST (another CipherHorizon, or another program). Start on another port with --port N+1`.
- **`healthcheck.go`**: the default address comes from the same env resolution.
- **`service_windows.go` `serviceURL`**: understands `--port`.
- **Deploy**:
  - the Dockerfile `ENV CIPHERHORIZON_PORT=8080` and `CMD ["serve","--addr","0.0.0.0",…]`;
  - the healthcheck drops `--addr`;
  - compose, the Quadlet, the systemd unit and env file, and the plist have comments;
  - `testing/deploy/smoke.sh` gets a `PORT` case.

## WP-4 · CBOM completeness (internal/algo, internal/tlscbom, internal/cbom)

- **`algo/catalogue.go`**:
  - `ECDH-P256/P384/P521` (OID 1.3.132.1.12, curve secp256r1/secp384r1/secp521r1);
  - `X448` 1.3.101.111 and `Ed448` 1.3.101.113 (RFC 8410);
  - `ECDSA-SHA256/384/512` (RFC 5758);
  - `RSA-SHA256/384/512` (PKCS#1 v1.5, RFC 8017: 1.2.840.113549.1.1.11/12/13) and `RSASSA-PSS` (.1.1.10);
  - the ChaCha20-Poly1305 OID (RFC 8103).
  - Each gets a provenance comment. `registryFamily` gets the new rows (ECDH, ECDSA, EdDSA, RSASSA-PKCS1,
    RSASSA-PSS) so `TestRegistryMappingIsCompleteAndValid` passes.
- **The PQC rules** (`internal/pqc/rules.go`): confirm that the new entries match.
  - The ECDH OID and the ECDSA arc 1.2.840.10045 match already.
  - The RSA signature OIDs sit under 1.2.840.113549.1.1, which matches the RSA arc rule if it is an arc rule;
    if it is an exact OID, add an arc rule.
  - X448 and Ed448: check the rules for 1.3.101.
- **`tlscbom.go`**:
  - `cipherCatalogueID`: 3DES, RC4 and DES;
  - `groupCatalogueID`: secp*, x448;
  - `sigCatalogueID` / certificate: from `ci.SignatureAlg.OID` via `algo.ByOID`;
  - de-duplicate suite algorithms.
- **`cbom/spec17.go`**: certificates get `serialNumber` and `fingerprint` in 1.7.
  - The `cipherhorizon:cert-serial` property moves into these fields; it stays in 1.6.
  - Check whether cyclonedx-go has the fields; if not, set them in the JSON post-process that already exists for
    1.7.
- Regenerate the goldens (`go test ./internal/app -update` and any tlscbom goldens) and read the diff.

## Order and gates

1. WP-4, then WP-3: Go only, unit tested.
2. WP-1 with WP-2.
3. Rebuild, then the journey with the new `charts-phase.mjs`, then the screen walk (UX-REVIEW-009).
4. Gates: `go test ./...`, golangci-lint with `GOOS=windows` and `GOOS=linux`, govulncheck, journey, security.sh,
   and smoke with the PORT case.
