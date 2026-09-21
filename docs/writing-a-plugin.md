# Writing a plugin

A plugin is a package under `internal/plugins/<name>` that implements `collector.Collector` and registers
itself. `internal/plugins/apt` is the reference.

1. **Implement the three methods.** Read the host only through the `fs.FS` you were constructed with, never
   via `os` paths, so containerized agents and tests work. `Detect` returns `(false, nil)` when your
   ecosystem is simply absent. Respect `ctx`. Return partial findings *with* an error rather than nothing.

2. **Register in `init`, and link it in.**

   ```go
   func init() {
       collector.Register("myplugin", func(h collector.Host) (collector.Collector, error) {
           return New(h.FS), nil // constructors must be cheap: do I/O in Detect/Collect
       })
   }
   ```

   Then add a blank import to `internal/plugins/all/all.go`. The registry checks that
   `Metadata().Name` equals the registered name.

3. **Build algorithm findings through the catalogue.** `algo.MustGet("RSA").Asset()`, never a hand-written
   component. If the algorithm isn't in `internal/algo/catalogue.go`, add it *with* a primary-source OID
   (or no OID) and add its verdict to `internal/pqc/rules.go` with citations; a test fails until you do.

4. **Separate what you observed from what you inferred.** Emit facts (an installed package, a parsed
   certificate) as components. Emit inferred capability (`provides` edges) only from a cited mapping, gate
   it by version where the source does, and omit it when you cannot establish it.

5. **Give each component a stable `BOMRef`** that is identical across scans of an unchanged host (a Package
   URL is ideal), and record where you found it (`evidence.occurrences[].location`, host-relative).

6. **Test with `fstest.MapFS`**, plus a synthetic root under `testing/fixtures/` and a golden CBOM under
   `testing/golden/` (`go test ./internal/app -update`, then read the diff before committing).
