# Writing a sensor

A sensor looks at one kind of thing on a host (a package database, a file tree, later a certificate store) and
reports **what it saw**: nothing more. `internal/sense/debian` (the dpkg database) and `internal/sense/pefiles`
(loose crypto libraries on Windows) are the references. Read
[the evidence model](../artifacts/evidence-model.md) and [ADR-0001](decisions/ADR-0001-evidence-pipeline.md) first:
the rules below follow from them.

## The one rule

**A sensor returns observations and coverage. It never says what software can do, never builds a CBOM, and never
claims a fact is stronger than the method that found it.** Capability is applied afterwards from cited knowledge
(`internal/knowledge`, `internal/derive`); the CBOM is a projection of the result (`internal/cbom`). If you are
tempted to add a `provides` edge in a sensor, you want a knowledge entry instead.

## Steps

1. **Declare your methods** in `internal/evidence/method.go`: an ID (`debian.dpkg.status@1`), the CycloneDX
   evidence *technique* it corresponds to (a closed list), its **quality** (`authoritative`: a complete
   authoritative source was parsed or the system was asked; `parsed`: a file was parsed in a stable format;
   `heuristic`: a name or pattern match; `sampled`: a runtime observation that may miss), the minimum privilege,
   and its *secret proximity* (`adjacent` if it works near key material, which needs extra review and tests).
   Quality is declared once per method, not guessed per fact. There is no numeric confidence.

2. **Implement the three methods** of `sense.Sensor`:
   - `Info()` returns the name (lowercase kebab-case), a version and the methods you use.
   - `Detect` returns `(false, nil)` when your kind of thing is simply absent (the normal case on the wrong OS).
   - `Collect` returns an `evidence.Batch`. Return partial observations *with* an error rather than nothing.

3. **Read the host only through `env.FS`** (an `fs.FS`), never through `os` paths, so a mounted host, a container
   and a test all work. No `os/exec`, no `net`, no `syscall`, no CycloneDX: an architecture test enforces this
   for everything under `internal/sense`. OS-specific calls belong in `internal/hostinfo` behind build tags.

4. **Emit `present` observations with allow-listed attributes.** Each observation has a canonical subject key (a
   purl for a package, `file:<path>` for a file: the same thing seen by two methods must get the same key so the
   graph merges them), a claim (`present` for L1), a method, a source (`file`/`database` plus a host-relative,
   forward-slash path), and the privilege tier you actually ran with (`env.Tier`). Call `evidence.Finish(&o)`
   last; it computes the deterministic ID. Attributes must be on the per-kind allow-list in
   `evidence.AllowedAttrs`: anything else is rejected, because free-form host data is how secrets and hostile
   strings travel.

5. **Redact.** Pass paths through `evidence.RedactPath` so user names never appear (`Users/%USER%/...`).

6. **Bound everything.** Budgets on depth, entries, file size and time. Hitting one is a `Coverage` with
   `Reason: budget` and status `partial`, never a silent truncation. A directory you may not read is counted in
   `Coverage.Denied`; the run then tells the operator that Administrator/root may reveal more (ADR-0009).

7. **Never read what you do not need.** Open only files you have a reason to parse. The pe-files sensor opens
   only files whose *name* matches a recognised crypto library; a test uses a spying filesystem to prove that
   keys, certificates and anything else are never opened. Do the same for yours.

8. **Report what you could not see.** `Coverage.Unseen` names your blind spots ("statically linked crypto",
   "libraries outside the searched locations"). They end up in the CBOM as `cipherhorizon:not-seen`, so silence is
   never read as safety.

9. **Register** in `init` and link it in:

   ```go
   func init() {
       sense.Register("myplugin", func(env sense.Env) (sense.Sensor, error) { return New(env), nil })
   }
   ```

   then add a blank import to `internal/sense/all/all.go`. The registry checks that `Info().Name` equals the
   registered name and that every method is declared.

10. **Test with `fstest.MapFS`**, including the hostile cases: a decoy with the right name and the wrong content,
    a symlink, a denied directory, a budget hit, cancellation, and a determinism check (two runs, identical IDs).
    If your sensor parses a binary format, write a fuzz test and run it (`go test -fuzz`).

## What the pipeline does for you

`discover.Run` validates every observation against the contract (`evidence.Validate`), merges observations of the
same subject, derives capability from knowledge, re-checks the whole graph, and projects it to CycloneDX. A
sensor that breaks the contract fails the run loudly; it is a bug, not a partial result.

## Adding knowledge

Recognising a package or file name (`internal/knowledge`, `Family.Package` / `Family.Files`) needs no citation
and is a heuristic. Crediting a family with *capabilities* needs a citation per claim and, where the standard
gates it, a minimum version; a test fails until every claimed algorithm is in the catalogue
(`internal/algo`) and has a post-quantum verdict (`internal/pqc/rules.go`). Under-claiming is the rule: a
family with no citable mapping is inventoried and nothing more.
