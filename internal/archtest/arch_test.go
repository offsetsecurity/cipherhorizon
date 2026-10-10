// Package archtest holds tests of the code base's structure rather than its
// behaviour: which packages may import which. They enforce the rules the host
// discovery design depends on (docs/decisions/ADR-0001, ADR-0004, ADR-0005):
// operating-system code stops at the sensor, and nothing that collects evidence can
// run a subprocess or reach the network.
package archtest

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/offsetsecurity/cipherhorizon"

// importsOf returns every import path used by the non-test Go files under dir
// (recursively), ignoring build tags: a windows-only file still counts.
func importsOf(t *testing.T, dir string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, im := range f.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			out[p] = append(out[p], filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func forbid(t *testing.T, dir string, banned ...string) {
	t.Helper()
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	for imp, files := range importsOf(t, dir) {
		for _, b := range banned {
			if imp == b || strings.HasPrefix(imp, b+"/") {
				t.Errorf("%s must not import %s (used in %s)", dir, imp, strings.Join(files, ", "))
			}
		}
	}
}

// The shared banned sets.
var (
	noProcessOrNetwork = []string{"os/exec", "net", "net/http", "net/rpc", "syscall"}
	noPlatform         = []string{"golang.org/x/sys", "syscall", "unsafe"}
	noCycloneDX        = []string{"github.com/CycloneDX/cyclonedx-go"}
)

// The evidence model, the knowledge tables and the derivation rules know nothing
// about any operating system and nothing about CycloneDX.
func TestEvidenceKnowledgeAndDeriveArePlatformNeutral(t *testing.T) {
	for _, dir := range []string{"../evidence", "../knowledge", "../derive"} {
		forbid(t, dir, append(append(append([]string{}, noProcessOrNetwork...), noPlatform...), noCycloneDX...)...)
		forbid(t, dir, module+"/internal/cbom", module+"/internal/collector", module+"/internal/sense", module+"/internal/hostinfo", module+"/internal/server")
	}
}

// Sensors observe the host and return evidence. They do not run subprocesses, touch the
// network, call the operating system directly, build a CBOM, or derive capability.
func TestSensorsOnlyObserve(t *testing.T) {
	forbid(t, "../sense",
		append(append(append([]string{}, noProcessOrNetwork...), noPlatform...), noCycloneDX...)...)
	forbid(t, "../sense", module+"/internal/cbom", module+"/internal/derive", module+"/internal/discover", module+"/internal/collector", module+"/internal/server")
}

// The pipeline orchestrator and the projection never touch the OS themselves.
func TestDiscoverDoesNotTouchTheOSDirectly(t *testing.T) {
	forbid(t, "../discover", append(append(append([]string{}, noProcessOrNetwork...), noPlatform...), noCycloneDX...)...)
}

// The only packages allowed a Windows or unsafe import are the two platform layers:
// hostinfo (who and what this machine is) and winapi (what Windows cryptography says),
// each behind build tags. Neither may run subprocesses or use the network, and winapi
// may import nothing else from this module, so it stays a pure platform layer that
// answers "what does the system say" and knows nothing of evidence or CBOMs.
func TestOnlyPlatformLayersTouchTheOS(t *testing.T) {
	forbid(t, "../hostinfo", "os/exec", "net", "net/http")
	forbid(t, "../winapi", "os/exec", "net", "net/http", "net/rpc", module+"/internal")

	platform := map[string]bool{"hostinfo": true, "winapi": true}
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() || platform[e.Name()] {
			continue
		}
		for imp, files := range importsOf(t, filepath.Join("..", e.Name())) {
			if imp == "golang.org/x/sys/windows" || strings.HasPrefix(imp, "golang.org/x/sys/windows/") || imp == "unsafe" {
				t.Errorf("only internal/hostinfo and internal/winapi may import %s (used in %s)", imp, strings.Join(files, ", "))
			}
		}
	}
}

// No library code runs a subprocess (ADR-0004). The scan and serve paths already
// did not; this keeps it that way for everything under internal/.
func TestNoSubprocessAnywhereInLibraryCode(t *testing.T) {
	forbid(t, "..", "os/exec")
}

// The collector is the program deployed on endpoints, so it must stay small and auditable: no
// web server, no database, no TLS scanner, no HTTP or TLS client. This checks the *linked*
// dependency set of cmd/cipherhorizon-collector, not just its imports.
//
// The network package is the one careful case. Two standard packages import it for
// parsing types only, and nothing in the collector calls it: crypto/x509 (which the
// certificate sensors need to read certificates; ADR-0015) and, on Windows, x/sys/windows
// (for socket type definitions). So `net` may be linked, but ONLY through those named
// importers: any other package importing it, above all any of this module's own, fails.
func TestCollectorLinksNoServerStoreOrScanner(t *testing.T) {
	banned := []string{
		"net/http", "crypto/tls", "database/sql", "modernc.org", "golang.org/x/net",
		module + "/internal/server", module + "/internal/store", module + "/internal/tlsprobe",
		module + "/internal/tlscbom", module + "/internal/eval", module + "/internal/app", module + "/internal/estate",
	}
	// Who may import "net" in the collector's dependency graph, per platform.
	netImporters := map[string]map[string]bool{
		"linux":   {"crypto/x509": true},
		"windows": {"crypto/x509": true, "golang.org/x/sys/windows": true},
	}
	for goos, allowed := range netImporters {
		cmd := exec.Command("go", "list", "-deps", "-json", "./cmd/cipherhorizon-collector")
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v", goos, err)
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		linked := 0
		for dec.More() {
			var pkg struct {
				ImportPath string
				Imports    []string
			}
			if err := dec.Decode(&pkg); err != nil {
				t.Fatalf("go list output (%s): %v", goos, err)
			}
			linked++
			for _, b := range banned {
				if pkg.ImportPath == b || strings.HasPrefix(pkg.ImportPath, b+"/") {
					t.Errorf("the collector (%s) links %s; it must not (see cmd/cipherhorizon-collector)", goos, pkg.ImportPath)
				}
			}
			for _, imp := range pkg.Imports {
				if imp == "net" && !allowed[pkg.ImportPath] {
					t.Errorf("the collector (%s) links net through %s; only %v may import it (ADR-0015)", goos, pkg.ImportPath, keysOf(allowed))
				}
			}
		}
		if linked < 50 {
			t.Errorf("go list (%s) returned only %d packages: the check is not seeing the dependency graph", goos, linked)
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
