package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/app"
	"github.com/example/cbom-scan/internal/collector"
	"github.com/example/cbom-scan/internal/collector/collectortest"
	_ "github.com/example/cbom-scan/internal/plugins/all" // registers "apt" in collector.Default
	"github.com/example/cbom-scan/internal/schematest"
)

var update = flag.Bool("update", false, "rewrite the golden CBOMs in testing/golden")

const (
	fixturesDir = "../../testing/fixtures"
	goldenDir   = "../../testing/golden"
)

// run drives the CLI in-process with a fixed clock, serial number and hostname,
// so the CBOM is byte-for-byte reproducible.
func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	return runWith(t, context.Background(), nil, args...)
}

func runWith(t *testing.T, ctx context.Context, reg *collector.Registry, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := app.Main(ctx, args, app.Env{
		Stdout:    &out,
		Stderr:    &errOut,
		Registry:  reg,
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
		Hostname:  func() (string, error) { return "fixture-host", nil },
	})
	return code, out.String(), errOut.String()
}

func fixture(name string) string { return filepath.Join(fixturesDir, name) }

func TestGoldenCBOMs(t *testing.T) {
	for _, name := range []string{"ubuntu-24.04", "debian-13"} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, "run", "--root", fixture(name))
			if code != app.ExitOK {
				t.Fatalf("exit %d\nstderr:\n%s", code, stderr)
			}
			// stdout is the document and nothing else; diagnostics stay on stderr.
			if !json.Valid([]byte(stdout)) {
				t.Fatalf("stdout is not JSON:\n%s", stdout)
			}
			if !strings.Contains(stderr, "plugin apt: ok") || !strings.Contains(stderr, "PQC:") {
				t.Errorf("stderr lacks plugin/PQC report:\n%s", stderr)
			}
			schematest.Validate(t, []byte(stdout))

			golden := filepath.Join(goldenDir, name+".cbom.json")
			if *update {
				if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("updated %s", golden)
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run `go test ./internal/app -update` to create it)", err)
			}
			if stdout != string(want) {
				t.Errorf("output differs from %s; review the diff, then run `go test ./internal/app -update`\n%s",
					golden, firstDifference(string(want), stdout))
			}
			// The committed baseline itself must remain valid CycloneDX 1.6.
			schematest.Validate(t, want)
		})
	}
}

// The two fixtures pin the behaviour that matters most to a reviewer.
func TestGoldenContent(t *testing.T) {
	load := func(name string) []component {
		t.Helper()
		_, stdout, _ := run(t, "run", "--root", fixture(name))
		var doc struct {
			Components []component `json:"components"`
		}
		if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Components
	}
	status := func(cs []component, name string) string {
		for _, c := range cs {
			if c.Name == name && c.Type == "cryptographic-asset" {
				return c.prop("cbom-scan:pqc:status")
			}
		}
		return "<absent>"
	}

	ubuntu := load("ubuntu-24.04")
	for name, want := range map[string]string{
		"RSA": "quantum-vulnerable", "ECDSA": "quantum-vulnerable", "Ed25519": "quantum-vulnerable",
		"AES": "quantum-safe", "SHA-256": "quantum-safe",
		"ML-KEM-768": "<absent>", // OpenSSL 3.0.13 must not be credited with PQC
	} {
		if got := status(ubuntu, name); got != want {
			t.Errorf("ubuntu-24.04: %s = %s, want %s", name, got, want)
		}
	}
	for _, c := range ubuntu {
		switch c.Name {
		case "libssl-dev", "libssl1.1", "bash", "coreutils", "libc6":
			t.Errorf("ubuntu-24.04: %s must not be inventoried", c.Name)
		}
	}

	debian := load("debian-13")
	for name, want := range map[string]string{
		"ML-KEM-768": "quantum-safe", "ML-DSA-65": "quantum-safe", "SLH-DSA-SHA2-128s": "quantum-safe", "RSA": "quantum-vulnerable",
	} {
		if got := status(debian, name); got != want {
			t.Errorf("debian-13: %s = %s, want %s", name, got, want)
		}
	}
	// os-release lives only under usr/lib in this fixture: purls must still be built.
	var sawPurl bool
	for _, c := range debian {
		sawPurl = sawPurl || strings.HasPrefix(c.Purl, "pkg:deb/debian/libssl3t64@3.5.1-1")
	}
	if !sawPurl {
		t.Error("debian-13: no purl built from usr/lib/os-release")
	}
}

type component struct {
	Type, Name, Purl string
	Properties       []struct{ Name, Value string }
}

func (c component) prop(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func (c *component) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Purl       string `json:"purl"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	c.Type, c.Name, c.Purl = raw.Type, raw.Name, raw.Purl
	for _, p := range raw.Properties {
		c.Properties = append(c.Properties, struct{ Name, Value string }{p.Name, p.Value})
	}
	return nil
}

func TestOutputFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "host.cbom.json")

	for i := 0; i < 2; i++ { // second pass overwrites the first
		code, stdout, stderr := run(t, "run", "--root", fixture("ubuntu-24.04"), "-o", out)
		if code != app.ExitOK || stdout != "" {
			t.Fatalf("pass %d: exit %d, stdout %q, stderr %s", i, code, stdout, stderr)
		}
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	schematest.Validate(t, data)

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestPQCCanBeDisabled(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte("pqc:\n  enabled: false\noutput:\n  pretty: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(t, "run", "--config", cfg, "--root", fixture("ubuntu-24.04"))
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout, "cbom-scan:pqc") || strings.Contains(stderr, "PQC:") {
		t.Error("PQC output present although disabled")
	}
	if strings.Contains(stdout, "\n  ") {
		t.Error("output is indented although pretty: false")
	}
	schematest.Validate(t, []byte(stdout))
}

func TestFlagsOverrideConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	// The config points at a root with no dpkg database; the flag must win.
	if err := os.WriteFile(cfg, []byte("host:\n  root: "+filepath.ToSlash(t.TempDir())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := run(t, "run", "--config", cfg, "--root", fixture("ubuntu-24.04"))
	if code != app.ExitOK || !strings.Contains(stderr, "plugin apt: ok") {
		t.Errorf("--root did not override host.root: exit %d\n%s", code, stderr)
	}
}

// A host with no dpkg database is normal for the apt plugin: skipped, not failed,
// and the (empty) CBOM is still valid.
func TestHostWithoutDpkgIsNotAnError(t *testing.T) {
	code, stdout, stderr := run(t, "run", "--root", t.TempDir())
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "plugin apt: skipped") {
		t.Errorf("stderr = %s", stderr)
	}
	schematest.Validate(t, []byte(stdout))
}

// Exit 2 means: a CBOM was written, but it is incomplete.
func TestIncompleteScanExitsTwoButStillWritesTheCBOM(t *testing.T) {
	reg := collector.NewRegistry()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(reg.Register("good", collectortest.Factory(&collectortest.Fake{Info: collectortest.Info("good"),
		CollectFn: func(context.Context) ([]collector.CryptoAsset, error) {
			return []collector.CryptoAsset{{Component: cdx.Component{BOMRef: "g", Name: "g", Type: cdx.ComponentTypeLibrary}}}, nil
		}})))
	must(reg.Register("flaky", collectortest.Factory(&collectortest.Fake{Info: collectortest.Info("flaky"),
		CollectFn: func(context.Context) ([]collector.CryptoAsset, error) {
			return []collector.CryptoAsset{{Component: cdx.Component{BOMRef: "f", Name: "f", Type: cdx.ComponentTypeLibrary}}}, errors.New("read error half way")
		}})))

	code, stdout, stderr := runWith(t, context.Background(), reg, "run")
	if code != app.ExitIncomplete {
		t.Errorf("exit %d, want %d", code, app.ExitIncomplete)
	}
	if !strings.Contains(stderr, "plugin flaky: partial") || !strings.Contains(stderr, "read error half way") {
		t.Errorf("stderr should name the failing plugin:\n%s", stderr)
	}
	schematest.Validate(t, []byte(stdout))
	if !strings.Contains(stdout, `"name": "f"`) || !strings.Contains(stdout, `"name": "g"`) {
		t.Error("partial findings were dropped from the CBOM")
	}
}

func TestInterruptedScanWritesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, stdout, stderr := runWith(t, ctx, nil, "run", "--root", fixture("ubuntu-24.04"))
	if code != app.ExitFatal || stdout != "" || !strings.Contains(stderr, "interrupted") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestFatalErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, args := range map[string][]string{
		"no arguments":           {},
		"unknown command":        {"scan"},
		"unknown flag":           {"run", "--nope"},
		"stray argument":         {"run", "extra"},
		"missing config":         {"run", "--config", filepath.Join(dir, "absent.yaml")},
		"config typo":            {"run", "--config", write("typo.yaml", "plugins:\n  disable: [apt]\n")},
		"unknown plugin":         {"run", "--config", write("unk.yaml", "plugins:\n  enabled: [atp]\n")},
		"output dir missing":     {"run", "--root", fixture("ubuntu-24.04"), "-o", filepath.Join(dir, "no", "such", "dir", "x.json")},
		"unwritable output path": {"run", "--root", fixture("ubuntu-24.04"), "-o", dir}, // a directory
	} {
		code, stdout, stderr := run(t, args...)
		if code != app.ExitFatal {
			t.Errorf("%s: exit %d, want %d (stderr: %s)", name, code, app.ExitFatal, stderr)
		}
		if strings.Contains(stdout, `"bomFormat"`) {
			t.Errorf("%s: a CBOM was written despite the fatal error", name)
		}
	}
}

func TestVersionHelpAndPlugins(t *testing.T) {
	if code, out, _ := run(t, "version"); code != 0 || !strings.HasPrefix(out, "cbom-scan ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := run(t, "help"); code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("help: %d %q", code, out)
	}
	if code, _, errOut := run(t, "run", "-h"); code != 0 {
		t.Errorf("run -h: exit %d\n%s", code, errOut)
	}
	code, out, _ := run(t, "plugins")
	if code != 0 || !strings.Contains(out, "apt") || !strings.Contains(out, "os-package") {
		t.Errorf("plugins: %d\n%s", code, out)
	}
}

// firstDifference locates the first differing line, for readable golden failures.
func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return "line " + itoa(i+1) + ":\n  golden: " + wl + "\n  actual: " + gl
		}
	}
	return "(no line differs)"
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
