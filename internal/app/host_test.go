package app_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/sense/pefiles/pefilestest"
)

// ADR-0009: a run below the highest privilege tier says so, every time, and says that
// full results may need Administrator/root. It is a warning, not an error.
func TestPrivilegeWarning(t *testing.T) {
	code, _, stderr := runTier(t, context.Background(), nil, "user", "run", "--root", fixture("ubuntu-24.04"))
	if code != app.ExitOK {
		t.Errorf("a warning must not change the exit code: %d", code)
	}
	if !strings.Contains(stderr, "warning: Running without elevated privileges") ||
		!strings.Contains(stderr, "Administrator (Windows) or root (Linux) may reveal more") {
		t.Errorf("no privilege warning in stderr:\n%s", stderr)
	}

	code, _, stderr = runTier(t, context.Background(), nil, "admin", "run", "--root", fixture("ubuntu-24.04"))
	if code != app.ExitOK || strings.Contains(stderr, "elevated privileges") {
		t.Errorf("admin run: exit %d, unexpected warning:\n%s", code, stderr)
	}
}

func TestRedactHostFlag(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("var/lib/dpkg/status", "Package: libssl3\nStatus: install ok installed\nVersion: 3.0.13-1\nArchitecture: amd64\n\n")

	// No machine id: refuse rather than emit an unstable label, and write no CBOM.
	code, stdout, stderr := run(t, "run", "--root", dir, "--redact-host")
	if code != app.ExitFatal || !strings.Contains(stderr, "machine id") || strings.Contains(stdout, `"bomFormat"`) {
		t.Errorf("without a machine id: exit %d, stderr %q", code, stderr)
	}

	write("etc/machine-id", "0123456789abcdef0123456789abcdef\n")
	code, stdout, stderr = run(t, "run", "--root", dir, "--redact-host")
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var doc struct {
		Metadata struct {
			Component struct {
				Name string `json:"name"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(doc.Metadata.Component.Name, "host-") || strings.Contains(stdout, "fixture-host") || strings.Contains(stdout, "0123456789abcdef") {
		t.Errorf("host name = %q; the real name or machine id leaked", doc.Metadata.Component.Name)
	}
}

// A Windows-shaped host through the whole CLI: the bundled OpenSSL is found, versioned
// from the file, and credited (mapped, cited) with post-quantum capability; a key file
// beside it is never read.
func TestWindowsHostThroughTheCLI(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, b []byte) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("Program Files/Git/mingw64/bin/libcrypto-3-x64.dll", pefilestest.Build(pefilestest.Opts{}, 3<<16|5, 7<<16, "3.5.7", "The OpenSSL Toolkit"))
	write("Program Files/Git/mingw64/bin/server.key", []byte("-----BEGIN PRIVATE KEY-----"))

	code, stdout, stderr := runOS(t, context.Background(), nil, "windows", "user", "run", "--root", dir)
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	schematest.Validate(t, []byte(stdout))
	for _, want := range []string{`"version": "3.5.7.0"`, "pe-files", "ML-KEM-768", "capable-mapped", "the OpenSSL Toolkit"} {
		if !strings.Contains(strings.ToLower(stdout), strings.ToLower(want)) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(stdout, "PRIVATE KEY") || strings.Contains(stdout, "server.key") {
		t.Error("a key file leaked into the CBOM")
	}
	if !strings.Contains(stderr, "plugin pe-files: ok") || !strings.Contains(stderr, "plugin apt: skipped") {
		t.Errorf("stderr = %s", stderr)
	}
}
