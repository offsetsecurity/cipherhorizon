package app_test

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/version"
)

// saveResult writes what "tls scan --json" printed to a file, unchanged.
func saveResult(t *testing.T, stdout string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(name, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// content is a CBOM without the two fields that differ between two documents of one report.
func content(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("not JSON: %v\n%.300s", err, doc)
	}
	delete(m, "serialNumber")
	if md, ok := m["metadata"].(map[string]any); ok {
		delete(md, "timestamp")
	}
	return m
}

// One server is scanned twice, once for JSON and once for the CBOM. The clock is fixed and the
// server answers the same way each time, so the two reports say the same thing.
func TestTLSCBOMFromEqualsScanCBOM(t *testing.T) {
	addr := hybridServer(t)
	code, saved, stderr := run(t, "tls", "scan", "--json", addr)
	if code != app.ExitOK {
		t.Fatalf("scan --json: exit %d\n%s", code, stderr)
	}
	code, want, stderr := run(t, "tls", "scan", "--cbom", addr)
	if code != app.ExitOK {
		t.Fatalf("scan --cbom: exit %d\n%s", code, stderr)
	}

	f := &fakeNet{names: map[string][]net.IP{}}
	code, got, stderr := runNet(t, f, "tls", "cbom", "--from", saveResult(t, saved))
	if code != app.ExitOK {
		t.Fatalf("cbom --from: exit %d\n%s", code, stderr)
	}
	schematest.Validate(t, []byte(got))
	if !reflect.DeepEqual(content(t, got), content(t, want)) {
		t.Errorf("the CBOM from --from differs from the CBOM of scan --cbom: %s", firstDifference(want, got))
	}
	if f.dials.Load() != 0 || f.lookups.Load() != 0 {
		t.Errorf("tls cbom made %d connections and %d lookups, want none", f.dials.Load(), f.lookups.Load())
	}
	if !strings.Contains(stderr, "quantum-vulnerable") && !strings.Contains(stderr, "quantum-safe") {
		t.Errorf("the PQC summary should print to stderr, as scan --cbom prints it: %s", stderr)
	}

	// CycloneDX 1.6 the same way.
	_, want16, _ := run(t, "tls", "scan", "--cbom", "--spec", "1.6", addr)
	code, got16, stderr := run(t, "tls", "cbom", "--spec", "1.6", "--from", saveResult(t, saved))
	if code != app.ExitOK || !strings.Contains(got16, `"specVersion": "1.6"`) {
		t.Fatalf("--spec 1.6: exit %d\n%s", code, stderr)
	}
	schematest.Validate(t, []byte(got16))
	if !reflect.DeepEqual(content(t, got16), content(t, want16)) {
		t.Errorf("--spec 1.6: %s", firstDifference(want16, got16))
	}
}

func TestTLSCBOMFromStdinNamesTheEndpointFromTheReport(t *testing.T) {
	f := &fakeNet{server: hybridServer(t)}
	code, saved, stderr := runNet(t, f, "tls", "scan", "--json", "--connect-to", "8.8.8.8", "www.example:8443")
	if code != app.ExitOK {
		t.Fatalf("scan: exit %d\n%s", code, stderr)
	}
	code, stdout, stderr := runEnv(t, func(e *app.Env) { e.Stdin = strings.NewReader(saved) }, "tls", "cbom", "--from", "-")
	if code != app.ExitOK {
		t.Fatalf("cbom --from -: exit %d\n%s", code, stderr)
	}
	schematest.Validate(t, []byte(stdout))
	var bom struct {
		Metadata struct {
			Component struct{ Name string }
			Tools     struct {
				Components []struct{ Name, Version string }
			}
		}
	}
	if err := json.Unmarshal([]byte(stdout), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Metadata.Component.Name != "www.example:8443" {
		t.Errorf("endpoint = %q, want the report's target, www.example:8443", bom.Metadata.Component.Name)
	}
	if tc := bom.Metadata.Tools.Components; len(tc) != 1 || tc[0].Name != "cipherhorizon" || tc[0].Version != version.Version {
		t.Errorf("tool = %+v, want cipherhorizon %s", tc, version.Version)
	}
}

func TestTLSCBOMFromAnIncompleteReport(t *testing.T) {
	// The connection budget runs out, so the report is marked incomplete.
	code, saved, stderr := run(t, "tls", "scan", "--json", "--max-connections", "12", hybridServer(t))
	if code != app.ExitIncomplete || !strings.Contains(saved, `"incomplete": true`) {
		t.Fatalf("scan: exit %d, want an incomplete report\n%s", code, stderr)
	}
	code, stdout, stderr := run(t, "tls", "cbom", "--from", saveResult(t, saved))
	if code != app.ExitIncomplete {
		t.Errorf("exit %d, want %d for an incomplete report\n%s", code, app.ExitIncomplete, stderr)
	}
	schematest.Validate(t, []byte(stdout))
}

func TestTLSCBOMFromInputErrors(t *testing.T) {
	code, good, stderr := run(t, "tls", "scan", "--json", "--no-certs", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("scan: exit %d\n%s", code, stderr)
	}
	var one []map[string]any
	if err := json.Unmarshal([]byte(good), &one); err != nil || len(one) != 1 {
		t.Fatal(err)
	}
	// edit returns the saved result after a change to its one element.
	edit := func(change func(result map[string]any)) string {
		var arr []map[string]any
		_ = json.Unmarshal([]byte(good), &arr)
		change(arr[0])
		b, err := json.Marshal(arr)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	for name, input := range map[string]string{
		"empty file":         "",
		"not JSON":           "TLS scan of example.org\n",
		"cut short":          good[:len(good)/2],
		"text after the end": good + "x",
		"an object":          strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(good), "["), "]"),
		"null":               "null",
		"empty array":        "[]",
		"two results":        "[" + strings.Trim(strings.TrimSpace(good), "[]") + "," + strings.Trim(strings.TrimSpace(good), "[]") + "]",
		"null result":        "[null]",
		"no report":          edit(func(r map[string]any) { delete(r, "report") }),
		"null report":        edit(func(r map[string]any) { r["report"] = nil }),
		"report is a string": edit(func(r map[string]any) { r["report"] = "x" }),
		"older schema":       edit(func(r map[string]any) { r["report"].(map[string]any)["schemaVersion"] = "tls-report/1" }),
		"no schemaVersion":   edit(func(r map[string]any) { delete(r["report"].(map[string]any), "schemaVersion") }),
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, "tls", "cbom", "--from", saveResult(t, input))
			if code != app.ExitFatal || stdout != "" || !strings.HasPrefix(stderr, "cipherhorizon: ") {
				t.Errorf("file: exit %d stdout %.80q stderr %q", code, stdout, stderr)
			}
			code, stdout, _ = runEnv(t, func(e *app.Env) { e.Stdin = bytes.NewBufferString(input) }, "tls", "cbom", "--from", "-")
			if code != app.ExitFatal || stdout != "" {
				t.Errorf("stdin: exit %d stdout %.80q", code, stdout)
			}
		})
	}

	saved := saveResult(t, good)
	for name, args := range map[string][]string{
		"no --from":         {"tls", "cbom"},
		"empty --from":      {"tls", "cbom", "--from", ""},
		"no such file":      {"tls", "cbom", "--from", filepath.Join(t.TempDir(), "absent.json")},
		"a directory":       {"tls", "cbom", "--from", t.TempDir()},
		"an extra argument": {"tls", "cbom", "--from", saved, "example.org"},
		"unknown flag":      {"tls", "cbom", "--from", saved, "--json"},
		"unknown spec":      {"tls", "cbom", "--spec", "9.9", "--from", saved},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := run(t, args...)
			if code != app.ExitFatal || stdout != "" || stderr == "" {
				t.Errorf("exit %d stdout %.80q stderr %q", code, stdout, stderr)
			}
		})
	}
}

// Callers find the command in the help of "tls", so it must be listed there, with --from.
func TestTLSHelpListsCBOM(t *testing.T) {
	const line = "cipherhorizon tls cbom --from FILE"
	code, stdout, _ := run(t, "tls", "-h")
	if code != app.ExitOK || !strings.Contains(stdout, line) {
		t.Errorf("tls -h: exit %d\n%s", code, stdout)
	}
	code, stdout, stderr := run(t, "tls")
	if code != app.ExitFatal || stdout != "" || !strings.Contains(stderr, line) {
		t.Errorf("tls: exit %d stdout %q\n%s", code, stdout, stderr)
	}
	code, _, stderr = run(t, "tls", "cbom", "-h")
	if code != app.ExitOK || !strings.Contains(stderr, "\n  -from FILE\n") || !strings.Contains(stderr, "\n  -spec ") {
		t.Errorf("tls cbom -h: exit %d\n%s", code, stderr)
	}
	if _, stdout, _ = run(t, "help"); !strings.Contains(stdout, line) {
		t.Error("the main help does not list tls cbom --from")
	}
}
