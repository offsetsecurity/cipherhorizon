package app_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// REQ-ING-1 (CLI): the command sends a document to a running server, naming the system itself.
func TestImportCommandSendsADocumentAndReportsWhatHappened(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close() //nolint:errcheck // test
	const token = "cli-test-token-0123456789"
	ts := httptest.NewServer(server.New(server.Config{Store: st, Token: token, Version: "test"}).Handler())
	defer ts.Close()

	doc := filepath.Join("..", "..", "testdata", "interop", "cbomlens-like-1.7.json")
	code, out, errOut := run(t, "import", "--server", ts.URL, "--token", token, "--new-system", "edge-proxy", doc)
	if code != 0 || !strings.Contains(out, "imported as CBOM-Lens") || !strings.Contains(out, `"edge-proxy"`) || !strings.Contains(out, "not interpreted: certificate without a SHA-256 hash") {
		t.Fatalf("first import: %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	// The same bytes again change nothing.
	code, out, _ = run(t, "import", "--server", ts.URL, "--token", token, "--system", "1", doc)
	if code != 0 || !strings.Contains(out, "already imported") {
		t.Errorf("second import: %d %s", code, out)
	}
	// A wrong token, a refused document and bad usage are failures with a message, never a stack trace.
	if code, _, errOut := run(t, "import", "--server", ts.URL, "--token", "wrong-token-0123456789", "--new-system", "x", doc); code != 1 || !strings.Contains(errOut, "refused") {
		t.Errorf("wrong token: %d %s", code, errOut)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":"one"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = run(t, "import", "--server", ts.URL, "--token", token, "--new-system", "x", bad)
	if code != 1 || !strings.Contains(errOut, "not valid CycloneDX 1.6") || !strings.Contains(errOut, "/version") {
		t.Errorf("schema refusal: %d %s", code, errOut)
	}
	for _, args := range [][]string{{"import"}, {"import", doc}, {"import", "--system", "1", "--new-system", "x", doc}, {"import", "--new-system", "x", "/no/such/file.json"}} {
		if code, _, _ := run(t, args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
	}
	if code, _, errOut := run(t, "import", "--server", "http://127.0.0.1:1", "--new-system", "x", doc); code != 1 || !strings.Contains(errOut, "cannot reach") {
		t.Errorf("unreachable server: %d %s", code, errOut)
	}
}
