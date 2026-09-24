package hostcmd_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/hostcmd"
	"github.com/example/cipherhorizon/internal/schematest"
)

const fixturesDir = "../../testing/fixtures"

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := hostcmd.Main(context.Background(), args, hostcmd.Env{
		Stdout: &out, Stderr: &errOut, OS: "linux",
		Tier:      func() string { return "user" },
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
		Hostname:  func() (string, error) { return "fixture-host", nil },
	})
	return code, out.String(), errOut.String()
}

// The collector program's whole command line is run, plugins, version and help: nothing else.
func TestCollectorCommandLine(t *testing.T) {
	if code, out, _ := run(t, "version"); code != 0 || !strings.HasPrefix(out, "cipherhorizon-collector ") {
		t.Errorf("version: %d %q", code, out)
	}
	if code, out, _ := run(t, "help"); code != 0 || !strings.Contains(out, "cipherhorizon-collector run") || !strings.Contains(out, "makes no network connection") {
		t.Errorf("help: %d %q", code, out)
	}
	if code, out, _ := run(t, "plugins"); code != 0 || !strings.Contains(out, "apt") || !strings.Contains(out, "pe-files") {
		t.Errorf("plugins: %d %q", code, out)
	}
	if code, _, _ := run(t); code != hostcmd.ExitFatal {
		t.Errorf("no arguments: exit %d, want %d", code, hostcmd.ExitFatal)
	}
	// The full product's commands do not exist here.
	for _, cmd := range []string{"serve", "tls", "scan"} {
		if code, _, stderr := run(t, cmd); code != hostcmd.ExitFatal || !strings.Contains(stderr, "unknown command") {
			t.Errorf("%s: exit %d, stderr %q; the collector must not have this command", cmd, code, stderr)
		}
	}
}

func TestCollectorRunWritesAValidCBOM(t *testing.T) {
	code, stdout, stderr := run(t, "run", "--root", filepath.Join(fixturesDir, "debian-13"))
	if code != hostcmd.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	schematest.Validate(t, []byte(stdout))
	if !strings.Contains(stdout, "ML-KEM-768") {
		t.Error("the Debian 13 fixture's OpenSSL 3.5 was not credited with ML-KEM")
	}
	if !strings.Contains(stderr, "warning: Running without elevated privileges") {
		t.Errorf("no privilege warning:\n%s", stderr)
	}
}

func TestMessagesUseTheCollectorsName(t *testing.T) {
	_, _, stderr := run(t, "run", "--nope")
	_, _, stderr2 := run(t, "run", "extra")
	if !strings.Contains(stderr2, "cipherhorizon-collector:") {
		t.Errorf("error does not name the program: %q (flag error: %q)", stderr2, stderr)
	}
}
