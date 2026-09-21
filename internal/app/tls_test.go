package app_test

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/example/cbom-scan/internal/app"
	"github.com/example/cbom-scan/internal/tlsprobe"
	"github.com/example/cbom-scan/internal/tlsprobe/testserver"
)

func hybridServer(t *testing.T) string {
	t.Helper()
	s := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS12, Cert: testserver.CertECDSA,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	})
	return s.Addr
}

func TestTLSScanTextReport(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--concurrency", "8", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	t.Logf("\n%s", stdout) // review the real report with -v
	for _, want := range []string{
		"TLS scan of 127.0.0.1", "Protocols", "TLSv1.3", "YES", "Cipher suites", "TLS_AES_128_GCM_SHA256",
		"Key-exchange groups", "X25519MLKEM768", "POST-QUANTUM HYBRID", "Certificates", "ECDSA", "P-256",
		"NOT trusted", "Negotiated by a current client", "(post-quantum)",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	// The authorisation notice and progress belong on stderr, never in the report.
	if !strings.Contains(stderr, "authorised") || strings.Contains(stdout, "authorised") {
		t.Errorf("notice placement: stderr=%q", stderr)
	}
}

func TestTLSScanJSON(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--json", "--no-certs", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var reports []tlsprobe.Report
	if err := json.Unmarshal([]byte(stdout), &reports); err != nil {
		t.Fatalf("stdout is not a JSON array of reports: %v\n%s", err, stdout)
	}
	if len(reports) != 1 || reports[0].SchemaVersion != tlsprobe.SchemaVersion || len(reports[0].Suites) == 0 {
		t.Fatalf("reports = %+v", reports)
	}
	if len(reports[0].Certificates) != 0 {
		t.Error("--no-certs ignored")
	}
}

func TestTLSScanSeveralTargetsAndFailures(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "127.0.0.1:" + strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()

	code, stdout, stderr := run(t, "tls", "scan", "--json", "--no-certs", hybridServer(t), dead)
	if code != app.ExitIncomplete {
		t.Errorf("exit %d, want %d when a target cannot be scanned", code, app.ExitIncomplete)
	}
	var reports []tlsprobe.Report
	if err := json.Unmarshal([]byte(stdout), &reports); err != nil || len(reports) != 2 {
		t.Fatalf("want a report for each target even if one failed: err=%v n=%d", err, len(reports))
	}
	if !strings.Contains(stderr, "no response") {
		t.Errorf("stderr should say why the dead target failed:\n%s", stderr)
	}
}

func TestTLSScanUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no subcommand":    {"tls"},
		"wrong subcommand": {"tls", "probe", "x"},
		"no targets":       {"tls", "scan"},
		"bad target":       {"tls", "scan", "host:notaport"},
		"unknown flag":     {"tls", "scan", "--nope", "x"},
	} {
		code, stdout, _ := run(t, args...)
		if code != app.ExitFatal || stdout != "" {
			t.Errorf("%s: exit %d stdout %q", name, code, stdout)
		}
	}
}
