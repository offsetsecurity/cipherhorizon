package app_test

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
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
	code, stdout, stderr := run(t, "tls", "scan", "--concurrency", "8", "--details", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	t.Logf("\n%s", stdout) // review the real report with -v
	for _, want := range []string{
		"TLS scan of 127.0.0.1", "Protocols", "TLSv1.3", "YES", "Cipher suites", "TLS_AES_128_GCM_SHA256",
		"Key-exchange groups", "X25519MLKEM768", "POST-QUANTUM HYBRID", "Certificates", "ECDSA", "P-256",
		"judged in evaluation", "Negotiated by a current client", "(post-quantum)",
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
	var results []struct {
		Target string
		Report tlsprobe.Report
	}
	if err := json.Unmarshal([]byte(stdout), &results); err != nil {
		t.Fatalf("stdout is not a JSON array of results: %v\n%s", err, stdout)
	}
	if len(results) != 1 || results[0].Report.SchemaVersion != tlsprobe.SchemaVersion || len(results[0].Report.Suites) == 0 {
		t.Fatalf("results = %+v", results)
	}
	if len(results[0].Report.Certificates) != 0 {
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
	var results []struct{ Report *tlsprobe.Report }
	if err := json.Unmarshal([]byte(stdout), &results); err != nil || len(results) != 2 {
		t.Fatalf("want a result for each target even if one failed: err=%v n=%d", err, len(results))
	}
	if !strings.Contains(stderr, "no response") {
		t.Errorf("stderr should say why the dead target failed:\n%s", stderr)
	}
}

func TestTLSScanCBOM(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--cbom", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	schematest.Validate(t, []byte(stdout))

	var bom struct {
		Metadata struct {
			Component struct{ Name, Type string }
			Tools     struct {
				Components []struct{ Name, Version string }
			}
			Timestamp string
		}
		Components []struct {
			BOMRef           string `json:"bom-ref"`
			Name             string
			CryptoProperties struct {
				AssetType          string `json:"assetType"`
				ProtocolProperties struct {
					Type         string
					Version      string
					CipherSuites []struct {
						Name       string
						Algorithms []string
					} `json:"cipherSuites"`
				} `json:"protocolProperties"`
				AlgorithmProperties struct {
					Primitive string
				} `json:"algorithmProperties"`
			} `json:"cryptoProperties"`
			Properties []struct{ Name, Value string }
		}
	}
	if err := json.Unmarshal([]byte(stdout), &bom); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if bom.Metadata.Component.Type != "device" || !strings.Contains(bom.Metadata.Component.Name, ":") {
		t.Errorf("metadata.component = %+v", bom.Metadata.Component)
	}
	if len(bom.Metadata.Tools.Components) != 1 || bom.Metadata.Tools.Components[0].Name != "cipherhorizon" {
		t.Errorf("metadata.tools = %+v", bom.Metadata.Tools)
	}

	var sawTLS13Protocol, sawHybridGroup, sawPQCVerdict bool
	for _, c := range bom.Components {
		if c.CryptoProperties.AssetType == "protocol" && c.CryptoProperties.ProtocolProperties.Version == "1.3" {
			sawTLS13Protocol = true
			if len(c.CryptoProperties.ProtocolProperties.CipherSuites) == 0 {
				t.Error("TLS 1.3 protocol component has no cipher suites")
			}
		}
		if c.Name == "X25519MLKEM768" && c.CryptoProperties.AlgorithmProperties.Primitive == "combiner" {
			sawHybridGroup = true
		}
		for _, p := range c.Properties {
			if strings.HasSuffix(p.Name, ":pqc:status") {
				sawPQCVerdict = true
			}
		}
	}
	if !sawTLS13Protocol {
		t.Error("no TLSv1.3 protocol component in the CBOM")
	}
	if !sawHybridGroup {
		t.Error("no X25519MLKEM768 combiner component in the CBOM")
	}
	if !sawPQCVerdict {
		t.Error("no algorithm was PQC-annotated (expected the same annotation a host inventory gets)")
	}
	if !strings.Contains(stderr, "quantum-vulnerable") && !strings.Contains(stderr, "quantum-safe") {
		t.Errorf("the PQC summary should still print to stderr: %s", stderr)
	}
}

func TestTLSScanCBOMRejectsMultipleTargets(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--cbom", "a.example", "b.example")
	if code != app.ExitFatal || stdout != "" {
		t.Errorf("exit %d stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "one target") {
		t.Errorf("stderr should explain why: %s", stderr)
	}
}

func TestTLSScanCBOMAndJSONAreMutuallyExclusive(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--cbom", "--json", "a.example")
	if code != app.ExitFatal || stdout != "" {
		t.Errorf("exit %d stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("stderr should explain why: %s", stderr)
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

func tls12Only(t *testing.T) string {
	t.Helper()
	return testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Cert: testserver.CertECDSA}).Addr
}

// PRD-007 REQ-CL-1: the text output leads with the verdict (readiness, TLS hygiene score, what
// was checked, what to do); the raw probe tables appear only with --details.
func TestTLSScanPrintsTheVerdict(t *testing.T) {
	code, stdout, stderr := run(t, "tls", "scan", "--concurrency", "8", hybridServer(t))
	if code != app.ExitOK {
		t.Fatalf("exit %d\nstderr: %s", code, stderr)
	}
	t.Logf("\n%s", stdout)
	order := []string{"127.0.0.1:", "Post-quantum readiness   L3  Hybrid negotiated", "TLS hygiene score", "/ 100", "Checks", "run,", "What to do, worst first", "HIGH", "Certificate chain is not trusted"}
	at := 0
	for _, want := range order {
		i := strings.Index(stdout[at:], want)
		if i < 0 {
			t.Fatalf("the verdict lacks %q (in order)", want)
		}
		at += i
	}
	for _, raw := range []string{"Cipher suites", "TLS_AES_128_GCM_SHA256", "Key-exchange groups"} {
		if strings.Contains(stdout, raw) {
			t.Errorf("without --details the output holds the raw table %q", raw)
		}
	}
	if !strings.Contains(stderr, "--details") {
		t.Error("stderr does not say how to see the details")
	}
	// The verdict comes first with --details too.
	_, detailed, _ := run(t, "tls", "scan", "--concurrency", "8", "--details", hybridServer(t))
	if v, d := strings.Index(detailed, "Post-quantum readiness"), strings.Index(detailed, "Cipher suites"); v < 0 || d < 0 || v > d {
		t.Errorf("with --details: verdict at %d, details at %d; the verdict must come first", v, d)
	}
}

// REQ-CL-2: --json carries the evaluation beside the report, for each target.
func TestTLSScanJSONHasTheEvaluation(t *testing.T) {
	addr := hybridServer(t)
	code, stdout, stderr := run(t, "tls", "scan", "--json", "--concurrency", "8", addr)
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var results []struct {
		Target     string          `json:"target"`
		Report     tlsprobe.Report `json:"report"`
		Evaluation struct {
			Version   string `json:"version"`
			Readiness struct {
				Level int    `json:"level"`
				Label string `json:"label"`
			} `json:"readiness"`
			Hygiene struct {
				Score int    `json:"score"`
				Band  string `json:"band"`
			} `json:"hygiene"`
			Findings []struct {
				ID, Severity string
			} `json:"findings"`
			Checks []struct{ ID, Result string } `json:"checks"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal([]byte(stdout), &results); err != nil || len(results) != 1 {
		t.Fatalf("not one {target, report, evaluation}: %v\n%s", err, stdout)
	}
	r := results[0]
	if r.Target != addr || len(r.Report.Suites) == 0 || r.Evaluation.Version == "" || r.Evaluation.Readiness.Level != 3 ||
		r.Evaluation.Hygiene.Band == "" || len(r.Evaluation.Checks) == 0 || len(r.Evaluation.Findings) == 0 {
		t.Fatalf("result = %+v", r)
	}
}

// REQ-CL-3: each --fail-on condition, met and not met, against real servers; exit 3 only when met.
func TestFailOnConditions(t *testing.T) {
	hybrid, old := hybridServer(t), tls12Only(t)
	_, out, _ := run(t, "tls", "scan", "--json", "--concurrency", "8", hybrid)
	var res []struct {
		Evaluation struct {
			Hygiene struct{ Score int } `json:"hygiene"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || len(res) != 1 {
		t.Fatalf("baseline: %v", err)
	}
	score := res[0].Evaluation.Hygiene.Score
	dead := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := l.Addr().String()
		_ = l.Close()
		return a
	}()

	for _, c := range []struct {
		name, cond, target string
		want               int
		says               string
	}{
		{"level met", "level<L3", old, app.ExitPolicy, "readiness below L3"},
		{"level not met", "level<L3", hybrid, app.ExitOK, ""},
		{"level as a number", "level<4", hybrid, app.ExitPolicy, "readiness below L4"},
		{"score not met", "score<" + strconv.Itoa(score), hybrid, app.ExitOK, ""},
		{"score met", "score<" + strconv.Itoa(score+1), hybrid, app.ExitPolicy, "hygiene score below"},
		{"severity met", "severity>=high", hybrid, app.ExitPolicy, "CERT.UNTRUSTED"},
		{"severity not met", "severity>=critical", hybrid, app.ExitOK, ""},
		{"finding met", "finding=PROTO.NO-TLS13", old, app.ExitPolicy, "finding PROTO.NO-TLS13"},
		{"finding not met", "finding=proto.no-tls13", hybrid, app.ExitOK, ""},
		{"several, one met", "severity>=critical,level<L3", old, app.ExitPolicy, "readiness below L3"},
		{"a target that cannot be scanned", "level<L1", dead, app.ExitPolicy, "could not be scanned"},
	} {
		code, _, stderr := run(t, "tls", "scan", "--no-certs=false", "--concurrency", "8", "--fail-on", c.cond, c.target)
		if code != c.want {
			t.Errorf("%s (%s): exit %d, want %d\n%s", c.name, c.cond, code, c.want, stderr)
		}
		if c.says != "" && !strings.Contains(stderr, c.says) {
			t.Errorf("%s: stderr does not say %q:\n%s", c.name, c.says, stderr)
		}
	}
	// Two targets, one failing: the step fails and names only that one.
	code, _, stderr := run(t, "tls", "scan", "--concurrency", "8", "--fail-on", "level<L3", hybrid, old)
	if code != app.ExitPolicy || !strings.Contains(stderr, "policy: "+old) || strings.Contains(stderr, "policy: "+hybrid) {
		t.Errorf("two targets: exit %d\n%s", code, stderr)
	}
	for _, bad := range []string{"level<L9", "score<0", "severity>=urgent", "finding=", "grade<A", "level>L2"} {
		if code, _, stderr := run(t, "tls", "scan", "--fail-on", bad, hybrid); code != app.ExitFatal || !strings.Contains(stderr, "--fail-on") {
			t.Errorf("--fail-on %q: exit %d, want 1 with a reason\n%s", bad, code, stderr)
		}
	}
	if code, _, _ := run(t, "tls", "scan", "--cbom", "--fail-on", "level<L3", hybrid); code != app.ExitFatal {
		t.Errorf("--cbom with --fail-on: exit %d, want 1", code)
	}
}

// A target that answers nothing gets no verdict, and the output says so instead of "nothing to fix".
func TestTLSScanSaysWhenATargetCouldNotBeScanned(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := l.Addr().String()
	_ = l.Close()
	code, stdout, _ := run(t, "tls", "scan", dead)
	if code != app.ExitIncomplete || !strings.Contains(stdout, "Could not be scanned") || strings.Contains(stdout, "Nothing to fix") {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
}
