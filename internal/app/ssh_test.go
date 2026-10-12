package app_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	sshtest "github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

func sshServer(t *testing.T, kex ...string) string {
	t.Helper()
	return sshtest.Start(t, sshtest.Config{KeyExchanges: kex, Keys: []string{sshtest.KeyEd25519}}).Addr
}

// REQ-SHO-4: the verdict first, labelled for SSH; --details adds the lists and keys.
func TestSSHScanPrintsTheVerdict(t *testing.T) {
	code, stdout, stderr := run(t, "ssh", "scan", "--details", sshServer(t, ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519))
	if code != app.ExitOK {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	t.Logf("\n%s", stdout)
	for _, want := range []string{"Post-quantum readiness   L3  Hybrid negotiated", "SSH hygiene score", "Checks", "Key exchange", "mlkem768x25519-sha256",
		"Host key         ssh-ed25519 SHA256:", "verified"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(stdout, "TLS hygiene") {
		t.Error("an SSH verdict says TLS hygiene")
	}
	if !strings.Contains(stderr, "never logs in") {
		t.Errorf("notice: %s", stderr)
	}
}

// REQ-SHO-4: --fail-on uses the same conditions and exit codes as tls scan.
func TestSSHFailOn(t *testing.T) {
	classical := sshServer(t, ssh.KeyExchangeCurve25519)
	if code, _, stderr := run(t, "ssh", "scan", "--fail-on", "level<L3", classical); code != app.ExitPolicy || !strings.Contains(stderr, "policy:") {
		t.Errorf("classical server: exit %d\n%s", code, stderr)
	}
	hybrid := sshServer(t, ssh.KeyExchangeMLKEM768X25519)
	if code, _, stderr := run(t, "ssh", "scan", "--fail-on", "level<L3", hybrid); code != app.ExitOK {
		t.Errorf("hybrid server: exit %d\n%s", code, stderr)
	}
	if code, _, _ := run(t, "ssh", "scan", "--fail-on", "finding=PQC.HNDL-EXPOSED", classical); code != app.ExitPolicy {
		t.Errorf("finding condition: exit %d", code)
	}
}

func TestSSHScanJSONAndCBOM(t *testing.T) {
	addr := sshServer(t, ssh.KeyExchangeMLKEM768X25519)
	code, stdout, stderr := run(t, "ssh", "scan", "--json", addr)
	if code != app.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var res []struct {
		Report struct {
			SchemaVersion string `json:"schemaVersion"`
		} `json:"report"`
		Evaluation struct {
			Protocol string `json:"protocol"`
		} `json:"evaluation"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || len(res) != 1 || res[0].Report.SchemaVersion != "ssh-report/1" || res[0].Evaluation.Protocol != "ssh" {
		t.Fatalf("%v %+v", err, res)
	}
	code, stdout, stderr = run(t, "ssh", "scan", "--cbom", "--spec", "1.6", addr)
	if code != app.ExitOK {
		t.Fatalf("cbom exit %d: %s", code, stderr)
	}
	schematest.Validate(t, []byte(stdout))
	if !strings.Contains(stdout, `"ssh"`) {
		t.Error("CBOM has no ssh protocol")
	}
}
