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
	for _, want := range []string{"Post-quantum readiness   L3  Hybrid negotiated", "Baseline                 does not meet CipherHorizon SSH baseline 2026",
		"sshd_config lines that meet the baseline", "    MACs hmac-sha2-256-etm@openssh.com", "Checks", "Key exchange", "mlkem768x25519-sha256",
		"Host key         ssh-ed25519 SHA256:", "verified"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(stdout), "hygiene") || strings.Contains(stdout, "/ 100") {
		t.Error("an SSH verdict shows a score")
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

// REQ-SHB-6: --fail-on baseline exits 3 when a server does not meet it, 0 when it does; a score
// condition is refused for SSH, and the baseline condition for TLS.
func TestSSHFailOnBaseline(t *testing.T) {
	stock := sshServer(t, ssh.KeyExchangeMLKEM768X25519) // x/crypto's default MACs include non-ETM ones
	if code, _, stderr := run(t, "ssh", "scan", "--fail-on", "baseline", stock); code != app.ExitPolicy ||
		!strings.Contains(stderr, "does not meet CipherHorizon SSH baseline 2026") {
		t.Errorf("stock server: exit %d\n%s", code, stderr)
	}
	hardened := sshtest.Start(t, sshtest.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519},
		MACs: []string{ssh.HMACSHA256ETM}, Keys: []string{sshtest.KeyEd25519}}).Addr
	code, stdout, stderr := run(t, "ssh", "scan", "--fail-on", "baseline", hardened)
	if code != app.ExitOK || !strings.Contains(stdout, "Baseline                 meets CipherHorizon SSH baseline 2026") || strings.Contains(stdout, "sshd_config") {
		t.Errorf("hardened server: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if code, _, stderr := run(t, "ssh", "scan", "--fail-on", "score<70", hardened); code != app.ExitFatal || !strings.Contains(stderr, "no score") {
		t.Errorf("score condition for SSH: exit %d %s", code, stderr)
	}
	if code, _, stderr := run(t, "tls", "scan", "--fail-on", "baseline", "127.0.0.1:1"); code != app.ExitFatal || !strings.Contains(stderr, "ssh scan") {
		t.Errorf("baseline condition for TLS: exit %d %s", code, stderr)
	}
	if code, _, stderr := run(t, "ssh", "scan", "--baseline", "nope", hardened); code != app.ExitFatal || !strings.Contains(stderr, "no such baseline") {
		t.Errorf("unknown baseline: exit %d %s", code, stderr)
	}
}

// REQ-SHB-6: ssh baselines lists every baseline with its entries and sources.
func TestSSHBaselinesCommand(t *testing.T) {
	code, stdout, _ := run(t, "ssh", "baselines")
	if code != app.ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"cipherhorizon-ssh-2026  (default)", "CipherHorizon SSH baseline 2026", "mlkem768x25519-sha256",
		"OpenSSH 9.9", "RFC 10042", "Requirements", "Strict key exchange", "RSA host keys of at least 3072 bits"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}
