package reportpdf

import (
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pdf/pdfcheck"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
)

// legacySSHServer offers SHA-1 key exchange, CBC, SHA-1 MACs and a 2048-bit ssh-rsa key.
func legacySSHServer() *sshprobe.Report {
	return &sshprobe.Report{
		SchemaVersion: sshprobe.SchemaVersion, Address: "192.0.2.7:22", Started: now, Connections: 4,
		Identification: &sshprobe.Identification{Raw: "SSH-2.0-OpenSSH_7.4", ProtoVersion: "2.0", Software: "OpenSSH_7.4"},
		Algorithms: &sshprobe.Algorithms{
			Kex: []string{"curve25519-sha256", "diffie-hellman-group14-sha1"}, HostKey: []string{"ssh-rsa", "rsa-sha2-512"},
			CipherC2S: []string{"aes128-ctr", "aes128-cbc"}, CipherS2C: []string{"aes128-ctr", "aes128-cbc"},
			MACC2S: []string{"hmac-sha1", "hmac-sha2-256"}, MACS2C: []string{"hmac-sha1", "hmac-sha2-256"},
			CompressionC2S: []string{"none"}, CompressionS2C: []string{"none"},
		},
		Negotiated: &sshprobe.Negotiated{Client: sshprobe.CurrentClient, Kex: "curve25519-sha256", HostKey: "rsa-sha2-512", Cipher: "aes128-ctr",
			MAC: "hmac-sha2-256", Completed: true, Verified: true, Evidence: sshprobe.EvidenceObserved},
		HostKeys: []sshprobe.HostKey{{Type: "ssh-rsa", Algorithm: "RSA", Bits: 2048, Fingerprint: "SHA256:legacy", Verified: true, ServedBy: []string{"ssh-rsa", "rsa-sha2-512"}}},
	}
}

// REQ-SHO-3, REQ-SHB-8: the SSH PDF has the verdict, the baseline (requirements, changes, the
// sshd_config lines), the algorithms judged against it, and no score anywhere.
func TestSSHPDF(t *testing.T) {
	rep := legacySSHServer()
	ev := eval.EvaluateSSH(rep, eval.Input{Now: now})
	b, err := SSH(SSHInput{Name: "bastion", Address: "bastion.example:22", ScanID: 9, Report: rep, Eval: &ev, Version: "test", Generated: now})
	if err != nil {
		t.Fatal(err)
	}
	info, err := pdfcheck.Check(b)
	if err != nil {
		t.Fatalf("not a well-formed PDF: %v", err)
	}
	for _, want := range []string{"SSH SECURITY REPORT", "PQC READINESS", "BASELINE", "Baseline: CipherHorizon SSH baseline 2026",
		"Does not meet the baseline", "A post-quantum hybrid key exchange is offered", "NOT MET", "sshd_config lines",
		"KexAlgorithms mlkem768x25519-sha256,curve25519-sha256", "SHOULD BE OFF", "ALLOWED", "How the baseline verdict was worked out",
		"ssh-keygen -t rsa -b 3072"} {
		if !strings.Contains(info.Text, want) {
			t.Errorf("SSH PDF lacks %q", want)
		}
	}
	for _, unwanted := range []string{"hygiene", "HYGIENE", "out of 100"} {
		if strings.Contains(info.Text, unwanted) {
			t.Errorf("SSH PDF says %q: SSH servers have no score", unwanted)
		}
	}
	for _, f := range ev.Findings {
		if !strings.Contains(info.Text, f.Title) {
			t.Errorf("finding %s (%q) is missing", f.ID, f.Title)
		}
	}
}
