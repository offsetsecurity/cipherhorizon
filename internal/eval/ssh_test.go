package eval_test

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

func sshScan(t *testing.T, s *testserver.Server) *sshprobe.Report {
	t.Helper()
	rep, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: s.Host, Port: s.Port}, sshprobe.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return rep
}

func sshEval(rep *sshprobe.Report) eval.Evaluation {
	return eval.EvaluateSSH(rep, eval.Input{Now: now})
}

// modernSSH is an OpenSSH 10-like report: hybrid negotiated, Ed25519 and ECDSA keys, AEAD and CTR, ETM MACs.
func modernSSH() *sshprobe.Report {
	return &sshprobe.Report{
		SchemaVersion:  sshprobe.SchemaVersion,
		Identification: &sshprobe.Identification{Raw: "SSH-2.0-OpenSSH_10.0", ProtoVersion: "2.0", Software: "OpenSSH_10.0"},
		Algorithms: &sshprobe.Algorithms{
			Kex:     []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256", "ecdh-sha2-nistp256"},
			HostKey: []string{"ssh-ed25519", "ecdsa-sha2-nistp256"}, StrictKex: true,
			CipherC2S: []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"}, CipherS2C: []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"},
			MACC2S: []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"}, MACS2C: []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"},
			CompressionC2S: []string{"none", "zlib@openssh.com"}, CompressionS2C: []string{"none", "zlib@openssh.com"},
		},
		Negotiated: &sshprobe.Negotiated{Client: sshprobe.CurrentClient, Kex: "mlkem768x25519-sha256", HostKey: "ssh-ed25519", Cipher: "chacha20-poly1305@openssh.com",
			Completed: true, Verified: true, Evidence: sshprobe.EvidenceObserved},
		HostKeys: []sshprobe.HostKey{{Type: "ssh-ed25519", Algorithm: "Ed25519", Bits: 256, Fingerprint: "SHA256:a", Verified: true, ServedBy: []string{"ssh-ed25519"}},
			{Type: "ecdsa-sha2-nistp256", Algorithm: "ECDSA", Bits: 256, Curve: "P-256", Fingerprint: "SHA256:b", Verified: true, ServedBy: []string{"ecdsa-sha2-nistp256"}}},
		Stages: []sshprobe.Stage{{Name: "identification", Outcome: "done"}, {Name: "algorithms", Outcome: "done"}, {Name: "negotiation", Outcome: "done"}, {Name: "host-keys", Outcome: "done"}},
	}
}

// REQ-SHE-2: the SSH readiness rules, level by level.
func TestSSHReadinessLevels(t *testing.T) {
	classical := modernSSH()
	classical.Algorithms.Kex = []string{"curve25519-sha256", "ecdh-sha2-nistp256"}
	classical.Negotiated.Kex = "curve25519-sha256"

	failed := modernSSH()
	failed.Negotiated.Completed, failed.Negotiated.Error = false, "the server disconnected"

	pqKey := modernSSH()
	pqKey.HostKeys = append(pqKey.HostKeys, sshprobe.HostKey{Type: "ssh-mldsa44-ed25519", Algorithm: "ML-DSA-44+Ed25519", PQ: true, Fingerprint: "SHA256:c", Verified: true})

	pqKeyClassicalKex := modernSSH()
	pqKeyClassicalKex.Algorithms.Kex = []string{"curve25519-sha256"}
	pqKeyClassicalKex.Negotiated.Kex = "curve25519-sha256"
	pqKeyClassicalKex.HostKeys = pqKey.HostKeys

	ssh1 := &sshprobe.Report{Identification: &sshprobe.Identification{Raw: "SSH-1.5-x", ProtoVersion: "1.5", SSH1: true, SSH1Only: true}}
	unread := &sshprobe.Report{Identification: &sshprobe.Identification{Raw: "SSH-2.0-x", ProtoVersion: "2.0"}}

	for name, tc := range map[string]struct {
		rep     *sshprobe.Report
		level   int
		exposed bool
	}{
		"classical only":             {classical, eval.LevelExposed, true},
		"hybrid negotiated":          {modernSSH(), eval.LevelHybridNeg, false},
		"hybrid offered, not used":   {failed, eval.LevelHybridAvail, true},
		"hybrid and a PQ host key":   {pqKey, eval.LevelPQAuth, false},
		"PQ host key, classical kex": {pqKeyClassicalKex, eval.LevelExposed, true},
		"SSH-1 only":                 {ssh1, eval.LevelNotReady, true},
		"lists not read":             {unread, eval.LevelUndetermined, false},
	} {
		r := sshEval(tc.rep).Readiness
		if r.Level != tc.level || r.HNDLExposed != tc.exposed {
			t.Errorf("%s: level %d exposed=%v, want %d %v\n%+v", name, r.Level, r.HNDLExposed, tc.level, tc.exposed, r.KeyEstablishment)
		}
	}
}

// REQ-SHE-3 and PD-3: sntrup761 alone counts as post-quantum, with a Low note.
func TestSntrupCountsButIsNoted(t *testing.T) {
	r := modernSSH()
	r.Algorithms.Kex = []string{"sntrup761x25519-sha512", "curve25519-sha256"}
	r.Negotiated = &sshprobe.Negotiated{Client: sshprobe.CurrentClient, Kex: "sntrup761x25519-sha512", HostKey: "ssh-ed25519", Evidence: sshprobe.EvidenceComputed}
	ev := sshEval(r)
	if ev.Readiness.Level != eval.LevelHybridNeg || ev.Readiness.KeyEstablishment.Evidence != eval.Inferred {
		t.Errorf("readiness %+v", ev.Readiness)
	}
	var note *eval.Finding
	for i := range ev.Findings {
		if ev.Findings[i].ID == "SSH.PQ-NOT-FIPS" {
			note = &ev.Findings[i]
		}
	}
	if note == nil || note.Severity != eval.Low {
		t.Fatalf("SSH.PQ-NOT-FIPS missing or not Low: %+v", ev.Findings)
	}
	if ids(ev)["PQC.HNDL-EXPOSED"] {
		t.Error("sntrup761 must count against harvest-now-decrypt-later")
	}
	// With ML-KEM also offered there is nothing to note.
	if ids(sshEval(modernSSH()))["SSH.PQ-NOT-FIPS"] {
		t.Error("SSH.PQ-NOT-FIPS raised although ML-KEM is offered")
	}
}

// REQ-SHE-4: each rule fires on its condition and stays quiet on a modern server.
func TestSSHRules(t *testing.T) {
	if got := ids(sshEval(modernSSH())); len(got) != 1 || !got["PQC.CLASSICAL-AUTH"] {
		t.Errorf("a modern server raised %v; want only PQC.CLASSICAL-AUTH", got)
	}
	cases := map[string]func(r *sshprobe.Report){
		"SSH.PROTOCOL-1":       func(r *sshprobe.Report) { r.Identification.ProtoVersion, r.Identification.SSH1 = "1.99", true },
		"SSH.KEX-WEAK-GROUP":   func(r *sshprobe.Report) { r.Algorithms.Kex = append(r.Algorithms.Kex, "diffie-hellman-group1-sha1") },
		"SSH.KEX-SHA1":         func(r *sshprobe.Report) { r.Algorithms.Kex = append(r.Algorithms.Kex, "diffie-hellman-group14-sha1") },
		"SSH.HOSTKEY-DSA":      func(r *sshprobe.Report) { r.Algorithms.HostKey = append(r.Algorithms.HostKey, "ssh-dss") },
		"SSH.HOSTKEY-RSA-SHA1": func(r *sshprobe.Report) { r.Algorithms.HostKey = append(r.Algorithms.HostKey, "ssh-rsa") },
		"SSH.HOSTKEY-RSA-SMALL": func(r *sshprobe.Report) {
			r.HostKeys = append(r.HostKeys, sshprobe.HostKey{Type: "ssh-rsa", Algorithm: "RSA", Bits: 1024, Fingerprint: "SHA256:r"})
		},
		"SSH.HOSTKEY-BAD-SIGNATURE": func(r *sshprobe.Report) {
			r.HostKeys[0].Verified, r.HostKeys[0].VerifyNote = false, "the signature did not verify"
		},
		"SSH.CIPHER-NONE":        func(r *sshprobe.Report) { r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "none") },
		"SSH.CIPHER-RC4":         func(r *sshprobe.Report) { r.Algorithms.CipherS2C = append(r.Algorithms.CipherS2C, "arcfour256") },
		"SSH.CIPHER-DES":         func(r *sshprobe.Report) { r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "des-cbc") },
		"SSH.CIPHER-64BIT-BLOCK": func(r *sshprobe.Report) { r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "3des-cbc") },
		"SSH.CIPHER-CBC":         func(r *sshprobe.Report) { r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "aes128-cbc") },
		"SSH.MAC-NONE":           func(r *sshprobe.Report) { r.Algorithms.MACC2S = append(r.Algorithms.MACC2S, "none") },
		"SSH.MAC-WEAK":           func(r *sshprobe.Report) { r.Algorithms.MACC2S = append(r.Algorithms.MACC2S, "umac-64@openssh.com") },
		"SSH.MAC-SHA1": func(r *sshprobe.Report) {
			r.Algorithms.MACC2S = append(r.Algorithms.MACC2S, "hmac-sha1-etm@openssh.com")
		},
		"SSH.MAC-NOT-ETM":         func(r *sshprobe.Report) { r.Algorithms.MACC2S = append(r.Algorithms.MACC2S, "hmac-sha2-256") },
		"SSH.COMPRESSION-PREAUTH": func(r *sshprobe.Report) { r.Algorithms.CompressionC2S = append(r.Algorithms.CompressionC2S, "zlib") },
		"SSH.TERRAPIN":            func(r *sshprobe.Report) { r.Algorithms.StrictKex = false },
	}
	for id, mutate := range cases {
		r := modernSSH()
		mutate(r)
		if !ids(sshEval(r))[id] {
			t.Errorf("%s did not fire", id)
		}
	}
	for _, id := range eval.SSHRuleIDs() {
		if _, ok := cases[id]; !ok {
			t.Errorf("rule %s has no case here", id)
		}
	}
	// Severity follows RFC 9142: group14-sha1 is Low (MAY), group-exchange-sha1 Medium (SHOULD NOT).
	r := modernSSH()
	r.Algorithms.Kex = append(r.Algorithms.Kex, "diffie-hellman-group-exchange-sha1")
	for _, f := range sshEval(r).Findings {
		if f.ID == "SSH.KEX-SHA1" && f.Severity != eval.Medium {
			t.Errorf("group-exchange-sha1: %s", f.Severity)
		}
	}
	// Terrapin with CBC + ETM, strict key exchange off, no ChaCha20.
	r = modernSSH()
	r.Algorithms.StrictKex = false
	r.Algorithms.CipherC2S = []string{"aes128-cbc"}
	r.Algorithms.CipherS2C = []string{"aes128-cbc"}
	ev := sshEval(r)
	if !ids(ev)["SSH.TERRAPIN"] {
		t.Error("CBC with ETM and no strict kex must raise Terrapin")
	}
	exposed := false
	for _, a := range ev.Vulnerabilities {
		if a.Name == "Terrapin" && a.Status == "exposed" {
			exposed = true
		}
	}
	if !exposed {
		t.Errorf("vulnerabilities %+v", ev.Vulnerabilities)
	}
}

// REQ-SHE-4 and REQ-SHE-6: every rule is cited, has a pass text, and names the sshd_config line.
func TestEverySSHRuleIsCited(t *testing.T) {
	r := modernSSH()
	r.Identification.ProtoVersion, r.Identification.SSH1 = "1.99", true
	r.Algorithms.Kex = append(r.Algorithms.Kex, "diffie-hellman-group1-sha1")
	r.Algorithms.HostKey = append(r.Algorithms.HostKey, "ssh-dss", "ssh-rsa")
	r.HostKeys = append(r.HostKeys, sshprobe.HostKey{Type: "ssh-rsa", Algorithm: "RSA", Bits: 1024, Fingerprint: "SHA256:r", VerifyNote: "the signature did not verify"})
	r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "none", "arcfour", "des-cbc", "3des-cbc", "aes128-cbc")
	r.Algorithms.MACC2S = append(r.Algorithms.MACC2S, "none", "hmac-md5", "hmac-sha1", "hmac-sha2-256")
	r.Algorithms.CompressionC2S = append(r.Algorithms.CompressionC2S, "zlib")
	r.Algorithms.StrictKex = false
	ev := sshEval(r)
	seen := map[string]bool{}
	for _, f := range ev.Findings {
		seen[f.ID] = true
		if len(f.Citations) == 0 || f.Remediation == "" || f.Detail == "" {
			t.Errorf("%s: citations %d, remediation %q, detail %q", f.ID, len(f.Citations), f.Remediation, f.Detail)
		}
		if strings.HasPrefix(f.ID, "SSH.") && !strings.Contains(f.Remediation, "sshd_config") && !strings.Contains(f.Remediation, "OpenSSH") &&
			!strings.Contains(f.Remediation, "ssh-keygen") && f.Severity != eval.Info {
			t.Errorf("%s: the remediation names no sshd_config directive, command or version: %q", f.ID, f.Remediation)
		}
		if strings.HasPrefix(f.ID, "SSH.") && f.ID != "SSH.PQ-NOT-FIPS" && eval.PassText(f.ID) == "" {
			t.Errorf("%s has no pass text", f.ID)
		}
	}
	for _, id := range eval.SSHRuleIDs() {
		if !seen[id] {
			t.Errorf("%s did not fire on the worst-case report", id)
		}
	}
}

// REQ-SHE-1: the same shape as a TLS evaluation; every section and check accounted for.
func TestSSHEvaluationHasTheSameShape(t *testing.T) {
	ev := sshEval(modernSSH())
	if ev.Protocol != eval.ProtocolSSH || ev.Version != eval.Version {
		t.Errorf("protocol %q version %q", ev.Protocol, ev.Version)
	}
	var secs []string
	for _, s := range ev.Sections {
		secs = append(secs, s.ID)
	}
	if !reflect.DeepEqual(secs, eval.SSHSectionOrder) {
		t.Errorf("sections %v", secs)
	}
	for _, c := range ev.Checks {
		if !contains(eval.SSHSectionOrder, c.Section) {
			t.Errorf("check %s in section %q", c.ID, c.Section)
		}
	}
	if ev.Hygiene.Score != 100 || ev.Hygiene.Band != "Strong" || !strings.HasPrefix(ev.Hygiene.Methodology, "SSH hygiene") {
		t.Errorf("hygiene %+v", ev.Hygiene)
	}
	if ev.Counts == nil || ev.FixFirst == nil || ev.Vulnerabilities == nil {
		t.Error("an empty shape field")
	}
}

// REQ-SHE-5: the same arithmetic as TLS: deductions, ceilings, bands.
func TestSSHHygieneUsesTheSameArithmetic(t *testing.T) {
	r := modernSSH()
	r.Algorithms.HostKey = append(r.Algorithms.HostKey, "ssh-rsa") // medium: -10
	r.Algorithms.CipherC2S = append(r.Algorithms.CipherC2S, "aes128-cbc")
	h := sshEval(r).Hygiene
	if h.Score != 86 || h.Band != "Sound" || len(h.Deductions) != 2 {
		t.Errorf("hygiene %+v; want 100 - 10 (ssh-rsa) - 4 (CBC) = 86", h)
	}
	r.Identification.ProtoVersion, r.Identification.SSH1 = "1.99", true
	if h := sshEval(r).Hygiene; h.Score > 29 || h.Ceiling == nil {
		t.Errorf("a critical finding must cap the score at 29: %+v", h)
	}
}

// End to end against an independent server: a legacy configuration raises its findings.
func TestSSHLegacyServerEndToEnd(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1, ssh.KeyExchangeCurve25519},
		Ciphers:      []string{ssh.InsecureCipherAES128CBC, ssh.CipherAES128CTR}, MACs: []string{ssh.HMACSHA1, ssh.HMACSHA256},
		Keys: []string{testserver.KeyRSA}, RSAAlgorithms: []string{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256}})
	ev := sshEval(sshScan(t, srv))
	got := ids(ev)
	for _, want := range []string{"SSH.KEX-SHA1", "SSH.CIPHER-CBC", "SSH.HOSTKEY-RSA-SHA1", "SSH.MAC-SHA1", "SSH.MAC-NOT-ETM", "PQC.HNDL-EXPOSED"} {
		if !got[want] {
			t.Errorf("%s not raised; got %v", want, keys(got))
		}
	}
	if ev.Readiness.Level != eval.LevelExposed {
		t.Errorf("level %d", ev.Readiness.Level)
	}
	if got["SSH.TERRAPIN"] {
		t.Error("x/crypto offers strict key exchange: no Terrapin")
	}
}

// End to end: a hybrid server with an ML-DSA host key is L4.
func TestSSHHybridServerWithMLDSAKeyIsL4(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		Keys: []string{testserver.KeyEd25519, testserver.KeyMLDSA65}})
	ev := sshEval(sshScan(t, srv))
	if ev.Readiness.Level != eval.LevelPQAuth || ev.Readiness.KeyEstablishment.Evidence != eval.Observed {
		t.Errorf("readiness %+v", ev.Readiness)
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// REQ-SHE-7: changes between two SSH scans.
func TestSSHDiff(t *testing.T) {
	from := modernSSH()
	from.Algorithms.Kex = []string{"curve25519-sha256"}
	from.Negotiated.Kex = "curve25519-sha256"
	to := modernSSH()
	to.HostKeys[0].Fingerprint = "SHA256:new"
	to.Algorithms.CipherC2S = append(to.Algorithms.CipherC2S, "aes128-cbc")
	d := eval.CompareSSH(from, to, sshEval(from), sshEval(to))
	want := map[string]eval.Impact{
		"readiness:PQC readiness level":          eval.Better,
		"kex:mlkem768x25519-sha256":              eval.Better,
		"cipher:aes128-cbc":                      eval.Worse,
		"host-key:ssh-ed25519 host key replaced": eval.Neutral,
	}
	got := map[string]eval.Impact{}
	for _, c := range d.Changes {
		got[c.Area+":"+c.Subject] = c.Impact
	}
	for k, imp := range want {
		if got[k] != imp {
			t.Errorf("%s: %q, want %q (all: %v)", k, got[k], imp, got)
		}
	}
	if d.Better == 0 || d.Worse == 0 {
		t.Errorf("summary %q", d.Summary)
	}
}
