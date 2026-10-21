package eval_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

// stockOpenSSH10 is what an unconfigured OpenSSH 10.0 sshd offers (sshd_config(5) defaults), with
// the Ed25519, ECDSA and 3072-bit RSA keys a package install generates.
func stockOpenSSH10() *sshprobe.Report {
	r := modernSSH()
	a := r.Algorithms
	a.Kex = []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
		"curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"}
	a.HostKey = []string{"rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"}
	ciphers := []string{"chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr"}
	macs := []string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"}
	a.CipherC2S, a.CipherS2C, a.MACC2S, a.MACS2C = ciphers, ciphers, macs, macs
	r.HostKeys = append(r.HostKeys, sshprobe.HostKey{Type: "ssh-rsa", Algorithm: "RSA", Bits: 3072, Fingerprint: "SHA256:r",
		Verified: true, ServedBy: []string{"rsa-sha2-512", "rsa-sha2-256"}})
	return r
}

// legacySSH is an old server: SHA-1 key exchange, an ssh-rsa-only 2048-bit key, CBC and 3DES,
// SHA-1 and MD5 MACs, compression before authentication, no strict key exchange.
func legacySSH() *sshprobe.Report {
	r := modernSSH()
	r.Algorithms = &sshprobe.Algorithms{
		Kex: []string{"curve25519-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"}, HostKey: []string{"ssh-rsa"},
		CipherC2S: []string{"aes128-cbc", "3des-cbc"}, CipherS2C: []string{"aes128-cbc", "3des-cbc"},
		MACC2S: []string{"hmac-sha1", "hmac-md5"}, MACS2C: []string{"hmac-sha1", "hmac-md5"},
		CompressionC2S: []string{"none", "zlib"}, CompressionS2C: []string{"none", "zlib"},
	}
	r.HostKeys = []sshprobe.HostKey{{Type: "ssh-rsa", Algorithm: "RSA", Bits: 2048, Fingerprint: "SHA256:old", Verified: true, ServedBy: []string{"ssh-rsa"}}}
	return r
}

// REQ-SHB-1: every entry and requirement is cited, names its OpenSSH version, and is a name the
// registry knows with the same kind; no name is listed twice.
func TestEveryBaselineEntryIsCited(t *testing.T) {
	if len(eval.SSHBaselines()) == 0 {
		t.Fatal("no baselines")
	}
	for _, b := range eval.SSHBaselines() {
		if b.ID == "" || b.Title == "" || b.Version == "" {
			t.Errorf("baseline %+v lacks an id, title or version", b)
		}
		for kind, list := range b.Allowed {
			seen := map[string]bool{}
			for _, e := range list {
				if e.Cite.Title == "" || e.Cite.URL == "" || e.Since == "" {
					t.Errorf("%s: %s %s is not cited or has no version", b.ID, kind, e.Name)
				}
				if a, ok := registry.Lookup(kind, e.Name); !ok || a.Kind != kind && kind != registry.KindCompression {
					t.Errorf("%s: %s %s is not a registry name of that kind", b.ID, kind, e.Name)
				}
				if seen[e.Name] {
					t.Errorf("%s: %s %s listed twice", b.ID, kind, e.Name)
				}
				seen[e.Name] = true
			}
		}
		for _, r := range b.Requires {
			if r.Cite.Title == "" || r.Cite.URL == "" || r.Text == "" {
				t.Errorf("%s: requirement %s is not cited", b.ID, r.ID)
			}
			for _, n := range r.AnyOf {
				found := false
				for _, e := range b.Allowed[r.Kind] {
					found = found || e.Name == n
				}
				if !found {
					t.Errorf("%s: requirement %s names %s, which the baseline does not allow", b.ID, r.ID, n)
				}
			}
		}
	}
	if _, ok := eval.SSHBaselineByID(eval.BaselineDefault); !ok {
		t.Errorf("the default baseline %s is missing", eval.BaselineDefault)
	}
}

func baselineOf(t *testing.T, r *sshprobe.Report) *eval.Conformance {
	t.Helper()
	c := sshEval(r).Baseline
	if c == nil {
		t.Fatal("no baseline on an SSH evaluation")
	}
	return c
}

// REQ-SHB-2: a stock OpenSSH 10 server does not meet the 2026 baseline, only because of its MACs;
// the hardened configuration does.
func TestCipherHorizonBaseline2026(t *testing.T) {
	c := baselineOf(t, stockOpenSSH10())
	if !c.Judged || c.Meets || c.Baseline != eval.BaselineDefault {
		t.Fatalf("stock OpenSSH 10: %+v", c)
	}
	var removed []string
	for _, ch := range c.Changes {
		if ch.Action != eval.ChangeRemove || ch.Kind != registry.KindMAC {
			t.Errorf("unexpected change %+v", ch)
		}
		removed = append(removed, ch.Name)
	}
	want := "umac-64-etm@openssh.com hmac-sha1-etm@openssh.com umac-64@openssh.com umac-128@openssh.com hmac-sha2-256 hmac-sha2-512 hmac-sha1"
	if strings.Join(removed, " ") != want {
		t.Errorf("removed %v\nwant %s", removed, want)
	}
	for _, r := range c.Requires {
		if !r.Met {
			t.Errorf("requirement %s not met on stock OpenSSH 10", r.ID)
		}
	}
	if m := baselineOf(t, modernSSH()); !m.Meets || len(m.Changes) != 0 || m.SSHDConfig != "" {
		t.Errorf("hardened server: %+v", m)
	}
}

// REQ-SHB-3: each kind of gap, and the cases that are not judged.
func TestBaselineConformance(t *testing.T) {
	noPQ := modernSSH()
	noPQ.Algorithms.Kex = []string{"curve25519-sha256"}
	noStrict := modernSSH()
	noStrict.Algorithms.StrictKex = false
	smallRSA := modernSSH()
	smallRSA.Algorithms.HostKey = append(smallRSA.Algorithms.HostKey, "rsa-sha2-512")
	smallRSA.HostKeys = append(smallRSA.HostKeys, sshprobe.HostKey{Type: "ssh-rsa", Algorithm: "RSA", Bits: 2048, Fingerprint: "SHA256:s", ServedBy: []string{"rsa-sha2-512"}})
	unknown := modernSSH()
	unknown.Algorithms.Kex = append(unknown.Algorithms.Kex, "gss-gex-sha1-x")

	for name, tc := range map[string]struct {
		rep     *sshprobe.Report
		judged  bool
		action  string
		require string
	}{
		"no post-quantum key exchange":     {noPQ, true, eval.ChangeAdd, eval.ReqPQKex},
		"no strict key exchange":           {noStrict, true, eval.ChangeUpgrade, eval.ReqStrictKex},
		"2048-bit RSA host key":            {smallRSA, true, eval.ChangeReplaceKey, eval.ReqRSASize},
		"a name this program doesn't know": {unknown, true, eval.ChangeRemove, ""},
		"SSH-1 only": {&sshprobe.Report{Identification: &sshprobe.Identification{Raw: "SSH-1.5-x", ProtoVersion: "1.5", SSH1: true, SSH1Only: true}},
			true, eval.ChangeUpgrade, ""},
		"lists not read": {&sshprobe.Report{Identification: &sshprobe.Identification{Raw: "SSH-2.0-x", ProtoVersion: "2.0"}}, false, "", ""},
	} {
		c := baselineOf(t, tc.rep)
		if c.Judged != tc.judged || c.Meets {
			t.Errorf("%s: judged %v meets %v", name, c.Judged, c.Meets)
			continue
		}
		if !tc.judged {
			if c.Reason == "" || len(c.Changes) != 0 {
				t.Errorf("%s: a server not judged needs a reason and no changes: %+v", name, c)
			}
			continue
		}
		if len(c.Changes) != 1 || c.Changes[0].Action != tc.action || c.Changes[0].Text == "" {
			t.Errorf("%s: changes %+v, want one %s", name, c.Changes, tc.action)
		}
		for _, r := range c.Requires {
			if r.Met == (r.ID == tc.require) {
				t.Errorf("%s: requirement %s met=%v", name, r.ID, r.Met)
			}
		}
	}

	// The per-algorithm verdicts agree with the conformance.
	for _, a := range sshEval(legacySSH()).SSHAlgorithms {
		if a.Baseline != eval.BaselineOff && a.Name != "curve25519-sha256" && a.Name != "none" {
			t.Errorf("%s %s is %q against the baseline", a.Kind, a.Name, a.Baseline)
		}
	}
}

// REQ-SHB-4: the generated sshd_config lines, golden.
func TestGeneratedSSHDConfig(t *testing.T) {
	header := "# CipherHorizon SSH baseline 2026 (cipherhorizon-ssh-2026). Put these lines before any other setting of the same keyword:\n" +
		"# sshd uses the first value it reads. Check with sshd -t, then reload sshd.\n"
	for name, tc := range map[string]struct {
		rep  *sshprobe.Report
		want string
	}{
		"stock OpenSSH 10: only the MACs change": {stockOpenSSH10(), header +
			"MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com\n"},
		"legacy server": {legacySSH(), header +
			"# mlkem768x25519-sha256 needs OpenSSH 9.9 or later\n" +
			"KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n" +
			"# rsa-sha2-512 needs OpenSSH 7.2 or later\n" +
			"HostKeyAlgorithms rsa-sha2-512\n" +
			"# chacha20-poly1305@openssh.com needs OpenSSH 6.5 or later\n" +
			"Ciphers chacha20-poly1305@openssh.com\n" +
			"# hmac-sha2-256-etm@openssh.com needs OpenSSH 6.2 or later\n" +
			"MACs hmac-sha2-256-etm@openssh.com\n" +
			"Compression no\n" +
			"# Upgrade to OpenSSH 9.6 or later for strict key exchange.\n" +
			"# Replace the 2048-bit RSA host key with one of at least 3072 bits. Then restart sshd:\n" +
			"#   ssh-keygen -t rsa -b 3072 -f /etc/ssh/ssh_host_rsa_key\n"},
	} {
		if got := baselineOf(t, tc.rep).SSHDConfig; got != tc.want {
			t.Errorf("%s:\n%s\nwant:\n%s", name, got, tc.want)
		}
	}
	// No comment shares a line with a directive: sshd has no trailing comments.
	for _, line := range strings.Split(baselineOf(t, legacySSH()).SSHDConfig, "\n") {
		if !strings.HasPrefix(line, "#") && strings.Contains(line, "#") {
			t.Errorf("trailing comment in %q", line)
		}
	}
}

// REQ-SHE-5: an SSH server has no score: none stored, none ranked, none banded.
func TestSSHHasNoHygieneScore(t *testing.T) {
	for _, r := range []*sshprobe.Report{modernSSH(), legacySSH(), stockOpenSSH10()} {
		h := sshEval(r).Hygiene
		if h.Score != -1 || h.Band != "" || len(h.Deductions) != 0 || strings.Contains(strings.ToLower(h.Methodology), "hygiene") {
			t.Errorf("hygiene %+v", h)
		}
	}
	id, meets, n := eval.SSHBaselineSummary(sshEval(legacySSH()))
	if id != eval.BaselineDefault || meets == nil || *meets || n == 0 {
		t.Errorf("summary %q %v %d", id, meets, n)
	}
	if id, meets, _ := eval.SSHBaselineSummary(eval.Evaluation{}); id != "" || meets != nil {
		t.Error("a TLS evaluation has no baseline summary")
	}
}

// The baseline can be chosen; an unknown id falls back to the default rather than judging nothing.
func TestBaselineChoice(t *testing.T) {
	ev := eval.EvaluateSSH(modernSSH(), eval.Input{Now: now, SSHBaseline: "no-such-baseline"})
	if ev.Baseline == nil || ev.Baseline.Baseline != eval.BaselineDefault {
		t.Errorf("baseline %+v", ev.Baseline)
	}
}

// REQ-SHN-1, REQ-SHB-3 end to end: the demo's hardened configuration, served by an independent
// implementation (x/crypto), meets the baseline; the same server with OpenSSH-style non-ETM MACs does not.
func TestHardenedServerMeetsTheBaseline(t *testing.T) {
	cfg := testserver.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		MACs: []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM}, Keys: []string{testserver.KeyEd25519, testserver.KeyECDSA}}
	c := baselineOf(t, sshScan(t, testserver.Start(t, cfg)))
	if !c.Judged || !c.Meets {
		t.Errorf("hardened server: %+v", c)
	}
	cfg.MACs = append(cfg.MACs, ssh.HMACSHA256)
	c = baselineOf(t, sshScan(t, testserver.Start(t, cfg)))
	if c.Meets || len(c.Changes) != 1 || c.Changes[0].Name != ssh.HMACSHA256 {
		t.Errorf("with a non-ETM MAC: %+v", c)
	}
}

// A section never reads good beside a baseline change: stock OpenSSH 10's MACs are only notes as
// findings, but the integrity area needs attention because the baseline wants them off.
func TestBaselineChangesMarkTheirSection(t *testing.T) {
	st := map[string]string{}
	for _, s := range sshEval(stockOpenSSH10()).Sections {
		st[s.ID] = s.Status
	}
	if st[eval.SecIntegrity] != eval.StatusAttention || st[eval.SecEncryption] != eval.StatusGood {
		t.Errorf("sections %v", st)
	}
	noPQ := modernSSH()
	noPQ.Algorithms.Kex = []string{"curve25519-sha256"}
	for _, s := range sshEval(noPQ).Sections {
		if s.ID == eval.SecKeyExchange && s.Status == eval.StatusGood {
			t.Error("key exchange reads good without the required hybrid")
		}
	}
}

// REQ-SHE-6: every SSH finding says how to fix it in sshd_config terms: the directive to change,
// or, where configuration cannot fix it, the upgrade or the ssh-keygen command.
func TestSSHRemediationNamesTheDirective(t *testing.T) {
	r := legacySSH()
	a := r.Algorithms
	a.Kex = append(a.Kex, "rsa1024-sha1")
	a.HostKey = append(a.HostKey, "ssh-dss")
	a.CipherC2S = append(a.CipherC2S, "none", "arcfour", "des-cbc", "chacha20-poly1305@openssh.com")
	a.MACC2S = append(a.MACC2S, "none", "umac-64@openssh.com")
	a.StrictKex = false
	r.HostKeys[0].Bits = 1024
	r.Identification.SSH1 = true
	directive := regexp.MustCompile(`KexAlgorithms|HostKeyAlgorithms|HostKey |Ciphers|MACs|Compression|[Uu]pgrade|ssh-keygen|-etm@openssh\.com`)
	seen := map[string]bool{}
	for _, f := range sshEval(r).Findings {
		if !strings.HasPrefix(f.ID, "SSH.") || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		if !directive.MatchString(f.Remediation) {
			t.Errorf("%s: remediation names no sshd_config directive or upgrade: %q", f.ID, f.Remediation)
		}
	}
	if len(seen) < 14 {
		t.Errorf("only %d SSH rules fired: %v", len(seen), seen)
	}
}

// QA of PR #24: a requirement with nothing to judge says so. A server with no RSA host key meets the
// RSA size rule, but "met" would claim a check that never ran: it does not apply.
func TestRSASizeRuleWithoutAnRSAKeyDoesNotApply(t *testing.T) {
	for name, tc := range map[string]struct {
		rep *sshprobe.Report
		na  bool
		met bool
	}{
		"no RSA host key":    {modernSSH(), true, true},
		"a 3072-bit RSA key": {stockOpenSSH10(), false, true},
		"a 2048-bit RSA key": {legacySSH(), false, false},
	} {
		ev := eval.EvaluateSSH(tc.rep, eval.Input{Now: now})
		var got *eval.RequireView
		for i, r := range ev.Baseline.Requires {
			if r.ID == eval.ReqRSASize {
				got = &ev.Baseline.Requires[i]
			}
		}
		if got == nil {
			t.Fatalf("%s: no RSA size requirement", name)
		}
		if got.NotApplicable != tc.na || got.Met != tc.met {
			t.Errorf("%s: notApplicable %v met %v, want %v %v (%s)", name, got.NotApplicable, got.Met, tc.na, tc.met, got.Detail)
		}
	}
}

// QA of PR #24: next steps name OpenSSH releases only to an OpenSSH server; any other server is told
// what to offer.
func TestSSHNextStepsNameOpenSSHOnlyForOpenSSH(t *testing.T) {
	noPQ := func(software string) *sshprobe.Report {
		r := modernSSH()
		r.Identification.Software = software
		r.Algorithms.Kex = []string{"curve25519-sha256"}
		r.Negotiated.Kex = "curve25519-sha256"
		return r
	}
	open := eval.EvaluateSSH(noPQ("OpenSSH_9.6"), eval.Input{Now: now})
	if !strings.HasPrefix(open.Readiness.NextSteps[0], "Upgrade to OpenSSH 9.9") {
		t.Errorf("an OpenSSH server is told %q", open.Readiness.NextSteps[0])
	}
	other := eval.EvaluateSSH(noPQ("Go"), eval.Input{Now: now})
	if strings.HasPrefix(other.Readiness.NextSteps[0], "Upgrade to OpenSSH") || !strings.Contains(other.Readiness.NextSteps[0], "mlkem768x25519-sha256") {
		t.Errorf("a Go server is told %q", other.Readiness.NextSteps[0])
	}
	noStrict := modernSSH()
	noStrict.Identification.Software = "Go"
	noStrict.Algorithms.StrictKex = false
	for _, c := range eval.EvaluateSSH(noStrict, eval.Input{Now: now}).Baseline.Changes {
		if c.Action == eval.ChangeUpgrade && strings.HasPrefix(c.Text, "Upgrade to OpenSSH") {
			t.Errorf("a Go server is told %q", c.Text)
		}
	}
}

// QA of PR #24: a truncated MAC is as strong as its tag (SP 800-107 Rev. 1 section 5.3.5).
func TestTruncatedMACIsBoundedByItsTag(t *testing.T) {
	r := modernSSH()
	r.Algorithms.MACC2S = []string{"hmac-sha1", "hmac-sha1-96", "hmac-sha2-256-etm@openssh.com"}
	r.Algorithms.MACS2C = r.Algorithms.MACC2S
	want := map[string]int{"hmac-sha1": 128, "hmac-sha1-96": 96, "hmac-sha2-256-etm@openssh.com": 256}
	for _, a := range eval.EvaluateSSH(r, eval.Input{Now: now}).SSHAlgorithms {
		if w, ok := want[a.Name]; ok {
			if a.Strength == nil || a.Strength.Bits != w {
				t.Errorf("%s: %+v, want %d bits", a.Name, a.Strength, w)
			}
			delete(want, a.Name)
		}
	}
	if len(want) > 0 {
		t.Errorf("not listed: %v", want)
	}
}
