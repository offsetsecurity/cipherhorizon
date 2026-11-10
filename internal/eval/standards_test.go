package eval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Standards (PRD-017). The matrix below pins, for each standard, one endpoint that meets it and
// the clauses a deliberately non-compliant endpoint fails, so a transcription error in a clause
// surfaces as a test failure, not on a customer's audit.

func standardOf(t *testing.T, ev eval.Evaluation, id string) eval.StandardResult {
	t.Helper()
	for _, s := range ev.Standards {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("standard %s missing from the evaluation", id)
	return eval.StandardResult{}
}

func reqOf(t *testing.T, s eval.StandardResult, id string) eval.RequirementResult {
	t.Helper()
	for _, r := range s.Requirements {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("%s: requirement %s missing", s.ID, id)
	return eval.RequirementResult{}
}

func expectReq(t *testing.T, s eval.StandardResult, id, status string) {
	t.Helper()
	if r := reqOf(t, s, id); r.Status != status {
		t.Errorf("%s/%s: got %s (%s), want %s", s.ID, id, r.Status, r.Detail, status)
	}
}

func TestEveryStandardIsCompleteAndJudged(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range eval.Standards() {
		if seen[s.ID] {
			t.Errorf("duplicate standard id %s", s.ID)
		}
		seen[s.ID] = true
		if s.Title == "" || s.Publisher == "" || s.Edition == "" || s.URL == "" || s.Scope == "" {
			t.Errorf("%s: a standard names its title, publisher, edition, URL and scope", s.ID)
		}
		if s.Protocol != "tls" && s.Protocol != eval.ProtocolSSH {
			t.Errorf("%s: protocol %q", s.ID, s.Protocol)
		}
		ids := map[string]bool{}
		for _, r := range s.Requirements {
			if r.ID == "" || r.Clause == "" || r.Text == "" {
				t.Errorf("%s: requirement %q needs an id, a clause and a text", s.ID, r.ID)
			}
			if r.Level != eval.LevelMust && r.Level != eval.LevelShould {
				t.Errorf("%s/%s: level %q", s.ID, r.ID, r.Level)
			}
			if ids[r.ID] {
				t.Errorf("%s: duplicate requirement %s", s.ID, r.ID)
			}
			ids[r.ID] = true
		}
	}
	// Every TLS standard appears on a TLS evaluation, every SSH one on an SSH evaluation, and
	// every requirement has a status.
	ev := eval.Evaluate(modern(), now)
	if len(ev.Standards) != len(eval.StandardsFor("tls")) {
		t.Fatalf("TLS evaluation carries %d standards, want %d", len(ev.Standards), len(eval.StandardsFor("tls")))
	}
	for _, s := range ev.Standards {
		std, _ := eval.StandardByID(s.ID)
		if len(s.Requirements) != len(std.Requirements) {
			t.Errorf("%s: %d results for %d requirements", s.ID, len(s.Requirements), len(std.Requirements))
		}
		for _, r := range s.Requirements {
			switch r.Status {
			case eval.ReqMet, eval.ReqNotMet, eval.ReqNotAssessed, eval.ReqNotApplicable:
			default:
				t.Errorf("%s/%s: status %q", s.ID, r.ID, r.Status)
			}
		}
		if s.Verdict != eval.StdMeets && s.Verdict != eval.StdFails && s.Verdict != eval.StdNotAssessed {
			t.Errorf("%s: verdict %q", s.ID, s.Verdict)
		}
	}
	sev := eval.EvaluateSSH(sshHybridReport(), eval.Input{Now: now})
	if len(sev.Standards) != len(eval.StandardsFor(eval.ProtocolSSH)) {
		t.Fatalf("SSH evaluation carries %d standards, want %d", len(sev.Standards), len(eval.StandardsFor(eval.ProtocolSSH)))
	}
	if ev.Version != "eval/17" {
		t.Errorf("version %s", ev.Version)
	}
}

// exemplary is a TLS endpoint that meets BCP 195 and the NIST, Mozilla Intermediate and PCI
// profiles: TLS 1.2 and 1.3, ECDHE AES-GCM only, P-256 and X25519MLKEM768, an ECDSA P-256
// certificate signed with SHA-256, 90 days, stapled, with HSTS for two years.
func exemplary() *tlsprobe.Report {
	rep := modern()
	ecdhe := func(name string, bits int) tlsprobe.SuiteResult {
		s := suite("TLSv1.2", name, "ECDHE", "ECDSA", "AES", "GCM", bits, 128, true, true)
		s.Rank = 1
		return s
	}
	rep.Suites = []tlsprobe.SuiteResult{t13a, t13b, ecdhe("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 128), ecdhe("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 256)}
	rep.Groups = []tlsprobe.GroupResult{hybrid, x25519, p256, {Version: "TLSv1.2", ID: 23, Name: "secp256r1"}}
	rep.Preference = []tlsprobe.PreferenceResult{{Version: "TLSv1.3", Subject: "suites", Order: "server"}, {Version: "TLSv1.2", Subject: "suites", Order: "server"}}
	rep.Certificates = []tlsprobe.CertResult{cert("ECDSA", 256, func(c *tlsprobe.CertResult) {
		l := &c.Chain[0]
		l.PublicKey.Curve = "P-256"
		l.SignatureAlg.Name = "ECDSA-SHA256"
		l.NotBefore, l.NotAfter = now.AddDate(0, 0, -30), now.AddDate(0, 0, 60)
		l.ExtKeyUsage = []string{"serverAuth"}
		l.DNSNames = []string{"test.example"}
		l.OCSPServers = []string{"http://ocsp.example"}
	})}
	yes, no := true, false
	rep.Features = tlsprobe.Features{SecureRenegotiation: &yes, ExtendedMasterSecret: &yes, Compression: &no, FallbackSCSV: &yes, OCSPStapling: &yes, Heartbeat: &no}
	age := int64(63072000)
	rep.HSTS = &yes
	rep.HSTSHeader = &tlsprobe.HSTSResult{MaxAge: &age, IncludeSubDomains: true}
	return rep
}

func TestExemplaryEndpointMeetsTheMainstreamStandards(t *testing.T) {
	ev := eval.Evaluate(exemplary(), now)
	for _, id := range []string{"bcp195", "nist-sp800-52r2", "mozilla-intermediate-6.0", "pci-dss-4"} {
		s := standardOf(t, ev, id)
		if s.Verdict != eval.StdMeets {
			var bad []string
			for _, r := range s.Requirements {
				if r.Status == eval.ReqNotMet {
					bad = append(bad, r.ID+": "+r.Detail)
				}
			}
			t.Errorf("%s: %s; failing: %s", id, s.Verdict, strings.Join(bad, "; "))
		}
	}
	// The certificate is a test fixture (no served DER), so trust-dependent clauses read as the
	// fixture says, and the chain-analysis clauses are not assessed rather than invented.
	bcp := standardOf(t, ev, "bcp195")
	expectReq(t, bcp, "versions", eval.ReqMet)
	expectReq(t, bcp, "fs-preferred", eval.ReqMet)
	expectReq(t, bcp, "hsts", eval.ReqMet)
	nist := standardOf(t, ev, "nist-sp800-52r2")
	expectReq(t, nist, "stapling", eval.ReqMet)
	expectReq(t, nist, "groups", eval.ReqMet)
	moz := standardOf(t, ev, "mozilla-intermediate-6.0")
	expectReq(t, moz, "lifespan-90", eval.ReqMet)
	expectReq(t, moz, "pq", eval.ReqMet)
	// Modern wants TLS 1.3 only: this endpoint keeps TLS 1.2, so it does not meet Modern.
	mod := standardOf(t, ev, "mozilla-modern-6.0")
	if mod.Verdict != eval.StdFails {
		t.Errorf("Modern: %s", mod.Verdict)
	}
	expectReq(t, mod, "versions", eval.ReqNotMet)
	// BSI does not list X25519 or ChaCha20, and recommends classical-only key agreement only until 2031:
	// the X25519 group fails Table 10, and the PKCS#1 certificate rule does not apply to ECDSA.
	bsi := standardOf(t, ev, "bsi-tr-02102-2")
	expectReq(t, bsi, "groups", eval.ReqNotMet)
	expectReq(t, bsi, "cert-sig", eval.ReqMet)
	expectReq(t, bsi, "pq-hybrid", eval.ReqMet)
	expectReq(t, bsi, "keys", eval.ReqMet)
	// ANSSI accepts x25519 (R7) and wants the server's order (R13).
	anssi := standardOf(t, ev, "anssi-tls-v1.2")
	expectReq(t, anssi, "r7", eval.ReqMet)
	expectReq(t, anssi, "r13", eval.ReqMet)
	expectReq(t, anssi, "r25", eval.ReqMet)
	// CNSA: P-256 and AES-128 are outside the suite.
	cnsa := standardOf(t, ev, "cnsa-2.0-tls")
	expectReq(t, cnsa, "suite13", eval.ReqNotMet)
	expectReq(t, cnsa, "cert-key", eval.ReqNotMet)
}

func TestTerribleEndpointFailsTheRightClauses(t *testing.T) {
	ev := eval.Evaluate(terrible(), now)
	bcp := standardOf(t, ev, "bcp195")
	if bcp.Verdict != eval.StdFails {
		t.Fatalf("bcp195 on the terrible endpoint: %s", bcp.Verdict)
	}
	expectReq(t, bcp, "versions", eval.ReqNotMet)
	expectReq(t, bcp, "no-null-rc4-export", eval.ReqNotMet)
	expectReq(t, bcp, "no-under-128", eval.ReqNotMet)
	expectReq(t, bcp, "no-static-rsa", eval.ReqNotMet)
	expectReq(t, bcp, "sig-hash", eval.ReqNotMet)
	expectReq(t, bcp, "rsa-2048", eval.ReqNotMet)
	nist := standardOf(t, ev, "nist-sp800-52r2")
	expectReq(t, nist, "no-ssl", eval.ReqNotMet)
	expectReq(t, nist, "suites", eval.ReqNotMet)
	pci := standardOf(t, ev, "pci-dss-4")
	expectReq(t, pci, "no-ssl-early-tls", eval.ReqNotMet)
	expectReq(t, pci, "strong-112", eval.ReqNotMet)
	expectReq(t, pci, "trusted", eval.ReqNotMet)
	anssi := standardOf(t, ev, "anssi-tls-v1.2")
	expectReq(t, anssi, "r4", eval.ReqNotMet)
	expectReq(t, anssi, "r6", eval.ReqNotMet)
	expectReq(t, anssi, "r11", eval.ReqNotMet)
	// Every must-failure is counted, and the summary map says does-not-meet.
	if bcp.MustFailures < 5 {
		t.Errorf("bcp195 must failures: %d", bcp.MustFailures)
	}
	if sum := eval.StandardsSummary(ev); sum["bcp195"] != eval.StdFails || sum["pci-dss-4"] != eval.StdFails {
		t.Errorf("summary: %v", sum)
	}
}

func TestClausesNotSeenAreNotAssessed(t *testing.T) {
	// A report with no certificates and no feature probes must not invent a verdict.
	rep := &tlsprobe.Report{Protocols: protocols("TLSv1.3"), Suites: []tlsprobe.SuiteResult{t13a},
		Stages: []tlsprobe.Stage{{Name: tlsprobe.StageProtocols, Outcome: tlsprobe.OutcomeDone}, {Name: tlsprobe.StageSuites, Outcome: tlsprobe.OutcomeDone},
			{Name: tlsprobe.StageFeatures, Outcome: tlsprobe.OutcomeSkipped}, {Name: tlsprobe.StageCerts, Outcome: tlsprobe.OutcomeSkipped},
			{Name: tlsprobe.StageHTTP, Outcome: tlsprobe.OutcomeSkipped}, {Name: tlsprobe.StageKeyExchange, Outcome: tlsprobe.OutcomeSkipped}}}
	ev := eval.Evaluate(rep, now)
	bcp := standardOf(t, ev, "bcp195")
	expectReq(t, bcp, "compression", eval.ReqNotAssessed)
	expectReq(t, bcp, "rsa-2048", eval.ReqNotAssessed)
	expectReq(t, bcp, "hsts", eval.ReqNotAssessed)
	expectReq(t, bcp, "dh-2048", eval.ReqNotApplicable)
	// TLS 1.3 only: the TLS 1.2 renegotiation and EMS clauses do not apply.
	expectReq(t, bcp, "reneg", eval.ReqNotApplicable)
	expectReq(t, bcp, "ems", eval.ReqNotApplicable)
	// The verdict is still "meets" for what could be judged (versions, suites), never invented.
	if bcp.Verdict == eval.StdNotAssessed {
		t.Errorf("bcp195: nothing judged although versions and suites were")
	}
	mod := standardOf(t, ev, "mozilla-modern-6.0")
	expectReq(t, mod, "versions", eval.ReqMet)
	expectReq(t, mod, "cert", eval.ReqNotAssessed)
}

func TestBSIPeriodsOfUseApplyAtEvaluationTime(t *testing.T) {
	rep := exemplary()
	// An RSA-3072 certificate signed sha256WithRSA (PKCS #1 v1.5): recommended until 2025, not after.
	rep.Certificates = []tlsprobe.CertResult{cert("RSA", 3072, func(c *tlsprobe.CertResult) {
		c.Chain[0].SignatureAlg.Name = "SHA256-RSA"
		c.Chain[0].OCSPServers = []string{"http://ocsp.example"}
	})}
	in2025 := eval.Evaluate(rep, time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))
	expectReq(t, standardOf(t, in2025, "bsi-tr-02102-2"), "cert-sig", eval.ReqMet)
	in2026 := eval.Evaluate(rep, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	expectReq(t, standardOf(t, in2026, "bsi-tr-02102-2"), "cert-sig", eval.ReqNotMet)
	// A non-forward-secrecy ECDH suite is recommended until the end of 2026 and not in 2027.
	rep.Suites = append(rep.Suites, suite("TLSv1.2", "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", "ECDH", "ECDSA", "AES", "GCM", 128, 128, true, false))
	expectReq(t, standardOf(t, eval.Evaluate(rep, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)), "bsi-tr-02102-2"), "suites12", eval.ReqMet)
	expectReq(t, standardOf(t, eval.Evaluate(rep, time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)), "bsi-tr-02102-2"), "suites12", eval.ReqNotMet)
}

func TestCNSAProfileOnACNSAEndpoint(t *testing.T) {
	rep := &tlsprobe.Report{
		Protocols: protocols("TLSv1.3"),
		Suites:    []tlsprobe.SuiteResult{t13b},
		Groups:    []tlsprobe.GroupResult{{Version: "TLSv1.3", ID: 514, Name: "MLKEM1024", PQ: true}, {Version: "TLSv1.3", ID: 24, Name: "secp384r1"}},
		Certificates: []tlsprobe.CertResult{cert("ECDSA", 384, func(c *tlsprobe.CertResult) {
			c.Chain[0].PublicKey.Curve = "P-384"
			c.Chain[0].SignatureAlg.Name = "ECDSA-SHA384"
		})},
		Negotiated: &tlsprobe.Negotiated{Version: "TLSv1.3", Group: "MLKEM1024", GroupID: 514, PQ: true},
	}
	cnsa := standardOf(t, eval.Evaluate(rep, now), "cnsa-2.0-tls")
	for _, id := range []string{"tls13-only", "versions", "suite13", "groups", "mlkem", "cert-key", "cert-sig"} {
		expectReq(t, cnsa, id, eval.ReqMet)
	}
	expectReq(t, cnsa, "suite12", eval.ReqNotApplicable)
	if cnsa.Verdict != eval.StdMeets {
		t.Errorf("verdict %s", cnsa.Verdict)
	}
}

// ---- SSH --------------------------------------------------------------------------------------------

func sshReport(kex, hostKey, ciphers, macs []string) *sshprobe.Report {
	return &sshprobe.Report{
		Identification: &sshprobe.Identification{Raw: "SSH-2.0-OpenSSH_10.0", ProtoVersion: "2.0", Software: "OpenSSH_10.0"},
		Algorithms: &sshprobe.Algorithms{Kex: kex, HostKey: hostKey, CipherC2S: ciphers, CipherS2C: ciphers, MACC2S: macs, MACS2C: macs,
			CompressionC2S: []string{"none"}, CompressionS2C: []string{"none"}, StrictKex: true},
	}
}

func sshHybridReport() *sshprobe.Report {
	return sshReport([]string{"mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"}, []string{"ssh-ed25519", "ecdsa-sha2-nistp256"},
		[]string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"}, []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512"})
}

func TestSSHStandards(t *testing.T) {
	// A typical hardened OpenSSH: BSI does not list curve25519, Ed25519 or ChaCha20, so it does
	// not meet TR-02102-4, and the report says exactly which names are outside the tables.
	ev := eval.EvaluateSSH(sshHybridReport(), eval.Input{Now: now})
	bsi := standardOf(t, ev, "bsi-tr-02102-4")
	if bsi.Verdict != eval.StdFails {
		t.Errorf("bsi: %s", bsi.Verdict)
	}
	expectReq(t, bsi, "ssh2", eval.ReqMet)
	expectReq(t, bsi, "kex", eval.ReqNotMet)
	expectReq(t, bsi, "pq-kex", eval.ReqMet)
	expectReq(t, bsi, "ciphers", eval.ReqNotMet)
	expectReq(t, bsi, "macs", eval.ReqMet)
	expectReq(t, bsi, "hostkeys", eval.ReqNotMet)
	if r := reqOf(t, bsi, "kex"); !strings.Contains(r.Detail, "curve25519-sha256") || strings.Contains(r.Detail, "ecdh-sha2-nistp256") {
		t.Errorf("kex detail: %s", r.Detail)
	}
	// A BSI-conformant server.
	conf := eval.EvaluateSSH(sshReport([]string{"mlkem768nistp256-sha256", "ecdh-sha2-nistp384", "diffie-hellman-group16-sha512"}, []string{"ecdsa-sha2-nistp384"},
		[]string{"aes256-gcm@openssh.com", "aes256-ctr"}, []string{"hmac-sha2-512-etm@openssh.com"}), eval.Input{Now: now})
	if s := standardOf(t, conf, "bsi-tr-02102-4"); s.Verdict != eval.StdMeets {
		t.Errorf("conformant server: %s (%+v)", s.Verdict, s.Requirements)
	}
	// CNSA 2.0: the CNSA server meets it; the hybrid OpenSSH does not.
	cnsa := eval.EvaluateSSH(sshReport([]string{"mlkem1024-sha384", "ecdh-sha2-nistp384"}, []string{"ssh-mldsa-87", "ecdsa-sha2-nistp384"},
		[]string{"aes256-gcm@openssh.com"}, []string{"hmac-sha2-512"}), eval.Input{Now: now})
	if s := standardOf(t, cnsa, "cnsa-2.0-ssh"); s.Verdict != eval.StdMeets || s.ShouldFailures != 0 {
		t.Errorf("CNSA server: %s, %d recommendations missed (%+v)", s.Verdict, s.ShouldFailures, s.Requirements)
	}
	expectReq(t, standardOf(t, ev, "cnsa-2.0-ssh"), "kex", eval.ReqNotMet)
	// Lists not read: nothing is assessed, and the verdict says so.
	unread := eval.EvaluateSSH(&sshprobe.Report{Identification: &sshprobe.Identification{Raw: "SSH-2.0-x", ProtoVersion: "2.0"}}, eval.Input{Now: now})
	if s := standardOf(t, unread, "cnsa-2.0-ssh"); s.Verdict != eval.StdNotAssessed {
		t.Errorf("unread lists: %s", s.Verdict)
	}
}
