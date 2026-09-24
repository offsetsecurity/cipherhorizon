package eval_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/eval"
	"github.com/example/cipherhorizon/internal/tlsprobe"
	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// ---- builders for synthetic reports ---------------------------------------------------

var allVersions = []string{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"}

func protocols(supported ...string) []tlsprobe.ProtocolResult {
	on := map[string]bool{}
	for _, s := range supported {
		on[s] = true
	}
	var out []tlsprobe.ProtocolResult
	for _, v := range allVersions {
		p := tlsprobe.ProtocolResult{Version: v, Supported: on[v], Evidence: tlsprobe.EvidenceAlert}
		if on[v] {
			p.Evidence = tlsprobe.EvidenceServerHello
		}
		out = append(out, p)
	}
	return out
}

func suite(version, name, kx, auth, cipher, mode string, bits, block int, aead, ephemeral bool) tlsprobe.SuiteResult {
	return tlsprobe.SuiteResult{Version: version, Name: name, Kx: kx, Auth: auth, Cipher: cipher, Mode: mode,
		KeyBits: bits, BlockBits: block, AEAD: aead, Ephemeral: ephemeral, IANARecommended: "Y", MAC: "AEAD"}
}

var (
	gcm128 = suite("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "RSA", "AES", "GCM", 128, 128, true, true)
	gcm256 = suite("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "RSA", "AES", "GCM", 256, 128, true, true)
	t13a   = suite("TLSv1.3", "TLS_AES_128_GCM_SHA256", "", "", "AES", "GCM", 128, 128, true, false)
	t13b   = suite("TLSv1.3", "TLS_AES_256_GCM_SHA384", "", "", "AES", "GCM", 256, 128, true, false)
)

func cert(alg string, bits int, opts ...func(*tlsprobe.CertResult)) tlsprobe.CertResult {
	cr := tlsprobe.CertResult{
		Source: "tls-default", Trusted: true, NameMatches: true,
		Chain: []tlsprobe.CertInfo{{
			Subject: "CN=test.example", Issuer: "CN=Test CA", SHA256: "aa" + alg,
			NotBefore: now.AddDate(0, -1, 0), NotAfter: now.AddDate(0, 6, 0),
			PublicKey:    tlsprobe.KeyInfo{Algorithm: alg, Bits: bits},
			SignatureAlg: tlsprobe.AlgInfo{Name: "SHA256-RSA"},
		}},
	}
	for _, o := range opts {
		o(&cr)
	}
	return cr
}

func group(id uint16, name string, pq, hybrid, obsolete bool) tlsprobe.GroupResult {
	return tlsprobe.GroupResult{Version: "TLSv1.3", ID: id, Name: name, PQ: pq, Hybrid: hybrid, Obsolete: obsolete}
}

var (
	x25519   = group(29, "x25519", false, false, false)
	p256     = group(23, "secp256r1", false, false, false)
	hybrid   = group(4588, "X25519MLKEM768", true, true, false)
	obsolete = group(25497, "X25519Kyber768Draft00", true, true, true)
)

func negotiated(g tlsprobe.GroupResult) *tlsprobe.Negotiated {
	return &tlsprobe.Negotiated{Version: "TLSv1.3", Group: g.Name, GroupID: g.ID, PQ: g.PQ}
}

// modern: TLS 1.3 + 1.2, AES-GCM, RSA-2048, trusted, hybrid negotiated.
func modern() *tlsprobe.Report {
	return &tlsprobe.Report{
		Protocols:    protocols("TLSv1.3", "TLSv1.2"),
		Suites:       []tlsprobe.SuiteResult{t13a, t13b, gcm128, gcm256},
		Groups:       []tlsprobe.GroupResult{hybrid, x25519},
		Preference:   []tlsprobe.PreferenceResult{{Version: "TLSv1.3", Subject: "groups", Order: "server"}},
		Certificates: []tlsprobe.CertResult{cert("RSA", 2048)},
		Negotiated:   negotiated(hybrid),
		Features:     tlsprobe.Features{SecureRenegotiation: ptr(true), Compression: ptr(false), FallbackSCSV: ptr(true)},
	}
}

func ptr[T any](v T) *T { return &v }

func ids(ev eval.Evaluation) map[string]bool {
	m := map[string]bool{}
	for _, f := range ev.Findings {
		m[f.ID] = true
	}
	return m
}

// ---- the evidence rules ----------------------------------------------------------------

// A worst-case endpoint that trips (nearly) every rule.
func terrible() *tlsprobe.Report {
	bad := func(v, name, kx, auth, cipher, mode string, bits, block int) tlsprobe.SuiteResult {
		s := suite(v, name, kx, auth, cipher, mode, bits, block, false, false)
		s.MAC = "SHA1"
		s.IANARecommended = "D"
		return s
	}
	null := bad("SSLv3", "TLS_RSA_WITH_NULL_MD5", "RSA", "RSA", "NULL", "NONE", 0, 0)
	exp := bad("SSLv3", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "RSA", "RSA", "RC4", "STREAM", 40, 0)
	exp.Export = true
	anon := bad("SSLv3", "TLS_DH_anon_WITH_AES_128_CBC_SHA", "DHE", "anon", "AES", "CBC", 128, 128)
	anon.Anon, anon.Ephemeral = true, true
	rc4 := bad("SSLv3", "TLS_RSA_WITH_RC4_128_SHA", "RSA", "RSA", "RC4", "STREAM", 128, 0)
	des := bad("SSLv3", "TLS_RSA_WITH_DES_CBC_SHA", "RSA", "RSA", "DES", "CBC", 56, 64)
	tdes := bad("TLSv1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", "RSA", "3DES", "CBC", 168, 64)
	cbc10 := bad("TLSv1.0", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", "CBC", 128, 128)
	cbc3 := bad("SSLv3", "TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", "RSA", "AES", "CBC", 128, 128)
	oddD := bad("TLSv1.0", "TLS_RSA_WITH_SEED_CBC_SHA", "RSA", "RSA", "SEED", "CBC", 128, 128)

	expired := cert("RSA", 512, func(c *tlsprobe.CertResult) {
		l := &c.Chain[0]
		l.NotAfter = now.AddDate(0, 0, -3)
		l.SignatureAlg.Name = "SHA1-RSA"
		c.Trusted, c.TrustError = false, "x509: certificate has expired"
		c.NameMatches, c.NameError = false, "x509: certificate is valid for other.example, not test.example"
	})
	soon := cert("ECDSA", 256, func(c *tlsprobe.CertResult) {
		c.Chain[0].NotAfter = now.AddDate(0, 0, 5)
		c.Chain[0].SHA256 = "soon"
	})
	untrusted := cert("RSA", 2048, func(c *tlsprobe.CertResult) {
		c.Trusted, c.TrustError = false, "x509: certificate signed by unknown authority"
		c.Chain[0].SelfSigned = true
		c.Chain[0].SHA256 = "untrusted"
	})
	future := cert("RSA", 2048, func(c *tlsprobe.CertResult) {
		c.Chain[0].NotBefore = now.AddDate(0, 1, 0)
		c.Chain[0].SHA256 = "future"
	})
	small := cert("RSA", 1536, func(c *tlsprobe.CertResult) { c.Chain[0].SHA256 = "small" })
	tinyEC := cert("ECDSA", 192, func(c *tlsprobe.CertResult) { c.Chain[0].SHA256 = "tinyec" })

	return &tlsprobe.Report{
		Protocols: protocols("TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"),
		Suites:    []tlsprobe.SuiteResult{null, exp, anon, rc4, des, tdes, cbc10, cbc3, oddD},
		DH:        &tlsprobe.DHResult{PrimeBits: 768},
		Features: tlsprobe.Features{
			SecureRenegotiation: ptr(false), Compression: ptr(true), FallbackSCSV: ptr(false),
			ClientCertRequested: ptr(true),
		},
		Certificates: []tlsprobe.CertResult{expired, soon, untrusted, future, small, tinyEC},
		HSTS:         ptr(false),
	}
}

func TestEveryRuleFiresAndIsCited(t *testing.T) {
	ev := eval.Evaluate(terrible(), now)

	fired := ids(ev)
	for _, id := range eval.RuleIDs() {
		if !fired[id] {
			t.Errorf("rule %s never fired on the worst-case endpoint (dead rule, or the fixture misses it)", id)
		}
	}

	for _, f := range ev.Findings {
		switch {
		case len(f.Citations) == 0:
			t.Errorf("%s has no citation", f.ID)
		case strings.TrimSpace(f.Detail) == "":
			t.Errorf("%s has no detail: a finding must say what was seen", f.ID)
		case strings.TrimSpace(f.Remediation) == "":
			t.Errorf("%s has no remediation", f.ID)
		case f.Evidence == "":
			t.Errorf("%s has no evidence tier", f.ID)
		}
		for _, c := range f.Citations {
			if c.Title == "" || !strings.HasPrefix(c.URL, "https://") {
				t.Errorf("%s: bad citation %+v", f.ID, c)
			}
		}
	}
}

func TestEveryReadinessClaimIsCited(t *testing.T) {
	for name, rep := range map[string]*tlsprobe.Report{
		"modern": modern(), "terrible": terrible(),
		"classical": {Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{x25519}, Suites: []tlsprobe.SuiteResult{t13a}},
	} {
		r := eval.Evaluate(rep, now).Readiness
		for dim, d := range map[string]eval.Dimension{"key establishment": r.KeyEstablishment, "authentication": r.Authentication, "symmetric": r.Symmetric} {
			if len(d.Citations) == 0 || d.Detail == "" || d.Evidence == "" {
				t.Errorf("%s / %s: dimension is missing citation, detail or evidence: %+v", name, dim, d)
			}
		}
		if len(r.Citations) == 0 || r.Summary == "" || len(r.NextSteps) == 0 || r.Label == "" {
			t.Errorf("%s: readiness incomplete: %+v", name, r)
		}
	}
}

func TestRuleIDsAreUniqueAndStable(t *testing.T) {
	seen := map[string]bool{}
	for _, id := range eval.RuleIDs() {
		if seen[id] {
			t.Errorf("duplicate rule id %s", id)
		}
		seen[id] = true
	}
	if len(seen) < 20 {
		t.Errorf("only %d rules", len(seen))
	}
}

func TestSpecificFindings(t *testing.T) {
	ev := eval.Evaluate(terrible(), now)
	get := func(id string) []eval.Finding {
		var out []eval.Finding
		for _, f := range ev.Findings {
			if f.ID == id {
				out = append(out, f)
			}
		}
		return out
	}

	if f := get("PROTO.SSL2"); len(f) != 1 || f[0].Severity != eval.Critical {
		t.Errorf("PROTO.SSL2 = %+v", f)
	}
	// DH prime under 1024 is high; 1024-2047 medium.
	if f := get("KX.DH-SMALL"); len(f) != 1 || f[0].Severity != eval.High || !strings.Contains(f[0].Detail, "768") {
		t.Errorf("KX.DH-SMALL = %+v", f)
	}
	// Certificate rules fire per certificate, with the right severities.
	sev := map[string]eval.Severity{}
	for _, f := range get("CERT.EXPIRING") {
		sev["expiring"] = f.Severity
	}
	if sev["expiring"] != eval.High { // 5 days left
		t.Errorf("CERT.EXPIRING for 5 days left = %q, want high", sev["expiring"])
	}
	if f := get("CERT.WEAK-KEY"); len(f) != 3 { // RSA-512 (critical), RSA-1536, ECDSA-192
		t.Errorf("CERT.WEAK-KEY fired %d times: %+v", len(f), f)
	}
	if f := get("CERT.UNTRUSTED"); len(f) != 1 || !strings.Contains(f[0].Detail, "self-signed") {
		t.Errorf("CERT.UNTRUSTED = %+v (the expired certificate must not also be reported untrusted)", f)
	}
	// Findings are sorted most severe first.
	for i := 1; i < len(ev.Findings); i++ {
		if ev.Findings[i-1].Severity.Rank() > ev.Findings[i].Severity.Rank() {
			t.Fatal("findings not sorted by severity")
		}
	}
	if ev.Counts[eval.Critical] == 0 || ev.Counts[eval.High] == 0 {
		t.Errorf("counts = %v", ev.Counts)
	}
}

func TestInferredFindingsSayTheyAreInferred(t *testing.T) {
	ev := eval.Evaluate(terrible(), now)
	for _, f := range ev.Findings {
		if (f.ID == "VULN.POODLE" || f.ID == "VULN.BEAST" || f.ID == "FEAT.RENEGOTIATION") && f.Evidence != eval.Inferred {
			t.Errorf("%s evidence = %q, want inferred (it was not attempted)", f.ID, f.Evidence)
		}
	}
}

func TestACleanEndpointHasNoActionableFindings(t *testing.T) {
	ev := eval.Evaluate(modern(), now)
	for _, f := range ev.Findings {
		if f.Severity.Rank() < eval.Low.Rank() {
			t.Errorf("clean endpoint got %s %s: %s", f.Severity, f.ID, f.Detail)
		}
	}
}

func TestNoFindingsFromInconclusiveProbes(t *testing.T) {
	rep := &tlsprobe.Report{Protocols: protocols("TLSv1.2")}
	for i := range rep.Protocols {
		if rep.Protocols[i].Version == "TLSv1.3" {
			rep.Protocols[i].Evidence = tlsprobe.EvidenceInconclusive // timed out
		}
	}
	ev := eval.Evaluate(rep, now)
	if ids(ev)["PROTO.NO-TLS13"] {
		t.Error("a timed-out TLS 1.3 probe was reported as 'TLS 1.3 not supported'")
	}
	if ev.Readiness.Level != eval.LevelUndetermined || ev.Readiness.HNDLExposed {
		t.Errorf("readiness = %+v; want undetermined and not 'exposed'", ev.Readiness)
	}
}

// ---- PQC readiness (AC-04.x) ---------------------------------------------------------------

func TestReadinessLevels(t *testing.T) {
	pqCert := cert("ML-DSA-65", 0)
	for name, tc := range map[string]struct {
		rep      *tlsprobe.Report
		level    int
		exposed  bool
		keyState string
	}{
		"no TLS 1.3": {&tlsprobe.Report{Protocols: protocols("TLSv1.2"), Suites: []tlsprobe.SuiteResult{gcm128}},
			eval.LevelNotReady, true, "unavailable"},
		"TLS 1.3 classical only": {&tlsprobe.Report{Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{x25519, p256},
			Negotiated: negotiated(x25519), Suites: []tlsprobe.SuiteResult{t13a}},
			eval.LevelExposed, true, "classical"},
		"hybrid supported, client got classical": {&tlsprobe.Report{Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{x25519, hybrid},
			Negotiated: negotiated(x25519), Suites: []tlsprobe.SuiteResult{t13a}},
			eval.LevelHybridAvail, true, "hybrid-available"},
		"hybrid negotiated": {modern(), eval.LevelHybridNeg, false, "hybrid-negotiated"},
		"hybrid + PQ certificate": {func() *tlsprobe.Report {
			r := modern()
			r.Certificates = []tlsprobe.CertResult{pqCert}
			return r
		}(), eval.LevelPQAuth, false, "hybrid-negotiated"},
		"only obsolete Kyber drafts do not count": {&tlsprobe.Report{Protocols: protocols("TLSv1.3"),
			Groups: []tlsprobe.GroupResult{obsolete, x25519}, Negotiated: negotiated(x25519), Suites: []tlsprobe.SuiteResult{t13a}},
			eval.LevelExposed, true, "classical"},
		// No handshake data: the server's own preference decides, and the evidence says inferred.
		"no handshake, server prefers hybrid": {&tlsprobe.Report{Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{hybrid, x25519},
			Preference: []tlsprobe.PreferenceResult{{Version: "TLSv1.3", Subject: "groups", Order: "server"}}, Suites: []tlsprobe.SuiteResult{t13a}},
			eval.LevelHybridNeg, false, "hybrid-negotiated"},
		"no handshake, client-order server": {&tlsprobe.Report{Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{hybrid, x25519},
			Preference: []tlsprobe.PreferenceResult{{Version: "TLSv1.3", Subject: "groups", Order: "client"}}, Suites: []tlsprobe.SuiteResult{t13a}},
			eval.LevelHybridAvail, true, "hybrid-available"},
	} {
		r := eval.Evaluate(tc.rep, now).Readiness
		if r.Level != tc.level || r.HNDLExposed != tc.exposed || r.KeyEstablishment.Status != tc.keyState {
			t.Errorf("%s: level %d exposed=%v key=%q; want level %d exposed=%v key=%q\n%+v",
				name, r.Level, r.HNDLExposed, r.KeyEstablishment.Status, tc.level, tc.exposed, tc.keyState, r.KeyEstablishment)
		}
		if r.Label != eval.LevelLabel(r.Level) {
			t.Errorf("%s: label %q", name, r.Label)
		}
	}

	inferred := eval.Evaluate(&tlsprobe.Report{Protocols: protocols("TLSv1.3"), Groups: []tlsprobe.GroupResult{hybrid, x25519},
		Preference: []tlsprobe.PreferenceResult{{Version: "TLSv1.3", Subject: "groups", Order: "server"}}, Suites: []tlsprobe.SuiteResult{t13a}}, now)
	if inferred.Readiness.KeyEstablishment.Evidence != eval.Inferred {
		t.Errorf("without a handshake the evidence must be 'inferred', got %q", inferred.Readiness.KeyEstablishment.Evidence)
	}
	if modern := eval.Evaluate(modern(), now); modern.Readiness.KeyEstablishment.Evidence != eval.Observed {
		t.Errorf("with a handshake the evidence must be 'observed', got %q", modern.Readiness.KeyEstablishment.Evidence)
	}
}

func TestReadinessDimensions(t *testing.T) {
	r := eval.Evaluate(modern(), now).Readiness
	if r.Authentication.Status != "classical" || !strings.Contains(r.Authentication.Detail, "RSA 2048-bit") {
		t.Errorf("authentication = %+v", r.Authentication)
	}
	if r.Symmetric.Status != "adequate" {
		t.Errorf("symmetric = %+v", r.Symmetric)
	}
	if !reflect.DeepEqual(r.PQGroups, []string{"X25519MLKEM768"}) {
		t.Errorf("PQGroups = %v", r.PQGroups)
	}

	weak := modern()
	weak.Suites = append(weak.Suites, suite("TLSv1.0", "x", "RSA", "RSA", "RC4", "STREAM", 40, 0, false, false))
	if s := eval.Evaluate(weak, now).Readiness.Symmetric.Status; s != "inadequate" {
		t.Errorf("40-bit cipher: symmetric = %q", s)
	}
	none := modern()
	none.Certificates = nil
	if a := eval.Evaluate(none, now).Readiness.Authentication; a.Status != "unknown" || a.Evidence != eval.NotMeasured {
		t.Errorf("no certificates: authentication = %+v", a)
	}

	// A classical-authentication finding exists, at info level, and is not alarmist.
	for _, f := range eval.Evaluate(modern(), now).Findings {
		if f.ID == "PQC.CLASSICAL-AUTH" && f.Severity != eval.Info {
			t.Errorf("classical certificates rated %s; want info", f.Severity)
		}
	}
}

// ---- determinism and serialisation ----------------------------------------------------------

func TestEvaluateIsDeterministicAndSerialisable(t *testing.T) {
	a, b := eval.Evaluate(terrible(), now), eval.Evaluate(terrible(), now)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("Evaluate is not deterministic")
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back eval.Evaluation
	if err := json.Unmarshal(raw, &back); err != nil || !reflect.DeepEqual(a, back) {
		t.Fatalf("JSON round trip differs: %v", err)
	}
	if a.Version != eval.Version {
		t.Errorf("version = %q", a.Version)
	}
}

// ---- AC-04.4: readiness verified against real servers -----------------------------------------

func scanReal(t *testing.T, cfg testserver.Config) eval.Evaluation {
	t.Helper()
	s := testserver.Start(t, cfg)
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: s.Host, Port: s.Port},
		tlsprobe.Options{Timeout: 3 * time.Second, Concurrency: 8})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return eval.Evaluate(rep, time.Now())
}

func TestReadinessAgainstRealServers(t *testing.T) {
	hybridSrv := scanReal(t, testserver.Config{MinVersion: tls.VersionTLS12,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})
	if r := hybridSrv.Readiness; r.Level != eval.LevelHybridNeg || r.HNDLExposed || r.KeyEstablishment.Evidence != eval.Observed {
		t.Errorf("hybrid server: %+v", r)
	}

	classical := scanReal(t, testserver.Config{MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519, tls.CurveP256}})
	if r := classical.Readiness; r.Level != eval.LevelExposed || !r.HNDLExposed {
		t.Errorf("classical TLS 1.3 server: %+v", r)
	}

	tls12 := scanReal(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if r := tls12.Readiness; r.Level != eval.LevelNotReady || !r.HNDLExposed {
		t.Errorf("TLS 1.2-only server: %+v", r)
	}
	if !ids(tls12)["PQC.NO-PQ-POSSIBLE"] || !ids(tls12)["PROTO.NO-TLS13"] {
		t.Errorf("TLS 1.2-only findings: %v", ids(tls12))
	}
	// The self-signed test certificate must be judged untrusted; a real scan carries real certificates.
	if !ids(classical)["CERT.UNTRUSTED"] {
		t.Errorf("findings = %v", ids(classical))
	}
}
