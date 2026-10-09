package reportpdf

import (
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/eval"
	"github.com/example/cipherhorizon/internal/pdf/pdfcheck"
	"github.com/example/cipherhorizon/internal/tlsprobe"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// legacyServer is a deliberately bad endpoint whose certificate carries hostile text.
func legacyServer() *tlsprobe.Report {
	yes, no := true, false
	return &tlsprobe.Report{
		SchemaVersion: "tls-report/1",
		Target:        tlsprobe.Target{Host: "legacy.example", Port: 443},
		Address:       "192.0.2.10:443",
		Started:       now.Add(-time.Hour),
		DurationMS:    2300,
		Connections:   120,
		Protocols: []tlsprobe.ProtocolResult{
			{Version: "TLSv1.3", Supported: false, Evidence: "alert"},
			{Version: "TLSv1.2", Supported: true, Evidence: "server-hello"},
			{Version: "SSLv3", Supported: true, Evidence: "server-hello"},
		},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.2", Name: "TLS_RSA_WITH_RC4_128_SHA", Cipher: "RC4", KeyBits: 128, Mode: "STREAM", Kx: "RSA", IANARecommended: "D", Rank: 1},
			{Version: "TLSv1.2", Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Cipher: "AES", KeyBits: 128, Mode: "GCM", Kx: "ECDHE", Ephemeral: true, AEAD: true, IANARecommended: "Y", Rank: 2},
		},
		Groups:   []tlsprobe.GroupResult{{Version: "TLSv1.2", Name: "secp256r1", IANARecommended: "Y", Rank: 1}},
		Features: tlsprobe.Features{SecureRenegotiation: &yes, Compression: &no, FallbackSCSV: &no},
		Certificates: []tlsprobe.CertResult{{
			Source: "tls-default",
			Chain: []tlsprobe.CertInfo{{
				Subject: `CN=<img src=x onerror=alert(1)> (evil) \ name`, Issuer: "CN=Example CA,O=Example",
				SerialHex: "0a", NotBefore: now.Add(-60 * 24 * time.Hour), NotAfter: now.Add(20 * 24 * time.Hour),
				DNSNames: []string{"legacy.example"}, SHA256: strings.Repeat("ab", 32),
				PublicKey:    tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 1024},
				SignatureAlg: tlsprobe.AlgInfo{Name: "SHA1-RSA"},
			}},
			NameMatches: true,
		}},
		HSTS: &no,
	}
}

func render(t *testing.T, kind string) pdfcheck.Info {
	t.Helper()
	rep := legacyServer()
	ev := eval.Evaluate(rep, now)
	b, err := Endpoint(EndpointInput{Name: "legacy-web", Address: "legacy.example:443", ScanID: 7, Report: rep, Eval: &ev, Kind: kind, Version: "test", Generated: now})
	if err != nil {
		t.Fatal(err)
	}
	info, err := pdfcheck.Check(b)
	if err != nil {
		t.Fatalf("%s: not a well-formed PDF: %v", kind, err)
	}
	return info
}

func TestEndpointReportHasEverySectionAndFinding(t *testing.T) {
	info := render(t, KindFull)
	rep := legacyServer()
	ev := eval.Evaluate(rep, now)
	for _, want := range []string{"legacy-web", "TLS SECURITY REPORT", "PQC READINESS", "TLS HYGIENE", "Fix first", "Sections at a glance",
		"Protocols", "Cipher suites", "Vulnerabilities", "About this report", "How the TLS hygiene score was worked out",
		"TLS_RSA_WITH_RC4_128_SHA", "Page 1 of", "What each TLS version ran", "Every check run", "PASSED", "ON: TURN OFF"} {
		if !strings.Contains(info.Text, want) {
			t.Errorf("full report lacks %q", want)
		}
	}
	// Every finding the evaluation made is in the report, with its fix.
	for _, f := range ev.Findings {
		if !strings.Contains(info.Text, f.Title) {
			t.Errorf("finding %s (%q) is missing", f.ID, f.Title)
		}
	}
	// Hostile certificate text is shown as text, verbatim.
	if !strings.Contains(info.Text, `<img src=x onerror=alert(1)> (evil) \ name`) {
		t.Error("hostile subject not shown verbatim")
	}
	if info.Pages < 3 {
		t.Errorf("expected a multi-page report, got %d pages", info.Pages)
	}
	if len(info.Outline) < 8 || info.Outline[0] != "Certificates & trust" {
		t.Errorf("outline: %q", info.Outline)
	}
	for _, l := range info.Links {
		if !strings.HasPrefix(l, "https://") && !strings.HasPrefix(l, "http://") {
			t.Errorf("non-http link %q", l)
		}
	}
	if len(info.Links) == 0 {
		t.Error("finding sources are links")
	}
}

func TestReportKindsChooseTheirSections(t *testing.T) {
	tls := render(t, KindTLS)
	cert := render(t, KindCert)
	if !strings.Contains(tls.Text, "TLS CONFIGURATION REPORT") || strings.Contains(tls.Text, "Every certificate, field by field") {
		t.Error("the TLS report is about the TLS configuration")
	}
	for _, s := range []string{"Certificates & trust", "Revocation & transparency"} {
		if contains(tls.Outline, s) {
			t.Errorf("TLS report has section %s", s)
		}
		if !contains(cert.Outline, s) {
			t.Errorf("certificate report lacks section %s", s)
		}
	}
	if !strings.Contains(cert.Text, "Every certificate, field by field") || !strings.Contains(cert.Text, "SHA1-RSA") || contains(cert.Outline, "Cipher suites") {
		t.Errorf("the certificate report lists every field and no TLS sections: %q", cert.Outline)
	}
	if ValidKind("pdf") || !ValidKind(KindCert) {
		t.Error("ValidKind")
	}
}

func TestInventoryReport(t *testing.T) {
	left := 12
	in := InventoryInput{
		Version: "test", Generated: now,
		Totals:  map[string]int{"algorithm": 2, "key": 1, "protocol": 2, "endpoints": 2, "machines": 1},
		Quantum: map[string]int{"vulnerable": 2, "safe": 1},
		Algorithms: []InvItem{
			{Name: "RSA", Kind: "algorithm", Detail: "pke", Purpose: "Public-key encryption", Quantum: "quantum-vulnerable", Endpoints: 2, Places: []string{"a", "b"}, LastSeen: now},
			{Name: "AES-128-GCM", Kind: "algorithm", Detail: "ae · 128", Purpose: "Symmetric encryption", Quantum: "quantum-safe", Endpoints: 2, LastSeen: now},
		},
		Keys:      []InvItem{{Name: "CN=web.example public key", Kind: "key", Quantum: "quantum-vulnerable", Machines: 1}},
		Protocols: []InvItem{{Name: "TLSv1.3", Kind: "protocol", Endpoints: 2}, {Name: "SSLv3", Kind: "protocol", Legacy: true, Endpoints: 1}},
		ByPurpose: []InvPurpose{{Purpose: "Public-key encryption", Vulnerable: 1}, {Purpose: "Symmetric encryption", Safe: 1}},
		Certs:     []InvCert{{Name: "CN=web.example", Issuer: "CN=Example CA", Key: "RSA 2048", NotAfter: now.Add(12 * 24 * time.Hour).Format(time.RFC3339), DaysLeft: &left}},
		Sources:   []InvSource{{Label: "web", Kind: "endpoint", When: now, Items: 3}, {Label: "db-01", Kind: "machine", When: now.Add(-50 * time.Hour), Items: 9}},
	}
	in.Replace = []InvItem{in.Algorithms[0], in.Keys[0]}
	in.CertCounts.Total, in.CertCounts.Within30 = 1, 1
	b, err := Inventory(in)
	if err != nil {
		t.Fatal(err)
	}
	info, err := pdfcheck.Check(b)
	if err != nil {
		t.Fatalf("not a well-formed PDF: %v", err)
	}
	for _, want := range []string{"Cryptographic inventory", "Post-quantum status", "Replace first", "web.example", "DEPRECATED", "12 DAYS",
		"Algorithms (2)", "Sources", "db-01", "2 days ago", "public-key encryption"} {
		if !strings.Contains(info.Text, want) {
			t.Errorf("inventory report lacks %q", want)
		}
	}
	if strings.Contains(info.Text, "CN=web.example public key") {
		t.Error("a certificate key is named by its common name")
	}
}

// PRD-007 REQ-BR-6: every report cover carries the flat lockup, the Offset credit and the standards.
func TestPDFCarriesTheLockup(t *testing.T) {
	info := render(t, "full")
	for _, want := range []string{"CipherHorizon", "TLS and post-quantum scanner", "NIST IR 8547", "FIPS 203/204/205", "CycloneDX"} {
		if !strings.Contains(info.Text, want) {
			t.Errorf("the cover lacks %q", want)
		}
	}
}
