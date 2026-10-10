package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

func target(t testing.TB, s *testserver.Server) tlsprobe.Target {
	t.Helper()
	return tlsprobe.Target{Host: s.Host, Port: s.Port}
}

func opts() tlsprobe.Options {
	return tlsprobe.Options{Timeout: 3 * time.Second, Concurrency: 8}
}

func scan(t testing.TB, s *testserver.Server, o tlsprobe.Options) *tlsprobe.Report {
	t.Helper()
	rep, err := tlsprobe.Scan(context.Background(), target(t, s), o)
	if err != nil {
		t.Fatalf("Scan: %v\n%+v", err, rep)
	}
	return rep
}

func supported(rep *tlsprobe.Report) []string {
	var out []string
	for _, p := range rep.Protocols {
		if p.Supported {
			out = append(out, p.Version)
		}
	}
	return out
}

func suiteIDs(rep *tlsprobe.Report, version string) []uint16 {
	var out []uint16
	for _, s := range rep.Suites {
		if s.Version == version {
			out = append(out, s.ID)
		}
	}
	return out
}

func groupIDs(rep *tlsprobe.Report, version string) []uint16 {
	var out []uint16
	for _, g := range rep.Groups {
		if g.Version == version {
			out = append(out, g.ID)
		}
	}
	return out
}

func sameSet(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]uint16(nil), a...), append([]uint16(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// The core guarantee: what the scanner enumerates is exactly what the server is
// configured to accept.
func TestEnumeratesExactlyWhatTheServerIsConfiguredFor(t *testing.T) {
	want12 := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS12, Suites: want12, Cert: testserver.CertECDSA,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	})
	rep := scan(t, srv, opts())

	if got := supported(rep); strings.Join(got, ",") != "TLSv1.3,TLSv1.2" {
		t.Errorf("supported versions = %v, want TLSv1.3,TLSv1.2", got)
	}
	for _, p := range rep.Protocols {
		if p.Evidence == tlsprobe.EvidenceInconclusive {
			t.Errorf("%s inconclusive: %s", p.Version, p.Detail)
		}
	}

	if got := suiteIDs(rep, "TLSv1.2"); !sameSet(got, want12) {
		t.Errorf("TLSv1.2 suites = %v, want %v", got, want12)
	}
	// TLS 1.3 suites are fixed by crypto/tls.
	if got := suiteIDs(rep, "TLSv1.3"); !sameSet(got, []uint16{0x1301, 0x1302, 0x1303}) {
		t.Errorf("TLSv1.3 suites = %v", got)
	}

	// TLS 1.3 groups, learned from HelloRetryRequests, in the server's order.
	got13 := groupIDs(rep, "TLSv1.3")
	if want := []uint16{4588, 29, 23}; len(got13) != 3 || got13[0] != want[0] || got13[1] != want[1] || got13[2] != want[2] {
		t.Errorf("TLSv1.3 groups = %v, want %v in server order", got13, want)
	}
	// TLS 1.2 ECDHE curves: the hybrid is TLS 1.3-only, so it must not appear here.
	if got := groupIDs(rep, "TLSv1.2"); !sameSet(got, []uint16{29, 23}) {
		t.Errorf("TLSv1.2 curves = %v, want {29, 23}", got)
	}

	var sawHybrid bool
	for _, g := range rep.Groups {
		if g.ID == 4588 {
			sawHybrid = true
			if !g.PQ || !g.Hybrid || g.Name != "X25519MLKEM768" || g.IANARecommended != "Y" {
				t.Errorf("hybrid group described as %+v", g)
			}
		}
		if g.ID == 29 && g.PQ {
			t.Error("x25519 flagged as post-quantum")
		}
	}
	if !sawHybrid {
		t.Error("X25519MLKEM768 not detected")
	}

	// Registry properties travel with each suite.
	for _, s := range rep.Suites {
		if s.ID == tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 &&
			(s.Kx != "ECDHE" || s.Auth != "ECDSA" || s.Cipher != "AES" || s.KeyBits != 256 || !s.AEAD || !s.Ephemeral) {
			t.Errorf("suite properties: %+v", s)
		}
	}

	prefs := map[string]string{}
	for _, p := range rep.Preference {
		prefs[p.Version+"/"+p.Subject] = p.Order
	}
	// crypto/tls uses its own order for TLS 1.3 groups, follows the client for TLS 1.2
	// curves, and is mixed for TLS 1.2 suites (it flips ChaCha20/AES-GCM by client
	// order). Whatever it is, the scanner must report a real verdict, and ranks must
	// exist exactly when the order is the server's.
	if prefs["TLSv1.3/groups"] != "server" {
		t.Errorf("TLSv1.3 groups preference = %q, want server", prefs["TLSv1.3/groups"])
	}
	for k, v := range prefs {
		if v != "server" && v != "client" && v != "mixed" {
			t.Errorf("%s: preference %q is not a verdict", k, v)
		}
	}
	for _, s := range rep.Suites {
		if s.Version == "TLSv1.2" && (s.Rank != 0) != (prefs["TLSv1.2/suites"] == "server") {
			t.Errorf("rank %d with TLSv1.2 suite preference %q: %+v", s.Rank, prefs["TLSv1.2/suites"], s)
		}
	}
	if rep.Incomplete {
		t.Errorf("complete scan marked incomplete; notes=%v", rep.Notes)
	}
	if rep.Connections < 10 || rep.Connections > 400 {
		t.Errorf("used %d connections", rep.Connections)
	}
}

func TestClassicalOnlyServerHasNoPostQuantumGroup(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519, tls.CurveP256},
	})
	rep := scan(t, srv, opts())
	for _, g := range rep.Groups {
		if g.PQ {
			t.Errorf("PQ group reported for a classical-only server: %+v", g)
		}
	}
	if !sameSet(groupIDs(rep, "TLSv1.3"), []uint16{29, 23}) {
		t.Errorf("groups = %v", groupIDs(rep, "TLSv1.3"))
	}
	if rep.Negotiated == nil || rep.Negotiated.PQ || rep.Negotiated.GroupID == 0 {
		t.Errorf("negotiated = %+v", rep.Negotiated)
	}
}

func TestNegotiatedShowsHybridWhenAvailable(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})
	n := scan(t, srv, opts()).Negotiated
	if n == nil || n.Error != "" || n.Version != "TLSv1.3" || n.GroupID != 4588 || !n.PQ || n.Group != "X25519MLKEM768" {
		t.Errorf("negotiated = %+v", n)
	}
}

func TestOldProtocolOnlyServer(t *testing.T) {
	want := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10, Suites: want, Cert: testserver.CertRSA,
	})
	rep := scan(t, srv, opts())

	if got := supported(rep); strings.Join(got, ",") != "TLSv1.0" {
		t.Errorf("supported = %v, want only TLSv1.0", got)
	}
	for _, p := range rep.Protocols {
		if p.Version == "TLSv1.1" && !strings.Contains(p.Detail, "TLSv1.0") {
			t.Errorf("TLSv1.1 probe detail %q should say the server chose TLSv1.0", p.Detail)
		}
	}
	if got := suiteIDs(rep, "TLSv1.0"); !sameSet(got, want) {
		t.Errorf("TLSv1.0 suites = %v, want %v", got, want)
	}
	if rep.Features.FallbackSCSV != nil {
		t.Error("FALLBACK_SCSV tested on a single-version server")
	}
}

func TestCertificatesAndTrust(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Cert: testserver.CertBoth})
	rep := scan(t, srv, opts())

	algs := map[string]bool{}
	for _, c := range rep.Certificates {
		if len(c.Chain) == 0 {
			t.Fatal("certificate result without a chain")
		}
		leaf := c.Chain[0]
		algs[leaf.PublicKey.Algorithm] = true
		if c.Trusted || c.TrustError != "" {
			t.Errorf("the OS store must not be consulted unless OSTrust is set: %+v", c)
		}
		if leaf.DER == "" || leaf.SPKISHA256 == "" {
			t.Errorf("tls-report/2 raw certificate missing: %+v", leaf)
		}
		if !c.NameMatches {
			t.Errorf("127.0.0.1 is a SAN of the test certificate: %s", c.NameError)
		}
		if !leaf.SelfSigned || leaf.SHA256 == "" || leaf.SignatureAlg.OID == "" || leaf.PublicKey.OID == "" {
			t.Errorf("leaf description incomplete: %+v", leaf)
		}
		switch leaf.PublicKey.Algorithm {
		case "RSA":
			if leaf.PublicKey.Bits != 2048 || leaf.PublicKey.OID != "1.2.840.113549.1.1.1" {
				t.Errorf("RSA key: %+v", leaf.PublicKey)
			}
		case "ECDSA":
			if leaf.PublicKey.Curve != "P-256" || leaf.PublicKey.Bits != 256 || leaf.PublicKey.OID != "1.2.840.10045.2.1" {
				t.Errorf("ECDSA key: %+v", leaf.PublicKey)
			}
		}
	}
	if !algs["RSA"] || !algs["ECDSA"] {
		t.Errorf("a dual-certificate server must yield both; got %v from %d results", algs, len(rep.Certificates))
	}
}

func TestClientCertRequested(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert})
	got := scan(t, srv, opts()).Features.ClientCertRequested
	if got == nil || !*got {
		t.Errorf("ClientCertRequested = %v, want true: the server sent a CertificateRequest", got)
	}
}

func TestClientCertNotRequested(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	got := scan(t, srv, opts()).Features.ClientCertRequested
	if got == nil || *got {
		t.Errorf("ClientCertRequested = %v, want false: a full handshake completed without a request", got)
	}
}

func TestHSTSNotCheckedByDefault(t *testing.T) {
	called := false
	cfg := testserver.Config{MinVersion: tls.VersionTLS12, HTTPResponse: func(req []byte) []byte {
		if len(req) > 0 { // a plain handshake-then-close also reaches this callback, with an empty read
			called = true
		}
		return []byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n")
	}}

	without := scan(t, testserver.Start(t, cfg), opts())
	if without.HSTS != nil {
		t.Errorf("HSTS = %v, want nil: --http-checks was not set", without.HSTS)
	}
	if called {
		t.Error("an HTTP request was sent although HTTPChecks was not set")
	}

	o := opts()
	o.HTTPChecks = true
	with := scan(t, testserver.Start(t, cfg), o)
	if with.Connections != without.Connections+1 {
		t.Errorf("HTTPChecks should add exactly one connection: without=%d with=%d", without.Connections, with.Connections)
	}
}

func TestHSTSPresent(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, HTTPResponse: func([]byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Length: 0\r\n\r\n")
	}})
	o := opts()
	o.HTTPChecks = true
	rep := scan(t, srv, o)
	if rep.HSTS == nil || !*rep.HSTS {
		t.Errorf("HSTS = %v, want true", rep.HSTS)
	}
}

func TestHSTSAbsent(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, HTTPResponse: func([]byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	}})
	o := opts()
	o.HTTPChecks = true
	rep := scan(t, srv, o)
	if rep.HSTS == nil || *rep.HSTS {
		t.Errorf("HSTS = %v, want false", rep.HSTS)
	}
}

func TestHSTSNilWhenNotSpeakingHTTP(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, HTTPResponse: func([]byte) []byte {
		return []byte("\x02\x01\x00garbage, not HTTP at all\r\n")
	}})
	o := opts()
	o.HTTPChecks = true
	rep := scan(t, srv, o)
	if rep.HSTS != nil {
		t.Errorf("HSTS = %v, want nil: the response was not HTTP", rep.HSTS)
	}
	// REQ-THTP-3: not an HTTP service is "not applicable", not a failure.
	for _, s := range rep.Stages {
		if s.Name == tlsprobe.StageHTTP && (s.Outcome != tlsprobe.OutcomeSkipped || s.ReasonCode != tlsprobe.ReasonNotApplicable) {
			t.Errorf("http stage on a non-HTTP service: %+v", s)
		}
	}
}

// REQ-TTRS-3: the machine's own store is an opt-in extra.
func TestOSTrustIsOptIn(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	o := opts()
	o.OSTrust = true
	for _, c := range scan(t, srv, o).Certificates {
		if c.Trusted || c.TrustError == "" {
			t.Errorf("with OSTrust, a self-signed certificate must carry the OS verdict: %+v", c)
		}
	}
}

func TestSkipCertificates(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	o := opts()
	o.SkipCertificates = true
	rep := scan(t, srv, o)
	if len(rep.Certificates) != 0 || rep.Negotiated != nil {
		t.Errorf("certificates fetched despite SkipCertificates: %+v", rep)
	}
}

func TestNameMismatchIsReported(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	o := opts()
	o.LookupIP = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "other.example", Port: srv.Port, SNI: "other.example"}, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Certificates) == 0 || rep.Certificates[0].NameMatches || rep.Certificates[0].NameError == "" {
		t.Errorf("certificate for localhost must not match other.example: %+v", rep.Certificates)
	}
}

// ---- endpoints that cannot be scanned ------------------------------------------------

func TestPlainHTTPPortIsRecognised(t *testing.T) {
	srv := testserver.StartScript(t, func([]byte) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") })
	rep, err := tlsprobe.Scan(context.Background(), target(t, srv), opts())
	if err == nil || !strings.Contains(err.Error(), "not with TLS") {
		t.Errorf("err = %v", err)
	}
	if rep == nil || len(supported(rep)) != 0 {
		t.Errorf("report = %+v", rep)
	}
}

func TestClosedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	_, err = tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "127.0.0.1", Port: port}, opts())
	if err == nil || !strings.Contains(err.Error(), "no response") {
		t.Errorf("err = %v", err)
	}
}

func TestSilentServerTimesOut(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }() // accept and say nothing, until the test ends
		}
	}()
	o := opts()
	o.Timeout = 250 * time.Millisecond
	start := time.Now()
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}, o)
	if err == nil || !strings.Contains(err.Error(), "no response") {
		t.Errorf("err = %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("a silent server stalled the scan")
	}
	if rep == nil || !rep.Incomplete {
		t.Errorf("report should be incomplete: %+v", rep)
	}
}

func TestUnresolvableName(t *testing.T) {
	o := opts()
	o.LookupIP = func(context.Context, string) ([]net.IP, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "nope.invalid"}
	}
	_, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "nope.invalid", Port: 443}, o)
	if err == nil || !strings.Contains(err.Error(), "resolving") {
		t.Errorf("err = %v", err)
	}
}

// ---- safety limits ---------------------------------------------------------------------

func TestConnectionBudgetIsAHardCap(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	o := opts()
	o.MaxConnections = 12
	rep, _ := tlsprobe.Scan(context.Background(), target(t, srv), o)
	if rep.Connections > 12 {
		t.Errorf("made %d connections with a budget of 12", rep.Connections)
	}
	if !rep.Incomplete {
		t.Error("a budget-limited scan must be marked incomplete")
	}
}

func TestCancellationStopsTheScan(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	rep, err := tlsprobe.Scan(ctx, target(t, srv), opts())
	if err == nil || rep == nil || !rep.Incomplete {
		t.Errorf("err=%v rep=%+v", err, rep)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("cancelled scan kept running")
	}
}

func TestSpacingBetweenConnections(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519}})
	o := opts()
	o.MinInterval = 20 * time.Millisecond
	o.SkipCertificates = true
	start := time.Now()
	rep := scan(t, srv, o)
	if min := time.Duration(rep.Connections-1) * o.MinInterval; time.Since(start) < min {
		t.Errorf("%d connections in %v; spacing of %v requires at least %v", rep.Connections, time.Since(start), o.MinInterval, min)
	}
}

func TestParseTarget(t *testing.T) {
	for in, want := range map[string]tlsprobe.Target{
		"example.org":       {Host: "example.org", Port: 443, SNI: "example.org"},
		"example.org:8443":  {Host: "example.org", Port: 8443, SNI: "example.org"},
		"10.0.0.1":          {Host: "10.0.0.1", Port: 443},
		"10.0.0.1:993":      {Host: "10.0.0.1", Port: 993},
		"[2001:db8::1]:443": {Host: "2001:db8::1", Port: 443},
		"2001:db8::1":       {Host: "2001:db8::1", Port: 443},
	} {
		got, err := tlsprobe.ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	if got, err := tlsprobe.ParseTarget("  example.org "); err != nil || got.Host != "example.org" {
		t.Errorf("surrounding whitespace not trimmed: %+v, %v", got, err)
	}
	for _, bad := range []string{"", " ", "host:0", "host:70000", "host:abc", ":443", "a:b:c"} {
		if _, err := tlsprobe.ParseTarget(bad); err == nil {
			t.Errorf("ParseTarget(%q) accepted", bad)
		}
	}
}
