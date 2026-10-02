package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
	"github.com/example/cipherhorizon/internal/tlsprobe"
	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

func stageMap(rep *tlsprobe.Report) map[string]tlsprobe.Stage {
	m := map[string]tlsprobe.Stage{}
	for _, s := range rep.Stages {
		m[s.Name] = s
	}
	return m
}

func TestStagesRecorded(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12})
	rep := scan(t, srv, opts())
	if rep.SchemaVersion != "tls-report/2" {
		t.Errorf("schema %s", rep.SchemaVersion)
	}
	var names []string
	sum := 0
	for _, s := range rep.Stages {
		names = append(names, s.Name)
		sum += s.Connections
		if s.Outcome == tlsprobe.OutcomeDone && len(s.Probes) == 0 {
			t.Errorf("%s: done without saying what was sent", s.Name)
		}
	}
	if got := strings.Join(names, ","); got != strings.Join(tlsprobe.StageNames, ",") {
		t.Errorf("stages %s", got)
	}
	if sum != rep.Connections {
		t.Errorf("stage connections add up to %d, the scan made %d", sum, rep.Connections)
	}
	st := stageMap(rep)
	if h := st["http"]; h.Outcome != tlsprobe.OutcomeSkipped || h.ReasonCode != tlsprobe.ReasonOptionOff || h.Reason == "" {
		t.Errorf("http stage with HTTPChecks off: %+v", h)
	}
	for _, n := range []string{"protocols", "suites", "key-exchange", "features", "certificates", "revocation"} {
		if st[n].Outcome != tlsprobe.OutcomeDone {
			t.Errorf("%s: %+v", n, st[n])
		}
	}

	o := opts()
	o.SkipCertificates = true
	st = stageMap(scan(t, srv, o))
	if st["certificates"].ReasonCode != tlsprobe.ReasonOptionOff || st["revocation"].ReasonCode != tlsprobe.ReasonOptionOff {
		t.Errorf("SkipCertificates: %+v %+v", st["certificates"], st["revocation"])
	}
	if st["http"].ReasonCode != tlsprobe.ReasonOptionOff {
		t.Errorf("http: %+v", st["http"])
	}
}

func TestStagesTLS13Only(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13})
	st := stageMap(scan(t, srv, opts()))
	if k := st["key-exchange"]; k.Outcome != tlsprobe.OutcomeDone || !strings.Contains(k.Reason, "TLS 1.3 only") {
		t.Errorf("key-exchange on a TLS 1.3-only server: %+v", k)
	}
	if f := st["features"]; f.Outcome != tlsprobe.OutcomeSkipped || f.ReasonCode != tlsprobe.ReasonNotApplicable {
		t.Errorf("features on a TLS 1.3-only server: %+v", f)
	}
}

func TestStagesUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "127.0.0.1", Port: addr.Port}, opts())
	if err == nil {
		t.Fatal("scan of a closed port succeeded")
	}
	if len(rep.Stages) != len(tlsprobe.StageNames) {
		t.Fatalf("stages %+v", rep.Stages)
	}
	for _, s := range rep.Stages[1:] {
		if s.Outcome != tlsprobe.OutcomeSkipped || s.ReasonCode != tlsprobe.ReasonNotReached {
			t.Errorf("%s: %+v", s.Name, s)
		}
	}
}

// namedTarget scans the server under a DNS name (so SNI is sent), resolving
// the name to the server's address and recording every lookup and dial.
type recorder struct {
	mu      sync.Mutex
	dials   []string
	lookups []string
}

func namedScan(t *testing.T, srv *testserver.Server, o tlsprobe.Options, rec *recorder) *tlsprobe.Report {
	t.Helper()
	if rec == nil {
		rec = &recorder{}
	}
	o.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		rec.mu.Lock()
		rec.lookups = append(rec.lookups, host)
		rec.mu.Unlock()
		return []net.IP{net.ParseIP(srv.Host)}, nil
	}
	d := &net.Dialer{}
	o.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rec.mu.Lock()
		rec.dials = append(rec.dials, addr)
		rec.mu.Unlock()
		return d.DialContext(ctx, network, addr)
	}
	rep, err := tlsprobe.Scan(context.Background(), tlsprobe.Target{Host: "leaf.test", Port: srv.Port, SNI: "leaf.test"}, o)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return rep
}

func TestRawChainStapleAndSCTs(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "Inter", pkitest.CAOpts{})
	cert := inter.TLS(t, pkitest.LeafOpts{DNS: []string{"leaf.test"}}, inter.Cert)
	staple := []byte{0x30, 0x03, 0x0a, 0x01, 0x03} // any bytes: the scanner keeps, evaluation decodes
	cert.OCSPStaple = staple
	sct := pkitest.SCT(pkitest.SCTSpec{LogID: [32]byte{7}, Timestamp: pkitest.Epoch})
	cert.SignedCertificateTimestamps = [][]byte{sct}
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{cert}})

	rep := namedScan(t, srv, opts(), nil)
	if len(rep.Certificates) != 1 {
		t.Fatalf("certificates: %+v", rep.Certificates)
	}
	c := rep.Certificates[0]
	if len(c.Chain) != 2 {
		t.Fatalf("chain of %d", len(c.Chain))
	}
	var der [][]byte
	for _, ci := range c.Chain {
		b, err := base64.StdEncoding.DecodeString(ci.DER)
		if err != nil {
			t.Fatal(err)
		}
		der = append(der, b)
	}
	served, err := pki.AnalyzeServed(der)
	if err != nil || len(served.Path) != 2 || len(served.Issues) != 0 {
		t.Errorf("served chain from the report: %+v %v", served, err)
	}
	if got, _ := base64.StdEncoding.DecodeString(c.OCSPStaple); string(got) != string(staple) {
		t.Errorf("staple %x", got)
	}
	if len(c.TLSSCTs) != 1 {
		t.Fatalf("TLS SCTs %v", c.TLSSCTs)
	}
	b, _ := base64.StdEncoding.DecodeString(c.TLSSCTs[0])
	if s, err := pki.ParseSCT(b); err != nil || s.LogID[0] != 7 {
		t.Errorf("SCT %+v %v", s, err)
	}
	if rep.NoSNI != "same" {
		t.Errorf("NoSNI = %q, want same", rep.NoSNI)
	}
	// 90 days between the dates, both ends inclusive: 90 days and a second.
	if c.Chain[0].LifetimeDays != 91 || len(c.Chain[0].ExtKeyUsage) != 1 {
		t.Errorf("extension facts missing: %+v", c.Chain[0])
	}
}

func TestNoSNIDifferent(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	main := root.TLS(t, pkitest.LeafOpts{DNS: []string{"leaf.test"}})
	fallback := root.TLS(t, pkitest.LeafOpts{CN: "default.test", DNS: []string{"default.test"}})
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{main}, NoSNI: &fallback})
	rep := namedScan(t, srv, opts(), nil)
	if rep.NoSNI != "different" {
		t.Fatalf("NoSNI = %q", rep.NoSNI)
	}
	var found bool
	for _, c := range rep.Certificates {
		if c.NoSNI {
			found = true
			if c.Chain[0].Subject != "CN=default.test" {
				t.Errorf("no-SNI chain %s", c.Chain[0].Subject)
			}
		} else if c.Chain[0].Subject != "CN=leaf.test" {
			t.Errorf("SNI chain %s", c.Chain[0].Subject)
		}
	}
	if !found {
		t.Error("no certificate result marked NoSNI")
	}
}

// TestTargetOnlyTraffic is SR-19: a standard scan, HTTP stage included,
// resolves only the target's name and dials only the target's address.
func TestTargetOnlyTraffic(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	cert := root.TLS(t, pkitest.LeafOpts{DNS: []string{"leaf.test"}, OCSP: []string{"http://ocsp.elsewhere.test/"},
		AIA: []string{"http://ca.elsewhere.test/i.der"}, CRL: []string{"http://crl.elsewhere.test/c.crl"}})
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{cert},
		HTTPResponse: func([]byte) []byte { return []byte("HTTP/1.1 301 Moved\r\nLocation: https://elsewhere.test/\r\n\r\n") }})
	o := opts()
	o.HTTPChecks = true
	rec := &recorder{}
	rep := namedScan(t, srv, o, rec)
	want := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	for _, d := range rec.dials {
		if d != want {
			t.Errorf("dialled %s; only %s is allowed", d, want)
		}
	}
	for _, l := range rec.lookups {
		if l != "leaf.test" {
			t.Errorf("looked up %s", l)
		}
	}
	if len(rec.dials) != rep.Connections {
		t.Errorf("%d dials recorded, report says %d connections", len(rec.dials), rep.Connections)
	}
}

func TestHSTSHeaderParsedInScan(t *testing.T) {
	cfg := testserver.Config{MinVersion: tls.VersionTLS12, HTTPResponse: func([]byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=0\r\nStrict-Transport-Security: max-age=600\r\n\r\n")
	}}
	o := opts()
	o.HTTPChecks = true
	rep := scan(t, testserver.Start(t, cfg), o)
	h := rep.HSTSHeader
	if h == nil || len(h.Values) != 2 || h.MaxAge == nil || *h.MaxAge != 0 || len(h.Problems) != 1 {
		t.Fatalf("HSTS header %+v", h)
	}
	if rep.HSTS == nil || *rep.HSTS {
		t.Errorf("an invalid (duplicated) header must not count as HSTS: %v", rep.HSTS)
	}
	if st := stageMap(rep)["http"]; st.Outcome != tlsprobe.OutcomeDone || st.Connections != 1 {
		t.Errorf("http stage %+v", st)
	}
}

func TestParseHSTS(t *testing.T) {
	i := func(v int64) *int64 { return &v }
	cases := []struct {
		in       []string
		maxAge   *int64
		subs     bool
		problems int
	}{
		{nil, nil, false, 0},
		{[]string{"max-age=31536000; includeSubDomains; preload"}, i(31536000), true, 0},
		{[]string{`MAX-AGE="600"`}, i(600), false, 0},
		{[]string{"max-age=0"}, i(0), false, 0},
		{[]string{"includeSubDomains"}, nil, true, 1},
		{[]string{"max-age=abc"}, nil, false, 1},
		{[]string{"max-age=1; max-age=2"}, i(1), false, 1},
		{[]string{"max-age=1; includeSubDomains=yes"}, i(1), false, 1},
		{[]string{"max-age=1;;unknown=x"}, i(1), false, 0},
		{[]string{"max-age=99999999999999999999999"}, i(9223372036854775807), false, 0},
		{[]string{`max-age="5`}, nil, false, 1},
		{[]string{"max-age=1", "max-age=2"}, i(1), false, 1},
	}
	for _, c := range cases {
		h := tlsprobe.ParseHSTS(c.in)
		if (h.MaxAge == nil) != (c.maxAge == nil) || (h.MaxAge != nil && *h.MaxAge != *c.maxAge) || h.IncludeSubDomains != c.subs || len(h.Problems) != c.problems {
			t.Errorf("%q: maxAge %v subs %v problems %v", c.in, h.MaxAge, h.IncludeSubDomains, h.Problems)
		}
	}
	long := tlsprobe.ParseHSTS([]string{"max-age=1; " + strings.Repeat("x", 2000) + "\x00\x1b"})
	if len(long.Values[0]) > 512 || strings.ContainsAny(long.Values[0], "\x00\x1b") {
		t.Errorf("value not cleaned/bounded: %d bytes", len(long.Values[0]))
	}
	if h := tlsprobe.ParseHSTS([]string{"a", "b", "c", "d", "e"}); len(h.Values) != 4 {
		t.Errorf("kept %d values", len(h.Values))
	}
}

func FuzzParseHSTS(f *testing.F) {
	for _, s := range []string{"max-age=31536000; includeSubDomains", `max-age="1"; preload`, "max-age=1;max-age=2", ";;;", `"`} {
		f.Add(s, "")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		vals := []string{a}
		if b != "" {
			vals = append(vals, b)
		}
		h := tlsprobe.ParseHSTS(vals)
		for _, v := range h.Values {
			if len(v) > 512+4 {
				t.Fatalf("value of %d bytes kept", len(v))
			}
		}
		if h.Valid() && (h.MaxAge == nil || *h.MaxAge < 0) {
			t.Fatal("valid without a max-age")
		}
	})
}
