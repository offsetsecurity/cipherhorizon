package namefind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDNS answers from maps. A name with no entry does not exist.
type fakeDNS struct {
	a      map[string][]string
	cname  map[string]string
	mx, ns []string
	txt    map[string][]string
	srv    map[string][]string
	any    []string // what the zone answers for any other name (a wildcard)
}

func nx(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	addrs := f.a[host]
	if c, ok := f.cname[host]; ok && addrs == nil {
		addrs = f.a[c]
	}
	if addrs == nil {
		addrs = f.any
	}
	if addrs == nil {
		return nil, nx(host)
	}
	var out []net.IPAddr
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (f *fakeDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cname[host]; ok {
		return c + ".", nil
	}
	return host + ".", nil
}

func (f *fakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	var out []*net.MX
	for _, h := range f.mx {
		out = append(out, &net.MX{Host: h + "."})
	}
	return out, nil
}

func (f *fakeDNS) LookupNS(context.Context, string) ([]*net.NS, error) {
	var out []*net.NS
	for _, h := range f.ns {
		out = append(out, &net.NS{Host: h + "."})
	}
	return out, nil
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if t, ok := f.txt[name]; ok {
		return t, nil
	}
	return nil, nx(name)
}

func (f *fakeDNS) LookupSRV(_ context.Context, service, proto, _ string) (string, []*net.SRV, error) {
	var out []*net.SRV
	for _, h := range f.srv[service+"/"+proto] {
		out = append(out, &net.SRV{Target: h + "."})
	}
	if out == nil {
		return "", nil, nx(service)
	}
	return "", out, nil
}

type fakeCT struct {
	names []string
	err   error
}

func (fakeCT) Name() string { return "the test log search" }
func (f fakeCT) Search(context.Context, string) ([]string, error) {
	return f.names, f.err
}

// openPorts makes a Dial that succeeds for the listed "address:port" pairs.
func openPorts(pairs ...string) (func(context.Context, string, int) (net.Conn, error), *int) {
	set := map[string]bool{}
	for _, p := range pairs {
		set[p] = true
	}
	var mu sync.Mutex
	dials := 0
	return func(_ context.Context, addr string, port int) (net.Conn, error) {
		mu.Lock()
		dials++
		mu.Unlock()
		if set[fmt.Sprintf("%s:%d", addr, port)] {
			a, b := net.Pipe()
			_ = b.Close()
			return a, nil
		}
		return nil, errors.New("connection refused")
	}, &dials
}

func byName(res *Result) map[string]Name {
	m := map[string]Name{}
	for _, n := range res.Names {
		m[n.Name] = n
	}
	return m
}

func report(res *Result, id string) SourceReport {
	for _, s := range res.Sources {
		if s.ID == id {
			return s
		}
	}
	return SourceReport{}
}

func TestRunCombinesSourcesAndSaysWhereEachNameCameFrom(t *testing.T) {
	dns := &fakeDNS{
		a: map[string][]string{
			"example.com": {"192.0.2.1"}, "www.example.com": {"192.0.2.1"}, "mail.example.com": {"192.0.2.25"},
			"ns1.example.com": {"192.0.2.53"}, "api.example.com": {"192.0.2.2"}, "lb.example.com": {"192.0.2.3"},
			"vpn.example.com": {"192.0.2.9"}, "shop.saas.test": {"203.0.113.5"}, "inside.example.com": {"127.0.0.1"},
		},
		cname: map[string]string{"portal.example.com": "lb.example.com", "shop.example.com": "shop.saas.test"},
		mx:    []string{"mail.example.com"}, ns: []string{"ns1.example.com", "ns.provider.test"},
		txt: map[string][]string{"example.com": {"v=spf1 a:vpn.example.com include:_spf.example.com include:spf.supplier.test -all"},
			"_spf.example.com": {"v=spf1 mx:mail.example.com ~all"}},
		srv: map[string][]string{"sip/tls": {"sip.example.com"}},
	}
	dial, _ := openPorts("192.0.2.1:443", "192.0.2.25:25", "192.0.2.2:443", "192.0.2.2:8443", "192.0.2.9:22", "203.0.113.5:443", "192.0.2.3:443")
	res, err := Run(context.Background(), Options{
		Domain: "Example.COM.", Sources: []string{SourceStored, SourceDNS, SourceCT, SourceList},
		Stored:   []string{"api.example.com", "*.apps.example.com", "other.test"},
		List:     []string{"shop.example.com", "inside.example.com", "elsewhere.test", "gone.example.com"},
		CT:       fakeCT{names: []string{"portal.example.com", "www.example.com", "*.example.com", "api.example.com"}},
		Resolver: dns, Dial: dial, QPS: 1000,
		CheckIP: func(_ string, ip net.IP) error {
			if ip.IsLoopback() {
				return errors.New("loopback is not allowed")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := byName(res)
	for name, want := range map[string]struct {
		sources string
		ports   string
	}{
		"example.com":        {"ct,domain", "[443]"},
		"www.example.com":    {"ct", "[443]"},
		"api.example.com":    {"ct,stored", "[443 8443]"},
		"mail.example.com":   {"dns", "[25]"},
		"ns1.example.com":    {"dns", "[]"},
		"vpn.example.com":    {"dns", "[22]"},
		"portal.example.com": {"ct", "[443]"},
		"lb.example.com":     {"dns", "[443]"}, // found as the target of the alias portal
		"shop.example.com":   {"list", "[443]"},
		"gone.example.com":   {"list", "[]"},
		"apps.example.com":   {"stored", "[]"},
	} {
		n, ok := got[name]
		if !ok {
			t.Errorf("%s not found", name)
			continue
		}
		if s := strings.Join(n.Sources, ","); s != want.sources {
			t.Errorf("%s sources = %s, want %s", name, s, want.sources)
		}
		if p := fmt.Sprint(n.Ports); p != want.ports {
			t.Errorf("%s ports = %s, want %s", name, p, want.ports)
		}
	}
	if n := got["shop.example.com"]; !n.External || n.CNAME != "shop.saas.test" {
		t.Errorf("shop is hosted elsewhere: got external=%v cname=%q", n.External, n.CNAME)
	}
	if n := got["portal.example.com"]; n.External || n.CNAME != "lb.example.com" {
		t.Errorf("portal aliases a name inside the domain: got external=%v cname=%q", n.External, n.CNAME)
	}
	if n := got["inside.example.com"]; n.Refused == "" || len(n.Ports) != 0 {
		t.Errorf("a name at a blocked address is listed as refused and never dialled: %+v", n)
	}
	if !got["mail.example.com"].Mail {
		t.Error("the MX host is marked as a mail server")
	}
	if len(got["gone.example.com"].Addresses) != 0 {
		t.Error("a name that does not resolve is kept, with no address")
	}
	for _, out := range []string{"other.test", "elsewhere.test", "ns.provider.test", "spf.supplier.test", "shop.saas.test"} {
		if _, ok := got[out]; ok {
			t.Errorf("%s is outside the domain and must not be listed", out)
		}
	}
	if res.Outside != 1 {
		t.Errorf("outside = %d, want 1 (one supplied name was not under the domain)", res.Outside)
	}
	if fmt.Sprint(res.WildcardCerts) != "[*.apps.example.com *.example.com]" {
		t.Errorf("wildcard certificates = %v", res.WildcardCerts)
	}
	if s := report(res, SourceWordlist); s.Status != "off" {
		t.Errorf("word list was not asked for: %+v", s)
	}
	if s := report(res, SourceCT); s.Status != "ran" || s.Found != 4 {
		t.Errorf("ct report = %+v", s)
	}
}

func TestWordlistDropsWhatOnlyMatchesTheWildcard(t *testing.T) {
	dns := &fakeDNS{
		a:   map[string][]string{"example.com": {"192.0.2.1"}, "vpn.example.com": {"192.0.2.9"}, "www.example.com": {"198.51.100.7"}},
		any: []string{"198.51.100.7"},
	}
	res, err := Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceWordlist, SourceList},
		List: []string{"www.example.com"}, Resolver: dns, SkipPorts: true, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	got := byName(res)
	if !res.Wildcard {
		t.Error("the wildcard zone was not noticed")
	}
	if _, ok := got["vpn.example.com"]; !ok {
		t.Error("a guess with its own address is kept")
	}
	if _, ok := got["www.example.com"]; !ok {
		t.Error("a name another source reported is kept even when it matches the wildcard")
	}
	if len(got) != 3 {
		t.Errorf("%d names, want 3: every other guess only matched the wildcard", len(got))
	}
	if s := report(res, SourceWordlist); s.Found != 2 || !strings.Contains(s.Detail, "answers for any name") {
		t.Errorf("word list report = %+v", s)
	}
}

func TestWordlistWithoutWildcardKeepsOnlyWhatResolves(t *testing.T) {
	dns := &fakeDNS{a: map[string][]string{"example.com": {"192.0.2.1"}, "api.example.com": {"192.0.2.2"}, "dev-api.example.com": {"192.0.2.3"}}}
	res, err := Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceWordlist}, Resolver: dns, SkipPorts: true, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if res.Wildcard || len(res.Names) != 3 {
		t.Errorf("wildcard=%v names=%d, want false and 3", res.Wildcard, len(res.Names))
	}
}

func TestAFailedSourceIsReportedAndTheRunGoesOn(t *testing.T) {
	dns := &fakeDNS{a: map[string][]string{"example.com": {"192.0.2.1"}}}
	res, err := Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceCT, SourceList},
		List: []string{"a.example.com"}, CT: fakeCT{err: errors.New("status 502")}, Resolver: dns, SkipPorts: true, QPS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if s := report(res, SourceCT); s.Status != "failed" || !strings.Contains(s.Detail, "did not answer") {
		t.Errorf("ct report = %+v", s)
	}
	if len(res.Names) != 2 {
		t.Errorf("names = %d, want 2", len(res.Names))
	}
	// Asked for but not available on this server.
	res, _ = Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceCT}, Resolver: dns, SkipPorts: true, QPS: 1000})
	if s := report(res, SourceCT); s.Status != "off" || !strings.Contains(s.Detail, "not turned on") {
		t.Errorf("ct without a searcher = %+v", s)
	}
}

func TestRunStopsAtTheNameLimit(t *testing.T) {
	var list []string
	for i := 0; i < 500; i++ {
		list = append(list, fmt.Sprintf("h%d.example.com", i))
	}
	res, err := Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceList}, List: list,
		Resolver: &fakeDNS{}, SkipPorts: true, MaxNames: 100, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Names) != 100 {
		t.Errorf("truncated=%v names=%d, want true and 100", res.Truncated, len(res.Names))
	}
}

func TestNamesOnOneAddressShareOnePortCheck(t *testing.T) {
	dns := &fakeDNS{a: map[string][]string{}}
	var list []string
	for i := 0; i < 200; i++ {
		n := fmt.Sprintf("site%d.example.com", i)
		dns.a[n] = []string{"192.0.2.80"}
		list = append(list, n)
	}
	dial, dials := openPorts("192.0.2.80:443")
	res, err := Run(context.Background(), Options{Domain: "example.com", Sources: []string{SourceList}, List: list, Resolver: dns, Dial: dial, QPS: 100000})
	if err != nil {
		t.Fatal(err)
	}
	if *dials != len(WebPorts) {
		t.Errorf("%d dials for 200 names on one address, want %d", *dials, len(WebPorts))
	}
	for _, n := range res.Names {
		if n.Name != "example.com" && fmt.Sprint(n.Ports) != "[443]" {
			t.Fatalf("%s ports = %v", n.Name, n.Ports)
		}
	}
}

func TestRunIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{Domain: "example.com", Sources: []string{SourceDNS}, Resolver: &fakeDNS{}}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want canceled", err)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{"Example.COM.": "example.com", "*.example.com": "example.com", "\ta.b.example.co.uk\n": "a.b.example.co.uk"} {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "192.0.2.1", "https://example.com", "example.com:443", "example.com/x", "exa mple.com", "-a.example.com", "a..example.com"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestParseSPF(t *testing.T) {
	hosts, inc := parseSPF("v=spf1 ip4:192.0.2.0/24 a:Out.Example.com/28 +mx:mail.example.com include:_spf.example.com redirect=_r.example.com ~all")
	if fmt.Sprint(hosts) != "[out.example.com mail.example.com]" || fmt.Sprint(inc) != "[_spf.example.com _r.example.com]" {
		t.Errorf("hosts=%v includes=%v", hosts, inc)
	}
	if h, i := parseSPF("google-site-verification=abc"); h != nil || i != nil {
		t.Error("a TXT record that is not SPF names nothing")
	}
}

func TestLabels(t *testing.T) {
	l := Labels()
	if len(l) < 1500 || len(l) > 2500 {
		t.Errorf("%d labels, want about 1,600", len(l))
	}
	seen := map[string]bool{}
	for _, x := range l {
		if seen[x] {
			t.Errorf("%q is listed twice", x)
		}
		seen[x] = true
		if _, ok := under(x+".example.com", "example.com"); !ok {
			t.Errorf("%q does not make a valid name", x)
		}
	}
}

func TestCrtSh(t *testing.T) {
	old := retryDelay
	retryDelay = time.Millisecond
	defer func() { retryDelay = old }()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("q") != "%.example.com" || r.URL.Query().Get("output") != "json" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`[{"common_name":"www.example.com","name_value":"www.example.com\nAPI.example.com"},
			{"common_name":"*.example.com","name_value":"*.example.com\nexample.com"},{"common_name":"Example Org","name_value":"admin@example.com"}]`))
	}))
	defer srv.Close()
	names, err := CrtSh{URL: srv.URL + "/"}.Search(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(names) != "[www.example.com api.example.com *.example.com example.com]" {
		t.Errorf("names = %v", names)
	}
	if calls != 2 {
		t.Errorf("%d requests, want 2 (one retry after the 502)", calls)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>busy</html>")) }))
	defer bad.Close()
	if _, err := (CrtSh{URL: bad.URL + "/"}).Search(context.Background(), "example.com"); err == nil {
		t.Error("an answer that is not JSON is an error")
	}
}
