package server_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

// zoneDNS is a resolver that answers from a small zone.
type zoneDNS struct {
	a     map[string][]string
	cname map[string]string
	mx    []string
	any   []string      // what the zone answers for any other name (wildcard DNS)
	block chan struct{} // when set, address lookups wait for it or for the context
}

func (z *zoneDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if z.block != nil {
		select {
		case <-z.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	addrs := z.a[host]
	if c, ok := z.cname[host]; ok && addrs == nil {
		addrs = z.a[c]
	}
	if addrs == nil {
		addrs = z.any
	}
	if addrs == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

func (z *zoneDNS) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := z.cname[host]; ok {
		return c + ".", nil
	}
	return host + ".", nil
}

func (z *zoneDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	var out []*net.MX
	for _, h := range z.mx {
		out = append(out, &net.MX{Host: h + "."})
	}
	return out, nil
}

func (z *zoneDNS) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }

func (z *zoneDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (z *zoneDNS) LookupSRV(_ context.Context, service, _, _ string) (string, []*net.SRV, error) {
	return "", nil, &net.DNSError{Err: "no such host", Name: service, IsNotFound: true}
}

type logSearch struct {
	names []string
	asked []string
}

func (*logSearch) Name() string { return "the test log search" }
func (l *logSearch) Search(_ context.Context, domain string) ([]string, error) {
	l.asked = append(l.asked, domain)
	return l.names, nil
}

// withDiscovery gives the server a zone, the "address:port" pairs that accept a connection, and a
// certificate log search.
func withDiscovery(z *zoneDNS, ct *logSearch, open ...string) envOpt {
	set := map[string]bool{}
	for _, o := range open {
		set[o] = true
	}
	return func(c *envCfg) {
		c.discovery = server.DiscoveryOptions{Resolver: z, QPS: 100000,
			Dial: func(_ context.Context, addr string, port int) (net.Conn, error) {
				if set[fmt.Sprintf("%s:%d", addr, port)] {
					a, b := net.Pipe()
					_ = b.Close()
					return a, nil
				}
				return nil, errors.New("connection refused")
			}}
		if ct != nil {
			c.discovery.CT = ct
		}
	}
}

type discoveryJSON struct {
	ID       int64    `json:"id"`
	Domain   string   `json:"domain"`
	Sources  []string `json:"sources"`
	Status   string   `json:"status"`
	Error    string   `json:"error"`
	Names    int      `json:"names"`
	Accepted int      `json:"accepted"`
	Report   struct {
		Sources []struct {
			ID, Status, Detail string
			Found              int
		} `json:"sources"`
		WildcardCerts     []string `json:"wildcardCerts"`
		WildcardAddresses []string `json:"wildcardAddresses"`
	} `json:"report"`
}

type discoveryNameJSON struct {
	Name      string   `json:"name"`
	Sources   []string `json:"sources"`
	Addresses []string `json:"addresses"`
	CNAME     string   `json:"cname"`
	External  bool     `json:"external"`
	Ports     []int    `json:"ports"`
	Refused   string   `json:"refused"`
	Accepted  bool     `json:"accepted"`
	New       bool     `json:"new"`
	Tracked   bool     `json:"tracked"`
	Wildcard  bool     `json:"wildcard"`
}

type discoveryResult struct {
	Discovery discoveryJSON       `json:"discovery"`
	Names     []discoveryNameJSON `json:"names"`
}

func (r discoveryResult) name(n string) discoveryNameJSON {
	for _, x := range r.Names {
		if x.Name == n {
			return x
		}
	}
	return discoveryNameJSON{}
}

// discover starts a run and waits for it to end.
func (e *env) discover(body map[string]any) discoveryResult {
	e.t.Helper()
	var rec discoveryJSON
	if s := e.call("POST", "/api/v1/discoveries", body, &rec); s != 202 {
		e.t.Fatalf("start discovery: status %d", s)
	}
	return e.waitDiscovery(rec.ID)
}

func (e *env) waitDiscovery(id int64) discoveryResult {
	e.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var out discoveryResult
		if s := e.call("GET", fmt.Sprintf("/api/v1/discoveries/%d", id), nil, &out); s != 200 {
			e.t.Fatalf("get discovery: status %d", s)
		}
		if out.Discovery.Status != "running" {
			return out
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("discovery %d still running", id)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func exampleZone() *zoneDNS {
	return &zoneDNS{
		a: map[string][]string{
			"example.com": {"192.0.2.1"}, "www.example.com": {"192.0.2.1"}, "git.example.com": {"192.0.2.7"},
			"mail.example.com": {"192.0.2.25"}, "quiet.example.com": {"192.0.2.99"}, "shop.saas.test": {"203.0.113.5"},
			"meta.example.com": {"169.254.169.254"},
		},
		cname: map[string]string{"shop.example.com": "shop.saas.test"},
		mx:    []string{"mail.example.com"},
	}
}

var exampleOpen = []string{"192.0.2.1:443", "192.0.2.7:443", "192.0.2.7:22", "192.0.2.25:25", "203.0.113.5:443"}

// REQ-DD-1, 3, 6 (list), 7, 8, 9, 11, 12, 15: a run finds names, shows where each came from, and
// nothing becomes an endpoint until names are accepted.
func TestDiscoveryFindsReviewsAndAccepts(t *testing.T) {
	e := newEnv(t, withDiscovery(exampleZone(), nil, exampleOpen...))
	res := e.discover(map[string]any{"domain": "Example.com", "sources": []string{"dns"},
		"list": "https://www.example.com/login\ngit.example.com:22\nshop.example.com\nquiet.example.com\ngone.example.com\nmeta.example.com\nother.test\n"})
	d := res.Discovery
	if d.Status != "done" || d.Domain != "example.com" || strings.Join(d.Sources, ",") != "dns,list" {
		t.Fatalf("discovery = %+v", d)
	}
	if len(res.Names) != 8 {
		t.Errorf("%d names, want 8 (the domain, the mail server and six of the seven listed)", len(res.Names))
	}
	if n := res.name("git.example.com"); fmt.Sprint(n.Ports) != "[443 22]" || strings.Join(n.Sources, ",") != "list" {
		t.Errorf("git = %+v", n)
	}
	if n := res.name("mail.example.com"); fmt.Sprint(n.Ports) != "[25]" || strings.Join(n.Sources, ",") != "dns" {
		t.Errorf("mail = %+v", n)
	}
	if n := res.name("shop.example.com"); !n.External || n.CNAME != "shop.saas.test" {
		t.Errorf("shop is hosted elsewhere: %+v", n)
	}
	if n := res.name("gone.example.com"); n.Name == "" || len(n.Addresses) != 0 {
		t.Errorf("a name that does not resolve is listed without an address: %+v", n)
	}
	if n := res.name("meta.example.com"); n.Refused == "" || strings.Contains(n.Refused, "target address is not allowed") || len(n.Ports) != 0 {
		t.Errorf("a name at a blocked address is listed as refused, with the reason alone: %+v", n)
	}
	for _, s := range d.Report.Sources {
		if s.ID == "ct" && s.Status != "off" {
			t.Errorf("certificate logs were not asked for: %+v", s)
		}
	}

	// Nothing was added by the run itself.
	var list []struct {
		Host     string   `json:"host"`
		Port     int      `json:"port"`
		Protocol string   `json:"protocol"`
		Tags     []string `json:"tags"`
	}
	e.call("GET", "/api/v1/assets", nil, &list)
	if len(list) != 0 {
		t.Fatalf("%d endpoints exist before anything was accepted", len(list))
	}

	var acc struct {
		Names, Added, Duplicate, Invalid, Skipped, Unknown, Queued int
		Tag                                                        string
	}
	path := fmt.Sprintf("/api/v1/discoveries/%d/accept", d.ID)
	if s := e.call("POST", path, map[string]any{"names": []string{"git.example.com", "www.example.com", "quiet.example.com", "meta.example.com", "nobody.example.com"},
		"scan": true, "tags": []string{"web"}}, &acc); s != 200 {
		t.Fatalf("accept: status %d", s)
	}
	if acc.Names != 2 || acc.Added != 3 || acc.Skipped != 2 || acc.Unknown != 1 || acc.Queued != 3 || acc.Tag != "example.com" {
		t.Errorf("accept = %+v, want 2 names, 3 endpoints, 2 skipped (nothing answered; refused), 1 unknown, 3 scans", acc)
	}
	e.call("GET", "/api/v1/assets", nil, &list)
	kinds := map[string]string{}
	for _, a := range list {
		kinds[fmt.Sprintf("%s:%d", a.Host, a.Port)] = a.Protocol
		if strings.Join(a.Tags, ",") != "example.com,web" {
			t.Errorf("%s tags = %v", a.Host, a.Tags)
		}
	}
	want := map[string]string{"git.example.com:443": "tls", "git.example.com:22": "ssh", "www.example.com:443": "tls"}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Errorf("endpoints = %v, want %v", kinds, want)
	}

	// Accepting again adds nothing twice, and the run remembers what was accepted.
	if s := e.call("POST", path, map[string]any{"all": true}, &acc); s != 200 || acc.Added != 3 || acc.Duplicate != 3 {
		t.Errorf("accept all: status %d, %+v; want the 3 new endpoints (domain, mail, shop) and 3 already present", s, acc)
	}
	again := e.waitDiscovery(d.ID)
	if !again.name("git.example.com").Accepted || again.name("gone.example.com").Accepted || again.Discovery.Accepted != 5 {
		t.Errorf("accepted marks: git=%v gone=%v total=%d", again.name("git.example.com").Accepted, again.name("gone.example.com").Accepted, again.Discovery.Accepted)
	}

	// A second run of the same domain says what is new since the first.
	second := e.discover(map[string]any{"domain": "example.com", "sources": []string{"stored", "dns"}, "list": "fresh.example.com"})
	if !second.name("fresh.example.com").New || second.name("www.example.com").New {
		t.Errorf("new marks: fresh=%v www=%v", second.name("fresh.example.com").New, second.name("www.example.com").New)
	}
	if n := second.name("www.example.com"); !strings.Contains(strings.Join(n.Sources, ","), "stored") {
		t.Errorf("an endpoint already here is found by the stored source: %+v", n)
	}
	if !second.name("www.example.com").Tracked || second.name("fresh.example.com").Tracked {
		t.Errorf("a name that is already an endpoint says so: www=%v fresh=%v", second.name("www.example.com").Tracked, second.name("fresh.example.com").Tracked)
	}
	if res.name("www.example.com").New {
		t.Error("in a domain's first run nothing is marked new")
	}

	// The runs and the acceptance are in the activity list.
	_, raw := e.do("GET", "/api/v1/audit", nil)
	for _, want := range []string{`"discovery"`, "started", "names accepted"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("activity list lacks %s", want)
		}
	}

	// A finished run can be deleted; its endpoints stay.
	if s, _ := e.do("DELETE", fmt.Sprintf("/api/v1/discoveries/%d", d.ID), nil); s != 204 {
		t.Errorf("delete: status %d", s)
	}
	e.call("GET", "/api/v1/assets", nil, &list)
	if len(list) != 6 {
		t.Errorf("%d endpoints after deleting the run, want 6", len(list))
	}
}

// REQ-DD-4, D2: certificate logs are searched only after an administrator turns the source on.
func TestDiscoveryCertificateLogsAreOptIn(t *testing.T) {
	ct := &logSearch{names: []string{"api.example.com", "*.example.com"}}
	z := exampleZone()
	z.a["api.example.com"] = []string{"192.0.2.2"}
	e := newEnv(t, withDiscovery(z, ct))
	s, raw := e.do("POST", "/api/v1/discoveries", map[string]any{"domain": "example.com", "sources": []string{"ct"}})
	if s != 400 || !strings.Contains(string(raw), "turned off") || !strings.Contains(string(raw), "the test log search") {
		t.Fatalf("ct while off: status %d %s", s, raw)
	}
	if len(ct.asked) != 0 {
		t.Fatal("the log search was asked while the source was off")
	}
	if s, _ := e.do("PUT", "/api/v1/settings/discovery", map[string]any{"certificateTransparency": "maybe"}); s != 400 {
		t.Errorf("a value that is not on or off: status %d", s)
	}
	var set struct {
		CT      bool   `json:"certificateTransparency"`
		Service string `json:"service"`
	}
	if s := e.call("PUT", "/api/v1/settings/discovery", map[string]any{"certificateTransparency": "on"}, &set); s != 200 || !set.CT || set.Service != "the test log search" {
		t.Fatalf("turning it on: status %d %+v", s, set)
	}
	var settings struct {
		Discovery struct {
			CT bool `json:"certificateTransparency"`
		} `json:"discovery"`
	}
	e.call("GET", "/api/v1/settings", nil, &settings)
	if !settings.Discovery.CT {
		t.Error("Settings does not show the source as on")
	}
	res := e.discover(map[string]any{"domain": "example.com", "sources": []string{"ct"}})
	if fmt.Sprint(ct.asked) != "[example.com]" {
		t.Errorf("asked = %v", ct.asked)
	}
	if n := res.name("api.example.com"); strings.Join(n.Sources, ",") != "ct" {
		t.Errorf("api = %+v", n)
	}
	if fmt.Sprint(res.Discovery.Report.WildcardCerts) != "[*.example.com]" {
		t.Errorf("wildcard certificates = %v", res.Discovery.Report.WildcardCerts)
	}
}

// REQ-DD-10: a run obeys the scan scope.
func TestDiscoveryObeysTheScanScope(t *testing.T) {
	e := newEnv(t, withScanScope("example.com"), withDiscovery(exampleZone(), nil, exampleOpen...))
	s, raw := e.do("POST", "/api/v1/discoveries", map[string]any{"domain": "other.test"})
	if s != 400 || !strings.Contains(string(raw), "outside the scan scope") {
		t.Errorf("a domain outside the scope: status %d %s", s, raw)
	}
	if res := e.discover(map[string]any{"domain": "example.com", "list": "www.example.com"}); res.name("www.example.com").Refused != "" {
		t.Errorf("a name under the scope domain is allowed: %+v", res.name("www.example.com"))
	}

	// A scope of networks: any domain may be looked under, and names outside the networks are refused.
	e = newEnv(t, withScanScope("192.0.2.0/28"), withDiscovery(exampleZone(), nil, exampleOpen...))
	res := e.discover(map[string]any{"domain": "example.com", "list": "www.example.com\nmail.example.com"})
	if n := res.name("www.example.com"); n.Refused != "" || fmt.Sprint(n.Ports) != "[443]" {
		t.Errorf("www is inside the networks: %+v", n)
	}
	if n := res.name("mail.example.com"); !strings.Contains(n.Refused, "outside the scan scope") || len(n.Ports) != 0 {
		t.Errorf("mail is outside the networks: %+v", n)
	}
}

// REQ-DD-1: one run at a time; a run can be cancelled; bad requests are refused with a reason.
func TestDiscoveryRunsOneAtATimeAndCancels(t *testing.T) {
	z := exampleZone()
	z.block = make(chan struct{})
	e := newEnv(t, withDiscovery(z, nil))
	var rec discoveryJSON
	if s := e.call("POST", "/api/v1/discoveries", map[string]any{"domain": "example.com"}, &rec); s != 202 || rec.Status != "running" {
		t.Fatalf("start: status %d %+v", s, rec)
	}
	if s, raw := e.do("POST", "/api/v1/discoveries", map[string]any{"domain": "example.org"}); s != 409 || !strings.Contains(string(raw), "already running") {
		t.Errorf("a second run: status %d %s", s, raw)
	}
	if s, _ := e.do("DELETE", fmt.Sprintf("/api/v1/discoveries/%d", rec.ID), nil); s != 409 {
		t.Errorf("deleting a running discovery: status %d", s)
	}
	if s, _ := e.do("POST", fmt.Sprintf("/api/v1/discoveries/%d/accept", rec.ID), map[string]any{"all": true}); s != 409 {
		t.Errorf("accepting a running discovery: status %d", s)
	}
	if s := e.call("POST", fmt.Sprintf("/api/v1/discoveries/%d/cancel", rec.ID), nil, &rec); s != 200 || rec.Status != "canceled" {
		t.Fatalf("cancel: status %d %+v", s, rec)
	}
	// The run lets go, so the next one can start.
	deadline := time.Now().Add(10 * time.Second)
	for {
		s, _ := e.do("POST", "/api/v1/discoveries", map[string]any{"domain": "example.org", "sources": []string{"list"}, "list": "a.example.org"})
		if s == 202 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the cancelled run never let go")
		}
		time.Sleep(20 * time.Millisecond)
	}
	close(z.block)

	for body, want := range map[string]string{
		`{"domain":"localhost"}`:                           "full domain",
		`{"domain":"192.0.2.1"}`:                           "address",
		`{"domain":"https://example.com/"}`:                "alone",
		`{"domain":"example.com","sources":["guesswork"]}`: "unknown source",
	} {
		if s, raw := e.do("POST", "/api/v1/discoveries", body); s != 400 || !strings.Contains(string(raw), want) {
			t.Errorf("%s: status %d %s, want 400 mentioning %q", body, s, raw, want)
		}
	}
	if s, _ := e.do("GET", "/api/v1/discoveries/9999", nil); s != 404 {
		t.Errorf("an unknown discovery: status %d", s)
	}
	var list struct {
		Discoveries []discoveryJSON `json:"discoveries"`
	}
	if s := e.call("GET", "/api/v1/discoveries", nil, &list); s != 200 || len(list.Discoveries) < 2 || list.Discoveries[len(list.Discoveries)-1].Status != "canceled" {
		t.Errorf("list: status %d %+v", s, list.Discoveries)
	}
}

// Under wildcard DNS every name looks alive: names that resolve only to the zone's answer for any
// name are kept, marked, and the report names that answer.
func TestDiscoveryMarksWildcardOnlyNames(t *testing.T) {
	z := exampleZone()
	z.any = []string{"192.0.2.80"}
	e := newEnv(t, withDiscovery(z, nil, append(exampleOpen, "192.0.2.80:443")...))
	res := e.discover(map[string]any{"domain": "example.com", "list": "old-1.example.com\nold-2.example.com\nwww.example.com"})
	if fmt.Sprint(res.Discovery.Report.WildcardAddresses) != "[192.0.2.80]" {
		t.Errorf("wildcard addresses = %v", res.Discovery.Report.WildcardAddresses)
	}
	for name, want := range map[string]bool{"old-1.example.com": true, "old-2.example.com": true, "www.example.com": false, "example.com": false} {
		if n := res.name(name); n.Wildcard != want {
			t.Errorf("%s wildcard = %v, want %v (%+v)", name, n.Wildcard, want, n)
		}
	}
	if n := res.name("old-1.example.com"); fmt.Sprint(n.Ports) != "[443]" {
		t.Errorf("a wildcard-only name still shows what answers: %+v", n)
	}
}
