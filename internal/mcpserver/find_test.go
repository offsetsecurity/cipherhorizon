package mcpserver_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/mcpserver"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

type findZone struct {
	a   map[string][]string
	mx  []string
	any []string // wildcard DNS: the answer for any other name
}

func (z findZone) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, a := range z.a[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	if out == nil {
		for _, a := range z.any {
			out = append(out, net.IPAddr{IP: net.ParseIP(a)})
		}
	}
	if out == nil {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}
func (findZone) LookupCNAME(_ context.Context, host string) (string, error) { return host + ".", nil }
func (z findZone) LookupMX(context.Context, string) ([]*net.MX, error) {
	var out []*net.MX
	for _, h := range z.mx {
		out = append(out, &net.MX{Host: h + "."})
	}
	return out, nil
}
func (findZone) LookupNS(context.Context, string) ([]*net.NS, error) { return nil, nil }
func (findZone) LookupTXT(context.Context, string) ([]string, error) { return nil, nil }
func (findZone) LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error) {
	return "", nil, nil
}

type findLogs struct{ asked *int }

func (findLogs) Name() string { return "the test log search" }
func (f findLogs) Search(context.Context, string) ([]string, error) {
	*f.asked++
	return []string{"api.example.com", "meta.example.com"}, nil
}

// PRD-022 REQ-DD-13: domain_find lists names with where each came from, and says what it could not see.
func TestDomainFind(t *testing.T) {
	asked, allowed := 0, false
	find := mcpserver.FindOptions{
		Resolver: findZone{a: map[string][]string{"example.com": {"192.0.2.1"}, "mail.example.com": {"192.0.2.25"},
			"api.example.com": {"192.0.2.2"}, "meta.example.com": {"169.254.169.254"}}, mx: []string{"mail.example.com"}},
		CT: findLogs{asked: &asked}, CTAllowed: func() bool { return allowed },
		Dial: func(_ context.Context, addr string, port int) (net.Conn, error) {
			if map[string]bool{"192.0.2.1:443": true, "192.0.2.25:25": true, "192.0.2.2:8443": true}[fmt.Sprintf("%s:%d", addr, port)] {
				a, b := net.Pipe()
				_ = b.Close()
				return a, nil
			}
			return nil, errors.New("refused")
		},
	}
	cs := connect(t, mcpserver.Options{Scan: loopback(), Find: find})
	res := call(t, cs, "domain_find", map[string]any{"domain": "Example.com"})
	if res.IsError {
		t.Fatalf("domain_find: %s", text(res))
	}
	out := structured[mcpserver.FindResult](t, res)
	if out.Domain != "example.com" || out.Total != 2 || out.Resolving != 2 || out.Answering != 2 {
		t.Errorf("result = %+v", out)
	}
	if !strings.Contains(text(res), "mail.example.com  ports 25") || !strings.Contains(text(res), "Certificate Transparency logs were not searched") {
		t.Errorf("text = %s", text(res))
	}
	if asked != 0 {
		t.Error("certificate logs were searched without being asked")
	}

	// Certificate logs: refused until the operator allows them, with the reason.
	res = call(t, cs, "domain_find", map[string]any{"domain": "example.com", "certificateLogs": true})
	if !res.IsError || !strings.Contains(text(res), "turned off") || asked != 0 {
		t.Errorf("certificate logs while off: error=%v asked=%d %s", res.IsError, asked, text(res))
	}
	allowed = true
	res = call(t, cs, "domain_find", map[string]any{"domain": "example.com", "certificateLogs": true})
	out = structured[mcpserver.FindResult](t, res)
	if res.IsError || asked != 1 || out.Total != 4 {
		t.Fatalf("certificate logs when allowed: error=%v asked=%d total=%d", res.IsError, asked, out.Total)
	}
	for _, n := range out.Names {
		if n.Name == "meta.example.com" && (n.Refused == "" || len(n.Ports) != 0) {
			t.Errorf("a name at a metadata address is refused and never dialled: %+v", n)
		}
		if n.Name == "api.example.com" && (fmt.Sprint(n.Ports) != "[8443]" || strings.Join(n.Sources, ",") != "ct") {
			t.Errorf("api = %+v", n)
		}
	}

	for name, args := range map[string]map[string]any{"an address": {"domain": "192.0.2.1"}, "one label": {"domain": "localhost"}, "a URL": {"domain": "https://example.com/"}} {
		if res := call(t, cs, "domain_find", args); !res.IsError {
			t.Errorf("%s: want a tool error", name)
		}
	}
	// A scope of domains that does not cover the domain refuses the run.
	scope, err := server.ParseScope([]string{"example.org"})
	if err != nil {
		t.Fatal(err)
	}
	cs = connect(t, mcpserver.Options{Scan: mcpserver.ScanOptions{Guard: server.Guard{Scope: scope}}, Find: find})
	if res := call(t, cs, "domain_find", map[string]any{"domain": "example.com"}); !res.IsError || !strings.Contains(text(res), "outside the scan scope") {
		t.Errorf("scope: %s", text(res))
	}
}

// Under wildcard DNS, names with only that address are counted, left out of names, and explained.
func TestDomainFindWildcard(t *testing.T) {
	asked := 0
	find := mcpserver.FindOptions{
		Resolver: findZone{a: map[string][]string{"example.com": {"192.0.2.1"}}, any: []string{"198.51.100.7"}},
		CT:       findLogs{asked: &asked}, CTAllowed: func() bool { return true },
		Dial: func(context.Context, string, int) (net.Conn, error) { return nil, errors.New("refused") },
	}
	cs := connect(t, mcpserver.Options{Scan: loopback(), Find: find})
	res := call(t, cs, "domain_find", map[string]any{"domain": "example.com", "certificateLogs": true})
	out := structured[mcpserver.FindResult](t, res)
	if res.IsError || out.WildcardOnly != 2 || len(out.Names) != 1 || out.Names[0].Name != "example.com" {
		t.Fatalf("result = %+v (%s)", out, text(res))
	}
	if !strings.Contains(text(res), "resolves to 198.51.100.7 (wildcard DNS). 2 names resolve only there") {
		t.Errorf("text = %s", text(res))
	}
}
