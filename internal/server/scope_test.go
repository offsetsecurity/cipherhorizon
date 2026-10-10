package server_test

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// PRD-007 REQ-AC-1 (audit L-01): with --scan-allow, an endpoint outside the scope is refused when
// it is added, and a target that is (or has become) outside it is refused when the scan connects.
func TestScanScopeRefusesAtAddAndConnect(t *testing.T) {
	target := hybridServer(t)
	host, portStr, _ := net.SplitHostPort(target.Addr)
	port, _ := strconv.Atoi(portStr)

	e := newEnv(t, withScanScope("10.0.0.0/8", "lab.test"))
	for in, want := range map[string]int{
		target.Addr:        400, // loopback is allowed by --allow-loopback, but not inside the scope
		"10.1.2.3:443":     201, // inside the network
		"web.lab.test:443": 201, // under the domain
		"lab.test:8443":    201, // the domain itself
		"notlab.test:443":  400, // not under it: the suffix is a whole label
		"192.0.2.10:443":   400,
		"localhost:443":    400, // a name that resolves outside the networks
	} {
		status, body := e.do("POST", "/api/v1/assets", map[string]any{"target": in})
		if status != want {
			t.Errorf("add %s: %d %s, want %d", in, status, body, want)
		}
		if want == 400 && !strings.Contains(string(body), "scan scope") {
			t.Errorf("add %s: the refusal does not name the scan scope: %s", in, body)
		}
	}
	var about struct {
		ScanScope []string `json:"scanScope"`
	}
	if e.call("GET", "/api/v1/about", nil, &about); strings.Join(about.ScanScope, ",") != "10.0.0.0/8,lab.test" {
		t.Errorf("about scanScope = %v", about.ScanScope)
	}

	// An endpoint already in the database (added before the scope was set, or a name that now
	// points elsewhere) is refused at connect time and the scan says why.
	a, err := e.st.CreateAsset(store.Asset{Kind: store.KindTLS, Name: "old", Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	sc := e.scanAndWait(a.ID)
	if sc.Status != "failed" || !strings.Contains(sc.Error, "outside the scan scope") {
		t.Fatalf("scan outside the scope: %s %q", sc.Status, sc.Error)
	}

	// Inside the scope the same target scans normally.
	in := newEnv(t, withScanScope(host+"/32"))
	b := in.addAsset(target.Addr)
	if sc := in.scanAndWait(b.ID); sc.Status != "done" {
		t.Fatalf("scan inside the scope: %s %q", sc.Status, sc.Error)
	}

	// Without a scope nothing changes, and About says so with an empty list.
	open := newEnv(t)
	about.ScanScope = nil
	if open.call("GET", "/api/v1/about", nil, &about); about.ScanScope == nil || len(about.ScanScope) != 0 {
		t.Errorf("about scanScope without --scan-allow = %#v, want []", about.ScanScope)
	}
}

func TestScanScopeParsingAndMatching(t *testing.T) {
	for _, bad := range []string{"10.0.0.0/33", "exa mple.com", "-bad.com", "a..b"} {
		if _, err := server.ParseScope([]string{bad}); err == nil {
			t.Errorf("ParseScope(%q) accepted", bad)
		}
	}
	sc, err := server.ParseScope([]string{".Example.COM", "192.0.2.7", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	g := server.Guard{Scope: sc}
	ctx := context.Background()
	for host, ok := range map[string]bool{
		"example.com": true, "a.b.example.com": true, "EXAMPLE.com.": true, "badexample.com": false,
		"192.0.2.7": true, "192.0.2.8": false, "2001:db8::1": true, "2001:db9::1": false,
	} {
		err := g.CheckTarget(ctx, host)
		if (err == nil) != ok {
			t.Errorf("CheckTarget(%s) = %v, want allowed %v", host, err, ok)
		}
		if err != nil && !errors.Is(err, server.ErrBlocked) {
			t.Errorf("CheckTarget(%s): the refusal does not wrap ErrBlocked: %v", host, err)
		}
	}
	// Connect time: a name outside the domains is pinned to the networks; one under them is not.
	if err := g.ForTarget("other.org").CheckIP(net.ParseIP("198.51.100.1")); err == nil {
		t.Error("a name outside the domains connected outside the networks")
	}
	if err := g.ForTarget("other.org").CheckIP(net.ParseIP("192.0.2.7")); err != nil {
		t.Errorf("a name outside the domains, connecting inside the networks: %v", err)
	}
	if err := g.ForTarget("www.example.com").CheckIP(net.ParseIP("198.51.100.1")); err != nil {
		t.Errorf("a name under a scope domain: %v", err)
	}
	// The fixed rules still apply inside the scope.
	meta, _ := server.ParseScope([]string{"169.254.0.0/16"})
	if err := (server.Guard{Scope: meta}).ForTarget("169.254.169.254").CheckIP(net.ParseIP("169.254.169.254")); err == nil {
		t.Error("the scope let a metadata address through")
	}
}
