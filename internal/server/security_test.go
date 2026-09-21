package server_test

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/example/cbom-scan/internal/server"
	"github.com/example/cbom-scan/internal/store"
	"github.com/example/cbom-scan/internal/tlsprobe/testserver"
)

// rawReq sends a request with full control over Host and headers.
func (e *env) rawReq(method, path, host string, hdr map[string]string, body string) (int, http.Header) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	return resp.StatusCode, resp.Header
}

// AC-11.2
func TestAC11_TokenIsRequiredWhenConfigured(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token"))
	noAuth := map[string]string{"Authorization": ""}

	if s, _, _ := e.req("GET", "/api/v1/assets", nil, noAuth); s != 401 {
		t.Errorf("no token: %d, want 401", s)
	}
	if s, _, _ := e.req("GET", "/api/v1/assets", nil, map[string]string{"Authorization": "Bearer wrong"}); s != 401 {
		t.Errorf("wrong token: %d, want 401", s)
	}
	if s, _, _ := e.req("GET", "/api/v1/assets", nil, map[string]string{"Authorization": "s3cret-token"}); s != 401 {
		t.Errorf("token without the Bearer scheme: %d, want 401", s)
	}
	if s, _, _ := e.req("POST", "/api/v1/assets", map[string]any{"target": "x.example"}, noAuth); s != 401 {
		t.Errorf("mutation without a token: %d, want 401", s)
	}
	if s, _, _ := e.req("GET", "/api/v1/assets", nil, nil); s != 200 {
		t.Errorf("correct token: %d, want 200", s)
	}
	// Liveness and the UI shell stay reachable so the page can load and ask for the token.
	if s, _, _ := e.req("GET", "/api/v1/health", nil, noAuth); s != 200 {
		t.Errorf("health: %d", s)
	}
	if s, b, _ := e.req("GET", "/", nil, noAuth); s != 200 || !strings.Contains(string(b), "<html") {
		t.Errorf("UI shell without a token: %d", s)
	}
	// Every API route is protected, including ones added later: sample them all.
	for _, p := range []string{"/api/v1/summary", "/api/v1/scans", "/api/v1/hosts", "/api/v1/about", "/api/v1/export/assets.csv", "/api/v1/nope"} {
		if s, _, _ := e.req("GET", p, nil, noAuth); s != 401 {
			t.Errorf("%s without a token: %d, want 401", p, s)
		}
	}
}

// AC-11.3: DNS rebinding.
func TestAC11_ForeignHostHeaderIsRefusedWithoutAToken(t *testing.T) {
	e := newEnv(t)
	for _, host := range []string{"evil.example", "evil.example:8080", "127.0.0.1.evil.example", "169.254.169.254"} {
		if s, _ := e.rawReq("GET", "/api/v1/assets", host, nil, ""); s != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: %d, want 421", host, s)
		}
		if s, _ := e.rawReq("GET", "/", host, nil, ""); s != http.StatusMisdirectedRequest {
			t.Errorf("UI with Host %q: %d, want 421", host, s)
		}
	}
	for _, host := range []string{"127.0.0.1", "localhost", "localhost:3000", "[::1]:8080", "LOCALHOST"} {
		if s, _ := e.rawReq("GET", "/api/v1/assets", host, nil, ""); s != 200 {
			t.Errorf("Host %q: %d, want 200", host, s)
		}
	}
	// Once a token protects the API the Host header adds nothing, so any host works.
	et := newEnv(t, withToken("t"))
	if s, _ := et.rawReq("GET", "/api/v1/assets", "scanner.corp.example", map[string]string{"Authorization": "Bearer t"}, ""); s != 200 {
		t.Errorf("tokened server with another host name: %d", s)
	}
}

func TestAC11_ConfiguredAllowedHostsAreAccepted(t *testing.T) {
	e := newEnv(t, func(c *envCfg) { c.allowedHosts = []string{"scanner.corp.example:8080"} })
	if s, _ := e.rawReq("GET", "/api/v1/assets", "scanner.corp.example:8080", nil, ""); s != 200 {
		t.Errorf("allowed host: %d", s)
	}
	if s, _ := e.rawReq("GET", "/api/v1/assets", "other.corp.example", nil, ""); s != 421 {
		t.Errorf("host not on the list: %d", s)
	}
}

// AC-11.3: cross-site request forgery.
func TestAC11_MutationsAreProtectedFromForgery(t *testing.T) {
	e := newEnv(t)
	body := `{"target":"forged.example"}`
	js := map[string]string{"Content-Type": "application/json"}
	with := func(extra map[string]string) map[string]string {
		h := map[string]string{"Content-Type": "application/json", "X-Requested-With": "cbom-scan"}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}

	// A plain cross-site form/fetch cannot add the custom header, so this is what an attacker sends.
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", js, body); s != 403 {
		t.Errorf("no custom header: %d, want 403", s)
	}
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", map[string]string{"Content-Type": "text/plain"}, body); s != 403 {
		t.Errorf("text/plain forgery: %d, want 403", s)
	}
	if s, _ := e.rawReq("DELETE", "/api/v1/assets/1", "", nil, ""); s != 403 {
		t.Errorf("delete without header: %d, want 403", s)
	}
	if s, _ := e.rawReq("POST", "/api/v1/assets/1/scan", "", nil, ""); s != 403 {
		t.Errorf("body-less mutation without header: %d, want 403", s)
	}
	// Even with the header, another origin is refused.
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", with(map[string]string{"Origin": "https://evil.example"}), body); s != 403 {
		t.Errorf("foreign Origin: %d, want 403", s)
	}
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", with(map[string]string{"Sec-Fetch-Site": "cross-site"}), body); s != 403 {
		t.Errorf("cross-site fetch metadata: %d, want 403", s)
	}
	// A non-JSON body is refused.
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", map[string]string{"X-Requested-With": "cbom-scan", "Content-Type": "text/plain"}, body); s != 415 {
		t.Errorf("non-JSON body: %d, want 415", s)
	}
	// None of that created anything.
	var list []assetJSON
	e.call("GET", "/api/v1/assets", nil, &list)
	if len(list) != 0 {
		t.Fatalf("a forged request succeeded: %+v", list)
	}
	// The legitimate same-origin request works, with or without an Origin header.
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", with(map[string]string{"Origin": e.ts.URL}), body); s != 201 {
		t.Errorf("same-origin request: %d, want 201", s)
	}
	if s, _ := e.rawReq("POST", "/api/v1/assets", "", with(map[string]string{"Sec-Fetch-Site": "same-origin"}), `{"target":"second.example"}`); s != 201 {
		t.Errorf("same-origin fetch metadata: %d, want 201", s)
	}
}

// AC-11.5
func TestAC11_SecurityHeaders(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/api/v1/about", "/api/v1/assets"} {
		_, _, h := e.req("GET", p, nil, nil)
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP lacks %q: %s", p, want, csp)
			}
		}
		if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") || strings.Contains(csp, "http") {
			t.Errorf("%s: CSP is too permissive: %s", p, csp)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers = %v", p, h)
		}
	}
	if _, _, h := e.req("GET", "/api/v1/about", nil, nil); h.Get("Cache-Control") != "no-store" {
		t.Errorf("API responses must not be cached: %q", h.Get("Cache-Control"))
	}
}

// AC-11.4
func TestAC11_ScansCannotReachBlockedNetworks(t *testing.T) {
	// A name that resolves to loopback passes asset creation (it is a name) but is
	// refused when resolved, before any connection is made.
	e := newEnv(t, noLoopback())
	srv := testserver.Start(t, testserver.Config{})
	a := e.addAsset("localhost:" + itoa(int64(srv.Port)))
	sc := e.scanAndWait(a.ID)
	if sc.Status != "failed" || (!strings.Contains(sc.Error, "blocked") && !strings.Contains(sc.Error, "not allowed")) {
		t.Fatalf("a scan of a loopback name must fail with a reason: %+v", sc)
	}
	if sc.Connections != 0 {
		t.Errorf("%d connections were made to a blocked address", sc.Connections)
	}
}

func TestGuardCheckIP(t *testing.T) {
	strict, lax := server.Guard{}, server.Guard{AllowLoopback: true}
	for ip, blocked := range map[string]bool{
		"8.8.8.8": false, "10.1.2.3": false, "172.16.0.9": false, "192.168.1.1": false, "2001:db8::1": false, "fd12:3456::1": false,
		"127.0.0.1": true, "::1": true,
		"169.254.169.254": true, "169.254.1.1": true, "fe80::1": true,
		"0.0.0.0": true, "::": true, "224.0.0.1": true, "ff02::1": true, "255.255.255.255": true,
		"100.100.100.200": true, "192.0.0.192": true, "fd00:ec2::254": true, "168.63.129.16": true,
	} {
		err := strict.CheckIP(net.ParseIP(ip))
		if (err != nil) != blocked {
			t.Errorf("strict guard, %s: err=%v, blocked should be %v", ip, err, blocked)
		}
		if err != nil && !isBlocked(err) {
			t.Errorf("%s: error does not wrap ErrBlocked: %v", ip, err)
		}
	}
	// Loopback is the only thing --allow-loopback changes; metadata stays blocked.
	if lax.CheckIP(net.ParseIP("127.0.0.1")) != nil || lax.CheckIP(net.ParseIP("::1")) != nil {
		t.Error("AllowLoopback did not allow loopback")
	}
	if lax.CheckIP(net.ParseIP("169.254.169.254")) == nil {
		t.Error("AllowLoopback must never allow cloud metadata")
	}
	if strict.CheckIP(nil) == nil {
		t.Error("nil IP accepted")
	}
	// IPv4-mapped IPv6 must not be a way round the rules.
	if strict.CheckIP(net.ParseIP("::ffff:169.254.169.254")) == nil || strict.CheckIP(net.ParseIP("::ffff:127.0.0.1")) == nil {
		t.Error("IPv4-mapped IPv6 bypasses the guard")
	}
}

func isBlocked(err error) bool { return strings.Contains(err.Error(), "not allowed") }

// The check is enforced on the real connection, not just on the name.
func TestGuardDialRefusesBlockedAddressesAtConnectTime(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close() //nolint:errcheck // test

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := (server.Guard{}).Dial(ctx, "tcp", l.Addr().String()); err == nil {
		_ = c.Close()
		t.Fatal("dialed loopback with the strict guard")
	} else if !isBlocked(err) {
		t.Errorf("dial error = %v", err)
	}
	if c, err := (server.Guard{AllowLoopback: true}).Dial(ctx, "tcp", l.Addr().String()); err != nil {
		t.Errorf("dial with AllowLoopback: %v", err)
	} else {
		_ = c.Close()
	}
	if c, err := (server.Guard{AllowLoopback: true}).Dial(ctx, "tcp", "169.254.169.254:80"); err == nil {
		_ = c.Close()
		t.Error("dialed the metadata address")
	}
}

// AC-11.6 (server side): hostile strings are stored and returned as data, in JSON, escaped.
func TestAC11_HostileStringsAreInertData(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset("x.example")
	evil := `<img src=x onerror=alert(1)>"</script><script>alert(2)</script>`
	var up assetJSON
	if s := e.call("PATCH", "/api/v1/assets/"+itoa(a.ID), map[string]any{"name": evil, "notes": evil, "tags": []string{"<b>t</b>"}}, &up); s != 200 || up.Name != evil {
		t.Fatalf("patch: %d %q", s, up.Name)
	}
	_, raw, h := e.req("GET", "/api/v1/assets", nil, nil)
	if !strings.HasPrefix(h.Get("Content-Type"), "application/json") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers = %v", h)
	}
	if strings.Contains(string(raw), "<img") || strings.Contains(string(raw), "<script") {
		t.Errorf("raw angle brackets in the JSON body: %s", raw)
	}
}

func TestAPIRobustness(t *testing.T) {
	e := newEnv(t)
	for name, tc := range map[string]struct {
		method, path string
		body         any
		want         int
	}{
		"bad id":               {"GET", "/api/v1/assets/abc", nil, 400},
		"zero id":              {"GET", "/api/v1/assets/0", nil, 400},
		"negative id":          {"GET", "/api/v1/scans/-5", nil, 400},
		"missing asset":        {"GET", "/api/v1/assets/9999", nil, 404},
		"missing scan":         {"GET", "/api/v1/scans/9999", nil, 404},
		"missing report":       {"GET", "/api/v1/scans/9999/report", nil, 404},
		"unknown api path":     {"GET", "/api/v1/nope", nil, 404},
		"wrong method":         {"PUT", "/api/v1/assets", map[string]any{}, 405},
		"malformed json":       {"POST", "/api/v1/assets", `{"target":`, 400},
		"unknown field":        {"POST", "/api/v1/assets", map[string]any{"target": "a.example", "admin": true}, 400},
		"scan missing asset":   {"POST", "/api/v1/assets/9999/scan", nil, 404},
		"missing target":       {"POST", "/api/v1/assets", map[string]any{}, 400},
		"unknown route":        {"GET", "/nope", nil, 404},
		"host is not an asset": {"GET", "/api/v1/hosts/9999", nil, 404},
	} {
		if s, b := e.do(tc.method, tc.path, tc.body); s != tc.want {
			t.Errorf("%s: %s %s = %d, want %d (%s)", name, tc.method, tc.path, s, tc.want, b)
		}
	}
	// Every API error is JSON with an "error" message.
	var out map[string]string
	if s := e.call("GET", "/api/v1/assets/9999", nil, &out); s != 404 || out["error"] == "" {
		t.Errorf("error body = %v", out)
	}
	// Bodies over the limit are refused, not buffered.
	big := `{"target":"a.example","notes":"` + strings.Repeat("x", 2<<20) + `"}`
	if s, _ := e.do("POST", "/api/v1/assets", big); s != 413 {
		t.Errorf("oversized body: %d, want 413", s)
	}
}

// Deleting an asset while it is being scanned must not wedge the runner.
func TestDeletingAnAssetMidScanIsSafe(t *testing.T) {
	e := newEnv(t)
	real := classicalServer(t)
	victim := e.addAsset(slowProxy(t, real.Addr, 150*time.Millisecond))
	sc := e.startScan(victim.ID)
	time.Sleep(400 * time.Millisecond)
	if s, _ := e.do("DELETE", "/api/v1/assets/"+itoa(victim.ID), nil); s != 204 {
		t.Fatalf("delete mid-scan: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/scans/"+itoa(sc.ID), nil); s != 404 {
		t.Errorf("scan of a deleted asset: %d", s)
	}
	// The runner is still healthy.
	ok := e.addAsset(real.Addr)
	if got := e.scanAndWait(ok.ID); got.Status != "done" {
		t.Errorf("runner wedged after a delete mid-scan: %+v", got)
	}
}

// AC-12.2, at the level of a whole server restart.
func TestAC12_RestartMarksInterruptedScansFailed(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset("never-reached.example")
	sc, _, err := e.st.EnqueueScan(a.ID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: the scan is running when the process dies. (The worker is
	// stopped first so that it cannot pick the scan up itself.)
	_, _ = e.st.ClaimNext()
	n, err := e.st.FailInterrupted()
	if err != nil || n != 1 {
		t.Fatalf("FailInterrupted = %d, %v", n, err)
	}
	got, _ := e.st.GetScan(sc.ID)
	if got.Status != store.StatusFailed || !strings.Contains(got.Error, "restart") {
		t.Errorf("scan = %+v", got)
	}
}
