package server_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
)

// SECARCH-001 SR-12: a route added later cannot forget the token, the anti-forgery
// header, the origin check or the Host check, because these tests walk the real route
// table instead of a list somebody has to remember to extend.

var placeholder = regexp.MustCompile(`\{[A-Za-z]+\}`)

func fill(path string) string { return placeholder.ReplaceAllString(path, "1") }

func splitRoute(t *testing.T, route string) (method, path string) {
	t.Helper()
	m, p, ok := strings.Cut(route, " ")
	if !ok {
		t.Fatalf("route %q has no method", route)
	}
	return m, fill(p)
}

func TestTheRouteTableIsNotEmpty(t *testing.T) {
	e := newEnv(t)
	if n := len(e.srv.Routes()); n < 35 {
		t.Fatalf("only %d routes recorded; the table is not being filled", n)
	}
}

func TestEveryAPIRouteRequiresTheToken(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	for _, r := range e.srv.Routes() {
		method, path := splitRoute(t, r)
		if server.PublicAPI(path) {
			continue // health (for a load balancer) and the sign-in routes themselves
		}
		if s, _, _ := e.req(method, path, nil, map[string]string{"Authorization": ""}); s != 401 {
			t.Errorf("%s without a token: %d, want 401", r, s)
		}
		if s, _, _ := e.req(method, path, nil, map[string]string{"Authorization": "Bearer wrong-token-0123456789"}); s != 401 {
			t.Errorf("%s with a wrong token: %d, want 401", r, s)
		}
	}
}

func TestEveryMutatingRouteIsGuardedAgainstForgery(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	mutating := 0
	for _, r := range e.srv.Routes() {
		method, path := splitRoute(t, r)
		if method == "GET" || method == "HEAD" {
			continue
		}
		mutating++
		body := "{}"
		if s, _, _ := e.req(method, path, body, map[string]string{"X-Requested-With": ""}); s != 403 {
			t.Errorf("%s without X-Requested-With: %d, want 403", r, s)
		}
		if s, _, _ := e.req(method, path, body, map[string]string{"Origin": "https://evil.example"}); s != 403 {
			t.Errorf("%s from a foreign origin: %d, want 403", r, s)
		}
		if s, _, _ := e.req(method, path, body, map[string]string{"Sec-Fetch-Site": "cross-site"}); s != 403 {
			t.Errorf("%s marked cross-site: %d, want 403", r, s)
		}
		if s, _, _ := e.req(method, path, "x=1", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); s != 415 {
			t.Errorf("%s with a form body: %d, want 415", r, s)
		}
	}
	if mutating < 10 {
		t.Errorf("only %d mutating routes were found", mutating)
	}
}

func TestEveryRouteRefusesAForeignHost(t *testing.T) {
	e := newEnv(t) // no token: the Host check is what stops DNS rebinding
	for _, r := range e.srv.Routes() {
		method, path := splitRoute(t, r)
		s, _ := e.rawReq(method, path, "evil.example", map[string]string{"X-Requested-With": "cipherhorizon", "Content-Type": "application/json"}, "{}")
		if s != 421 {
			t.Errorf("%s with Host evil.example: %d, want 421", r, s)
		}
	}
}
