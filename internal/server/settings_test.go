package server_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

type settingsJSON struct {
	SignIn struct {
		Required   bool   `json:"required"`
		LockedBy   string `json:"lockedBy"`
		Accounts   int    `json:"accounts"`
		CanTurnOff bool   `json:"canTurnOff"`
	} `json:"signIn"`
}

// UX-REVIEW-008 S3: sign-in is off by default; a person who only wants to scan just scans.
func TestSignInIsOffByDefault(t *testing.T) {
	e := newEnv(t)
	if s, _ := e.do("GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("a default server asks for credentials: %d", s)
	}
	var st struct{ LoginRequired bool }
	e.call("GET", "/api/v1/auth/state", nil, &st)
	var set settingsJSON
	if s := e.call("GET", "/api/v1/settings", nil, &set); s != 200 || st.LoginRequired || set.SignIn.Required || set.SignIn.LockedBy != "" {
		t.Fatalf("settings %d %+v, state %+v", s, set, st)
	}
}

// Turning sign-in on in Settings creates the first administrator, signs this browser in, and from
// then on every request needs an account; the choice outlives a restart; turning it off again
// opens the server; both are in the activity log.
func TestSignInCanBeTurnedOnFromSettings(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t)
	if s, _ := e.do("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true, "username": "ana", "password": "short"}); s != 400 {
		t.Fatalf("a weak password: %d, want 400", s)
	}
	s, body, h := e.req("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true, "username": "ana", "password": "violet amber harbour"}, nil)
	if s != 200 || !strings.Contains(string(body), `"signedIn":true`) {
		t.Fatalf("turn on: %d %s", s, body)
	}
	cookie := cookieOf(t, h)
	if s, _ := e.do("GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("after turning sign-in on, an anonymous request: %d, want 401", s)
	}
	if s, _, _ := e.as(cookie, "GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("the browser that turned it on is signed in: %d", s)
	}
	if v, _ := e.st.Setting(store.SettingSignIn); v != "on" {
		t.Fatalf("setting stored as %q", v)
	}
	// A restart reads the stored choice.
	again := server.New(server.Config{Store: e.st, Runner: e.runner, AllowOpen: true})
	if s := statusOf(t, again, "GET", "/api/v1/assets"); s != 401 {
		t.Fatalf("after a restart, an anonymous request: %d, want 401", s)
	}
	// Only an administrator may turn it off.
	if s, _, _ := e.req("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false}, nil); s != 401 {
		t.Fatalf("anonymous turn-off: %d, want 401", s)
	}
	if s, b, _ := e.as(cookie, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "violet amber harbour"}); s != 200 {
		t.Fatalf("turn off: %d %s", s, b)
	}
	if s, _ := e.do("GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("after turning sign-in off: %d, want 200", s)
	}
	events, _ := e.st.AuthEvents(20)
	kinds := map[string]bool{}
	for _, ev := range events {
		kinds[ev.Kind] = true
	}
	if !kinds["sign-in-enabled"] || !kinds["sign-in-disabled"] || !kinds["user-created"] {
		t.Fatalf("activity log: %v", kinds)
	}
	// Turned on again with accounts already there: no new account, nobody signed in by it.
	s, body, _ = e.req("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true}, nil)
	if s != 200 || !strings.Contains(string(body), `"signedIn":false`) {
		t.Fatalf("turn on again: %d %s", s, body)
	}
	if n, _ := e.st.CountUsers(); n != 1 {
		t.Fatalf("%d accounts, want 1", n)
	}
}

// The command line wins, and a server on the network cannot be opened from the interface.
func TestSignInLocks(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	on := newEnv(t, withLogin(setupCode))
	cookie := setupAdmin(t, on)
	if s, b, _ := on.as(cookie, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "violet amber harbour"}); s != http.StatusConflict || !strings.Contains(string(b), "--sign-in on") {
		t.Fatalf("--sign-in on, turn off: %d %s", s, b)
	}
	off := newEnv(t, forbidLogin())
	if s, b := off.do("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true, "username": "ana", "password": "violet amber harbour"}); s != http.StatusConflict {
		t.Fatalf("--sign-in off, turn on: %d %s", s, b)
	}
	net := newEnv(t, notOpen())
	s, _, h := net.req("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true, "username": "ana", "password": "violet amber harbour"}, nil)
	if s != 200 {
		t.Fatalf("turn on: %d", s)
	}
	var set settingsJSON
	_, raw, _ := net.as(cookieOf(t, h), "GET", "/api/v1/settings", nil)
	mustJSON(t, raw, &set)
	if set.SignIn.CanTurnOff {
		t.Error("a network server offers to turn sign-in off")
	}
	if s, b, _ := net.as(cookieOf(t, h), "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "violet amber harbour"}); s != http.StatusConflict || !strings.Contains(string(b), "--open-network") {
		t.Fatalf("network server, turn off: %d %s", s, b)
	}
}

func statusOf(t *testing.T, s *server.Server, method, path string) int {
	t.Helper()
	req, _ := http.NewRequest(method, "http://127.0.0.1"+path, nil)
	req.Host = "127.0.0.1"
	rec := &recorder{h: http.Header{}}
	s.Handler().ServeHTTP(rec, req)
	return rec.code
}

type recorder struct {
	h    http.Header
	code int
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return len(b), nil }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// UX-REVIEW-008 addendum (D1 to D6): turning sign-in off keeps the accounts and their history,
// ends every session, freezes the accounts, records anonymous actions with their address, needs
// the administrator's password, and turning it on again restores everyone's roles.
func TestTurningSignInOffKeepsAccountsAndHistory(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t)
	_, _, h := e.req("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true, "username": "ana", "password": "violet amber harbour"}, nil)
	admin := cookieOf(t, h)
	if s, b, _ := e.as(admin, "POST", "/api/v1/users", map[string]any{"username": "vic", "role": "viewer", "password": "temporary pass phrase one"}); s != 201 {
		t.Fatalf("add a viewer: %d %s", s, b)
	}
	_, viewer := login(t, e, "vic", "temporary pass phrase one")
	// Something ana did while signed in.
	var a assetJSON
	_, raw, _ := e.as(admin, "POST", "/api/v1/assets", map[string]any{"target": "10.1.1.1:443"})
	mustJSON(t, raw, &a)

	// D5: her password, again; a viewer, a wrong password and an anonymous caller are refused.
	if s, _, _ := e.as(viewer, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "temporary pass phrase one"}); s != 403 {
		t.Fatalf("a viewer turned sign-in off: %d", s)
	}
	if s, b, _ := e.as(admin, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "not my password"}); s != 403 {
		t.Fatalf("a wrong password: %d %s", s, b)
	}
	if s, b, _ := e.as(admin, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false}); s != 403 {
		t.Fatalf("no password: %d %s", s, b)
	}
	s, b, _ := e.as(admin, "PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": false, "password": "violet amber harbour"})
	if s != 200 || !strings.Contains(string(b), `"sessionsEnded":2`) {
		t.Fatalf("turn off: %d %s", s, b)
	}

	// D2: the viewer's old cookie grants nothing different: it is the same anonymous operator.
	if s, _, _ := e.as(viewer, "POST", "/api/v1/assets", map[string]any{"target": "10.1.1.2:443"}); s != 201 {
		t.Fatalf("a leftover viewer cookie still limits its browser: %d", s)
	}
	var me struct {
		User struct{ Kind, Username string } `json:"user"`
	}
	_, raw, _ = e.as(viewer, "GET", "/api/v1/auth/state", nil)
	mustJSON(t, raw, &me)
	if me.User.Kind != "local" {
		t.Fatalf("a leftover cookie is still a session: %+v", me)
	}
	// D1, D3: accounts kept, and frozen.
	var users []struct{ Username, Role string }
	if s := e.call("GET", "/api/v1/users", nil, &users); s != 200 || len(users) != 2 {
		t.Fatalf("accounts while off: %d %+v", s, users)
	}
	for _, req := range []struct{ m, p string }{
		{"POST", "/api/v1/users"}, {"PATCH", "/api/v1/users/1"}, {"DELETE", "/api/v1/users/2"},
		{"POST", "/api/v1/users/1/password"}, {"POST", "/api/v1/users/1/unlock"},
	} {
		if s, b := e.do(req.m, req.p, map[string]any{"username": "eve", "role": "admin", "password": "evil takeover phrase"}); s != http.StatusConflict {
			t.Errorf("%s %s while sign-in is off: %d %s, want 409", req.m, req.p, s, b)
		}
	}
	// D4: history keeps its names; anonymous actions carry their address.
	list, _ := e.st.Activity(store.ActivityFilter{Source: "change", Limit: 50})
	var byAna, byAnyone bool
	for _, x := range list {
		if x.Action == "added" && x.ObjectID == a.ID && x.Actor == "ana" {
			byAna = true
		}
		if x.Action == "added" && x.Actor == "local" && x.Client == "127.0.0.1" {
			byAnyone = true
		}
	}
	if !byAna || !byAnyone {
		t.Fatalf("history: by ana %v, anonymous with address %v: %+v", byAna, byAnyone, list)
	}
	events, _ := e.st.AuthEvents(20)
	if events[0].Kind != "sign-in-disabled" || events[0].Actor != "ana" || !strings.Contains(events[0].Detail, "2 sessions ended") {
		t.Fatalf("the switch is not in the log as expected: %+v", events[0])
	}

	// D6: turned on again, everyone signs in with the account they had, roles unchanged.
	if s, _ := e.do("PUT", "/api/v1/settings/sign-in", map[string]any{"enabled": true}); s != 200 {
		t.Fatalf("turn on again: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("after turning on again, anonymous: %d", s)
	}
	_, viewer2 := login(t, e, "vic", "temporary pass phrase one")
	if s, _, _ := e.as(viewer2, "POST", "/api/v1/assets", map[string]any{"target": "10.1.1.3:443"}); s != 403 {
		t.Fatalf("the viewer is a viewer again: %d", s)
	}
	if s, _, _ := e.as(viewer, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("a cookie from before sign-in was turned off works again: %d", s)
	}
}
