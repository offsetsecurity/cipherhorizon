package server_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/auth"
	"github.com/example/cipherhorizon/internal/server"
)

// ADR-0018: accounts, sessions, roles and the defences around signing in.

const setupCode = "ABCD-EFGH-JKLM"

func cookieOf(t *testing.T, h http.Header) string {
	t.Helper()
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == "ch_session" {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatalf("session cookie flags: %+v", c)
			}
			return c.Value
		}
	}
	return ""
}

// as sends a request with a session cookie (and no bearer token).
func (e *env) as(cookie, method, path string, body any) (int, []byte, http.Header) {
	return e.req(method, path, body, map[string]string{"Cookie": "ch_session=" + cookie, "Authorization": ""})
}

func setupAdmin(t *testing.T, e *env) string {
	t.Helper()
	s, b, h := e.req("POST", "/api/v1/auth/setup", map[string]any{"code": "abcd efgh jklm", "username": "ana", "password": "violet amber harbour"}, nil)
	if s != 201 {
		t.Fatalf("setup: %d %s", s, b)
	}
	return cookieOf(t, h)
}

func login(t *testing.T, e *env, user, pw string) (int, string) {
	t.Helper()
	s, _, h := e.req("POST", "/api/v1/auth/login", map[string]any{"username": user, "password": pw}, nil)
	return s, cookieOf(t, h)
}

func TestSignInIsRequiredAndSetupNeedsTheCode(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	var st struct {
		LoginRequired, SetupRequired bool
		User                         any
	}
	if s := e.call("GET", "/api/v1/auth/state", nil, &st); s != 200 || !st.LoginRequired || !st.SetupRequired || st.User != nil {
		t.Fatalf("state before setup: %d %+v", s, st)
	}
	for _, path := range []string{"/api/v1/assets", "/api/v1/inventory/cbom", "/api/v1/users", "/api/v1/about"} {
		if s, _ := e.do("GET", path, nil); s != 401 {
			t.Errorf("%s without signing in: %d, want 401", path, s)
		}
	}
	if s, _, _ := e.req("POST", "/api/v1/auth/setup", map[string]any{"code": "WRONG-CODE-0000", "username": "eve", "password": "violet amber harbour"}, nil); s != 403 {
		t.Fatalf("setup with a wrong code: %d, want 403", s)
	}
	if s, _, _ := e.req("POST", "/api/v1/auth/setup", map[string]any{"code": setupCode, "username": "ana", "password": "short"}, nil); s != 400 {
		t.Fatalf("setup with a weak password: %d, want 400", s)
	}
	cookie := setupAdmin(t, e)
	if cookie == "" {
		t.Fatal("setup did not sign the administrator in")
	}
	if s, _, _ := e.req("POST", "/api/v1/auth/setup", map[string]any{"code": setupCode, "username": "eve", "password": "violet amber harbour"}, nil); s != 409 {
		t.Fatalf("a second setup: %d, want 409", s)
	}
	if s, _, _ := e.as(cookie, "GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("signed in: %d", s)
	}
	// Only the token's hash is stored: the cookie value appears nowhere in the database.
	if _, _, err := e.st.SessionByHash(cookie); err == nil {
		t.Fatal("the raw session token is stored")
	}
	if _, _, err := e.st.SessionByHash(auth.HashToken(cookie)); err != nil {
		t.Fatalf("the session is not stored under the token's hash: %v", err)
	}
	// Signing out ends the session on the server, not only in the browser.
	if s, _, _ := e.as(cookie, "POST", "/api/v1/auth/logout", nil); s != 204 {
		t.Fatalf("logout: %d", s)
	}
	if s, _, _ := e.as(cookie, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("after logout: %d, want 401", s)
	}
}

func TestWrongPasswordsAreGenericAndLockTheAccount(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	setupAdmin(t, e)
	_, b1, _ := e.req("POST", "/api/v1/auth/login", map[string]any{"username": "ana", "password": "not the password"}, nil)
	_, b2, _ := e.req("POST", "/api/v1/auth/login", map[string]any{"username": "nobody", "password": "not the password"}, nil)
	if string(b1) != string(b2) {
		t.Fatalf("a wrong password and an unknown user answer differently:\n%s\n%s", b1, b2)
	}
	for i := 0; i < 4; i++ { // with the one above, five in a row
		_, _ = login(t, e, "ana", "still not it at all")
	}
	if s, _ := login(t, e, "ana", "violet amber harbour"); s != 401 {
		t.Fatalf("after five failures the right password still signs in (%d); the account should be locked", s)
	}
	_, b, _ := e.req("POST", "/api/v1/auth/login", map[string]any{"username": "ana", "password": "violet amber harbour"}, nil)
	if !strings.Contains(string(b), "locked") {
		t.Fatalf("a locked account with the right password should say so: %s", b)
	}
	evs, _ := e.st.AuthEvents(50)
	kinds := map[string]int{}
	for _, ev := range evs {
		kinds[ev.Kind]++
		if strings.Contains(ev.Detail, "violet") || strings.Contains(ev.Detail, "not the password") {
			t.Fatalf("a password reached the audit trail: %+v", ev)
		}
	}
	if kinds["locked"] != 1 || kinds["login-failed"] < 5 || kinds["setup"] != 1 {
		t.Fatalf("audit trail: %v", kinds)
	}
}

func TestOneAddressIsRateLimited(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	setupAdmin(t, e)
	last := 0
	for i := 0; i < 22; i++ {
		last, _ = login(t, e, "user"+string(rune('a'+i)), "not a real password")
	}
	if last != 429 {
		t.Fatalf("22 failures from one address: last answer %d, want 429", last)
	}
}

func TestRolesAndAccountAdministration(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode))
	admin := setupAdmin(t, e)
	for _, u := range []map[string]any{
		{"username": "vic", "role": "viewer", "password": "temporary pass phrase one"},
		{"username": "alex", "role": "analyst", "password": "temporary pass phrase two"},
	} {
		if s, b, _ := e.as(admin, "POST", "/api/v1/users", u); s != 201 {
			t.Fatalf("add %v: %d %s", u["username"], s, b)
		}
	}
	// An account an administrator made must replace its password before anything else.
	_, vic := login(t, e, "vic", "temporary pass phrase one")
	if s, _, _ := e.as(vic, "GET", "/api/v1/assets", nil); s != 403 {
		t.Fatalf("before changing the temporary password: %d, want 403", s)
	}
	if s, b, _ := e.as(vic, "POST", "/api/v1/auth/password", map[string]any{"current": "temporary pass phrase one", "new": "my own long phrase here"}); s != 204 {
		t.Fatalf("change password: %d %s", s, b)
	}
	if s, _, _ := e.as(vic, "GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("a viewer reads: %d", s)
	}
	if s, _, _ := e.as(vic, "POST", "/api/v1/assets", map[string]any{"target": "example.com"}); s != 403 {
		t.Fatalf("a viewer adds an endpoint: %d, want 403", s)
	}
	if s, _, _ := e.as(vic, "GET", "/api/v1/users", nil); s != 403 {
		t.Fatalf("a viewer lists accounts: %d, want 403", s)
	}
	_, al := login(t, e, "alex", "temporary pass phrase two")
	_, _, _ = e.as(al, "POST", "/api/v1/auth/password", map[string]any{"current": "temporary pass phrase two", "new": "analyst own phrase here"})
	if s, _, _ := e.as(al, "POST", "/api/v1/assets", map[string]any{"target": "example.com"}); s != 201 {
		t.Fatalf("an analyst adds an endpoint: %d", s)
	}
	if s, _, _ := e.as(al, "GET", "/api/v1/auth/events", nil); s != 403 {
		t.Fatalf("an analyst reads the audit trail: %d, want 403", s)
	}
	// The last administrator cannot be demoted, disabled or deleted.
	var users []struct {
		ID       int64
		Username string
	}
	_, b, _ := e.as(admin, "GET", "/api/v1/users", nil)
	_ = json.Unmarshal(b, &users)
	var anaID int64
	for _, u := range users {
		if u.Username == "ana" {
			anaID = u.ID
		}
	}
	if s, _, _ := e.as(admin, "PATCH", "/api/v1/users/"+itoa(anaID), map[string]any{"role": "viewer"}); s != 409 {
		t.Fatalf("demoting the last administrator: %d, want 409", s)
	}
	// Disabling an account ends its sessions at once.
	var vicID int64
	for _, u := range users {
		if u.Username == "vic" {
			vicID = u.ID
		}
	}
	if s, _, _ := e.as(admin, "PATCH", "/api/v1/users/"+itoa(vicID), map[string]any{"disabled": true}); s != 200 {
		t.Fatalf("disable: %d", s)
	}
	if s, _, _ := e.as(vic, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("a disabled account's session: %d, want 401", s)
	}
}

func TestSessionsExpireAndPasswordChangesEndOthers(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	clock := &fakeClock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	e := newEnv(t, withLogin(setupCode), withClock(clock))
	a := setupAdmin(t, e)
	_, b := login(t, e, "ana", "violet amber harbour")
	clock.Advance(20 * time.Minute)
	if s, _, _ := e.as(a, "GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("20 minutes idle: %d", s)
	}
	clock.Advance(31 * time.Minute)
	if s, _, _ := e.as(b, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("51 minutes idle: %d, want 401", s)
	}
	_, a = login(t, e, "ana", "violet amber harbour")
	_, c := login(t, e, "ana", "violet amber harbour")
	if s, _, _ := e.as(a, "POST", "/api/v1/auth/password", map[string]any{"current": "violet amber harbour", "new": "a brand new phrase"}); s != 204 {
		t.Fatalf("change: %d", s)
	}
	if s, _, _ := e.as(a, "GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("the session that changed the password: %d", s)
	}
	if s, _, _ := e.as(c, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("another session after a password change: %d, want 401", s)
	}
	for i := 0; i < 30; i++ { // an active session still ends at the absolute limit
		clock.Advance(25 * time.Minute)
		_, _, _ = e.as(a, "GET", "/api/v1/assets", nil)
	}
	if s, _, _ := e.as(a, "GET", "/api/v1/assets", nil); s != 401 {
		t.Fatalf("after 12 hours: %d, want 401", s)
	}
}

func TestTheAutomationTokenStillWorksWithAccounts(t *testing.T) {
	defer server.SetAuthFailDelay(0)()
	e := newEnv(t, withLogin(setupCode), withToken("automation-token-0123456789"))
	if s, _ := e.do("GET", "/api/v1/assets", nil); s != 200 {
		t.Fatalf("bearer token: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/users", nil); s != 403 {
		t.Fatalf("the token administers accounts: %d, want 403", s)
	}
}
