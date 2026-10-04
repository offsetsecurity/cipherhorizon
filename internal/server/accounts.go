package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/cipherhorizon/internal/auth"
	"github.com/example/cipherhorizon/internal/store"
)

// Accounts and sign-in (ADR-0018). Who is calling is decided once per request by identify: a
// session cookie (a person in a browser), the automation bearer token (a script), or nobody.
// Roles are enforced centrally in authorize, so a new route is protected without remembering to.

// Session cookie and timeouts.
const (
	sessionCookie      = "ch_session"
	defaultSessionIdle = 30 * time.Minute
	defaultSessionMax  = 12 * time.Hour
	touchEvery         = time.Minute
)

// Lockout and rate limits for password guessing.
const (
	lockAfter       = 5                // consecutive failures on one account
	lockFor         = 15 * time.Minute // how long the account then refuses sign-in
	clientFailLimit = 20               // failed attempts from one client address ...
	clientFailSpan  = 15 * time.Minute // ... within this window, after which it gets 429
)

// principal is who a request acts for.
type principal struct {
	Kind       string // session | token | local
	UserID     int64
	Username   string
	Role       string
	SessionID  int64
	MustChange bool
}

type ctxKey struct{}

func principalOf(r *http.Request) (principal, bool) {
	p, ok := r.Context().Value(ctxKey{}).(principal)
	return p, ok
}

// actor is the name recorded in audit trails for a change.
func (s *Server) actor(r *http.Request) string {
	if p, ok := principalOf(r); ok {
		return p.Username
	}
	if s.cfg.Token != "" {
		return "api-token"
	}
	return "local"
}

func clientOf(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// limiter counts failed sign-ins per client address.
type limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *limiter) blocked(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(client, now)) >= clientFailLimit
}

func (l *limiter) fail(client string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	if len(l.hits) > 10000 { // a flood of addresses cannot grow the map without bound
		l.hits = map[string][]time.Time{}
	}
	l.hits[client] = append(l.recent(client, now), now)
}

func (l *limiter) recent(client string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.hits[client] {
		if now.Sub(t) < clientFailSpan {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.hits, client)
	}
	return keep
}

// hashSlots bounds concurrent password hashing (each takes a few hundred milliseconds of CPU),
// so a burst of sign-in attempts cannot starve the scanner.
var hashSlots = make(chan struct{}, 4)

func withHashSlot(ctx context.Context, f func()) error {
	select {
	case hashSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-hashSlots }()
	f()
	return nil
}

func (s *Server) sessionIdle() time.Duration {
	if s.cfg.SessionIdle > 0 {
		return s.cfg.SessionIdle
	}
	return defaultSessionIdle
}

func (s *Server) sessionMax() time.Duration {
	if s.cfg.SessionMax > 0 {
		return s.cfg.SessionMax
	}
	return defaultSessionMax
}

func (s *Server) audit(r *http.Request, kind, username, detail string) {
	actor := ""
	if p, ok := principalOf(r); ok {
		actor = p.Username
	}
	if err := s.cfg.Store.AddAuthEvent(store.AuthEvent{Kind: kind, Username: username, Actor: actor, Client: clientOf(r), Detail: detail}); err != nil {
		s.log.Error("audit write failed", "kind", kind, "err", err)
	}
	s.log.Info("auth", "event", kind, "user", username, "actor", actor, "client", clientOf(r))
}

// identify finds who is calling. bad is true when credentials were offered and were wrong.
func (s *Server) identify(r *http.Request) (p principal, ok, bad bool) {
	if h := r.Header.Get("Authorization"); h != "" {
		got, hasScheme := strings.CutPrefix(h, "Bearer ")
		if s.cfg.Token != "" && hasScheme && constEq(got, s.cfg.Token) {
			return principal{Kind: "token", Username: "api-token", Role: store.RoleAnalyst}, true, false
		}
		return principal{}, false, true
	}
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		sess, u, err := s.cfg.Store.SessionByHash(auth.HashToken(c.Value))
		if err != nil {
			return principal{}, false, false
		}
		now := s.cfg.Now()
		if u.Disabled || now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.sessionIdle() {
			_ = s.cfg.Store.DeleteSession(sess.ID, 0)
			return principal{}, false, false
		}
		if now.Sub(sess.LastSeenAt) > touchEvery {
			_ = s.cfg.Store.TouchSession(sess.ID)
		}
		return principal{Kind: "session", UserID: u.ID, Username: u.Username, Role: u.Role, SessionID: sess.ID, MustChange: u.MustChange}, true, false
	}
	if !s.cfg.RequireLogin && s.cfg.Token == "" {
		// Loopback without sign-in (--no-login): one local operator with every right.
		return principal{Kind: "local", Username: "local", Role: store.RoleAdmin}, true, false
	}
	return principal{}, false, false
}

// publicAPI are the routes that answer without a principal.
func publicAPI(path string) bool {
	switch path {
	case "/api/v1/health", "/api/v1/auth/state", "/api/v1/auth/login", "/api/v1/auth/setup", "/api/v1/auth/logout":
		return true
	}
	return false
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r) // the UI's files hold no data
			return
		}
		p, ok, bad := s.identify(r)
		if ok {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, p))
		}
		if !ok && !publicAPI(r.URL.Path) {
			if bad {
				// Record who tried (never what they sent) and slow the guessing down.
				s.log.Warn("authentication failed", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				select {
				case <-time.After(authFailDelay):
				case <-r.Context().Done():
				}
			}
			if s.cfg.RequireLogin {
				writeErr(w, http.StatusUnauthorized, "sign in to continue")
			} else {
				writeErr(w, http.StatusUnauthorized, "a valid bearer token is required")
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

// roles applies authorize to every identified API request.
func (s *Server) roles(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := principalOf(r); ok && strings.HasPrefix(r.URL.Path, "/api/") && !s.authorize(w, r, p) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorize applies the roles: a viewer only reads; accounts and the audit trail are for
// administrators; an account that must change its password can do only that.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, p principal) bool {
	path := r.URL.Path
	self := strings.HasPrefix(path, "/api/v1/auth/")
	if p.MustChange && !self {
		writeErr(w, http.StatusForbidden, "change your password before continuing")
		return false
	}
	if (strings.HasPrefix(path, "/api/v1/users") || path == "/api/v1/auth/events") && p.Role != store.RoleAdmin {
		writeErr(w, http.StatusForbidden, "only an administrator can do this")
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if !self && p.Role == store.RoleViewer {
		writeErr(w, http.StatusForbidden, "your account can view and download only")
		return false
	}
	return true
}

// ---- cookies ----------------------------------------------------------------------------

// secureRequest reports whether the browser reached the server over HTTPS: a TLS listener, or a
// TLS-terminating proxy that says so. Trusting the proxy header here is safe: a forged one can
// only make the cookie stricter.
func (s *Server) secureRequest(r *http.Request) bool {
	return s.cfg.SecureCookies || r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// Secure is set whenever the browser's connection is HTTPS (see secureRequest). serve refuses
// plain HTTP beyond loopback unless --plain-http says a TLS proxy is in front.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: Secure is conditional by design, see above
		Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.secureRequest(r), MaxAge: int(s.sessionMax() / time.Second),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, //nolint:gosec // G124: as setSessionCookie
		Secure: s.secureRequest(r), MaxAge: -1})
}

// startSession signs u in on this browser: a new token every time (never reuse one a client
// brought), stored only as its hash.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User) error {
	token, hash, err := auth.NewToken()
	if err != nil {
		return err
	}
	if _, err := s.cfg.Store.CreateSession(hash, u.ID, s.cfg.Now().Add(s.sessionMax()), clientOf(r), r.UserAgent()); err != nil {
		return err
	}
	s.setSessionCookie(w, r, token)
	return nil
}

// ---- handlers ---------------------------------------------------------------------------

type meView struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Role        string `json:"role"`
	Kind        string `json:"kind"`
	MustChange  bool   `json:"mustChangePassword"`
}

func (s *Server) me(r *http.Request) *meView {
	p, ok := principalOf(r)
	if !ok {
		return nil
	}
	v := &meView{ID: p.UserID, Username: p.Username, Role: p.Role, Kind: p.Kind, MustChange: p.MustChange}
	if p.UserID != 0 {
		if u, err := s.cfg.Store.GetUser(p.UserID); err == nil {
			v.DisplayName = u.DisplayName
		}
	}
	return v
}

func (s *Server) authState(w http.ResponseWriter, r *http.Request) {
	setup := false
	if s.cfg.RequireLogin {
		n, err := s.cfg.Store.CountUsers()
		if err != nil {
			storeErr(w, err)
			return
		}
		setup = n == 0
	}
	writeJSON(w, 200, map[string]any{
		"loginRequired": s.cfg.RequireLogin, "setupRequired": setup, "user": s.me(r),
		"passwordMinLength": auth.MinPasswordLen, "sessionIdleMinutes": int(s.sessionIdle() / time.Minute),
	})
}

func (s *Server) tooManyAttempts(w http.ResponseWriter, r *http.Request) bool {
	if s.failures.blocked(clientOf(r), s.cfg.Now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(clientFailSpan/time.Second)))
		writeErr(w, http.StatusTooManyRequests, "too many failed attempts from this address; try again in 15 minutes")
		return true
	}
	return false
}

func (s *Server) authSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code, Username, DisplayName, Password string
	}
	if !decode(w, r, &in) || s.tooManyAttempts(w, r) {
		return
	}
	if !s.cfg.RequireLogin {
		writeErr(w, http.StatusConflict, "this server runs without sign-in")
		return
	}
	if n, err := s.cfg.Store.CountUsers(); err != nil || n > 0 {
		writeErr(w, http.StatusConflict, "setup is already complete; sign in instead")
		return
	}
	if s.cfg.SetupCode == "" || !auth.SameCode(in.Code, s.cfg.SetupCode) {
		s.failures.fail(clientOf(r), s.cfg.Now())
		s.audit(r, "setup-failed", in.Username, "wrong setup code")
		writeErr(w, http.StatusForbidden, "the setup code is wrong; it is printed in the server's log when it starts")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := auth.CheckUsername(in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := auth.CheckPassword(in.Password, in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var hash string
	var herr error
	if err := withHashSlot(r.Context(), func() { hash, herr = auth.Hash(in.Password) }); err != nil || herr != nil {
		writeErr(w, http.StatusServiceUnavailable, "try again")
		return
	}
	u, err := s.cfg.Store.CreateFirstAdmin(in.Username, strings.TrimSpace(in.DisplayName), hash)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "setup is already complete; sign in instead")
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "setup", u.Username, "first administrator created")
	_ = s.cfg.Store.RecordLoginSuccess(u.ID)
	if err := s.startSession(w, r, u); err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"user": meView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Kind: "session"}})
}

// loginRefused is the one message for a wrong username or password, so the answer does not say
// which accounts exist.
const loginRefused = "the username or password is wrong"

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) || s.tooManyAttempts(w, r) {
		return
	}
	if !s.cfg.RequireLogin {
		writeErr(w, http.StatusConflict, "this server runs without sign-in")
		return
	}
	_ = s.cfg.Store.PruneSessions(s.sessionIdle())
	now := s.cfg.Now()
	u, err := s.cfg.Store.UserByName(in.Username)
	var ok, rehash bool
	if herr := withHashSlot(r.Context(), func() {
		if err != nil || len(in.Password) > auth.MaxPasswordLen*4 {
			auth.VerifyNothing(in.Password)
			return
		}
		ok, rehash = auth.Verify(in.Password, u.PasswordHash)
	}); herr != nil {
		writeErr(w, http.StatusServiceUnavailable, "try again")
		return
	}
	switch {
	case err != nil && !errors.Is(err, store.ErrNotFound):
		storeErr(w, err)
		return
	case err != nil || !ok:
		s.failures.fail(clientOf(r), now)
		detail := "wrong password"
		if err != nil {
			detail = "no such account"
		} else if n, until, lerr := s.cfg.Store.RecordLoginFailure(u.ID, lockAfter, lockFor); lerr == nil && until != nil {
			detail = fmt.Sprintf("wrong password; account locked until %s after %d failures", until.Format(time.RFC3339), lockAfter)
			s.audit(r, "locked", u.Username, detail)
		} else if lerr == nil {
			detail = fmt.Sprintf("wrong password (%d of %d)", n, lockAfter)
		}
		s.audit(r, "login-failed", in.Username, detail)
		select {
		case <-time.After(authFailDelay):
		case <-r.Context().Done():
		}
		writeErr(w, http.StatusUnauthorized, loginRefused)
		return
	case u.Disabled:
		s.audit(r, "login-failed", u.Username, "account disabled")
		writeErr(w, http.StatusUnauthorized, "this account is disabled; ask an administrator")
		return
	case u.LockedUntil != nil && now.Before(*u.LockedUntil):
		// Only someone who knows the password learns the account is locked.
		s.audit(r, "login-failed", u.Username, "account locked")
		mins := int(u.LockedUntil.Sub(now).Minutes()) + 1
		writeErr(w, http.StatusUnauthorized, fmt.Sprintf("this account is locked after repeated failed sign-ins; try again in %d minutes or ask an administrator", mins))
		return
	}
	if rehash {
		if h, err := auth.Hash(in.Password); err == nil {
			_ = s.cfg.Store.SetPassword(u.ID, h, u.MustChange, -1)
		}
	}
	_ = s.cfg.Store.RecordLoginSuccess(u.ID)
	if err := s.startSession(w, r, u); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "login", u.Username, "")
	writeJSON(w, 200, map[string]any{"user": meView{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Kind: "session", MustChange: u.MustChange}})
}

func (s *Server) authLogout(w http.ResponseWriter, r *http.Request) {
	if p, ok := principalOf(r); ok && p.SessionID != 0 {
		_ = s.cfg.Store.DeleteSession(p.SessionID, 0)
		s.audit(r, "logout", p.Username, "")
	}
	s.clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.me(r))
}

func (s *Server) authPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Current, New string }
	if !decode(w, r, &in) || s.tooManyAttempts(w, r) {
		return
	}
	p, _ := principalOf(r)
	if p.UserID == 0 {
		writeErr(w, http.StatusConflict, "only a signed-in account has a password")
		return
	}
	u, err := s.cfg.Store.GetUser(p.UserID)
	if err != nil {
		storeErr(w, err)
		return
	}
	var ok bool
	if herr := withHashSlot(r.Context(), func() { ok, _ = auth.Verify(in.Current, u.PasswordHash) }); herr != nil {
		writeErr(w, http.StatusServiceUnavailable, "try again")
		return
	}
	if !ok {
		s.failures.fail(clientOf(r), s.cfg.Now())
		s.audit(r, "password-change-failed", u.Username, "wrong current password")
		writeErr(w, http.StatusForbidden, "the current password is wrong")
		return
	}
	if in.New == in.Current {
		writeErr(w, http.StatusBadRequest, "choose a password different from the current one")
		return
	}
	if err := auth.CheckPassword(in.New, u.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.Hash(in.New)
	if err != nil {
		storeErr(w, err)
		return
	}
	// Every other session of the account ends: a stolen session does not survive a password change.
	if err := s.cfg.Store.SetPassword(u.ID, hash, false, p.SessionID); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "password-changed", u.Username, "other sessions ended")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authSessions(w http.ResponseWriter, r *http.Request) {
	p, _ := principalOf(r)
	if p.UserID == 0 {
		writeJSON(w, 200, []any{})
		return
	}
	list, err := s.cfg.Store.UserSessions(p.UserID)
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		out = append(out, map[string]any{"id": v.ID, "createdAt": v.CreatedAt, "lastSeenAt": v.LastSeenAt, "expiresAt": v.ExpiresAt,
			"client": v.Client, "userAgent": v.UserAgent, "current": v.ID == p.SessionID})
	}
	writeJSON(w, 200, out)
}

func (s *Server) authEndSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	p, _ := principalOf(r)
	if p.UserID == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if err := s.cfg.Store.DeleteSession(id, p.UserID); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "session-ended", p.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ev, err := s.cfg.Store.AuthEvents(limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	if ev == nil {
		ev = []store.AuthEvent{}
	}
	writeJSON(w, 200, ev)
}

// ---- account administration (administrators only; enforced in authorize) ---------------------

func validRole(role string) bool {
	for _, r := range store.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func userErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrUsernameTaken), errors.Is(err, store.ErrLastAdmin):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		storeErr(w, err)
	}
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	us, err := s.cfg.Store.ListUsers()
	if err != nil {
		storeErr(w, err)
		return
	}
	if us == nil {
		us = []store.User{}
	}
	writeJSON(w, 200, us)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, DisplayName, Role, Password string }
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := auth.CheckUsername(in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validRole(in.Role) {
		writeErr(w, http.StatusBadRequest, "role must be admin, analyst or viewer")
		return
	}
	if err := auth.CheckPassword(in.Password, in.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.Hash(in.Password)
	if err != nil {
		storeErr(w, err)
		return
	}
	// The administrator chose this password, so its owner replaces it at first sign-in.
	u, err := s.cfg.Store.CreateUser(in.Username, strings.TrimSpace(in.DisplayName), in.Role, hash, true, s.actor(r))
	if err != nil {
		userErr(w, err)
		return
	}
	s.audit(r, "user-created", u.Username, "role "+u.Role)
	writeJSON(w, 201, u)
}

func (s *Server) userID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(w, r)
	if !ok {
		return
	}
	var in struct {
		DisplayName *string
		Role        *string
		Disabled    *bool
	}
	if !decode(w, r, &in) {
		return
	}
	u, err := s.cfg.Store.GetUser(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	name, role, disabled := u.DisplayName, u.Role, u.Disabled
	if in.DisplayName != nil {
		name = strings.TrimSpace(*in.DisplayName)
	}
	if in.Role != nil {
		if !validRole(*in.Role) {
			writeErr(w, http.StatusBadRequest, "role must be admin, analyst or viewer")
			return
		}
		role = *in.Role
	}
	if in.Disabled != nil {
		disabled = *in.Disabled
	}
	nu, err := s.cfg.Store.UpdateUser(id, name, role, disabled)
	if err != nil {
		userErr(w, err)
		return
	}
	s.audit(r, "user-updated", nu.Username, fmt.Sprintf("role %s, disabled %v", nu.Role, nu.Disabled))
	writeJSON(w, 200, nu)
}

func (s *Server) resetUserPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(w, r)
	if !ok {
		return
	}
	var in struct{ Password string }
	if !decode(w, r, &in) {
		return
	}
	u, err := s.cfg.Store.GetUser(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := auth.CheckPassword(in.Password, u.Username); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.Hash(in.Password)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := s.cfg.Store.SetPassword(id, hash, true, 0); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "password-reset", u.Username, "sessions ended; must change at next sign-in")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Store.UnlockUser(id); err != nil {
		storeErr(w, err)
		return
	}
	if u, err := s.cfg.Store.GetUser(id); err == nil {
		s.audit(r, "user-unlocked", u.Username, "")
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.userID(w, r)
	if !ok {
		return
	}
	if p, _ := principalOf(r); p.UserID == id {
		writeErr(w, http.StatusConflict, "you cannot delete your own account")
		return
	}
	u, err := s.cfg.Store.GetUser(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if err := s.cfg.Store.DeleteUser(id); err != nil {
		userErr(w, err)
		return
	}
	s.audit(r, "user-deleted", u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}
