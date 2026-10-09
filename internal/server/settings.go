package server

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/example/cipherhorizon/internal/auth"
	"github.com/example/cipherhorizon/internal/store"
)

// Settings (UX-REVIEW-008 S3, S4): sign-in is off by default, because most people come for a TLS
// scan on their own machine. A team turns it on here; the first administrator is created in the
// same step. The server's own configuration (from its command line) is shown here too, read-only.

// initialSignIn decides whether sign-in is required when the server starts.
func (s *Server) initialSignIn() bool {
	switch {
	case s.cfg.RequireLogin:
		return true
	case s.cfg.ForbidLogin:
		return false
	}
	v, err := s.cfg.Store.Setting(store.SettingSignIn)
	if err != nil {
		// Unreadable: fail closed.
		s.log.Error("reading the sign-in setting failed; requiring sign-in", "err", err)
		return true
	}
	return v == "on"
}

// signInOn reports whether every API call needs a signed-in account (or the automation token).
func (s *Server) signInOn() bool { return s.signIn.Load() }

// signInLock says who decided sign-in, when it cannot be changed here: "on" or "off" from the
// server's command line, or "" when Settings decides.
func (s *Server) signInLock() string {
	switch {
	case s.cfg.RequireLogin:
		return "on"
	case s.cfg.ForbidLogin:
		return "off"
	}
	return ""
}

func (s *Server) getSettings(w http.ResponseWriter, _ *http.Request) {
	n, err := s.cfg.Store.CountUsers()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"signIn": map[string]any{
			"required": s.signInOn(), "lockedBy": s.signInLock(), "accounts": n,
			// canTurnOff is false on a server reachable from the network without --open-network.
			"canTurnOff": s.cfg.AllowOpen && s.signInLock() == "",
		},
		"server": map[string]any{
			"version": s.cfg.Version, "evalVersion": s.cfg.EvalVersion,
			"automationToken": s.cfg.Token != "", "allowLoopback": s.cfg.Guard.AllowLoopback,
			"scanScope":          append([]string{}, s.cfg.Guard.Scope.Entries()...),
			"httpChecks":         s.cfg.Runner.HTTPChecks(),
			"maxConcurrentScans": s.cfg.MaxConcurrentScans, "retentionPerAsset": store.Retention,
			"sessionIdleMinutes": int(s.sessionIdle().Minutes()), "sessionMaxHours": int(s.sessionMax().Hours()),
		},
	})
}

// putSignIn turns sign-in on or off. Turning it on with no account yet creates the first
// administrator from the request and signs this browser in; the caller, with sign-in off, already
// has every right on this server.
func (s *Server) putSignIn(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled                         bool
		Username, DisplayName, Password string
	}
	if !decode(w, r, &in) {
		return
	}
	if lock := s.signInLock(); lock != "" {
		writeErr(w, http.StatusConflict, "sign-in is set to "+lock+" by the server's command line (--sign-in "+lock+"); change it there")
		return
	}
	if !in.Enabled {
		if !s.signInOn() {
			writeJSON(w, 200, map[string]any{"required": false})
			return
		}
		if !s.cfg.AllowOpen {
			writeErr(w, http.StatusConflict, "this server is reachable from the network; turning sign-in off would let anyone who reaches it use it. "+
				"Restart it with --open-network to allow that")
			return
		}
		// D5: an administrator, signed in, who types their own password again.
		p, _ := principalOf(r)
		if p.Kind != "session" || p.Role != store.RoleAdmin {
			writeErr(w, http.StatusForbidden, "turning sign-in off needs an administrator signed in with their own account")
			return
		}
		if s.tooManyAttempts(w, r, p.Username) {
			return
		}
		u, err := s.cfg.Store.GetUser(p.UserID)
		if err != nil {
			storeErr(w, err)
			return
		}
		ok := false
		if herr := withHashSlot(r.Context(), func() { ok, _ = auth.Verify(in.Password, u.PasswordHash) }); herr != nil {
			writeErr(w, http.StatusServiceUnavailable, "try again")
			return
		}
		if !ok {
			s.failedSignIn(r, p.Username)
			writeErr(w, http.StatusForbidden, "that is not your password")
			return
		}
		if err := s.cfg.Store.SetSetting(store.SettingSignIn, "off"); err != nil {
			storeErr(w, err)
			return
		}
		s.signIn.Store(false)
		ended, err := s.cfg.Store.EndAllSessions()
		if err != nil {
			s.log.Error("ending sessions after turning sign-in off failed", "err", err)
		}
		s.clearSessionCookie(w, r)
		sessions := "1 session"
		if ended != 1 {
			sessions = fmt.Sprintf("%d sessions", ended)
		}
		s.audit(r, "sign-in-disabled", s.actor(r), "sign-in is no longer required; "+sessions+" ended; accounts kept and frozen")
		writeJSON(w, 200, map[string]any{"required": false, "sessionsEnded": ended})
		return
	}
	if s.signInOn() {
		writeJSON(w, 200, map[string]any{"required": true})
		return
	}
	n, err := s.cfg.Store.CountUsers()
	if err != nil {
		storeErr(w, err)
		return
	}
	var created *store.User
	if n == 0 {
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
			writeErr(w, http.StatusConflict, "an account was created meanwhile; reload")
			return
		}
		if err != nil {
			storeErr(w, err)
			return
		}
		created = &u
		s.audit(r, "user-created", u.Username, "first administrator, when sign-in was turned on")
	}
	if err := s.cfg.Store.SetSetting(store.SettingSignIn, "on"); err != nil {
		storeErr(w, err)
		return
	}
	s.signIn.Store(true)
	s.audit(r, "sign-in-enabled", s.actor(r), "sign-in is now required")
	out := map[string]any{"required": true, "signedIn": false}
	if created != nil {
		if err := s.cfg.Store.RecordLoginSuccess(created.ID); err != nil {
			s.log.Warn("recording a sign-in failed", "user", created.Username, "err", err)
		}
		if err := s.startSession(w, r, *created); err != nil {
			storeErr(w, err)
			return
		}
		out["signedIn"] = true
	}
	writeJSON(w, 200, out)
}
