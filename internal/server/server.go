package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/example/cbom-scan/internal/store"
	"github.com/example/cbom-scan/web"
)

// Config configures the HTTP server.
type Config struct {
	Store  *store.Store
	Runner *Runner
	Guard  Guard

	// Token, if set, is required as a bearer token on every API call. With no
	// token the API is unauthenticated and the server must be bound to loopback
	// (the caller enforces that), and the Host header is checked to defeat DNS
	// rebinding.
	Token string
	// AllowedHosts are extra Host header values accepted when no token is set.
	AllowedHosts []string

	Version            string
	RegistryRetrieved  string
	EvalVersion        string
	MaxConcurrentScans int
	Log                *slog.Logger
	Now                func() time.Time
}

// Server is the HTTP handler and its dependencies.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	handler http.Handler
	log     *slog.Logger
}

// New builds the server.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), log: cfg.Log}
	s.routes()
	s.handler = s.recoverer(s.secureHeaders(s.hostCheck(s.auth(s.mutationGuard(s.mux)))))
	return s
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Handler returns the full handler chain.
func (s *Server) Handler() http.Handler { return s.handler }

// ---- middleware ---------------------------------------------------------------------------

// The CSP forbids everything except same-origin scripts, styles, images and
// fetches: the UI makes no external requests (AC-11.5).
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("handler panic", "path", r.URL.Path, "panic", p, "stack", string(debug.Stack()))
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostport, "[]")
}

// hostCheck rejects requests whose Host header is not one we expect. Without a
// token this is what stops a web page the user visits from reaching a local
// server through DNS rebinding (AC-11.3). With a token the header adds nothing:
// the attacker's page cannot know the token.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	allowed := map[string]bool{"127.0.0.1": true, "localhost": true, "::1": true}
	for _, h := range s.cfg.AllowedHosts {
		allowed[strings.ToLower(hostOnly(h))] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token == "" && !allowed[strings.ToLower(hostOnly(r.Host))] {
			writeErr(w, http.StatusMisdirectedRequest, "unexpected Host header; start the server with --allowed-host to permit it")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" && strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/health" {
			// The scheme is required: a bare token is not accepted.
			got, hasScheme := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !hasScheme || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "a valid bearer token is required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// mutationGuard protects state-changing requests from cross-site forgery
// (AC-11.3): they must carry a custom header (which a foreign page cannot add
// without a CORS preflight the server never approves), must not come from another
// origin, and must send JSON when they send a body.
func (s *Server) mutationGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if strings.HasPrefix(r.URL.Path, "/api/") {
				if r.Header.Get("X-Requested-With") != "cbom-scan" {
					writeErr(w, http.StatusForbidden, "missing X-Requested-With: cbom-scan header")
					return
				}
				if origin := r.Header.Get("Origin"); origin != "" {
					if u, err := url.Parse(origin); err != nil || !strings.EqualFold(u.Host, r.Host) {
						writeErr(w, http.StatusForbidden, "cross-origin request refused")
						return
					}
				}
				if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
					writeErr(w, http.StatusForbidden, "cross-site request refused")
					return
				}
				if r.ContentLength != 0 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- JSON helpers --------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

const maxBody = 1 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// ---- routes ---------------------------------------------------------------------------------

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /api/v1/about", s.about)
	m.HandleFunc("GET /api/v1/summary", s.summary)

	m.HandleFunc("GET /api/v1/assets", s.listAssets)
	m.HandleFunc("POST /api/v1/assets", s.createAsset)
	m.HandleFunc("POST /api/v1/assets/bulk", s.bulkAssets)
	m.HandleFunc("GET /api/v1/assets/{id}", s.getAsset)
	m.HandleFunc("PATCH /api/v1/assets/{id}", s.patchAsset)
	m.HandleFunc("DELETE /api/v1/assets/{id}", s.deleteAsset)
	m.HandleFunc("POST /api/v1/assets/{id}/scan", s.scanAsset)
	m.HandleFunc("GET /api/v1/assets/{id}/history", s.history)
	m.HandleFunc("GET /api/v1/assets/{id}/diff", s.diff)

	m.HandleFunc("POST /api/v1/scans", s.scanMany)
	m.HandleFunc("GET /api/v1/scans", s.listScans)
	m.HandleFunc("GET /api/v1/scans/{id}", s.getScan)
	m.HandleFunc("POST /api/v1/scans/{id}/cancel", s.cancelScan)
	m.HandleFunc("GET /api/v1/scans/{id}/report", s.report)
	m.HandleFunc("GET /api/v1/scans/{id}/evaluation", s.evaluation)

	m.HandleFunc("GET /api/v1/export/assets.csv", s.exportCSV)

	m.HandleFunc("POST /api/v1/hosts/ingest", s.ingestHost)
	m.HandleFunc("GET /api/v1/hosts", s.listHosts)
	m.HandleFunc("GET /api/v1/hosts/{id}", s.getHost)

	// Unknown API paths get a JSON 404. Registered for GET only so that a wrong
	// method on a real path is answered 405 by the mux rather than swallowed here.
	m.HandleFunc("GET /api/", func(w http.ResponseWriter, _ *http.Request) { writeErr(w, http.StatusNotFound, "no such API endpoint") })
	m.Handle("GET /", web.Handler()) // GET only, so a wrong method on an API path is a 405, not swallowed here
}
