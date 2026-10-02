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

	"github.com/example/cipherhorizon/internal/store"
	"github.com/example/cipherhorizon/web"
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

	routeTable []string
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
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()")
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

// authFailDelay is how long a failed authentication is held before it is
// answered, which makes guessing a token over the network slow.
var authFailDelay = 250 * time.Millisecond

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token != "" && strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/api/v1/health" {
			// The scheme is required: a bare token is not accepted.
			got, hasScheme := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !hasScheme || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.Token)) != 1 {
				// Record who tried (never what they sent) and slow the guessing down.
				s.log.Warn("authentication failed", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
				select {
				case <-time.After(authFailDelay):
				case <-r.Context().Done():
				}
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
				if r.Header.Get("X-Requested-With") != "cipherhorizon" {
					writeErr(w, http.StatusForbidden, "missing X-Requested-With: cipherhorizon header")
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
				if r.ContentLength != 0 && !bodyTypeOK(r) {
					writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// bodyTypeOK reports whether a request's body has a type the route accepts: JSON
// everywhere, and CSV on the one route that reads it.
func bodyTypeOK(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		return true
	}
	return r.URL.Path == "/api/v1/systems/import.csv" && strings.HasPrefix(ct, "text/csv")
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

// Routes lists every registered API route as "METHOD /path" with {name} placeholders,
// in registration order.
func (s *Server) Routes() []string { return append([]string(nil), s.routeTable...) }

// ---- routes ---------------------------------------------------------------------------------

func (s *Server) routes() {
	m := s.mux
	// handle registers a route and records it, so tests can walk the real route table
	// instead of a list that could drift from it.
	handle := func(pattern string, h http.HandlerFunc) {
		m.HandleFunc(pattern, h)
		s.routeTable = append(s.routeTable, pattern)
	}
	handle("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	handle("GET /api/v1/about", s.about)
	handle("GET /api/v1/openapi.json", s.openAPIDoc)
	handle("GET /api/v1/summary", s.summary)

	handle("GET /api/v1/assets", s.listAssets)
	handle("POST /api/v1/assets", s.createAsset)
	handle("POST /api/v1/assets/bulk", s.bulkAssets)
	handle("GET /api/v1/assets/{id}", s.getAsset)
	handle("PATCH /api/v1/assets/{id}", s.patchAsset)
	handle("DELETE /api/v1/assets/{id}", s.deleteAsset)
	handle("POST /api/v1/assets/{id}/scan", s.scanAsset)
	handle("GET /api/v1/assets/{id}/history", s.history)
	handle("GET /api/v1/assets/{id}/diff", s.diff)
	handle("GET /api/v1/assets/{id}/findings", s.listAssetFindings)
	handle("PUT /api/v1/assets/{id}/findings/{key}/status", s.setFindingStatus)
	handle("DELETE /api/v1/assets/{id}/findings/{key}/status", s.clearFindingStatus)
	handle("PUT /api/v1/assets/{id}/links/{otherId}", s.linkAssets)
	handle("DELETE /api/v1/assets/{id}/links/{otherId}", s.unlinkAssets)

	handle("GET /api/v1/findings", s.fleetFindings)

	handle("GET /api/v1/systems", s.listSystems)
	handle("GET /api/v1/systems/export.csv", s.exportSystemsCSV)
	handle("POST /api/v1/systems/import.csv", s.importSystemsCSV)
	handle("GET /api/v1/systems/{id}", s.getSystem)
	handle("PATCH /api/v1/systems/{id}", s.patchSystem)
	handle("GET /api/v1/systems/{id}/m2302.json", s.m2302JSON)
	handle("GET /api/v1/systems/{id}/m2302.csv", s.m2302CSV)
	handle("GET /api/v1/systems/{id}/audit", s.systemAudit)
	handle("GET /api/v1/systems/{id}/trust-anchors", s.listTrustAnchors)
	handle("POST /api/v1/systems/{id}/trust-anchors", s.addTrustAnchors)
	handle("DELETE /api/v1/systems/{id}/trust-anchors/{fingerprint}", s.removeTrustAnchor)
	handle("GET /api/v1/trust-anchors", s.serverTrustAnchors)
	handle("GET /api/v1/reference-data", s.referenceData)
	handle("GET /api/v1/systems/{id}/observations", s.systemObservations)
	handle("GET /api/v1/systems/{id}/certificates", s.systemCertificates)
	handle("GET /api/v1/certificates", s.listCertificates)
	handle("GET /api/v1/certificates/{fingerprint}", s.getCertificate)
	handle("POST /api/v1/imports", s.importDocument)
	handle("GET /api/v1/imports", s.listImports)
	handle("GET /api/v1/imports/{id}", s.getImport)
	handle("POST /api/v1/imports/{id}/withdraw", s.withdrawImport)
	handle("GET /api/v1/links", s.listLinks)
	handle("POST /api/v1/links/{id}/confirm", s.confirmLink)
	handle("POST /api/v1/links/{id}/reject", s.rejectLink)
	handle("GET /api/v1/systems/{id}/links", s.systemLinks)
	handle("GET /api/v1/estate", s.estateRanking)
	handle("GET /api/v1/entities", s.listEntities)
	handle("GET /api/v1/graph/stats", s.graphStats)

	handle("POST /api/v1/scans", s.scanMany)
	handle("GET /api/v1/scans", s.listScans)
	handle("GET /api/v1/scans/{id}", s.getScan)
	handle("POST /api/v1/scans/{id}/cancel", s.cancelScan)
	handle("POST /api/v1/scans/{id}/reevaluate", s.reevaluateScan)
	handle("GET /api/v1/scans/{id}/report", s.report)
	handle("GET /api/v1/scans/{id}/evaluation", s.evaluation)
	handle("GET /api/v1/scans/{id}/cbom", s.scanCBOM)

	handle("GET /api/v1/export/assets.csv", s.exportCSV)

	handle("POST /api/v1/hosts/ingest", s.ingestHost)
	handle("GET /api/v1/hosts", s.listHosts)
	handle("GET /api/v1/hosts/{id}", s.getHost)
	handle("GET /api/v1/hosts/{id}/snapshots/{snapshotId}/cbom", s.hostSnapshotCBOM)

	handle("GET /api/v1/collector/binaries", s.listCollectorBinaries)
	handle("GET /api/v1/collector/binaries/{name}", s.downloadCollectorBinary)

	// Unknown API paths get a JSON 404. Registered for GET only so that a wrong
	// method on a real path is answered 405 by the mux rather than swallowed here.
	m.HandleFunc("GET /api/", func(w http.ResponseWriter, _ *http.Request) { writeErr(w, http.StatusNotFound, "no such API endpoint") })
	m.Handle("GET /", web.Handler()) // GET only, so a wrong method on an API path is a 405, not swallowed here
}
