package mcpserver

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPOptions configures Handler.
type HTTPOptions struct {
	// Key, when set, is required as a bearer token on every request (compared in constant time).
	Key string
	// Authenticate, when set, runs before the MCP handler and decides whether the request may
	// proceed (serve --mcp passes the web server's own identification). It returns false after
	// writing its own refusal.
	Authenticate func(w http.ResponseWriter, r *http.Request) bool
	// ForwardCredentials makes the fleet tools call the API with the request's own Authorization
	// and Cookie headers rather than a fixed token (serve --mcp).
	ForwardCredentials bool
}

// Handler serves the MCP server over Streamable HTTP, stateless (the 2026-07-28 revision's
// mode): no sessions, every POST self-contained, GET and DELETE answered 405. The SDK refuses
// requests that reach a loopback listener with a foreign Host header (DNS rebinding); Origin is
// checked here as the specification asks.
func (s *Server) Handler(opts HTTPOptions) http.Handler {
	var h http.Handler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.Server
	}, &mcp.StreamableHTTPOptions{Stateless: true, Logger: s.opts.Log})

	if opts.ForwardCredentials {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner.ServeHTTP(w, r.WithContext(WithCredentials(r.Context(), r.Header)))
		})
	}
	if opts.Key != "" {
		key := []byte(opts.Key)
		verify := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
			if subtle.ConstantTimeCompare([]byte(token), key) != 1 {
				return nil, auth.ErrInvalidToken
			}
			return &auth.TokenInfo{UserID: "key"}, nil
		}
		h = auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(h)
	}
	if opts.Authenticate != nil {
		inner := h
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if opts.Authenticate(w, r) {
				inner.ServeHTTP(w, r)
			}
		})
	}
	// A browser page cannot be an MCP client: refuse anything a browser marks as cross-site, and
	// any Origin that is not this server. Assistants send neither header.
	return http.NewCrossOriginProtection().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}))
}
