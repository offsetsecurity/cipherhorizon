package app

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
)

// inProcessTransport is an http.RoundTripper that hands each request to an http.Handler in the
// same process: serve --mcp's fleet tools call the server's own API this way, with the caller's
// credentials, so roles, rate limits and the audit trail see them as they see the web interface.
// The handler is set once the server exists (the MCP handler is built before it).
type inProcessTransport struct {
	handler atomic.Pointer[http.Handler]
}

func (t *inProcessTransport) set(h http.Handler) { t.handler.Store(&h) }

// RoundTrip serves the request with the handler and returns what it wrote.
func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := t.handler.Load()
	if h == nil {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 starting", Header: http.Header{},
			Body: io.NopCloser(bytes.NewReader([]byte(`{"error":"the server is still starting"}`))), Request: req}, nil
	}
	rec := &memResponse{header: http.Header{}, status: http.StatusOK}
	r := req.Clone(req.Context())
	r.RemoteAddr = "127.0.0.1:0" // this process; the MCP guard already logged the real client
	r.RequestURI = req.URL.RequestURI()
	(*h).ServeHTTP(rec, r)
	return &http.Response{
		StatusCode: rec.status, Status: http.StatusText(rec.status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: rec.header, Body: io.NopCloser(bytes.NewReader(rec.body.Bytes())), ContentLength: int64(rec.body.Len()), Request: req,
	}, nil
}

// memResponse is the smallest http.ResponseWriter that holds a response.
type memResponse struct {
	header http.Header
	status int
	wrote  bool
	body   bytes.Buffer
}

// Header is the response header the handler writes to.
func (m *memResponse) Header() http.Header { return m.header }

// WriteHeader records the status; the first call wins, as in net/http.
func (m *memResponse) WriteHeader(status int) {
	if !m.wrote {
		m.status, m.wrote = status, true
	}
}

func (m *memResponse) Write(p []byte) (int, error) {
	m.wrote = true
	return m.body.Write(p)
}
