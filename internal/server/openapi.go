package server

import (
	_ "embed"
	"net/http"
)

// openAPI is the hand-maintained OpenAPI 3.1 description of every route (PRD-003 REQ-EXP-5).
// TestOpenAPIDescribesExactlyTheRegisteredRoutes fails when it and the route table disagree.
//
//go:embed openapi.json
var openAPI []byte

func (s *Server) openAPIDoc(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(openAPI)
}
