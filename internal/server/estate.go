package server

import (
	"net/http"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
)

// estateRanking is the prioritised list of systems, each row explained by cited rules. There is
// no score: the rules are the ordering, and they are published beside the list.
func (s *Server) estateRanking(w http.ResponseWriter, _ *http.Request) {
	inputs, err := s.cfg.Store.PriorityInputs()
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	writeJSON(w, 200, map[string]any{
		"version":     eval.PriorityVersion,
		"generatedAt": now.UTC().Format("2006-01-02T15:04:05Z"),
		"ranking":     eval.Prioritise(inputs, now),
		"rules":       eval.PriorityMethodology(),
	})
}
