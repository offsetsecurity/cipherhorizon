package server

import (
	"net/http"
	"sort"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// Standards (PRD-017): the catalogue, and how the fleet measures against each one.

// listStandards returns every standard this server judges scans against, with its clauses.
func (s *Server) listStandards(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"standards": eval.Standards()})
}

// standardTally is one standard's share of the fleet.
type standardTally struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Publisher string  `json:"publisher"`
	Protocol  string  `json:"protocol"`
	Meets     int     `json:"meets"`
	Fails     int     `json:"fails"`
	Unknown   int     `json:"notAssessed"`
	NotStored int     `json:"notStored"` // scanned before the standards existed: scan or re-evaluate
	MeetsIDs  []int64 `json:"meetsIds"`
	FailsIDs  []int64 `json:"failsIds"`
}

// standardsCSV lists, for the CSV export, the standards a scan meets and does not meet (by id,
// separated by semicolons), in the catalogue's order.
func standardsCSV(sum map[string]string) (meets, fails string) {
	var m, f []string
	for _, std := range eval.Standards() {
		switch sum[std.ID] {
		case eval.StdMeets:
			m = append(m, std.ID)
		case eval.StdFails:
			f = append(f, std.ID)
		}
	}
	return strings.Join(m, ";"), strings.Join(f, ";")
}

// standardsSummary counts, per standard, the endpoints whose latest scan meets it or not.
func (s *Server) standardsSummary(w http.ResponseWriter, _ *http.Request) {
	as, err := s.cfg.Store.ListAssets(store.KindEndpoint)
	if err != nil {
		storeErr(w, err)
		return
	}
	byID := map[string]*standardTally{}
	var order []string
	for _, std := range eval.Standards() {
		byID[std.ID] = &standardTally{ID: std.ID, Title: std.Title, Publisher: std.Publisher, Protocol: std.Protocol, MeetsIDs: []int64{}, FailsIDs: []int64{}}
		order = append(order, std.ID)
	}
	for _, a := range as {
		d := a.LastDone
		if d == nil {
			continue
		}
		proto := store.ProtocolOf(a.Kind)
		for _, std := range eval.StandardsFor(proto) {
			t := byID[std.ID]
			switch d.Standards[std.ID] {
			case eval.StdMeets:
				t.Meets++
				t.MeetsIDs = append(t.MeetsIDs, a.ID)
			case eval.StdFails:
				t.Fails++
				t.FailsIDs = append(t.FailsIDs, a.ID)
			case eval.StdNotAssessed:
				t.Unknown++
			default:
				t.NotStored++
			}
		}
	}
	out := make([]*standardTally, 0, len(order))
	for _, id := range order {
		t := byID[id]
		sort.Slice(t.MeetsIDs, func(i, j int) bool { return t.MeetsIDs[i] < t.MeetsIDs[j] })
		sort.Slice(t.FailsIDs, func(i, j int) bool { return t.FailsIDs[i] < t.FailsIDs[j] })
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"standards": out})
}
