package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

func parseIDPath(v string) (int64, error) {
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return 0, strconv.ErrSyntax
	}
	return id, nil
}

// FlatFinding is one triageable finding, from either a TLS scan's evaluation
// or a host's CBOM algorithm classification. The two source systems have
// different shapes — an eval.Finding carries a severity tier; a host's
// pqc-derived verdict only has a vulnerable/safe class — so this never claims
// a host finding has a severity it doesn't have: Severity is set only for TLS
// findings, Class only for host findings.
type FlatFinding struct {
	AssetID   int64  `json:"assetId"`
	AssetName string `json:"assetName"`
	AssetKind string `json:"assetKind"`

	// Key identifies the finding within its asset: a rule ID ("CIPHER.RC4") for
	// a TLS finding, or "pqc:<algorithm name>" for a host algorithm verdict.
	Key         string          `json:"key"`
	Title       string          `json:"title"`
	Detail      string          `json:"detail,omitempty"`
	Severity    string          `json:"severity,omitempty"`
	Category    string          `json:"category,omitempty"`
	Evidence    string          `json:"evidence,omitempty"`
	Class       string          `json:"class,omitempty"`
	Citations   []eval.Citation `json:"citations,omitempty"`
	Remediation string          `json:"remediation,omitempty"`

	Status *store.FindingStatus `json:"status,omitempty"`
}

// severityRank orders findings worst-first; host "vulnerable" findings sort
// alongside "high" without literally being labelled that severity, since
// their source (a capability classification) is not the same kind of
// evidence as a TLS finding's cited rule.
func severityRank(f FlatFinding) int {
	switch eval.Severity(f.Severity) {
	case eval.Critical:
		return 0
	case eval.High:
		return 1
	case eval.Medium:
		return 2
	case eval.Low:
		return 3
	}
	if f.Class == string(pqc.Vulnerable) {
		return 1
	}
	return 4
}

// assetFindings loads one asset's current findings with any triage state
// applied. Works for either asset kind.
func (s *Server) assetFindings(a store.Asset) ([]FlatFinding, error) {
	statuses, err := s.cfg.Store.FindingStatuses(a.ID)
	if err != nil {
		return nil, err
	}
	var out []FlatFinding
	switch a.Kind {
	case store.KindTLS:
		if a.LastDone == nil {
			return []FlatFinding{}, nil
		}
		eb, err := s.cfg.Store.Evaluation(a.LastDone.ID)
		if err != nil {
			return nil, err
		}
		var ev eval.Evaluation
		if err := json.Unmarshal(eb, &ev); err != nil {
			return nil, err
		}
		for _, f := range ev.Findings {
			ff := FlatFinding{AssetID: a.ID, AssetName: a.Name, AssetKind: a.Kind,
				Key: f.ID, Title: f.Title, Detail: f.Detail, Severity: string(f.Severity),
				Category: f.Category, Evidence: string(f.Evidence), Citations: f.Citations, Remediation: f.Remediation}
			if st, ok := statuses[ff.Key]; ok {
				stCopy := st
				ff.Status = &stCopy
			}
			out = append(out, ff)
		}
	case store.KindHost:
		snaps, err := s.cfg.Store.HostSnapshots(a.ID, 1)
		if err != nil {
			return nil, err
		}
		if len(snaps) == 0 {
			return []FlatFinding{}, nil
		}
		var sum HostSummary
		if err := json.Unmarshal(snaps[0].Summary, &sum); err != nil {
			return nil, err
		}
		for _, alg := range sum.Algorithms {
			if alg.Class != string(pqc.Vulnerable) {
				continue
			}
			key := "pqc:" + alg.Name
			cites := make([]eval.Citation, 0, len(alg.Basis))
			for _, b := range alg.Basis {
				cites = append(cites, eval.Citation{Title: b.Title, URL: b.URL})
			}
			ff := FlatFinding{AssetID: a.ID, AssetName: a.Name, AssetKind: a.Kind,
				Key: key, Title: alg.Name + " is quantum-vulnerable", Detail: alg.Rationale,
				Class: alg.Class, Citations: cites}
			if st, ok := statuses[key]; ok {
				stCopy := st
				ff.Status = &stCopy
			}
			out = append(out, ff)
		}
	}
	if out == nil {
		out = []FlatFinding{}
	}
	return out, nil
}

func (s *Server) listAssetFindings(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	a, err := s.cfg.Store.GetAsset(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	out, err := s.assetFindings(a)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, out)
}

// fleetFindings lists every asset's current findings, worst first, optionally
// filtered. Loading each asset's latest result is the same cost class as
// scanCBOM already pays per request; fine at the fleet sizes this product targets.
func (s *Server) fleetFindings(w http.ResponseWriter, r *http.Request) {
	assets, err := s.cfg.Store.ListAssets("")
	if err != nil {
		storeErr(w, err)
		return
	}
	sevFilter := strings.ToLower(r.URL.Query().Get("severity"))
	statusFilter := r.URL.Query().Get("status") // "new" | "acknowledged" | "accepted-risk"
	kindFilter := r.URL.Query().Get("kind")

	var out []FlatFinding
	for _, a := range assets {
		if kindFilter != "" && a.Kind != kindFilter {
			continue
		}
		ff, err := s.assetFindings(a)
		if err != nil {
			storeErr(w, err)
			return
		}
		for _, f := range ff {
			matchesSeverity := strings.EqualFold(f.Severity, sevFilter) || (sevFilter == "vulnerable" && f.Class == string(pqc.Vulnerable))
			if sevFilter != "" && !matchesSeverity {
				continue
			}
			switch statusFilter {
			case "":
			case "new":
				if f.Status != nil {
					continue
				}
			default:
				if f.Status == nil || f.Status.Status != statusFilter {
					continue
				}
			}
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i]) < severityRank(out[j]) })
	if out == nil {
		out = []FlatFinding{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) setFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if key == "" {
		writeErr(w, http.StatusBadRequest, "missing finding key")
		return
	}
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Status != store.FindingAcknowledged && req.Status != store.FindingAcceptedRisk {
		writeErr(w, http.StatusBadRequest, `status must be "acknowledged" or "accepted-risk"`)
		return
	}
	if len(req.Note) > 2000 {
		writeErr(w, http.StatusBadRequest, "note is limited to 2000 characters")
		return
	}
	if _, err := s.cfg.Store.GetAsset(id); err != nil {
		storeErr(w, err)
		return
	}
	if err := s.cfg.Store.SetFindingStatus(id, key, req.Status, req.Note); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) clearFindingStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	key := r.PathValue("key")
	if _, err := s.cfg.Store.GetAsset(id); err != nil {
		storeErr(w, err)
		return
	}
	if err := s.cfg.Store.ClearFindingStatus(id, key); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- asset links ------------------------------------------------------------------------------

func (s *Server) linkAssets(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	other, err := parseIDPath(r.PathValue("otherId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.cfg.Store.LinkAssetsAs(id, other, s.actor(r)); err != nil {
		systemErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unlinkAssets(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	other, err := parseIDPath(r.PathValue("otherId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.cfg.Store.UnlinkAssetsAs(id, other, s.actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
