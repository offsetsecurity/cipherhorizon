package server

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// The audit trail (PRD-007 REQ-AC-2, audit L-02). Every state-changing route is in exactly one
// of the two tables below, and a test walks the real route table to keep it so:
//
//   - auditedRoutes are recorded here, one row per successful call, by the wrapper handle()
//     puts around them;
//   - selfAuditedRoutes already record themselves in more detail: sign-in and account changes in
//     the sign-in log, system changes in the audit log with their before and after values.
type auditSpec struct {
	kind   string // the object: endpoint, finding, scan, host
	action string // what was done, in words a person reads in the Activity list
}

var auditedRoutes = map[string]auditSpec{
	"POST /api/v1/assets":                              {"endpoint", "added"},
	"POST /api/v1/assets/bulk":                         {"endpoint", "added in bulk"},
	"PATCH /api/v1/assets/{id}":                        {"endpoint", "edited"},
	"DELETE /api/v1/assets/{id}":                       {"endpoint", "deleted"},
	"POST /api/v1/assets/{id}/scan":                    {"endpoint", "scan started"},
	"PUT /api/v1/assets/{id}/findings/{key}/status":    {"endpoint", "finding status set"},
	"DELETE /api/v1/assets/{id}/findings/{key}/status": {"endpoint", "finding status cleared"},
	"PUT /api/v1/assets/{id}/links/{otherId}":          {"endpoint", "linked"},
	"DELETE /api/v1/assets/{id}/links/{otherId}":       {"endpoint", "unlinked"},
	"POST /api/v1/scans":                               {"scan", "scans started"},
	"POST /api/v1/scans/{id}/cancel":                   {"scan", "canceled"},
	"POST /api/v1/scans/{id}/reevaluate":               {"scan", "re-evaluated"},
	"POST /api/v1/hosts/ingest":                        {"host", "inventory uploaded"},
}

var selfAuditedRoutes = map[string]bool{
	"POST /api/v1/auth/setup":                                 true,
	"PUT /api/v1/settings/sign-in":                            true,
	"POST /api/v1/auth/login":                                 true,
	"POST /api/v1/auth/logout":                                true,
	"POST /api/v1/auth/password":                              true,
	"DELETE /api/v1/auth/sessions/{id}":                       true,
	"POST /api/v1/users":                                      true,
	"PATCH /api/v1/users/{id}":                                true,
	"DELETE /api/v1/users/{id}":                               true,
	"POST /api/v1/users/{id}/password":                        true,
	"POST /api/v1/users/{id}/unlock":                          true,
	"PATCH /api/v1/systems/{id}":                              true,
	"POST /api/v1/systems/import.csv":                         true,
	"POST /api/v1/systems/{id}/trust-anchors":                 true,
	"DELETE /api/v1/systems/{id}/trust-anchors/{fingerprint}": true,
	"POST /api/v1/imports":                                    true,
	"POST /api/v1/imports/{id}/withdraw":                      true,
	"POST /api/v1/links/{id}/confirm":                         true,
	"POST /api/v1/links/{id}/reject":                          true,
}

// AuditCoverage reports, for tests, which table a route is in: "audited", "self" or "".
func AuditCoverage(route string) string {
	switch {
	case auditedRoutes[route] != (auditSpec{}):
		return "audited"
	case selfAuditedRoutes[route]:
		return "self"
	}
	return ""
}

// AuditActionOf is the object kind and action an audited route records (tests).
func AuditActionOf(route string) (kind, action string) {
	sp := auditedRoutes[route]
	return sp.kind, sp.action
}

// auditRecorder keeps the status and the start of the body, enough to find a created object's id.
type auditRecorder struct {
	http.ResponseWriter
	status int
	head   bytes.Buffer
}

// WriteHeader records the status before passing it on.
func (a *auditRecorder) WriteHeader(code int) {
	if a.status == 0 {
		a.status = code
	}
	a.ResponseWriter.WriteHeader(code)
}

// Write keeps the start of the body (to find a created object's id) and passes it on.
func (a *auditRecorder) Write(b []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	if room := 64<<10 - a.head.Len(); room > 0 {
		a.head.Write(b[:min(room, len(b))])
	}
	return a.ResponseWriter.Write(b)
}

// audited wraps a route from auditedRoutes: after a successful call it writes one row.
func (s *Server) audited(pattern string, spec auditSpec, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &auditRecorder{ResponseWriter: w}
		h(rec, r)
		if rec.status < 200 || rec.status > 299 {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var detail []string
		var created struct {
			ID      int64  `json:"id"`
			Address string `json:"address"`
			Name    string `json:"name"`
			Results []struct {
				Status string `json:"status"`
			} `json:"results"`
			Asset struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"asset"` // a host upload names the host it created or updated
		}
		_ = json.Unmarshal(rec.head.Bytes(), &created) // best effort: a truncated or non-JSON body leaves it empty
		if id == 0 {
			id = created.ID
		}
		if id == 0 {
			id = created.Asset.ID
		}
		if created.Asset.Name != "" {
			detail = append(detail, clip(created.Asset.Name, 80))
		}
		if created.Address != "" {
			detail = append(detail, created.Address)
		}
		for _, p := range []string{"key", "otherId"} {
			if v := r.PathValue(p); v != "" {
				detail = append(detail, p+" "+clip(v, 80))
			}
		}
		if len(created.Results) > 0 {
			n := 0
			for _, x := range created.Results {
				if x.Status == "added" {
					n++
				}
			}
			detail = append(detail, strconv.Itoa(n)+" added of "+strconv.Itoa(len(created.Results))+" lines")
		}
		reason, _ := reasonOf(r)
		if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), spec.kind, id, spec.action, strings.Join(detail, "; "), reason); err != nil {
			s.log.Error("audit write failed", "route", pattern, "err", err)
		}
	}
}

// activityFilter reads ?person=&source=&limit= for the Activity list and its export.
func activityFilter(r *http.Request) (store.ActivityFilter, bool) {
	q := r.URL.Query()
	f := store.ActivityFilter{Person: strings.TrimSpace(q.Get("person")), Source: q.Get("source")}
	if f.Source != "" && f.Source != "change" && f.Source != "sign-in" {
		return f, false
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			return f, false
		}
		f.Limit = n
	}
	return f, len(f.Person) <= 100
}

// activity is the Activity list for administrators (REQ-AC-3): sign-ins and changes, newest first.
func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	f, ok := activityFilter(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "source is change or sign-in; limit is a positive number; person is at most 100 characters")
		return
	}
	list, err := s.cfg.Store.Activity(f)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"entries": list})
}

// activityCSV exports the same list as CSV; every cell a person or a scanned server could have
// written is made formula-safe for spreadsheets.
func (s *Server) activityCSV(w http.ResponseWriter, r *http.Request) {
	f, ok := activityFilter(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "source is change or sign-in; limit is a positive number; person is at most 100 characters")
		return
	}
	if f.Limit == 0 {
		f.Limit = 5000
	}
	list, err := s.cfg.Store.Activity(f)
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="cipherhorizon-activity.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"at", "source", "who", "action", "object", "objectId", "account", "client", "detail", "reason"})
	for _, e := range list {
		id := ""
		if e.ObjectID != 0 {
			id = strconv.FormatInt(e.ObjectID, 10)
		}
		_ = cw.Write([]string{e.At.UTC().Format(time.RFC3339), e.Source, csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.ObjectKind), id,
			csvSafe(e.Username), csvSafe(e.Client), csvSafe(e.Detail), csvSafe(e.Reason)})
	}
	cw.Flush()
}
