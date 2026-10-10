package server

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// actor names who is making a change, for the audit log. There is one shared token,
// so a change made with it is recorded as made by the token, not by a person
// (SECARCH-001 section 5 states this limit).
func systemErr(w http.ResponseWriter, err error) {
	var ce *store.ConflictError
	switch {
	case errors.As(err, &ce):
		writeJSON(w, http.StatusConflict, map[string]any{"error": ce.Error(), "fields": ce.Fields})
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		storeErr(w, err)
	}
}

// systemView adds which optional fields a person has filled in, so a client can say
// "based on evidence only" without guessing.
type systemView struct {
	store.System
	Provided []string `json:"provided"`
}

func viewSystem(sys store.System) systemView {
	p := sys.Provided()
	if p == nil {
		p = []string{}
	}
	return systemView{System: sys, Provided: p}
}

func (s *Server) listSystems(w http.ResponseWriter, _ *http.Request) {
	systems, err := s.cfg.Store.ListSystems()
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]systemView, 0, len(systems))
	for _, sys := range systems {
		out = append(out, viewSystem(sys))
	}
	writeJSON(w, 200, map[string]any{
		"systems": out,
		"enums": map[string][]string{
			"environment": store.Environments, "criticality": store.Criticalities, "exposure": store.Exposures,
			"fips199": store.FIPS199Levels, "hosting": store.HostingKinds,
		},
	})
}

func (s *Server) getSystem(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	sys, err := s.cfg.Store.GetSystem(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, viewSystem(sys))
}

const maxReason = 200

func reasonOf(r *http.Request) (string, bool) {
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))
	if len(reason) > maxReason || strings.ContainsAny(reason, "\r\n\x00") {
		return "", false
	}
	return reason, true
}

func (s *Server) patchSystem(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var patch store.SystemPatch
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&patch); err != nil || patch == nil {
		writeErr(w, http.StatusBadRequest, "the body must be a JSON object of system fields")
		return
	}
	if len(patch) == 0 {
		writeErr(w, http.StatusBadRequest, "no fields to change")
		return
	}
	sys, err := s.cfg.Store.UpdateSystem(id, patch, s.actor(r), reason)
	if err != nil {
		systemErr(w, err)
		return
	}
	writeJSON(w, 200, viewSystem(sys))
}

func (s *Server) systemAudit(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetSystem(id); err != nil {
		storeErr(w, err)
		return
	}
	log, err := s.cfg.Store.Audit("system", id, 200)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, log)
}

func (s *Server) systemObservations(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetSystem(id); err != nil {
		storeErr(w, err)
		return
	}
	obs, err := s.cfg.Store.SystemObservations(id, r.URL.Query().Get("current") == "1")
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, obs)
}

func (s *Server) listEntities(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ents, err := s.cfg.Store.Entities(r.URL.Query().Get("kind"), limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, ents)
}

func (s *Server) graphStats(w http.ResponseWriter, _ *http.Request) {
	st, err := s.cfg.Store.Stats()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

// ---- CSV -----------------------------------------------------------------------------------------

func (s *Server) exportSystemsCSV(w http.ResponseWriter, _ *http.Request) {
	systems, err := s.cfg.Store.ListSystems()
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="systems.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(append([]string{"id"}, store.SystemFields...))
	for _, sys := range systems {
		m := map[string]string{
			"name": sys.Name, "owner": sys.Owner, "environment": sys.Environment, "criticality": sys.Criticality, "exposure": sys.Exposure,
			"fismaId": sys.FISMAID, "fips199": sys.FIPS199, "hvaId": sys.HVAID, "hosting": sys.Hosting, "hostingProvider": sys.HostingProvider, "notes": sys.Notes,
		}
		if sys.DataLifetimeYears != nil {
			m["dataLifetimeYears"] = strconv.Itoa(*sys.DataLifetimeYears)
		}
		row := []string{strconv.FormatInt(sys.ID, 10)}
		for _, f := range store.SystemFields {
			row = append(row, csvSafe(m[f]))
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

// undoCSVSafe reverses csvSafe so an exported file can be edited and imported back
// without every value that starts with = + - @ gaining a quote each round trip.
func undoCSVSafe(s string) string {
	if len(s) >= 2 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

const maxCSVBody = 4 << 20

// importSystemsCSV updates systems from a CSV whose first column is the system id. An
// empty cell leaves the field as it is (clearing is done in the UI or with PATCH), so a
// partly filled spreadsheet cannot wipe what it does not mention. Every row is checked
// before any is applied: the import is all or nothing, and each problem names its line.
func (s *Server) importSystemsCSV(w http.ResponseWriter, r *http.Request) {
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCSVBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "CSV larger than 4 MiB")
			return
		}
		writeErr(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	patches, problems, refusal := parseSystemsCSV(raw)
	if refusal != "" {
		writeErr(w, http.StatusBadRequest, refusal)
		return
	}
	if len(problems) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the CSV was not applied", "problems": problems})
		return
	}
	if err := s.cfg.Store.UpdateSystems(patches, s.actor(r), reason); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusBadRequest, "the CSV names a system id that does not exist; nothing was applied")
			return
		}
		systemErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"applied": len(patches)})
}

// parseSystemsCSV reads a systems CSV into patches. A refusal is a problem with the file as a
// whole (its header); problems are per line, each naming its line. It changes nothing, so it is
// fuzzed on its own (PRD-007 REQ-TR-6).
func parseSystemsCSV(raw []byte) (patches []store.SystemPatchByID, problems []string, refusal string) {
	cr := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\ufeff")))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = false
	header, err := cr.Read()
	if err != nil {
		return nil, nil, "the CSV has no header row"
	}
	col := map[string]int{}
	for i, h := range header {
		h = strings.TrimSpace(h)
		if h == "id" || store.IsSystemField(h) {
			if _, dup := col[h]; dup {
				return nil, nil, fmt.Sprintf("column %q appears twice", clip(h, 40))
			}
			col[h] = i
			continue
		}
		return nil, nil, fmt.Sprintf("unknown column %q; columns are id and %s", clip(h, 40), strings.Join(store.SystemFields, ", "))
	}
	idCol, hasID := col["id"]
	if !hasID {
		return nil, nil, "the first column must be id: rows are matched to systems by id"
	}

	seen := map[int64]bool{}
	for {
		line, _ := cr.FieldPos(0)
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("line %d: %v", line, err))
			break
		}
		if len(rec) == 1 && strings.TrimSpace(rec[0]) == "" {
			continue // a blank line
		}
		line, _ = cr.FieldPos(0)
		if idCol >= len(rec) {
			problems = append(problems, fmt.Sprintf("line %d: no id", line))
			continue
		}
		id, err := strconv.ParseInt(strings.TrimSpace(rec[idCol]), 10, 64)
		if err != nil || id <= 0 {
			problems = append(problems, fmt.Sprintf("line %d: %q is not a system id", line, clip(rec[idCol], 30)))
			continue
		}
		if seen[id] {
			problems = append(problems, fmt.Sprintf("line %d: system %d appears twice", line, id))
			continue
		}
		seen[id] = true
		patch := store.SystemPatch{}
		for f, i := range col {
			if f == "id" || i >= len(rec) {
				continue
			}
			v := strings.TrimSpace(undoCSVSafe(rec[i]))
			if v == "" {
				continue
			}
			if f == "dataLifetimeYears" {
				n, err := strconv.Atoi(v)
				if err != nil {
					problems = append(problems, fmt.Sprintf("line %d: dataLifetimeYears %q is not a whole number", line, clip(v, 30)))
					continue
				}
				patch[f] = float64(n)
				continue
			}
			patch[f] = v
		}
		if err := store.ValidateSystemPatch(patch); err != nil {
			problems = append(problems, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		patches = append(patches, store.SystemPatchByID{ID: id, Patch: patch})
		if len(problems) >= 50 {
			problems = append(problems, "too many problems; stopping")
			break
		}
	}
	return patches, problems, ""
}
