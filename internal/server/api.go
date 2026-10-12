package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// assetView adds the address the UI shows to a stored asset, plus any assets
// a person has explicitly linked to it as the same machine (never inferred).
type assetView struct {
	store.Asset
	Address string `json:"address"`
	// StartTLSUsed is the protocol a scan negotiates (the choice applied to the port): "" for
	// direct TLS.
	StartTLSUsed string `json:"starttlsUsed"`
	// Protocol is "tls" or "ssh" for an endpoint, empty for a host (PRD-008).
	Protocol       string  `json:"protocol"`
	LinkedAssetIDs []int64 `json:"linkedAssetIds,omitempty"`
}

// view renders one asset. links may be nil (a freshly created/edited asset
// has nothing to show yet); pass a pre-fetched map from store.AllLinks for a
// list so linked IDs don't cost one query per row.
func view(a store.Asset, links map[int64][]int64) assetView {
	v := assetView{Asset: a, Address: a.Address(), LinkedAssetIDs: links[a.ID]}
	switch a.Kind {
	case store.KindTLS:
		v.Protocol = "tls"
		v.StartTLSUsed, _ = tlsprobe.ResolveStartTLS(a.StartTLS, a.Port)
	case store.KindSSH:
		v.Protocol = "ssh"
	}
	return v
}

func idParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, false
	}
	return id, true
}

func storeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrDuplicate):
		writeErr(w, http.StatusConflict, "already exists")
	default:
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// ---- about / summary --------------------------------------------------------------------

func (s *Server) about(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"name": "CipherHorizon", "version": s.cfg.Version,
		"registryRetrieved": s.cfg.RegistryRetrieved, "evalVersion": s.cfg.EvalVersion,
		"retentionPerAsset": store.Retention, "maxConcurrentScans": s.cfg.MaxConcurrentScans,
		"allowLoopback": s.cfg.Guard.AllowLoopback,
		// scanScope: the --scan-allow list; empty means anything routable the guard allows.
		"scanScope": append([]string{}, s.cfg.Guard.Scope.Entries()...),
		// authRequired: whether the API answers anyone without credentials (it does only with
		// --no-login and no token). signInRequired and automationToken say which credentials.
		"authRequired": s.signInOn() || s.cfg.Token != "", "signInRequired": s.signInOn(),
		"automationToken": s.cfg.Token != "",
		"httpChecks":      s.cfg.Runner.HTTPChecks(),
		"intervals":       []int{0, 3600, 21600, 86400, 604800},
		"notice": "This tool connects to the endpoints you add and makes a few hundred short TLS handshakes to each. " +
			"Scan only systems you own or are authorised to test.",
	})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	f, err := s.cfg.Store.FleetSummary(days)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, f)
}

// ---- assets -----------------------------------------------------------------------------------

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	as, err := s.cfg.Store.ListAssets(r.URL.Query().Get("kind"))
	if err != nil {
		storeErr(w, err)
		return
	}
	links, err := s.cfg.Store.AllLinks()
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]assetView, len(as))
	for i, a := range as {
		out[i] = view(a, links)
	}
	writeJSON(w, 200, out)
}

type createReq struct {
	Target string `json:"target"`
	Name   string `json:"name"`
	// StartTLS is "auto" (the default: by well-known port), "none" or a protocol. A scheme in
	// Target (smtp://) decides instead.
	StartTLS string `json:"starttls"`
	// Protocol is "auto" (the default: port 22 is SSH, anything else TLS), "tls" or "ssh".
	// A scheme in Target (ssh://, https://, smtp://) decides instead.
	Protocol string   `json:"protocol"`
	Tags     []string `json:"tags"`
	Notes    string   `json:"notes"`
}

func (s *Server) newAsset(ctx context.Context, req createReq) (store.Asset, int, string) {
	t, err := normalizeTarget(req.Target)
	if err != nil {
		return store.Asset{}, http.StatusBadRequest, "invalid target: " + err.Error()
	}
	kind, port, msg := assetKindFor(t, req.Protocol)
	if msg != "" {
		return store.Asset{}, http.StatusBadRequest, msg
	}
	host := t.host
	choice := "none"
	if kind == store.KindTLS {
		if choice, msg = startTLSChoice(req.StartTLS, t.starttls); msg != "" {
			return store.Asset{}, http.StatusBadRequest, msg
		}
	} else if s := strings.ToLower(strings.TrimSpace(req.StartTLS)); s != "" && s != "auto" && s != "none" {
		return store.Asset{}, http.StatusBadRequest, "STARTTLS applies to TLS endpoints, not SSH"
	}
	if err := s.cfg.Guard.CheckTarget(ctx, host); err != nil {
		return store.Asset{}, http.StatusBadRequest, err.Error()
	}
	tags, err := normalizeTags(req.Tags)
	if err != nil {
		return store.Asset{}, http.StatusBadRequest, err.Error()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = store.Asset{Host: host, Port: port}.Address()
	}
	if len(name) > 100 || len(req.Notes) > 2000 {
		return store.Asset{}, http.StatusBadRequest, "name (100) or notes (2000) too long"
	}
	a, err := s.cfg.Store.CreateAsset(store.Asset{Kind: kind, Name: name, Host: host, Port: port, StartTLS: choice, Tags: tags, Notes: req.Notes})
	if errors.Is(err, store.ErrDuplicate) {
		return store.Asset{}, http.StatusConflict, fmt.Sprintf("%s is already added", store.Asset{Host: host, Port: port}.Address())
	}
	if err != nil {
		return store.Asset{}, http.StatusInternalServerError, "internal error"
	}
	return a, 0, ""
}

func (s *Server) createAsset(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if !decode(w, r, &req) {
		return
	}
	a, status, msg := s.newAsset(r.Context(), req)
	if status != 0 {
		writeErr(w, status, msg)
		return
	}
	writeJSON(w, http.StatusCreated, view(a, nil))
}

// BulkResult is the outcome for one line of a bulk add (AC-01.2).
type BulkResult struct {
	Line   int        `json:"line"`
	Input  string     `json:"input"`
	Status string     `json:"status"` // added | duplicate | invalid
	Reason string     `json:"reason,omitempty"`
	Asset  *assetView `json:"asset,omitempty"`
}

func (s *Server) bulkAssets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string   `json:"text"`
		Tags []string `json:"tags"`
	}
	if !decode(w, r, &req) {
		return
	}
	results := []BulkResult{}
	counts := map[string]int{}
	lines := strings.Split(strings.ReplaceAll(req.Text, "\r\n", "\n"), "\n")
	if len(lines) > 1000 {
		writeErr(w, http.StatusBadRequest, "at most 1000 lines per request")
		return
	}
	for i, line := range lines {
		in := strings.TrimSpace(line)
		if in == "" || strings.HasPrefix(in, "#") {
			continue
		}
		a, status, msg := s.newAsset(r.Context(), createReq{Target: in, Tags: req.Tags})
		res := BulkResult{Line: i + 1, Input: in}
		switch status {
		case 0:
			res.Status = "added"
			v := view(a, nil)
			res.Asset = &v
		case http.StatusConflict:
			res.Status, res.Reason = "duplicate", msg
		default:
			res.Status, res.Reason = "invalid", msg
		}
		counts[res.Status]++
		results = append(results, res)
	}
	writeJSON(w, 200, map[string]any{"results": results, "added": counts["added"], "duplicate": counts["duplicate"], "invalid": counts["invalid"]})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	a, err := s.cfg.Store.GetAsset(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	linked, err := s.cfg.Store.LinkedAssetIDs(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, view(a, map[int64][]int64{id: linked}))
}

func (s *Server) patchAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var req struct {
		Name            *string   `json:"name"`
		Tags            *[]string `json:"tags"`
		Notes           *string   `json:"notes"`
		IntervalSeconds *int      `json:"intervalSeconds"`
		StartTLS        *string   `json:"starttls"`
	}
	if !decode(w, r, &req) {
		return
	}
	p := store.AssetPatch{Notes: req.Notes, IntervalSeconds: req.IntervalSeconds}
	if req.StartTLS != nil {
		if cur, err := s.cfg.Store.GetAsset(id); err == nil && cur.Kind == store.KindSSH {
			writeErr(w, http.StatusBadRequest, "STARTTLS applies to TLS endpoints, not SSH")
			return
		}
		c, msg := startTLSChoice(*req.StartTLS, "")
		if msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		p.StartTLS = &c
	}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" || len(n) > 100 {
			writeErr(w, http.StatusBadRequest, "name must be 1 to 100 characters")
			return
		}
		p.Name = &n
	}
	if req.Tags != nil {
		t, err := normalizeTags(*req.Tags)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p.Tags = &t
	}
	if req.Notes != nil && len(*req.Notes) > 2000 {
		writeErr(w, http.StatusBadRequest, "notes are limited to 2000 characters")
		return
	}
	if req.IntervalSeconds != nil && !allowedIntervals[*req.IntervalSeconds] {
		writeErr(w, http.StatusBadRequest, "intervalSeconds must be 0, 3600, 21600, 86400 or 604800")
		return
	}
	a, err := s.cfg.Store.UpdateAsset(id, p)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, view(a, nil))
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if a, err := s.cfg.Store.GetAsset(id); err == nil && a.Latest != nil {
		s.cfg.Runner.Cancel(a.Latest.ID)
	}
	if err := s.cfg.Store.DeleteAsset(id); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- scans ---------------------------------------------------------------------------------------

func (s *Server) queue(assetID int64, trigger, startedBy string) (store.ScanSummary, bool, error) {
	sc, existing, err := s.cfg.Store.EnqueueScan(assetID, trigger, startedBy)
	if err == nil && !existing {
		s.cfg.Runner.Notify()
	}
	return sc, existing, err
}

func (s *Server) scanAsset(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	a, err := s.cfg.Store.GetAsset(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if !store.IsEndpoint(a.Kind) {
		writeErr(w, http.StatusBadRequest, "only TLS and SSH endpoints can be scanned; hosts report by pushing a CBOM")
		return
	}
	sc, existing, err := s.queue(id, "manual", s.actor(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	status := http.StatusAccepted
	if existing {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"scan": sc, "alreadyActive": existing})
}

func (s *Server) scanMany(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AssetIDs []int64 `json:"assetIds"`
		All      bool    `json:"all"`
		Tag      string  `json:"tag"`
	}
	if !decode(w, r, &req) {
		return
	}
	ids := req.AssetIDs
	if req.All || req.Tag != "" {
		as, err := s.cfg.Store.ListAssets(store.KindEndpoint)
		if err != nil {
			storeErr(w, err)
			return
		}
		for _, a := range as {
			if req.Tag != "" && !hasTag(a.Tags, req.Tag) {
				continue
			}
			ids = append(ids, a.ID)
		}
	}
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "no assets selected")
		return
	}
	scans := []store.ScanSummary{}
	queued, already, missing := 0, 0, 0
	seen := map[int64]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		sc, existing, err := s.queue(id, "bulk", s.actor(r))
		switch {
		case errors.Is(err, store.ErrNotFound):
			missing++
		case err != nil:
			storeErr(w, err)
			return
		case existing:
			already++
			scans = append(scans, sc)
		default:
			queued++
			scans = append(scans, sc)
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": queued, "alreadyActive": already, "missing": missing, "scans": scans})
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ScanFilter{Status: q.Get("status"), Kind: q.Get("kind")}
	f.AssetID, _ = strconv.ParseInt(q.Get("assetId"), 10, 64)
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	scans, err := s.cfg.Store.ListScans(f)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, scans)
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	sc, err := s.cfg.Store.GetScan(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	events, err := s.cfg.Store.Events(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	a, err := s.cfg.Store.GetAsset(sc.AssetID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"scan": sc, "events": events,
		"asset": map[string]any{"id": a.ID, "name": a.Name, "address": a.Address()},
	})
}

func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Store.CancelScan(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
		} else {
			writeErr(w, http.StatusConflict, "the scan is not active")
		}
		return
	}
	s.cfg.Runner.Cancel(id)
	if err := s.cfg.Store.AddEvent(id, "canceled by user"); err != nil {
		s.log.Warn("recording a cancellation in the scan log failed", "scan", id, "err", err)
	}
	sc, err := s.cfg.Store.GetScan(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, sc)
}

func (s *Server) blob(w http.ResponseWriter, r *http.Request, kind string, get func(int64) ([]byte, error)) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	b, err := get(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%d-%s.json"`, id, kind))
	}
	_, _ = w.Write(b)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	s.blob(w, r, "report", s.cfg.Store.Report)
}

func (s *Server) evaluation(w http.ResponseWriter, r *http.Request) {
	s.blob(w, r, "evaluation", s.cfg.Store.Evaluation)
}

// scanCBOM rebuilds a CycloneDX CBOM from an already-completed scan's stored
// report — the same builder `tls scan --cbom` uses, so the two never diverge.
func (s *Server) scanCBOM(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	rb, err := s.cfg.Store.Report(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	dec, err := decodeReport(rb)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	spec := r.URL.Query().Get("spec")
	if spec == "" {
		spec = cbom.DefaultSpec
	}
	if spec != cbom.Spec16 && spec != cbom.Spec17 {
		writeErr(w, http.StatusBadRequest, "spec must be 1.6 or 1.7")
		return
	}
	assets, endpoint := endpointAssets(dec)
	bom, _ := cbom.Build(assets, cbom.Options{
		Tool:     cbom.Tool{Name: "cipherhorizon", Version: s.cfg.Version},
		Endpoint: endpoint,
	})
	pqcRep := pqc.Analyze(bom)
	pqc.Annotate(bom, pqcRep)

	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, bom, spec, true); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="scan-%d-cbom.json"`, id))
	}
	_, _ = w.Write(buf.Bytes())
}

// ---- history and diff ------------------------------------------------------------------------------

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetAsset(id); err != nil {
		storeErr(w, err)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	h, err := s.cfg.Store.History(id, limit)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, h)
}

// loadScan reads a done scan's report and evaluation.
func (s *Server) loadScan(assetID, scanID int64) (decodedReport, eval.Evaluation, *store.ScanSummary, error) {
	sc, err := s.cfg.Store.GetScan(scanID)
	if err != nil {
		return decodedReport{}, eval.Evaluation{}, nil, err
	}
	if sc.AssetID != assetID || sc.Status != store.StatusDone {
		return decodedReport{}, eval.Evaluation{}, nil, store.ErrNotFound
	}
	rb, err := s.cfg.Store.Report(scanID)
	if err != nil {
		return decodedReport{}, eval.Evaluation{}, nil, err
	}
	eb, err := s.cfg.Store.Evaluation(scanID)
	if err != nil {
		return decodedReport{}, eval.Evaluation{}, nil, err
	}
	dec, err := decodeReport(rb)
	if err != nil {
		return decodedReport{}, eval.Evaluation{}, nil, err
	}
	var ev eval.Evaluation
	if err := json.Unmarshal(eb, &ev); err != nil {
		return decodedReport{}, eval.Evaluation{}, nil, err
	}
	return dec, ev, &sc, nil
}

// diff compares two completed scans of an asset (AC-07.3). Without from/to it
// compares the latest completed scan with the one before it.
func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	if from == 0 || to == 0 {
		done, err := s.cfg.Store.ListScans(store.ScanFilter{AssetID: id, Status: store.StatusDone, Limit: 2})
		if err != nil {
			storeErr(w, err)
			return
		}
		if len(done) < 2 {
			writeErr(w, http.StatusConflict, "at least two completed scans are needed to compare")
			return
		}
		to, from = done[0].ID, done[1].ID
	}
	fr, fe, fs, err := s.loadScan(id, from)
	if err != nil {
		storeErr(w, err)
		return
	}
	tr, te, ts, err := s.loadScan(id, to)
	if err != nil {
		storeErr(w, err)
		return
	}
	var d eval.Diff
	switch {
	case fr.ssh != nil && tr.ssh != nil:
		d = eval.CompareSSH(fr.ssh, tr.ssh, fe, te)
	case fr.tls != nil && tr.tls != nil:
		d = eval.Compare(fr.tls, tr.tls, fe, te)
	default:
		writeErr(w, http.StatusConflict, "the two scans are of different protocols")
		return
	}
	writeJSON(w, 200, map[string]any{"from": fs, "to": ts, "diff": d})
}

// ---- export -------------------------------------------------------------------------------------------

// csvSafe defuses spreadsheet formula injection: a cell that starts with = + - @
// or a control character is prefixed so it is read as text.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) exportCSV(w http.ResponseWriter, r *http.Request) {
	as, err := s.cfg.Store.ListAssets(store.KindEndpoint)
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="assets.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"name", "address", "tags", "hygiene_band", "pqc_level", "pqc_label", "hndl_exposed", "critical", "high",
		"cert_expires", "last_scan", "status", "rescan_interval_seconds", "hygiene_score", "protocol", "service",
		"ssh_baseline", "ssh_baseline_meets", "ssh_baseline_changes"})
	for _, a := range as {
		row := []string{csvSafe(a.Name), csvSafe(a.Address()), csvSafe(strings.Join(a.Tags, ";")), "", "", "", "", "", "", "", "", "", strconv.Itoa(a.IntervalSeconds), "", view(a, nil).Protocol, "", "", "", ""}
		if a.Latest != nil {
			row[11] = a.Latest.Status
		}
		if d := a.LastDone; d != nil {
			row[3] = d.Band
			if d.Score >= 0 {
				row[13] = strconv.Itoa(d.Score)
			}
			if d.ReadinessLevel != nil {
				row[4] = strconv.Itoa(*d.ReadinessLevel)
				row[5] = eval.LevelLabel(*d.ReadinessLevel)
			}
			row[6] = strconv.FormatBool(d.HNDLExposed)
			row[7], row[8] = strconv.Itoa(d.Critical), strconv.Itoa(d.High)
			if d.CertNotAfter != nil {
				row[9] = d.CertNotAfter.Format("2006-01-02")
			}
			if d.FinishedAt != nil {
				row[10] = d.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
			}
			row[15] = csvSafe(d.Service)
			// An SSH server has no hygiene score: its measure is the baseline (PRD-008 REQ-SHE-5).
			if d.BaselineMeets != nil {
				row[16], row[17], row[18] = d.Baseline, strconv.FormatBool(*d.BaselineMeets), strconv.Itoa(d.BaselineChanges)
			}
		}
		_ = cw.Write(row)
	}
	cw.Flush()
}

// startTLSChoice validates an endpoint's STARTTLS choice. A scheme in the target wins; otherwise
// the request's value, "auto" when empty.
func startTLSChoice(requested, fromScheme string) (string, string) {
	if fromScheme != "" {
		return fromScheme, ""
	}
	c := strings.ToLower(strings.TrimSpace(requested))
	switch c {
	case "":
		return "auto", ""
	case "auto", "none":
		return c, ""
	}
	p, err := tlsprobe.ResolveStartTLS(c, 0)
	if err != nil || p == "" {
		return "", fmt.Sprintf("starttls must be auto, none or one of %s", strings.Join(tlsprobe.StartTLSProtocols, ", "))
	}
	return p, ""
}
