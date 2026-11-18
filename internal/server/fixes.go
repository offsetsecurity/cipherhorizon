package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/workflow"
)

// Fixes (UX-DESIGN-024): a problem is assigned to someone once, and every scan after that decides
// whether it is fixed. People assign, put on hold and resume; the scanner moves a fix to fixed, and
// back to came-back when a later scan finds the problem again. Underneath, a fix is a piece of work
// on the built-in "fix" workflow, so the audit trail and the verification rules are the same.

const (
	fixWorkflow  = "fix"
	stageNew     = "new"
	stageFixing  = "being-fixed"
	stageFixed   = "fixed"
	stageBack    = "came-back"
	stageOnHold  = "on-hold"
	scannerActor = "scanner"
	dailySeconds = 24 * 60 * 60
)

// FixRow is one fix as the pages show it. The page writes the sentence; this carries the facts.
type FixRow struct {
	ID          int64      `json:"id"`
	Title       string     `json:"title"`
	Group       string     `json:"group"`  // being-fixed, came-back, fixed, on-hold, closed
	Result      string     `json:"result"` // fixed, not-fixed, not-checked, cannot-check
	Detail      string     `json:"detail"` // what the last check saw, in plain words
	CheckedAt   *time.Time `json:"checkedAt"`
	FixedAt     *time.Time `json:"fixedAt"`
	CameBackAt  *time.Time `json:"cameBackAt"`
	HoldUntil   *time.Time `json:"holdUntil"`
	NextScanAt  *time.Time `json:"nextScanAt"`
	Owner       string     `json:"owner"`
	DueAt       *time.Time `json:"dueAt"`
	Overdue     bool       `json:"overdue"`
	Ticket      string     `json:"ticket"`
	Kind        string     `json:"kind"`
	AssetID     int64      `json:"assetId,omitempty"`
	AssetName   string     `json:"assetName,omitempty"`
	Certificate string     `json:"certificate,omitempty"`
	CreatedBy   string     `json:"createdBy"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func storedVerification(it store.WorkItem) *workflow.Verification {
	if len(it.Verification) == 0 {
		return nil
	}
	var v workflow.Verification
	if json.Unmarshal(it.Verification, &v) != nil {
		return nil
	}
	return &v
}

// syncFixes lets the scans decide: a fix being worked on whose check now passes becomes fixed; a fixed
// one whose check now fails comes back; a hold past its date resumes. It returns each fix's latest check.
func (s *Server) syncFixes(now time.Time) (map[int64]workflow.Verification, []store.WorkItem, error) {
	items, err := s.cfg.Store.ListWork(store.WorkFilter{Workflow: fixWorkflow, Limit: store.MaxWorkListed})
	if err != nil {
		return nil, nil, err
	}
	checks := map[int64]workflow.Verification{}
	move := func(it *store.WorkItem, m store.WorkMove) {
		moved, err := s.cfg.Store.MoveWork(it.ID, m, scannerActor)
		if err != nil {
			if !errors.Is(err, store.ErrConflict) {
				s.log.Warn("updating a fix from a scan failed", "fix", it.ID, "err", err)
			}
			return
		}
		*it = moved
	}
	for i := range items {
		it := &items[i]
		switch it.Stage {
		case stageFixing, stageBack:
			v := s.verifyWork(*it, now)
			checks[it.ID] = v
			if v.Status == workflow.Verified {
				b, _ := json.Marshal(v)
				move(it, store.WorkMove{Transition: "confirm", FromStage: it.Stage, ToStage: stageFixed, ToMarker: workflow.MarkVerified, Verification: b, Note: v.Detail})
			}
		case stageFixed:
			v := s.verifyWork(*it, now)
			checks[it.ID] = v
			if v.Status == workflow.NotVerified {
				b, _ := json.Marshal(v)
				move(it, store.WorkMove{Transition: "return", FromStage: stageFixed, ToStage: stageBack, ToMarker: workflow.MarkExecuted, Baseline: true, Verification: b, Note: v.Detail})
			}
		case stageOnHold:
			if it.ExceptionUntil != nil && now.After(*it.ExceptionUntil) {
				move(it, store.WorkMove{Transition: "resume", FromStage: stageOnHold, ToStage: stageFixing, ToMarker: workflow.MarkExecuted, Baseline: true, Note: "the hold ended"})
			}
		}
	}
	return checks, items, nil
}

func (s *Server) fixRow(it store.WorkItem, check *workflow.Verification, assets map[int64]store.Asset, now time.Time) FixRow {
	r := FixRow{ID: it.ID, Title: it.Title, Owner: it.Owner, DueAt: it.DueAt, Ticket: it.Ticket, Kind: it.SubjectKind, AssetID: it.AssetID,
		Certificate: it.Certificate, CreatedBy: it.CreatedBy, CreatedAt: it.CreatedAt, Result: "not-checked"}
	if a, ok := assets[it.AssetID]; ok {
		r.AssetName, r.NextScanAt = a.Name, a.NextScanAt
	}
	stored := storedVerification(it)
	switch it.Stage {
	case stageFixed:
		r.Group, r.Result = "fixed", "fixed"
		if stored != nil {
			r.FixedAt, r.CheckedAt, r.Detail = &stored.At, stored.CheckedAt, stored.Detail
		}
	case stageBack:
		r.Group, r.Result = "came-back", "not-fixed"
		r.CameBackAt = it.ExecutedAt
		if stored != nil {
			r.Detail, r.CheckedAt = stored.Detail, stored.CheckedAt
		}
	case stageOnHold:
		r.Group, r.HoldUntil = "on-hold", it.ExceptionUntil
	case stageFixing, stageNew:
		r.Group = "being-fixed"
	default:
		r.Group = "closed"
	}
	if check != nil && (it.Stage == stageFixing || it.Stage == stageBack) {
		switch check.Status {
		case workflow.NotVerified:
			r.Result, r.Detail, r.CheckedAt = "not-fixed", check.Detail, check.CheckedAt
		case workflow.NotVerifiable:
			r.Result, r.Detail = "cannot-check", check.Detail
		case workflow.Waiting:
			if it.Stage == stageFixing {
				r.Result, r.Detail = "not-checked", ""
			}
		}
	}
	r.Overdue = (r.Group == "being-fixed" || r.Group == "came-back") && it.DueAt != nil && now.After(*it.DueAt)
	return r
}

type fixesView struct {
	Progress   readinessTally `json:"progress"`
	CameBack   []FixRow       `json:"cameBack"`
	BeingFixed []FixRow       `json:"beingFixed"`
	OnHold     []FixRow       `json:"onHold"`
	Fixed      []FixRow       `json:"fixed"`
	ToFix      []Suggestion   `json:"toFix"`
	Scanned    int            `json:"scanned"`
}

func (s *Server) assetMap() (map[int64]store.Asset, []store.Asset, error) {
	list, err := s.cfg.Store.ListAssets("")
	if err != nil {
		return nil, nil, err
	}
	m := make(map[int64]store.Asset, len(list))
	for _, a := range list {
		m[a.ID] = a
	}
	return m, list, nil
}

func (s *Server) listFixes(w http.ResponseWriter, _ *http.Request) {
	now := s.cfg.Now()
	checks, items, err := s.syncFixes(now)
	if err != nil {
		storeErr(w, err)
		return
	}
	assets, list, err := s.assetMap()
	if err != nil {
		storeErr(w, err)
		return
	}
	v := fixesView{CameBack: []FixRow{}, BeingFixed: []FixRow{}, OnHold: []FixRow{}, Fixed: []FixRow{}}
	fixing := map[int64]bool{}
	for _, it := range items {
		var c *workflow.Verification
		if x, ok := checks[it.ID]; ok {
			c = &x
		}
		r := s.fixRow(it, c, assets, now)
		switch r.Group {
		case "came-back":
			v.CameBack = append(v.CameBack, r)
		case "being-fixed":
			v.BeingFixed = append(v.BeingFixed, r)
		case "on-hold":
			v.OnHold = append(v.OnHold, r)
		case "fixed":
			v.Fixed = append(v.Fixed, r)
		}
		if (r.Group == "being-fixed" || r.Group == "came-back") && it.SubjectKind == workflow.SubjectReadiness {
			fixing[it.AssetID] = true
		}
	}
	// Overdue first, then by due date; fixes with no date last.
	sort.SliceStable(v.BeingFixed, func(i, j int) bool {
		a, b := v.BeingFixed[i], v.BeingFixed[j]
		if a.Overdue != b.Overdue {
			return a.Overdue
		}
		if (a.DueAt == nil) != (b.DueAt == nil) {
			return b.DueAt == nil
		}
		return a.DueAt != nil && a.DueAt.Before(*b.DueAt)
	})
	for _, a := range list {
		if a.Kind != store.KindTLS && a.Kind != store.KindSSH {
			continue
		}
		v.Progress.Endpoints++
		if a.LastDone == nil {
			continue
		}
		v.Progress.Scanned++
		l := a.LastDone.ReadinessLevel
		switch {
		case l == nil || *l < 0:
			v.Progress.Undetermined++
		case *l >= eval.LevelHybridNeg:
			v.Progress.AtL3++
		default:
			v.Progress.BelowL3++
			if fixing[a.ID] {
				v.Progress.WithWork++
			}
		}
	}
	if v.ToFix, err = s.suggestions(now); err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, v)
}

type assignReq struct {
	Subject workSubjectReq `json:"subject"`
	Owner   string         `json:"owner"`
	Due     string         `json:"due"`
	Ticket  string         `json:"ticket"`
}

func cleanTicket(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || len(v) > 500 {
		return "", errors.New("the ticket is a link that starts with https:// (or leave it empty)")
	}
	return v, nil
}

// commonName is the CN of a certificate subject as the inventory writes it, or the whole subject.
func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		if p := strings.TrimSpace(part); strings.HasPrefix(strings.ToUpper(p), "CN=") {
			return p[3:]
		}
	}
	return subject
}

// fixTitle names a fix in plain words.
func (s *Server) fixTitle(sub workSubjectReq, a store.Asset) string {
	switch sub.Kind {
	case workflow.SubjectReadiness:
		if sub.TargetLevel != nil && *sub.TargetLevel >= eval.LevelPQAuth {
			return "Post-quantum certificate on " + a.Name
		}
		return "Post-quantum key exchange on " + a.Name
	case workflow.SubjectFinding:
		if fs, err := s.assetFindings(a); err == nil {
			for _, f := range fs {
				if f.Key == sub.FindingKey {
					return f.Title + " on " + a.Name
				}
			}
		}
		return sub.FindingKey + " on " + a.Name
	}
	name := sub.Certificate
	if len(name) > 16 {
		name = name[:16]
	}
	if certs, err := s.cfg.Store.Certificates(); err == nil {
		for _, c := range certs {
			if c.Fingerprint == strings.ToLower(sub.Certificate) {
				if n := commonName(c.Attrs["subject"]); n != "" {
					name = n
				} else if c.Name != "" {
					name = c.Name
				}
				break
			}
		}
	}
	return "Renew the certificate of " + name
}

func (s *Server) assignFix(w http.ResponseWriter, r *http.Request) {
	var in assignReq
	if !decode(w, r, &in) {
		return
	}
	ticket, err := cleanTicket(in.Ticket)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if !slices.Contains([]string{workflow.SubjectFinding, workflow.SubjectCertificate, workflow.SubjectReadiness}, in.Subject.Kind) {
		writeErr(w, http.StatusBadRequest, "a fix is about a finding, a certificate or an endpoint's post-quantum key exchange")
		return
	}
	if in.Subject.Kind == workflow.SubjectReadiness && in.Subject.TargetLevel == nil {
		l := eval.LevelHybridNeg
		in.Subject.TargetLevel = &l
	}
	in.Subject.Certificate = strings.ToLower(strings.TrimSpace(in.Subject.Certificate))
	var a store.Asset
	if in.Subject.AssetID > 0 {
		if a, err = s.cfg.Store.GetAsset(in.Subject.AssetID); err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("no endpoint or machine %d", in.Subject.AssetID))
			return
		}
	}
	// One fix per problem: a second assignment would split the history.
	open, err := s.cfg.Store.ListWork(store.WorkFilter{Workflow: fixWorkflow, AssetID: in.Subject.AssetID, Certificate: in.Subject.Certificate, Limit: store.MaxWorkListed})
	if err != nil {
		storeErr(w, err)
		return
	}
	for _, it := range open {
		same := it.SubjectKind == in.Subject.Kind && it.FindingKey == in.Subject.FindingKey
		if same && it.Stage != "closed" && it.Stage != "dropped" {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "this is already assigned", "id": it.ID})
			return
		}
	}
	item, status, err := s.workFromRequest(createWorkReq{Title: s.fixTitle(in.Subject, a), Workflow: fixWorkflow, Subject: in.Subject, Owner: in.Owner, Due: in.Due})
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	item.Ticket, item.CreatedBy = ticket, s.actor(r)
	created, err := s.cfg.Store.CreateWork(item)
	if err != nil {
		storeErr(w, err)
		return
	}
	moved, err := s.cfg.Store.MoveWork(created.ID, store.WorkMove{Transition: "assign", FromStage: stageNew, ToStage: stageFixing, ToMarker: workflow.MarkExecuted, Baseline: true}, s.actor(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	// A fix is checked by scans, so what it is about must be scanned regularly: daily, unless a schedule exists.
	scheduled := s.ensureDailyScans(moved)
	now := s.cfg.Now()
	assets, _, _ := s.assetMap()
	writeJSON(w, http.StatusCreated, map[string]any{"fix": s.fixRow(moved, nil, assets, now), "scheduled": scheduled})
}

// ensureDailyScans gives every endpoint a fix depends on a daily scan when it has no schedule. It
// returns the names of the endpoints it scheduled.
func (s *Server) ensureDailyScans(it store.WorkItem) []string {
	ids := []int64{}
	if it.AssetID != 0 {
		ids = append(ids, it.AssetID)
	}
	if it.Certificate != "" {
		if eps, _, _, err := s.cfg.Store.CertificateLeafEndpoints(it.Certificate, s.cfg.Now()); err == nil {
			ids = append(ids, eps...)
		}
	}
	names := []string{}
	for _, id := range ids {
		a, err := s.cfg.Store.GetAsset(id)
		if err != nil || a.Kind == store.KindHost || a.IntervalSeconds > 0 {
			continue
		}
		day := dailySeconds
		if _, err := s.cfg.Store.UpdateAsset(id, store.AssetPatch{IntervalSeconds: &day}); err == nil {
			names = append(names, a.Name)
		}
	}
	return names
}

type fixEvent struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // assigned, fixed, came-back, hold, resumed, changed, closed, dropped
	By   string    `json:"by"`
	Text string    `json:"text,omitempty"`
}

type fixDetail struct {
	FixRow
	HowTo   string          `json:"howTo"`
	Why     string          `json:"why"`
	Sources []eval.Citation `json:"sources"`
	Report  string          `json:"report"` // where the full evidence is, in the interface
	History []fixEvent      `json:"history"`
}

func (s *Server) getFix(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	now := s.cfg.Now()
	checks, items, err := s.syncFixes(now)
	if err != nil {
		storeErr(w, err)
		return
	}
	i := slices.IndexFunc(items, func(it store.WorkItem) bool { return it.ID == id })
	if i < 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	it := items[i]
	assets, _, err := s.assetMap()
	if err != nil {
		storeErr(w, err)
		return
	}
	var c *workflow.Verification
	if x, ok := checks[it.ID]; ok {
		c = &x
	}
	d := fixDetail{FixRow: s.fixRow(it, c, assets, now), Sources: []eval.Citation{}, History: []fixEvent{}}
	a := assets[it.AssetID]
	switch it.SubjectKind {
	case workflow.SubjectReadiness:
		d.HowTo = "Offer a hybrid post-quantum group first (X25519MLKEM768), so clients that support it use it and older ones carry on as before. The endpoint's Configuration tab has the lines for your server."
		d.Why = "A current client negotiates a classical key exchange with this endpoint, so traffic recorded today can be decrypted once a quantum computer exists."
		if b := basisOf("ir8547.key-establishment-deprecated"); b != nil {
			d.Sources = append(d.Sources, eval.Citation{Title: b.Document + ": " + b.Text, URL: b.URL})
		}
	case workflow.SubjectFinding:
		if fs, err := s.assetFindings(a); err == nil {
			for _, f := range fs {
				if f.Key == it.FindingKey {
					d.HowTo, d.Why, d.Sources = f.Remediation, f.Detail, append(d.Sources, f.Citations...)
				}
			}
		}
		if d.HowTo == "" && d.Group == "fixed" {
			d.HowTo = "Nothing to do: the latest scan no longer finds this."
		}
	case workflow.SubjectCertificate:
		d.HowTo = "Issue a new certificate and install it on every endpoint that serves this one. A scan marks the renewal done when each of them serves a certificate issued after this one."
		d.Report = "#/certificates/" + it.Certificate
	}
	if it.AssetID != 0 && d.Report == "" {
		d.Report = fmt.Sprintf("#/endpoints/%d", it.AssetID)
		if a.Kind == store.KindSSH {
			d.Report = fmt.Sprintf("#/ssh/%d", it.AssetID)
		}
	}
	hist, err := s.cfg.Store.Audit(store.WorkObject, id, 200)
	if err != nil {
		storeErr(w, err)
		return
	}
	kinds := map[string]string{"created": "assigned", "confirm": "fixed", "return": "came-back", "hold": "hold", "resume": "resumed", "edited": "changed", "close": "closed", "drop": "dropped"}
	for _, e := range hist {
		k, ok := kinds[e.Action]
		if !ok {
			continue
		}
		d.History = append(d.History, fixEvent{At: e.At, Kind: k, By: e.Actor, Text: e.Reason})
	}
	writeJSON(w, 200, d)
}

// ---- renewals ----------------------------------------------------------------------------------

type renewalRow struct {
	Fingerprint string     `json:"fingerprint"`
	Name        string     `json:"name"`
	Issuer      string     `json:"issuer"`
	NotAfter    *time.Time `json:"notAfter"`
	DaysLeft    int        `json:"daysLeft"`
	Endpoints   int        `json:"endpoints"`
	Renewal     string     `json:"renewal"`
	Owner       string     `json:"owner"`
	Fix         *FixRow    `json:"fix,omitempty"`
}

type unplannedRow struct {
	AssetID  int64     `json:"assetId"`
	Name     string    `json:"name"`
	At       time.Time `json:"at"`
	FromScan int64     `json:"fromScan"`
	ToScan   int64     `json:"toScan"`
	From     string    `json:"from"`
	To       string    `json:"to"`
}

const settingExpected = "renewals.expected"

func (s *Server) expectedChanges() map[string]bool {
	out := map[string]bool{}
	if raw, err := s.cfg.Store.Setting(settingExpected); err == nil && raw != "" {
		var keys []string
		if json.Unmarshal([]byte(raw), &keys) == nil {
			for _, k := range keys {
				out[k] = true
			}
		}
	}
	return out
}

func (s *Server) listRenewals(w http.ResponseWriter, _ *http.Request) {
	now := s.cfg.Now()
	checks, items, err := s.syncFixes(now)
	if err != nil {
		storeErr(w, err)
		return
	}
	assets, _, err := s.assetMap()
	if err != nil {
		storeErr(w, err)
		return
	}
	fixes := map[string]FixRow{}
	for _, it := range items {
		if it.Certificate == "" || it.Stage == "closed" || it.Stage == "dropped" {
			continue
		}
		var c *workflow.Verification
		if x, ok := checks[it.ID]; ok {
			c = &x
		}
		fixes[it.Certificate] = s.fixRow(it, c, assets, now)
	}
	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	life, err := s.cfg.Store.CertificateLifecycles()
	if err != nil {
		storeErr(w, err)
		return
	}
	rows := []renewalRow{}
	for _, c := range certs {
		if !c.Current || c.Role() != "end-entity" || !slices.Contains(c.Origins, "scanner") {
			continue
		}
		na, err := time.Parse(time.RFC3339, c.Attrs["notAfter"])
		if err != nil {
			continue
		}
		name := commonName(c.Attrs["subject"])
		if name == "" {
			name = c.Name
		}
		row := renewalRow{Fingerprint: c.Fingerprint, Name: name, Issuer: commonName(c.Attrs["issuer"]), NotAfter: &na,
			DaysLeft: int(na.Sub(now).Hours() / 24), Endpoints: c.Places, Renewal: life[c.Fingerprint].Renewal, Owner: life[c.Fingerprint].Owner}
		if f, ok := fixes[c.Fingerprint]; ok && f.Group != "fixed" {
			row.Fix = &f
			if row.Owner == "" {
				row.Owner = f.Owner
			}
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].NotAfter.Before(*rows[j].NotAfter) })

	planned, err := s.cfg.Store.WorkCertificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	changes, err := s.cfg.Store.RecentLeafChanges(now.Add(-30 * 24 * time.Hour))
	if err != nil {
		storeErr(w, err)
		return
	}
	expected := s.expectedChanges()
	unplanned := []unplannedRow{}
	for _, ch := range changes {
		if slices.ContainsFunc(ch.From, func(fp string) bool { _, ok := planned[fp]; return ok }) || expected[fmt.Sprintf("%d:%d", ch.AssetID, ch.ToScan)] {
			continue
		}
		unplanned = append(unplanned, unplannedRow{AssetID: ch.AssetID, Name: ch.Name, At: ch.At, FromScan: ch.FromScan, ToScan: ch.ToScan, From: ch.From[0], To: ch.To[0]})
	}
	writeJSON(w, 200, map[string]any{"certificates": rows, "unplanned": unplanned, "warnDays": s.lifecycleSettings().ExpiryWarnDays})
}

// expectChange records that a person says a certificate change was expected, so it is no longer listed.
func (s *Server) expectChange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AssetID int64 `json:"assetId"`
		ToScan  int64 `json:"toScan"`
	}
	if !decode(w, r, &in) {
		return
	}
	a, err := s.cfg.Store.GetAsset(in.AssetID)
	if err != nil || in.ToScan <= 0 {
		writeErr(w, http.StatusBadRequest, "name the endpoint and the scan that found the change")
		return
	}
	keys := []string{}
	for k := range s.expectedChanges() {
		keys = append(keys, k)
	}
	keys = append(keys, fmt.Sprintf("%d:%d", in.AssetID, in.ToScan))
	sort.Strings(keys)
	if len(keys) > 2000 {
		keys = keys[len(keys)-2000:]
	}
	b, _ := json.Marshal(slices.Compact(keys))
	if err := s.cfg.Store.SetSetting(settingExpected, string(b)); err != nil {
		storeErr(w, err)
		return
	}
	if err := s.cfg.Store.RecordAction(s.actor(r), s.clientOf(r), "endpoint", a.ID, "certificate change marked as expected", fmt.Sprintf("scan %d", in.ToScan), ""); err != nil {
		s.log.Warn("recording an expected change failed", "err", err)
	}
	w.WriteHeader(http.StatusNoContent)
}
