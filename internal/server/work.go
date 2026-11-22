package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/workflow"
)

// Tracked work (PRD-023, ADR-0021): the API over internal/workflow and the store. The workflow engine
// decides whether a transition is allowed; this file supplies who is asking, what the work waits for,
// and the product's own verification, computed from scans and uploads made after the change.

const (
	maxWorkTitle       = 200
	maxWorkShort       = 100
	maxWorkDescription = 4000
	maxWorkNote        = 1000
	maxWorkEvidence    = 500
)

// cleanLine checks a one-line text field: at most max bytes, no control characters.
func cleanLine(field, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return "", fmt.Errorf("%s is longer than %d characters", field, max)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", fmt.Errorf("%s contains a control character", field)
	}
	return v, nil
}

// cleanText checks a multi-line text field: line breaks and tabs are allowed, other control characters not.
func cleanText(field, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > max {
		return "", fmt.Errorf("%s is longer than %d characters", field, max)
	}
	if strings.ContainsFunc(v, func(r rune) bool { return (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || r == '\r' }) {
		return "", fmt.Errorf("%s contains a control character", field)
	}
	return v, nil
}

// parseDay accepts a date (2026-12-01, the end of that day UTC) or an RFC 3339 time.
func parseDay(field, v string) (*time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.DateOnly, v); err == nil {
		t = t.Add(24*time.Hour - time.Second)
		return &t, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, fmt.Errorf("%s must be a date (2026-12-01) or an RFC 3339 time", field)
	}
	t = t.UTC()
	return &t, nil
}

// template returns the workflow template with this id: a built-in one, or the latest version of a custom one.
func (s *Server) template(id string) (*workflow.Template, error) {
	if t, ok := workflow.BuiltInByID(id); ok {
		return t, nil
	}
	sw, err := s.cfg.Store.Workflow(id)
	if err != nil {
		return nil, err
	}
	return workflow.Parse(sw.Definition)
}

// actorOf is who asks, as the workflow engine sees it: a signed-in person, or not.
func (s *Server) actorOf(r *http.Request) workflow.Actor {
	p, _ := principalOf(r)
	return workflow.Actor{Name: s.actor(r), Role: p.Role, Person: p.Kind == "session"}
}

// ---- views ------------------------------------------------------------------------------------

type workView struct {
	store.WorkItem
	WorkflowTitle string `json:"workflowTitle"`
	StageLabel    string `json:"stageLabel"`
	// Overdue: a due date has passed and the work is not finished.
	Overdue bool `json:"overdue"`
	// ExceptionExpired: the work is in an exception whose end date has passed.
	ExceptionExpired bool `json:"exceptionExpired"`
}

type workTransitionView struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	To       string   `json:"to"`
	Role     string   `json:"role"`
	Require  []string `json:"require"`
	Approval bool     `json:"approval"`
	Verify   bool     `json:"verify"`
}

type workDetail struct {
	workView
	Stages       []workflow.Stage     `json:"stages"`
	Transitions  []workTransitionView `json:"transitions"`
	Dependencies []store.WorkDep      `json:"dependencies"`
	History      []store.AuditEntry   `json:"history"`
	// Labels names every transition of the workflow, so the history can say what was done in its words.
	Labels map[string]string `json:"labels"`
}

func (s *Server) viewWork(w store.WorkItem, now time.Time) (workView, *workflow.Template) {
	v := workView{WorkItem: w, StageLabel: w.Stage}
	t, err := workflow.Parse(w.WorkflowJSON)
	if err == nil {
		v.WorkflowTitle = t.Title
		if st, ok := t.Stage(w.Stage); ok {
			v.StageLabel = st.Label
		}
	}
	finished := workflow.Finished(w.Marker)
	v.Overdue = !finished && w.DueAt != nil && now.After(*w.DueAt)
	v.ExceptionExpired = w.Marker == workflow.MarkException && w.ExceptionUntil != nil && now.After(*w.ExceptionUntil)
	return v, t
}

// ---- handlers -----------------------------------------------------------------------------------

func (s *Server) listWork(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.WorkFilter{Marker: q.Get("marker"), Owner: q.Get("owner"), Project: q.Get("project"), Workflow: q.Get("workflow"),
		Certificate: q.Get("certificate")}
	for name, dst := range map[string]*int64{"asset": &f.AssetID, "system": &f.SystemID} {
		if v := q.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				writeErr(w, http.StatusBadRequest, name+" must be a positive id")
				return
			}
			*dst = n
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "limit must be a positive number")
			return
		}
		f.Limit = n
	}
	items, err := s.cfg.Store.ListWork(f)
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	out := make([]workView, 0, len(items))
	for _, it := range items {
		v, _ := s.viewWork(it, now)
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

type workSubjectReq struct {
	Kind        string `json:"kind"`
	AssetID     int64  `json:"assetId"`
	SystemID    int64  `json:"systemId"`
	Certificate string `json:"certificate"`
	FindingKey  string `json:"findingKey"`
	TargetLevel *int   `json:"targetLevel"`
}

type createWorkReq struct {
	Title       string         `json:"title"`
	Workflow    string         `json:"workflow"`
	Subject     workSubjectReq `json:"subject"`
	Owner       string         `json:"owner"`
	Due         string         `json:"due"`
	Project     string         `json:"project"`
	Description string         `json:"description"`
}

func (s *Server) createWork(w http.ResponseWriter, r *http.Request) {
	var req createWorkReq
	if !decode(w, r, &req) {
		return
	}
	item, status, err := s.workFromRequest(req)
	if err != nil {
		writeErr(w, status, err.Error())
		return
	}
	item.CreatedBy = s.actor(r)
	created, err := s.cfg.Store.CreateWork(item)
	if err != nil {
		storeErr(w, err)
		return
	}
	v, _ := s.viewWork(created, s.cfg.Now())
	writeJSON(w, http.StatusCreated, v)
}

// workFromRequest validates a new piece of work: its fields, its template and its subject, which must
// exist now (a finding must be among the endpoint's current findings).
func (s *Server) workFromRequest(req createWorkReq) (store.WorkItem, int, error) {
	bad := func(format string, a ...any) (store.WorkItem, int, error) {
		return store.WorkItem{}, http.StatusBadRequest, fmt.Errorf(format, a...)
	}
	var it store.WorkItem
	var err error
	if it.Title, err = cleanLine("title", req.Title, maxWorkTitle); err != nil {
		return bad("%v", err)
	}
	if it.Title == "" {
		return bad("a title is required")
	}
	if it.Owner, err = cleanLine("owner", req.Owner, maxWorkShort); err != nil {
		return bad("%v", err)
	}
	if it.Project, err = cleanLine("project", req.Project, maxWorkShort); err != nil {
		return bad("%v", err)
	}
	if it.Description, err = cleanText("description", req.Description, maxWorkDescription); err != nil {
		return bad("%v", err)
	}
	if it.DueAt, err = parseDay("due", req.Due); err != nil {
		return bad("%v", err)
	}
	tmpl, err := s.template(req.Workflow)
	if errors.Is(err, store.ErrNotFound) {
		return bad("no workflow %q; GET /api/v1/workflows lists them", req.Workflow)
	}
	if err != nil {
		return store.WorkItem{}, http.StatusInternalServerError, errors.New("the workflow could not be read")
	}
	sub := req.Subject
	if !tmpl.Applies(sub.Kind) {
		return bad("the %s workflow applies to %s, not to %q", tmpl.Title, strings.Join(tmpl.Subjects, ", "), sub.Kind)
	}
	it.SubjectKind = sub.Kind
	asset := func(kinds ...string) (store.Asset, int, error) {
		if sub.AssetID <= 0 {
			return store.Asset{}, http.StatusBadRequest, errors.New("subject.assetId is required")
		}
		a, err := s.cfg.Store.GetAsset(sub.AssetID)
		if errors.Is(err, store.ErrNotFound) {
			return a, http.StatusBadRequest, fmt.Errorf("no endpoint or host %d", sub.AssetID)
		}
		if err != nil {
			return a, http.StatusInternalServerError, errors.New("the endpoint could not be read")
		}
		if len(kinds) > 0 && !slices.Contains(kinds, a.Kind) {
			return a, http.StatusBadRequest, fmt.Errorf("%s is a %s; this subject needs a TLS endpoint or an SSH server", a.Name, a.Kind)
		}
		return a, 0, nil
	}
	switch sub.Kind {
	case workflow.SubjectFinding:
		a, status, err := asset()
		if err != nil {
			return store.WorkItem{}, status, err
		}
		if strings.TrimSpace(sub.FindingKey) == "" {
			return bad("subject.findingKey is required")
		}
		current, err := s.assetFindings(a)
		if err != nil {
			return store.WorkItem{}, http.StatusInternalServerError, errors.New("the findings could not be read")
		}
		if !slices.ContainsFunc(current, func(f FlatFinding) bool { return f.Key == sub.FindingKey }) {
			return bad("%q is not among the current findings of %s", sub.FindingKey, a.Name)
		}
		it.AssetID, it.SystemID, it.FindingKey = a.ID, a.SystemID, sub.FindingKey
	case workflow.SubjectReadiness:
		a, status, err := asset(store.KindTLS, store.KindSSH)
		if err != nil {
			return store.WorkItem{}, status, err
		}
		if sub.TargetLevel == nil && tmpl.Target > 0 {
			t := tmpl.Target
			sub.TargetLevel = &t
		}
		if sub.TargetLevel == nil || *sub.TargetLevel < eval.LevelExposed || *sub.TargetLevel > eval.LevelPQAuth {
			return bad("subject.targetLevel must be a readiness level from %d to %d", eval.LevelExposed, eval.LevelPQAuth)
		}
		if *sub.TargetLevel < tmpl.Target {
			return bad("the %s workflow is for reaching L%d; a target of L%d would call it done too early", tmpl.Title, tmpl.Target, *sub.TargetLevel)
		}
		if a.LastDone != nil && a.LastDone.ReadinessLevel != nil && *a.LastDone.ReadinessLevel >= *sub.TargetLevel {
			return bad("%s is already at L%d; there is nothing to reach at L%d", a.Name, *a.LastDone.ReadinessLevel, *sub.TargetLevel)
		}
		it.AssetID, it.SystemID, it.TargetLevel = a.ID, a.SystemID, sub.TargetLevel
	case workflow.SubjectEndpoint:
		a, status, err := asset()
		if err != nil {
			return store.WorkItem{}, status, err
		}
		it.AssetID, it.SystemID = a.ID, a.SystemID
	case workflow.SubjectCertificate:
		fp := strings.ToLower(strings.TrimSpace(sub.Certificate))
		if !fingerprintRE.MatchString(fp) {
			return bad("subject.certificate must be a SHA-256 fingerprint (64 hexadecimal characters)")
		}
		known, err := s.cfg.Store.CertificateKnown(fp)
		if err != nil {
			return store.WorkItem{}, http.StatusInternalServerError, errors.New("the certificate could not be read")
		}
		if !known {
			return bad("no certificate %s in the inventory", fp)
		}
		it.Certificate = fp
		if sub.SystemID > 0 {
			if _, err := s.cfg.Store.GetSystem(sub.SystemID); err != nil {
				return bad("no system %d", sub.SystemID)
			}
			it.SystemID = sub.SystemID
		}
	case workflow.SubjectSystem:
		if sub.SystemID <= 0 {
			return bad("subject.systemId is required")
		}
		if _, err := s.cfg.Store.GetSystem(sub.SystemID); err != nil {
			return bad("no system %d", sub.SystemID)
		}
		it.SystemID = sub.SystemID
	}
	def, err := json.Marshal(tmpl)
	if err != nil {
		return store.WorkItem{}, http.StatusInternalServerError, errors.New("the workflow could not be copied")
	}
	it.WorkflowID, it.WorkflowVersion, it.WorkflowJSON = tmpl.ID, tmpl.Version, def
	it.Stage, it.Marker = tmpl.Initial().ID, tmpl.Initial().Marker
	return it, 0, nil
}

func (s *Server) getWork(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	it, err := s.cfg.Store.GetWork(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	deps, err := s.cfg.Store.WorkDeps(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	hist, err := s.cfg.Store.Audit(store.WorkObject, id, 200)
	if err != nil {
		storeErr(w, err)
		return
	}
	v, t := s.viewWork(it, s.cfg.Now())
	d := workDetail{workView: v, Dependencies: deps, History: hist, Stages: []workflow.Stage{}, Transitions: []workTransitionView{}, Labels: map[string]string{}}
	if t != nil {
		d.Stages = t.Stages
		for _, tr := range t.Transitions {
			d.Labels[tr.ID] = tr.Label
		}
		for _, tr := range t.From(it.Stage) {
			role := tr.Role
			if role == "" {
				role = workflow.RoleAnalyst
			}
			req := tr.Require
			if req == nil {
				req = []string{}
			}
			d.Transitions = append(d.Transitions, workTransitionView{ID: tr.ID, Label: tr.Label, To: tr.To, Role: role, Require: req,
				Approval: tr.Approval, Verify: tr.Verify})
		}
	}
	writeJSON(w, 200, d)
}

type patchWorkReq struct {
	Title       *string `json:"title"`
	Owner       *string `json:"owner"`
	Project     *string `json:"project"`
	Description *string `json:"description"`
	// Ticket is a link to the organisation's own ticket; "" clears it.
	Ticket *string `json:"ticket"`
	// Due is a date or RFC 3339 time; "" clears it.
	Due *string `json:"due"`
}

func (s *Server) patchWork(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	var req patchWorkReq
	if !decode(w, r, &req) {
		return
	}
	var p store.WorkPatch
	for _, f := range []struct {
		name string
		in   *string
		out  **string
		max  int
		text bool
	}{
		{"title", req.Title, &p.Title, maxWorkTitle, false},
		{"owner", req.Owner, &p.Owner, maxWorkShort, false},
		{"project", req.Project, &p.Project, maxWorkShort, false},
		{"description", req.Description, &p.Description, maxWorkDescription, true},
	} {
		if f.in == nil {
			continue
		}
		clean := cleanLine
		if f.text {
			clean = cleanText
		}
		v, err := clean(f.name, *f.in, f.max)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if f.name == "title" && v == "" {
			writeErr(w, http.StatusBadRequest, "a title cannot be empty")
			return
		}
		*f.out = &v
	}
	if req.Ticket != nil {
		t, err := cleanTicket(*req.Ticket)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p.Ticket = &t
	}
	if req.Due != nil {
		due, err := parseDay("due", *req.Due)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p.DueAt, p.ClearDue = due, due == nil
	}
	it, err := s.cfg.Store.UpdateWork(id, p, s.actor(r), reason)
	if err != nil {
		storeErr(w, err)
		return
	}
	v, _ := s.viewWork(it, s.cfg.Now())
	writeJSON(w, 200, v)
}

type transitionReq struct {
	Transition string `json:"transition"`
	Note       string `json:"note"`
	Evidence   string `json:"evidence"`
	Until      string `json:"until"`
}

func (s *Server) transitionWork(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	var req transitionReq
	if !decode(w, r, &req) {
		return
	}
	note, err := cleanText("note", req.Note, maxWorkNote)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	evidence, err := cleanLine("evidence", req.Evidence, maxWorkEvidence)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	until, err := parseDay("until", req.Until)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	it, err := s.cfg.Store.GetWork(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	tmpl, err := workflow.Parse(it.WorkflowJSON)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "this work's workflow could not be read")
		return
	}
	deps, err := s.cfg.Store.WorkDeps(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	var unfinished []int64
	for _, d := range deps {
		if !workflow.Finished(d.Marker) {
			unfinished = append(unfinished, d.ID)
		}
	}
	now := s.cfg.Now()
	st := workflow.State{Stage: it.Stage, CreatedBy: it.CreatedBy, Approvers: it.Approvers, Unfinished: unfinished}
	act := s.actorOf(r)
	tr, to, ver, err := tmpl.Check(st, workflow.Request{Transition: req.Transition, Note: note, Evidence: evidence, Until: until}, act, now,
		func() workflow.Verification { return s.verifyWork(it, now) })
	if err != nil {
		var ref *workflow.Refusal
		if !errors.As(err, &ref) {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		status := http.StatusConflict
		switch ref.Code {
		case workflow.RefuseRole:
			status = http.StatusForbidden
		case workflow.RefuseUnknown, workflow.RefuseField, workflow.RefuseUntil:
			status = http.StatusBadRequest
		}
		body := map[string]any{"error": ref.Message, "code": ref.Code}
		if ver != nil {
			body["verification"] = ver
		}
		writeJSON(w, status, body)
		return
	}
	move := store.WorkMove{Transition: tr.ID, FromStage: it.Stage, ToStage: to.ID, ToMarker: to.Marker,
		Baseline: workflow.Baseline(to.Marker), Closed: to.Terminal, Note: note, Evidence: evidence}
	if tr.Approval {
		move.Approver = act.Name
	}
	if from, ok := tmpl.Stage(it.Stage); ok && workflow.Baseline(from.Marker) && !tr.Verify {
		// The change was rolled back or redone: what was approved is not what will be made next.
		move.ResetApprovers = true
	}
	if to.Marker == workflow.MarkException {
		move.Until = until
	}
	if ver != nil {
		if b, err := json.Marshal(ver); err == nil {
			move.Verification = b
		}
	}
	moved, err := s.cfg.Store.MoveWork(id, move, act.Name)
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "moved"})
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	v, _ := s.viewWork(moved, now)
	writeJSON(w, 200, v)
}

func (s *Server) workVerification(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	it, err := s.cfg.Store.GetWork(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, s.verifyWork(it, s.cfg.Now()))
}

func (s *Server) addWorkDep(w http.ResponseWriter, r *http.Request) {
	id, other, ok := workPair(w, r)
	if !ok {
		return
	}
	err := s.cfg.Store.AddWorkDep(id, other, s.actor(r))
	switch {
	case errors.Is(err, store.ErrCycle):
		writeErr(w, http.StatusConflict, err.Error())
	case err != nil:
		storeErr(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) removeWorkDep(w http.ResponseWriter, r *http.Request) {
	id, other, ok := workPair(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Store.RemoveWorkDep(id, other, s.actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func workPair(w http.ResponseWriter, r *http.Request) (int64, int64, bool) {
	id, ok := idParam(w, r)
	if !ok {
		return 0, 0, false
	}
	other, err := strconv.ParseInt(r.PathValue("otherId"), 10, 64)
	if err != nil || other <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return 0, 0, false
	}
	return id, other, true
}

// ---- workflows ----------------------------------------------------------------------------------

type workflowView struct {
	*workflow.Template
	BuiltIn   bool       `json:"builtIn"`
	Verifies  bool       `json:"verifies"`
	CreatedBy string     `json:"createdBy,omitempty"`
	CreatedAt *time.Time `json:"createdAt,omitempty"`
}

func (s *Server) listWorkflows(w http.ResponseWriter, _ *http.Request) {
	out := []workflowView{}
	for _, t := range workflow.BuiltIn() {
		out = append(out, workflowView{Template: t, BuiltIn: true, Verifies: t.Verifies()})
	}
	custom, err := s.cfg.Store.Workflows()
	if err != nil {
		storeErr(w, err)
		return
	}
	for _, c := range custom {
		t, err := workflow.Parse(c.Definition)
		if err != nil {
			s.log.Warn("a stored workflow no longer validates", "workflow", c.ID, "version", c.Version, "err", err)
			continue
		}
		at := c.CreatedAt
		out = append(out, workflowView{Template: t, Verifies: t.Verifies(), CreatedBy: c.CreatedBy, CreatedAt: &at})
	}
	writeJSON(w, 200, out)
}

func (s *Server) getWorkflow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("workflow")
	if t, ok := workflow.BuiltInByID(id); ok {
		writeJSON(w, 200, workflowView{Template: t, BuiltIn: true, Verifies: t.Verifies()})
		return
	}
	c, err := s.cfg.Store.Workflow(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	t, err := workflow.Parse(c.Definition)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "this workflow no longer validates")
		return
	}
	at := c.CreatedAt
	writeJSON(w, 200, workflowView{Template: t, Verifies: t.Verifies(), CreatedBy: c.CreatedBy, CreatedAt: &at})
}

// saveWorkflow stores a custom template, or a new version of one. Administrators only; a built-in id
// cannot be taken. The version in the body is ignored: the next version number is assigned.
func (s *Server) saveWorkflow(w http.ResponseWriter, r *http.Request) {
	if p, _ := principalOf(r); p.Role != store.RoleAdmin {
		writeErr(w, http.StatusForbidden, "only an administrator can add or change a workflow")
		return
	}
	var t workflow.Template
	if !decodeMax(w, r, &t, workflow.MaxBytes) {
		return
	}
	if workflow.IsBuiltIn(t.ID) {
		writeErr(w, http.StatusConflict, fmt.Sprintf("%q is a built-in workflow; copy it under a new id to change it", t.ID))
		return
	}
	next, err := s.cfg.Store.NextWorkflowVersion(t.ID)
	if err != nil {
		storeErr(w, err)
		return
	}
	t.Version = next
	if err := t.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "the workflow is not valid: "+err.Error())
		return
	}
	def, err := json.Marshal(&t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	sw, err := s.cfg.Store.SaveWorkflow(t.ID, t.Version, def, s.actor(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	at := sw.CreatedAt
	writeJSON(w, http.StatusCreated, workflowView{Template: &t, Verifies: t.Verifies(), CreatedBy: sw.CreatedBy, CreatedAt: &at})
}

// ---- verification -------------------------------------------------------------------------------

// verifyWork computes, from the product's own evidence made after the change was recorded as made,
// whether the change is in effect (ADR-0021 §5). It reads; it never writes.
func (s *Server) verifyWork(it store.WorkItem, now time.Time) workflow.Verification {
	v := workflow.Verification{At: now}
	result := func(status, detail string, evidence ...string) workflow.Verification {
		v.Status, v.Detail, v.Evidence = status, detail, evidence
		return v
	}
	if it.SubjectKind == workflow.SubjectSystem || it.SubjectKind == workflow.SubjectEndpoint {
		return result(workflow.NotVerifiable, "the product cannot observe a change to a "+it.SubjectKind+" as a whole; close this work without verification")
	}
	if it.ExecutedAt == nil {
		return result(workflow.Waiting, "nothing to verify yet: the change has not been recorded as made")
	}
	since := *it.ExecutedAt
	v.Since = &since
	when := since.Format("2006-01-02 15:04 UTC")
	failed := func() workflow.Verification {
		return result(workflow.Waiting, "the evidence could not be read; try again")
	}

	switch it.SubjectKind {
	case workflow.SubjectFinding, workflow.SubjectReadiness:
		if it.AssetID == 0 {
			return result(workflow.NotVerifiable, "the endpoint or host this work is about has been deleted")
		}
		a, err := s.cfg.Store.GetAsset(it.AssetID)
		if err != nil {
			return result(workflow.NotVerifiable, "the endpoint or host this work is about has been deleted")
		}
		if it.SubjectKind == workflow.SubjectFinding && a.Kind == store.KindHost {
			// A machine's inventory is a document someone uploads; whoever recorded the change could
			// upload an edited one. Until uploads are authenticated as a collector's, it verifies nothing.
			return result(workflow.NotVerifiable, "a machine's inventory is an uploaded document, not this product's own observation, so it cannot verify a change; close this work without verification")
		}
		scan, err := s.cfg.Store.LatestDoneScanAfter(a.ID, since)
		if errors.Is(err, store.ErrNotFound) {
			return result(workflow.Waiting, fmt.Sprintf("no scan of %s has finished since the change was recorded (%s); scan it to verify", a.Name, when))
		}
		if err != nil {
			return failed()
		}
		ev := fmt.Sprintf("scan %d", scan.ID)
		v.CheckedAt = scan.FinishedAt
		if it.SubjectKind == workflow.SubjectReadiness {
			target := 0
			if it.TargetLevel != nil {
				target = *it.TargetLevel
			}
			switch {
			case scan.ReadinessLevel != nil && *scan.ReadinessLevel >= target:
				return result(workflow.Verified, fmt.Sprintf("scan %d of %s reached L%d (%s); the target is L%d", scan.ID, a.Name, *scan.ReadinessLevel,
					eval.LevelLabel(*scan.ReadinessLevel), target), ev)
			case scan.Incomplete:
				return result(workflow.Waiting, fmt.Sprintf("scan %d of %s was incomplete and did not reach L%d; scan it again", scan.ID, a.Name, target), ev)
			case scan.ReadinessLevel == nil:
				return result(workflow.NotVerified, fmt.Sprintf("scan %d of %s could not determine a readiness level", scan.ID, a.Name), ev)
			}
			return result(workflow.NotVerified, fmt.Sprintf("scan %d of %s is at L%d (%s); the target is L%d", scan.ID, a.Name, *scan.ReadinessLevel,
				eval.LevelLabel(*scan.ReadinessLevel), target), ev)
		}
		raw, err := s.cfg.Store.Evaluation(scan.ID)
		if err != nil {
			return failed()
		}
		var e eval.Evaluation
		if err := json.Unmarshal(raw, &e); err != nil {
			return failed()
		}
		if slices.ContainsFunc(e.Findings, func(f eval.Finding) bool { return f.ID == it.FindingKey }) {
			return result(workflow.NotVerified, fmt.Sprintf("scan %d of %s still finds %s", scan.ID, a.Name, it.FindingKey), ev)
		}
		if scan.Incomplete {
			return result(workflow.Waiting, fmt.Sprintf("scan %d of %s was incomplete, and a finding missing from an incomplete scan proves nothing; scan it again", scan.ID, a.Name), ev)
		}
		// A finding is gone only when its check ran and found nothing: a check whose stage did not run or
		// proved nothing (no certificate seen, a host key not read) says nothing about it.
		if !eval.CheckedAbsent(e, it.FindingKey) {
			return result(workflow.Waiting, fmt.Sprintf("scan %d of %s could not check for %s (that part of the scan did not run or proved nothing); scan it again", scan.ID, a.Name, it.FindingKey), ev)
		}
		return result(workflow.Verified, fmt.Sprintf("scan %d of %s no longer finds %s", scan.ID, a.Name, it.FindingKey), ev)

	case workflow.SubjectCertificate:
		// Every endpoint a scan has seen presenting the old certificate must show its replacement: those
		// remembered on the work (which keeps endpoints deleted or pruned since) and any other endpoint a
		// kept scan saw presenting it, whenever that scan was made.
		live, old, found, err := s.cfg.Store.CertificateLeafEndpoints(it.Certificate)
		if err != nil {
			return failed()
		}
		kept, err := s.cfg.Store.WorkEndpoints(it.ID)
		if err != nil {
			return failed()
		}
		endpoints := slices.Concat(kept, live)
		slices.Sort(endpoints)
		endpoints = slices.Compact(endpoints)
		if !found {
			return result(workflow.NotVerifiable, "the certificate is no longer in the inventory")
		}
		if old.NotBefore == nil {
			return result(workflow.NotVerifiable, "the old certificate's dates are not known, so a replacement cannot be told from it")
		}
		var waiting, failedOn, ok, evidence []string
		counted, deleted := 0, 0
		for _, id := range endpoints {
			a, err := s.cfg.Store.GetAsset(id)
			if err != nil {
				deleted++ // an endpoint that served it is gone: its replacement can no longer be shown
				continue
			}
			counted++
			scan, err := s.cfg.Store.LatestDoneScanAfter(a.ID, since)
			if errors.Is(err, store.ErrNotFound) {
				waiting = append(waiting, a.Name+" (no scan since)")
				continue
			}
			if err != nil {
				return failed()
			}
			evidence = append(evidence, fmt.Sprintf("scan %d", scan.ID))
			if scan.FinishedAt != nil && (v.CheckedAt == nil || scan.FinishedAt.After(*v.CheckedAt)) {
				v.CheckedAt = scan.FinishedAt
			}
			leaves, err := s.cfg.Store.ScanLeafCertificates(scan.ID)
			if err != nil {
				return failed()
			}
			switch {
			case slices.ContainsFunc(leaves, func(l store.LeafCertificate) bool { return l.Fingerprint == it.Certificate }):
				failedOn = append(failedOn, fmt.Sprintf("%s still presents it (scan %d)", a.Name, scan.ID))
			case scan.Incomplete:
				waiting = append(waiting, fmt.Sprintf("%s (scan %d was incomplete)", a.Name, scan.ID))
			case len(leaves) == 0:
				waiting = append(waiting, fmt.Sprintf("%s (scan %d saw no certificate)", a.Name, scan.ID))
			default:
				// A replacement is a certificate issued after the old one and valid now. How long it
				// lives does not matter: a 90-day certificate replacing a one-year one is a replacement.
				replaced := slices.ContainsFunc(leaves, func(l store.LeafCertificate) bool {
					return l.NotBefore != nil && l.NotAfter != nil && l.NotBefore.After(*old.NotBefore) && !l.NotBefore.After(now) && l.NotAfter.After(now)
				})
				if replaced {
					ok = append(ok, a.Name)
				} else {
					failedOn = append(failedOn, fmt.Sprintf("%s presents a different certificate (%s…) that is not a replacement: it was not issued after the old one, or it is not valid now (scan %d)",
						a.Name, leaves[0].Fingerprint[:12], scan.ID))
				}
			}
		}
		switch {
		case len(failedOn) > 0:
			return result(workflow.NotVerified, strings.Join(failedOn, "; "), evidence...)
		case deleted > 0:
			return result(workflow.NotVerifiable, fmt.Sprintf("%d endpoint(s) that served this certificate have been deleted since, so the product cannot show it was replaced everywhere; close this work without verification", deleted), evidence...)
		case counted == 0:
			return result(workflow.NotVerifiable, "no scan has seen an endpoint presenting this certificate, so a scan cannot show its replacement; scan the endpoints that use it, or close this work without verification")
		case len(waiting) > 0:
			return result(workflow.Waiting, "waiting for "+strings.Join(waiting, ", ")+"; scan them to verify", evidence...)
		}
		return result(workflow.Verified, fmt.Sprintf("%s now present%s a certificate issued after the old one and valid now; the old one is no longer served", listWords(ok), plural(len(ok))), evidence...)
	}
	return result(workflow.NotVerifiable, "the product cannot observe a change to a "+it.SubjectKind+"; close this work without verification")
}

func plural(n int) string {
	if n == 1 {
		return "s"
	}
	return ""
}

func listWords(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}
