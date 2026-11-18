package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tracked work (PRD-023, ADR-0021). The rules of a workflow live in internal/workflow; the store keeps
// the rows, refuses a transition made on a stale stage, keeps dependencies free of cycles, and writes
// every change to the append-only audit log as object kind "work".

// WorkObject is the audit_log object kind of a piece of work; WorkflowObject that of a custom template.
const (
	WorkObject     = "work"
	WorkflowObject = "workflow"
)

// WorkItem is one piece of tracked work.
type WorkItem struct {
	ID              int64           `json:"id"`
	Title           string          `json:"title"`
	WorkflowID      string          `json:"workflow"`
	WorkflowVersion int             `json:"workflowVersion"`
	WorkflowJSON    json.RawMessage `json:"-"`
	Stage           string          `json:"stage"`
	Marker          string          `json:"marker"`
	SubjectKind     string          `json:"subjectKind"`
	AssetID         int64           `json:"assetId,omitempty"`
	SystemID        int64           `json:"systemId,omitempty"`
	Certificate     string          `json:"certificate,omitempty"`
	FindingKey      string          `json:"findingKey,omitempty"`
	TargetLevel     *int            `json:"targetLevel,omitempty"`
	Owner           string          `json:"owner"`
	DueAt           *time.Time      `json:"dueAt"`
	Project         string          `json:"project"`
	Description     string          `json:"description"`
	// Ticket is a link to the change in the organisation's own tracker (optional).
	Ticket    string    `json:"ticket"`
	Approvers []string  `json:"approvers"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// ExecutedAt is when the work last entered a stage that says the change was made: the baseline
	// verification reads evidence after.
	ExecutedAt     *time.Time      `json:"executedAt"`
	ExceptionUntil *time.Time      `json:"exceptionUntil"`
	Verification   json.RawMessage `json:"verification,omitempty"`
	ClosedAt       *time.Time      `json:"closedAt"`
}

const workCols = `id, title, workflow_id, workflow_version, workflow_json, stage, marker, subject_kind, asset_id, system_id,
	certificate, finding_key, target_level, owner, due_at, project, description, ticket, approvers, created_by, created_at, updated_at,
	executed_at, exception_until, verification, closed_at`

func scanWork(r scanner) (WorkItem, error) {
	var w WorkItem
	var wf, approvers, created, updated, verification string
	var asset, system, target sql.NullInt64
	var due, executed, until, closed sql.NullString
	err := r.Scan(&w.ID, &w.Title, &w.WorkflowID, &w.WorkflowVersion, &wf, &w.Stage, &w.Marker, &w.SubjectKind, &asset, &system,
		&w.Certificate, &w.FindingKey, &target, &w.Owner, &due, &w.Project, &w.Description, &w.Ticket, &approvers, &w.CreatedBy, &created, &updated,
		&executed, &until, &verification, &closed)
	if err != nil {
		return w, err
	}
	w.WorkflowJSON = json.RawMessage(wf)
	w.AssetID, w.SystemID = asset.Int64, system.Int64
	if target.Valid {
		l := int(target.Int64)
		w.TargetLevel = &l
	}
	_ = json.Unmarshal([]byte(approvers), &w.Approvers)
	if w.Approvers == nil {
		w.Approvers = []string{}
	}
	if t := parseTS(sql.NullString{String: created, Valid: true}); t != nil {
		w.CreatedAt = *t
	}
	if t := parseTS(sql.NullString{String: updated, Valid: true}); t != nil {
		w.UpdatedAt = *t
	}
	w.DueAt, w.ExecutedAt, w.ExceptionUntil, w.ClosedAt = parseTS(due), parseTS(executed), parseTS(until), parseTS(closed)
	if verification != "" {
		w.Verification = json.RawMessage(verification)
	}
	return w, nil
}

func nullInt(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// auditWorkTx appends one change to a piece of work (or a template) to the audit log.
func auditWorkTx(tx *sql.Tx, at time.Time, actor, kind string, id int64, action string, before, after any, reason string) error {
	b, err := json.Marshal(before)
	if err != nil {
		return err
	}
	a, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if actor == "" {
		actor = "unknown"
	}
	_, err = tx.Exec(`INSERT INTO audit_log (at, actor, object_kind, object_id, action, before_json, after_json, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ts(at), actor, kind, id, action, string(b), string(a), reason)
	return err
}

// workSnapshot is what the audit log records about a piece of work: its fields, never its template.
func workSnapshot(w WorkItem) map[string]any {
	m := map[string]any{"title": w.Title, "workflow": w.WorkflowID, "workflowVersion": w.WorkflowVersion, "stage": w.Stage,
		"marker": w.Marker, "subjectKind": w.SubjectKind, "owner": w.Owner, "project": w.Project}
	if w.AssetID != 0 {
		m["assetId"] = w.AssetID
	}
	if w.SystemID != 0 {
		m["systemId"] = w.SystemID
	}
	if w.Certificate != "" {
		m["certificate"] = w.Certificate
	}
	if w.FindingKey != "" {
		m["findingKey"] = w.FindingKey
	}
	if w.TargetLevel != nil {
		m["targetLevel"] = *w.TargetLevel
	}
	if w.DueAt != nil {
		m["dueAt"] = ts(*w.DueAt)
	}
	return m
}

// CreateWork stores a new piece of work in its template's first stage and records who asked for it.
func (s *Store) CreateWork(w WorkItem) (WorkItem, error) {
	now := s.now()
	approvers, _ := json.Marshal([]string{})
	tx, err := s.db.Begin()
	if err != nil {
		return WorkItem{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.Exec(`INSERT INTO work_items (title, workflow_id, workflow_version, workflow_json, stage, marker, subject_kind, asset_id,
		system_id, certificate, finding_key, target_level, owner, due_at, project, description, ticket, approvers, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.Title, w.WorkflowID, w.WorkflowVersion, string(w.WorkflowJSON), w.Stage, w.Marker, w.SubjectKind, nullID(w.AssetID),
		nullID(w.SystemID), w.Certificate, w.FindingKey, nullInt(w.TargetLevel), w.Owner, nullTS(w.DueAt), w.Project, w.Description, w.Ticket,
		string(approvers), w.CreatedBy, ts(now), ts(now))
	if err != nil {
		return WorkItem{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return WorkItem{}, err
	}
	w.ID = id
	if err := auditWorkTx(tx, now, w.CreatedBy, WorkObject, id, "created", map[string]any{}, workSnapshot(w), ""); err != nil {
		return WorkItem{}, err
	}
	if err := tx.Commit(); err != nil {
		return WorkItem{}, err
	}
	return s.GetWork(id)
}

// GetWork returns one piece of work.
func (s *Store) GetWork(id int64) (WorkItem, error) {
	w, err := scanWork(s.db.QueryRow(`SELECT `+workCols+` FROM work_items WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkItem{}, ErrNotFound
	}
	return w, err
}

// WorkFilter narrows ListWork. Empty fields match everything.
type WorkFilter struct {
	Marker      string // one marker, or "open" for any not finished (neither verified, complete nor cancelled)
	Owner       string
	Project     string
	Workflow    string
	AssetID     int64
	SystemID    int64
	Certificate string
	Limit       int // at most 5000; default 1000
}

// MaxWorkListed is the most work one listing returns; figures and exports say so when there is more.
const MaxWorkListed = 5000

// CountWork is how many pieces of work exist.
func (s *Store) CountWork() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM work_items`).Scan(&n)
	return n, err
}

// ListWork lists work, most recently changed first.
func (s *Store) ListWork(f WorkFilter) ([]WorkItem, error) {
	q := `SELECT ` + workCols + ` FROM work_items WHERE 1=1`
	var args []any
	switch f.Marker {
	case "":
	case "open":
		q += ` AND marker NOT IN ('verified','complete','cancelled')`
	default:
		q += ` AND marker = ?`
		args = append(args, f.Marker)
	}
	for _, c := range []struct {
		col string
		v   any
		set bool
	}{
		{"owner", f.Owner, f.Owner != ""},
		{"project", f.Project, f.Project != ""},
		{"workflow_id", f.Workflow, f.Workflow != ""},
		{"asset_id", f.AssetID, f.AssetID != 0},
		{"system_id", f.SystemID, f.SystemID != 0},
		{"certificate", strings.ToLower(f.Certificate), f.Certificate != ""},
	} {
		if c.set {
			q += ` AND ` + c.col + ` = ?` //nolint:gosec // c.col comes from the constant list above, never from input
			args = append(args, c.v)
		}
	}
	switch {
	case f.Limit <= 0:
		f.Limit = 1000
	case f.Limit > MaxWorkListed:
		f.Limit = MaxWorkListed
	}
	q += ` ORDER BY updated_at DESC, id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []WorkItem{}
	for rows.Next() {
		w, err := scanWork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WorkPatch is a change to the fields a person edits. A nil field is left alone; an empty string clears
// owner, project or description; ClearDue clears the due date.
type WorkPatch struct {
	Title       *string
	Owner       *string
	Project     *string
	Description *string
	Ticket      *string
	DueAt       *time.Time
	ClearDue    bool
}

// UpdateWork applies a patch and records the before and after values.
func (s *Store) UpdateWork(id int64, p WorkPatch, actor, reason string) (WorkItem, error) {
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return WorkItem{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	old, err := scanWork(tx.QueryRow(`SELECT `+workCols+` FROM work_items WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkItem{}, ErrNotFound
	}
	if err != nil {
		return WorkItem{}, err
	}
	before, after := map[string]any{}, map[string]any{}
	n := old
	set := func(field string, from, to any) {
		before[field], after[field] = from, to
	}
	if p.Title != nil && *p.Title != old.Title {
		set("title", old.Title, *p.Title)
		n.Title = *p.Title
	}
	if p.Owner != nil && *p.Owner != old.Owner {
		set("owner", old.Owner, *p.Owner)
		n.Owner = *p.Owner
	}
	if p.Project != nil && *p.Project != old.Project {
		set("project", old.Project, *p.Project)
		n.Project = *p.Project
	}
	if p.Ticket != nil && *p.Ticket != old.Ticket {
		set("ticket", old.Ticket, *p.Ticket)
		n.Ticket = *p.Ticket
	}
	if p.Description != nil && *p.Description != old.Description {
		set("description", old.Description, *p.Description)
		n.Description = *p.Description
	}
	tsOr := func(t *time.Time) any {
		if t == nil {
			return nil
		}
		return ts(*t)
	}
	switch {
	case p.ClearDue && old.DueAt != nil:
		set("dueAt", tsOr(old.DueAt), nil)
		n.DueAt = nil
	case p.DueAt != nil && (old.DueAt == nil || !old.DueAt.Equal(*p.DueAt)):
		set("dueAt", tsOr(old.DueAt), ts(*p.DueAt))
		d := *p.DueAt
		n.DueAt = &d
	}
	if len(after) == 0 {
		return old, nil
	}
	if _, err := tx.Exec(`UPDATE work_items SET title = ?, owner = ?, project = ?, description = ?, ticket = ?, due_at = ?, updated_at = ? WHERE id = ?`,
		n.Title, n.Owner, n.Project, n.Description, n.Ticket, nullTS(n.DueAt), ts(now), id); err != nil {
		return WorkItem{}, err
	}
	if err := auditWorkTx(tx, now, actor, WorkObject, id, "edited", before, after, reason); err != nil {
		return WorkItem{}, err
	}
	if err := tx.Commit(); err != nil {
		return WorkItem{}, err
	}
	return s.GetWork(id)
}

// WorkMove is one transition the workflow engine allowed, to be written.
type WorkMove struct {
	Transition string
	FromStage  string // the stage the engine checked: the move is refused if the work has moved since
	ToStage    string
	ToMarker   string
	Baseline   bool // the new stage says the change was made: executed_at becomes now
	Closed     bool // the new stage is terminal
	Approver   string
	// ResetApprovers forgets earlier approvals: the change they approved was rolled back.
	ResetApprovers bool
	Until          *time.Time
	Note           string
	Evidence       string
	// Verification is the product's verification result, recorded when the transition needed one.
	Verification json.RawMessage
}

// MoveWork applies a transition. It returns ErrConflict when the work is no longer in FromStage, so two
// people acting at once cannot both move it (REQ-WF-11).
func (s *Store) MoveWork(id int64, m WorkMove, actor string) (WorkItem, error) {
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return WorkItem{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	old, err := scanWork(tx.QueryRow(`SELECT `+workCols+` FROM work_items WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return WorkItem{}, ErrNotFound
	}
	if err != nil {
		return WorkItem{}, err
	}
	approvers := old.Approvers
	if m.ResetApprovers {
		approvers = []string{}
	}
	if m.Approver != "" {
		approvers = append(approvers, m.Approver)
	}
	ab, _ := json.Marshal(approvers)
	executed := nullTS(old.ExecutedAt)
	if m.Baseline {
		executed = ts(now)
	}
	var closed any
	if m.Closed {
		closed = ts(now)
	}
	verification := string(old.Verification)
	if len(m.Verification) > 0 {
		verification = string(m.Verification)
	}
	res, err := tx.Exec(`UPDATE work_items SET stage = ?, marker = ?, approvers = ?, executed_at = ?, exception_until = ?, verification = ?,
		closed_at = ?, updated_at = ? WHERE id = ? AND stage = ?`,
		m.ToStage, m.ToMarker, string(ab), executed, nullTS(m.Until), verification, closed, ts(now), id, m.FromStage)
	if err != nil {
		return WorkItem{}, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return WorkItem{}, err
	} else if n == 0 {
		return WorkItem{}, fmt.Errorf("%w: the work moved to %q while this was being decided", ErrConflict, old.Stage)
	}
	after := map[string]any{"stage": m.ToStage, "marker": m.ToMarker}
	if m.Evidence != "" {
		after["evidence"] = m.Evidence
	}
	if m.Until != nil {
		after["until"] = ts(*m.Until)
	}
	if m.Approver != "" {
		after["approval"] = true
	}
	if len(m.Verification) > 0 {
		after["verification"] = m.Verification
	}
	if err := auditWorkTx(tx, now, actor, WorkObject, id, m.Transition, map[string]any{"stage": old.Stage, "marker": old.Marker}, after, m.Note); err != nil {
		return WorkItem{}, err
	}
	if err := tx.Commit(); err != nil {
		return WorkItem{}, err
	}
	return s.GetWork(id)
}

// WorkDep is one prerequisite of a piece of work.
type WorkDep struct {
	ID     int64  `json:"id"`
	Title  string `json:"title"`
	Stage  string `json:"stage"`
	Marker string `json:"marker"`
}

// WorkDeps lists the prerequisites of a piece of work.
func (s *Store) WorkDeps(id int64) ([]WorkDep, error) {
	rows, err := s.db.Query(`SELECT w.id, w.title, w.stage, w.marker FROM work_deps d JOIN work_items w ON w.id = d.depends_on
		WHERE d.item_id = ? ORDER BY w.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []WorkDep{}
	for rows.Next() {
		var d WorkDep
		if err := rows.Scan(&d.ID, &d.Title, &d.Stage, &d.Marker); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ErrCycle is returned when a dependency would make work wait for itself.
var ErrCycle = errors.New("this dependency would make the work wait for itself")

// AddWorkDep makes id wait for dependsOn. It refuses a cycle.
func (s *Store) AddWorkDep(id, dependsOn int64, actor string) error {
	if id == dependsOn {
		return ErrCycle
	}
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	for _, x := range []int64{id, dependsOn} {
		var one int
		if err := tx.QueryRow(`SELECT 1 FROM work_items WHERE id = ?`, x).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
	}
	// A cycle exists if id is already reachable from dependsOn.
	var reach int
	err = tx.QueryRow(`WITH RECURSIVE up(n) AS (SELECT ? UNION SELECT d.depends_on FROM work_deps d JOIN up ON d.item_id = up.n)
		SELECT COUNT(*) FROM up WHERE n = ?`, dependsOn, id).Scan(&reach)
	if err != nil {
		return err
	}
	if reach > 0 {
		return ErrCycle
	}
	res, err := tx.Exec(`INSERT OR IGNORE INTO work_deps (item_id, depends_on) VALUES (?, ?)`, id, dependsOn)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return tx.Commit() // already there: nothing to record
	}
	if _, err := tx.Exec(`UPDATE work_items SET updated_at = ? WHERE id = ?`, ts(now), id); err != nil {
		return err
	}
	if err := auditWorkTx(tx, now, actor, WorkObject, id, "dependency added", map[string]any{}, map[string]any{"dependsOn": dependsOn}, ""); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveWorkDep removes a prerequisite.
func (s *Store) RemoveWorkDep(id, dependsOn int64, actor string) error {
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.Exec(`DELETE FROM work_deps WHERE item_id = ? AND depends_on = ?`, id, dependsOn)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(`UPDATE work_items SET updated_at = ? WHERE id = ?`, ts(now), id); err != nil {
		return err
	}
	if err := auditWorkTx(tx, now, actor, WorkObject, id, "dependency removed", map[string]any{"dependsOn": dependsOn}, map[string]any{}, ""); err != nil {
		return err
	}
	return tx.Commit()
}

// StoredWorkflow is one version of a custom workflow template.
type StoredWorkflow struct {
	ID         string          `json:"id"`
	Version    int             `json:"version"`
	Definition json.RawMessage `json:"definition"`
	CreatedBy  string          `json:"createdBy"`
	CreatedAt  time.Time       `json:"createdAt"`
}

// Workflows lists the latest version of every custom template.
func (s *Store) Workflows() ([]StoredWorkflow, error) {
	rows, err := s.db.Query(`SELECT w.id, w.version, w.definition, w.created_by, w.created_at FROM workflows w
		JOIN (SELECT id, MAX(version) v FROM workflows GROUP BY id) m ON m.id = w.id AND m.v = w.version ORDER BY w.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	out := []StoredWorkflow{}
	for rows.Next() {
		var w StoredWorkflow
		var def, at string
		if err := rows.Scan(&w.ID, &w.Version, &def, &w.CreatedBy, &at); err != nil {
			return nil, err
		}
		w.Definition = json.RawMessage(def)
		if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
			w.CreatedAt = *t
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Workflow returns the latest version of one custom template.
func (s *Store) Workflow(id string) (StoredWorkflow, error) {
	var w StoredWorkflow
	var def, at string
	err := s.db.QueryRow(`SELECT id, version, definition, created_by, created_at FROM workflows WHERE id = ? ORDER BY version DESC LIMIT 1`, id).
		Scan(&w.ID, &w.Version, &def, &w.CreatedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return StoredWorkflow{}, ErrNotFound
	}
	if err != nil {
		return StoredWorkflow{}, err
	}
	w.Definition = json.RawMessage(def)
	if t := parseTS(sql.NullString{String: at, Valid: true}); t != nil {
		w.CreatedAt = *t
	}
	return w, nil
}

// NextWorkflowVersion is the version a new definition of id would get.
func (s *Store) NextWorkflowVersion(id string) (int, error) {
	var v sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(version) FROM workflows WHERE id = ?`, id).Scan(&v); err != nil {
		return 0, err
	}
	return int(v.Int64) + 1, nil
}

// SaveWorkflow stores a new version of a custom template. definition must already carry that version;
// ErrDuplicate means someone saved the same version first.
func (s *Store) SaveWorkflow(id string, version int, definition []byte, actor string) (StoredWorkflow, error) {
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		return StoredWorkflow{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	if _, err := tx.Exec(`INSERT INTO workflows (id, version, definition, created_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, version, string(definition), actor, ts(now)); err != nil {
		if isConstraint(err) {
			return StoredWorkflow{}, ErrDuplicate
		}
		return StoredWorkflow{}, err
	}
	// audit_log keys objects by integer; a template is recorded under its version, with its id in the row.
	if err := auditWorkTx(tx, now, actor, WorkflowObject, int64(version), "saved", map[string]any{},
		map[string]any{"workflow": id, "version": version}, ""); err != nil {
		return StoredWorkflow{}, err
	}
	if err := tx.Commit(); err != nil {
		return StoredWorkflow{}, err
	}
	return s.Workflow(id)
}

// ---- evidence for verification --------------------------------------------------------------

// LatestDoneScanAfter is the most recent completed scan of an asset that finished after t.
func (s *Store) LatestDoneScanAfter(assetID int64, t time.Time) (ScanSummary, error) {
	v, err := scanSummary(s.db.QueryRow(`SELECT `+scanCols+` FROM scans WHERE asset_id = ? AND status = 'done' AND finished_at > ?
		ORDER BY finished_at DESC, id DESC LIMIT 1`, assetID, ts(t)))
	if errors.Is(err, sql.ErrNoRows) {
		return ScanSummary{}, ErrNotFound
	}
	return v, err
}

// LatestHostSnapshotAfter is the most recent inventory upload of a host made after t.
func (s *Store) LatestHostSnapshotAfter(assetID int64, t time.Time) (HostSnapshot, error) {
	var h HostSnapshot
	var at string
	err := s.db.QueryRow(`SELECT id, asset_id, at, summary_json FROM host_snapshots WHERE asset_id = ? AND at > ? ORDER BY at DESC, id DESC LIMIT 1`,
		assetID, ts(t)).Scan(&h.ID, &h.AssetID, &at, &h.Summary)
	if errors.Is(err, sql.ErrNoRows) {
		return HostSnapshot{}, ErrNotFound
	}
	if err != nil {
		return HostSnapshot{}, err
	}
	if p := parseTS(sql.NullString{String: at, Valid: true}); p != nil {
		h.At = *p
	}
	return h, nil
}

// LeafCertificate is a certificate a scan saw as an endpoint's leaf.
type LeafCertificate struct {
	Fingerprint string
	NotBefore   *time.Time
	NotAfter    *time.Time
	Subject     string
}

// ScanLeafCertificates lists the certificates a scan saw presented as the leaf (the projection of
// that scan into the estate graph).
func (s *Store) ScanLeafCertificates(scanID int64) ([]LeafCertificate, error) {
	rows, err := s.db.Query(`SELECT DISTINCT e.key, e.attrs_json FROM sources src JOIN observations o ON o.source_id = src.id
		JOIN entities e ON e.id = o.entity_id
		WHERE src.ref_kind = 'scan' AND src.ref_id = ? AND e.kind = 'certificate' AND o.relation = 'presents'
		AND json_extract(o.attrs_json, '$.position') = 'leaf' ORDER BY e.key`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []LeafCertificate
	for rows.Next() {
		var key, attrs string
		if err := rows.Scan(&key, &attrs); err != nil {
			return nil, err
		}
		out = append(out, leafOf(key, attrs))
	}
	return out, rows.Err()
}

func leafOf(key, attrs string) LeafCertificate {
	var a map[string]string
	_ = json.Unmarshal([]byte(attrs), &a)
	l := LeafCertificate{Fingerprint: strings.TrimPrefix(key, "cert:"), Subject: a["subject"]}
	if t, err := time.Parse(time.RFC3339, a["notAfter"]); err == nil {
		l.NotAfter = &t
	}
	if t, err := time.Parse(time.RFC3339, a["notBefore"]); err == nil {
		l.NotBefore = &t
	}
	return l
}

// CertificateLeafEndpoints lists the scanned endpoints that presented a certificate as their leaf in a
// scan made at or before t, with the certificate's own expiry. found is false when the certificate is
// not in the graph at all.
func (s *Store) CertificateLeafEndpoints(fingerprint string, t time.Time) (endpoints []int64, cert LeafCertificate, found bool, err error) {
	key := "cert:" + strings.ToLower(fingerprint)
	var attrs string
	err = s.db.QueryRow(`SELECT attrs_json FROM entities WHERE kind = 'certificate' AND key = ?`, key).Scan(&attrs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, LeafCertificate{}, false, nil
	}
	if err != nil {
		return nil, LeafCertificate{}, false, err
	}
	cert = leafOf(key, attrs)
	rows, err := s.db.Query(`SELECT DISTINCT src.asset_id FROM entities e JOIN observations o ON o.entity_id = e.id
		JOIN sources src ON src.id = o.source_id JOIN assets a ON a.id = src.asset_id
		WHERE e.kind = 'certificate' AND e.key = ? AND src.ref_kind = 'scan' AND o.relation = 'presents'
		AND json_extract(o.attrs_json, '$.position') = 'leaf' AND o.observed_at <= ? ORDER BY src.asset_id`, key, ts(t))
	if err != nil {
		return nil, cert, true, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, cert, true, err
		}
		endpoints = append(endpoints, id)
	}
	return endpoints, cert, true, rows.Err()
}

// CertificateKnown says whether a certificate with this fingerprint is in the graph.
func (s *Store) CertificateKnown(fingerprint string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM entities WHERE kind = 'certificate' AND key = ?`, "cert:"+strings.ToLower(fingerprint)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
