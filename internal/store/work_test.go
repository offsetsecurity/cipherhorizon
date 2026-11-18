package store_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

func newWork(t *testing.T, s *store.Store, title string) store.WorkItem {
	t.Helper()
	w, err := s.CreateWork(store.WorkItem{Title: title, WorkflowID: "manual", WorkflowVersion: 1, WorkflowJSON: json.RawMessage(`{}`),
		Stage: "open", Marker: "requested", SubjectKind: "system", CreatedBy: "ana"})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// REQ-WF-5, REQ-WF-10, REQ-WF-11: work is stored, every change is in the audit log, and a transition
// made on a stage the work has already left is refused.
func TestWorkIsStoredAuditedAndMovedOnlyFromItsCurrentStage(t *testing.T) {
	s, c := open(t)
	w := newWork(t, s, "Replace the payroll certificate")
	if w.ID == 0 || w.Stage != "open" || w.CreatedBy != "ana" || len(w.Approvers) != 0 {
		t.Fatalf("created: %+v", w)
	}

	owner, due := "bo", c.t.Add(14*24*time.Hour)
	c.advance(time.Minute)
	if _, err := s.UpdateWork(w.ID, store.WorkPatch{Owner: &owner, DueAt: &due}, "ana", "bo runs payroll"); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	moved, err := s.MoveWork(w.ID, store.WorkMove{Transition: "start", FromStage: "open", ToStage: "in-progress", Baseline: true,
		Approver: "bo", Note: "started"}, "bo")
	if err != nil {
		t.Fatal(err)
	}
	if moved.Stage != "in-progress" || moved.ExecutedAt == nil || !moved.ExecutedAt.Equal(c.t) || len(moved.Approvers) != 1 || moved.Owner != "bo" {
		t.Fatalf("after the move: %+v", moved)
	}

	// The second of two people acting on the same stage is refused, and nothing changes.
	_, err = s.MoveWork(w.ID, store.WorkMove{Transition: "finish", FromStage: "open", ToStage: "done", Closed: true}, "ana")
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a move from a stage the work has left: %v, want ErrConflict", err)
	}
	if got, _ := s.GetWork(w.ID); got.Stage != "in-progress" || got.ClosedAt != nil {
		t.Fatalf("a refused move changed the work: %+v", got)
	}

	log, err := s.Audit(store.WorkObject, w.ID, 50)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range log {
		actions = append(actions, e.Action)
	}
	if len(log) != 3 || log[0].Action != "start" || log[1].Action != "edited" || log[2].Action != "created" {
		t.Fatalf("audit trail: %v", actions)
	}
	if log[0].Reason != "started" || log[1].Reason != "bo runs payroll" || log[0].Actor != "bo" {
		t.Fatalf("audit rows lost who or why: %+v", log[:2])
	}

	open, err := s.ListWork(store.WorkFilter{Marker: "open"})
	if err != nil || len(open) != 1 {
		t.Fatalf("open work: %d %v", len(open), err)
	}
	if mine, _ := s.ListWork(store.WorkFilter{Owner: "bo"}); len(mine) != 1 {
		t.Fatalf("owner filter: %d", len(mine))
	}
	if none, _ := s.ListWork(store.WorkFilter{Owner: "nobody"}); len(none) != 0 {
		t.Fatalf("owner filter matched %d", len(none))
	}
}

// REQ-WF-9: dependencies never form a cycle, and each change is audited.
func TestWorkDependenciesRefuseCycles(t *testing.T) {
	s, _ := open(t)
	a, b, c := newWork(t, s, "a"), newWork(t, s, "b"), newWork(t, s, "c")
	if err := s.AddWorkDep(a.ID, b.ID, "ana"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddWorkDep(b.ID, c.ID, "ana"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]int64{{c.ID, a.ID}, {c.ID, b.ID}, {a.ID, a.ID}} {
		if err := s.AddWorkDep(pair[0], pair[1], "ana"); !errors.Is(err, store.ErrCycle) {
			t.Errorf("%d waits for %d: %v, want ErrCycle", pair[0], pair[1], err)
		}
	}
	if err := s.AddWorkDep(a.ID, 9999, "ana"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("a dependency on missing work: %v", err)
	}
	if err := s.AddWorkDep(a.ID, b.ID, "ana"); err != nil {
		t.Errorf("adding an existing dependency again: %v", err)
	}
	deps, _ := s.WorkDeps(a.ID)
	if len(deps) != 1 || deps[0].ID != b.ID || deps[0].Marker != "requested" {
		t.Fatalf("deps of a: %+v", deps)
	}
	if err := s.RemoveWorkDep(a.ID, b.ID, "ana"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveWorkDep(a.ID, b.ID, "ana"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("removing twice: %v", err)
	}
	log, _ := s.Audit(store.WorkObject, a.ID, 50)
	if len(log) != 3 || log[0].Action != "dependency removed" || log[1].Action != "dependency added" {
		t.Fatalf("dependency changes are not all audited: %+v", log)
	}
}

// REQ-WF-4: custom templates are versioned; a version is written once.
func TestCustomWorkflowsAreVersioned(t *testing.T) {
	s, _ := open(t)
	if v, _ := s.NextWorkflowVersion("ops"); v != 1 {
		t.Fatalf("first version %d", v)
	}
	if _, err := s.SaveWorkflow("ops", 1, []byte(`{"id":"ops","version":1}`), "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveWorkflow("ops", 1, []byte(`{"id":"ops","version":1}`), "root"); !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("saving the same version twice: %v", err)
	}
	if v, _ := s.NextWorkflowVersion("ops"); v != 2 {
		t.Fatalf("next version %d", v)
	}
	if _, err := s.SaveWorkflow("ops", 2, []byte(`{"id":"ops","version":2}`), "root"); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Workflows()
	if len(all) != 1 || all[0].Version != 2 {
		t.Fatalf("latest versions: %+v", all)
	}
	if _, err := s.Workflow("none"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing workflow: %v", err)
	}
}

// The subject of a piece of work may be deleted later; the work and its history stay.
func TestDeletingTheSubjectKeepsTheWork(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "pay.example", 443)
	w, err := s.CreateWork(store.WorkItem{Title: "x", WorkflowID: "manual", WorkflowVersion: 1, WorkflowJSON: json.RawMessage(`{}`),
		Stage: "open", Marker: "requested", SubjectKind: "endpoint", AssetID: a.ID, CreatedBy: "ana"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWork(w.ID)
	if err != nil || got.AssetID != 0 {
		t.Fatalf("after deleting the endpoint: %+v %v", got, err)
	}
}
