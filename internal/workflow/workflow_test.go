package workflow

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ-WF-1: the eight built-in templates exist and pass validation.
func TestTheBuiltInTemplatesAreValid(t *testing.T) {
	want := []string{"certificate-renewal", "emergency-certificate-replacement", "library-upgrade", "manual",
		"pki-signature-migration", "pq-key-exchange", "tls-configuration-change", "vendor-dependent"}
	got := BuiltIn()
	if len(got) != len(want) {
		t.Fatalf("%d built-in templates, want %d", len(got), len(want))
	}
	for i, tmpl := range got {
		if tmpl.ID != want[i] {
			t.Errorf("built-in %d is %q, want %q", i, tmpl.ID, want[i])
		}
		if err := tmpl.Validate(); err != nil {
			t.Errorf("%s: %v", tmpl.ID, err)
		}
	}
	// A template that verifies names only subjects the product can verify; one that cannot verify
	// anything says so in its purpose rather than pretending.
	for _, id := range []string{"certificate-renewal", "emergency-certificate-replacement", "tls-configuration-change", "pq-key-exchange", "pki-signature-migration"} {
		if tmpl, _ := BuiltInByID(id); !tmpl.Verifies() {
			t.Errorf("%s should require verification before it is marked verified", id)
		}
	}
	for _, id := range []string{"library-upgrade", "vendor-dependent", "manual"} {
		if tmpl, _ := BuiltInByID(id); tmpl.Verifies() {
			t.Errorf("%s names subjects the product cannot verify", id)
		}
	}
}

func mustTemplate(t *testing.T, id string) *Template {
	t.Helper()
	tmpl, ok := BuiltInByID(id)
	if !ok {
		t.Fatalf("no built-in %s", id)
	}
	// A copy, so a test that mutates it does not change the shared built-in.
	b, _ := json.Marshal(tmpl)
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// REQ-WF-3: every rule a template cannot switch off is enforced when it is validated.
func TestValidateRefusesTemplatesThatBendTheRules(t *testing.T) {
	cases := []struct {
		name, want string
		mutate     func(*Template)
	}{
		{"bad id", "id", func(x *Template) { x.ID = "Renew Certs" }},
		{"no subjects", "subjects", func(x *Template) { x.Subjects = nil }},
		{"unknown subject", "not one of", func(x *Template) { x.Subjects = []string{"database"} }},
		{"first stage not requested", "first stage", func(x *Template) { x.Stages[0].Marker = "" }},
		{"unknown marker", "marker", func(x *Template) { x.Stages[1].Marker = "done-ish" }},
		{"terminal not closed", "terminal", func(x *Template) { x.Stages[1].Terminal = true }},
		{"duplicate stage", "duplicate stage", func(x *Template) { x.Stages[2].ID = x.Stages[1].ID }},
		{"label with markup", "angle bracket", func(x *Template) { x.Stages[1].Label = "<b>x</b>" }},
		{"verified without verification", "without requiring verification", func(x *Template) {
			for i := range x.Transitions {
				x.Transitions[i].Verify = false
			}
		}},
		{"approved without approval", "without being an approval", func(x *Template) {
			for i := range x.Transitions {
				x.Transitions[i].Approval = false
			}
		}},
		{"verification on an unverifiable subject", "cannot be verified", func(x *Template) { x.Subjects = append(x.Subjects, SubjectSystem) }},
		{"transition to nowhere", "not a stage", func(x *Template) { x.Transitions[0].To = "nowhere" }},
		{"transition from a terminal stage", "terminal", func(x *Template) { x.Transitions[0].From = []string{"closed"} }},
		{"unknown role", "role", func(x *Template) { x.Transitions[0].Role = "owner" }},
		{"unknown field", "required field", func(x *Template) { x.Transitions[0].Require = []string{"signature"} }},
		{"unreachable stage", "cannot be reached", func(x *Template) {
			x.Stages = append(x.Stages, Stage{ID: "limbo", Label: "Limbo"})
		}},
		{"dead end", "never leads to a terminal", func(x *Template) {
			x.Stages = append(x.Stages, Stage{ID: "limbo", Label: "Limbo"})
			x.Transitions = append(x.Transitions, Transition{ID: "to-limbo", Label: "Limbo", From: []string{"requested"}, To: "limbo"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := mustTemplate(t, "certificate-renewal")
			tc.mutate(x)
			err := x.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// Exception stages need a reason and an end date, and must be leavable.
	x := mustTemplate(t, "tls-configuration-change")
	for i := range x.Transitions {
		if x.Transitions[i].ID == "accept-risk" {
			x.Transitions[i].Require = []string{FieldNote}
		}
	}
	if err := x.Validate(); err == nil || !strings.Contains(err.Error(), "end date") {
		t.Fatalf("an exception without an end date: %v", err)
	}
	x = mustTemplate(t, "tls-configuration-change")
	kept := x.Transitions[:0]
	for _, tr := range x.Transitions {
		if tr.ID != "reopen" {
			kept = append(kept, tr)
		}
	}
	x.Transitions = kept
	if err := x.Validate(); err == nil || !strings.Contains(err.Error(), "never be reopened") {
		t.Fatalf("an exception that cannot be left: %v", err)
	}

	// Parsing is strict: unknown fields and oversized documents are refused.
	if _, err := Parse([]byte(`{"id":"x","version":1,"title":"X","subjects":["system"],"stages":[],"transitions":[],"shortcut":true}`)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if _, err := Parse(make([]byte, MaxBytes+1)); err == nil {
		t.Fatal("an oversized template was accepted")
	}
}

var (
	now      = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	ana      = Actor{Name: "ana", Role: RoleAnalyst, Person: true}
	bo       = Actor{Name: "bo", Role: RoleAnalyst, Person: true}
	admin    = Actor{Name: "root", Role: RoleAdmin, Person: true}
	local    = Actor{Name: "local", Role: RoleAdmin}
	viewer   = Actor{Name: "vic", Role: "viewer", Person: true}
	verified = func() Verification {
		return Verification{Status: Verified, Detail: "scan 7 presents a new certificate"}
	}
	never = func() Verification { panic("verification must not be computed for this transition") }
)

func code(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

// REQ-WF-6, REQ-WF-7, REQ-WF-8: each guard, refusing and allowing.
func TestCheckEnforcesEveryGuard(t *testing.T) {
	cr := mustTemplate(t, "certificate-renewal")
	tls := mustTemplate(t, "tls-configuration-change")
	future := now.Add(30 * 24 * time.Hour)
	past := now.Add(-time.Hour)
	cases := []struct {
		name  string
		tmpl  *Template
		st    State
		req   Request
		act   Actor
		ver   func() Verification
		want  string // refusal code, "" for allowed
		stage string // the stage entered when allowed
	}{
		{"unknown transition", cr, State{Stage: "requested"}, Request{Transition: "teleport"}, ana, never, RefuseUnknown, ""},
		{"wrong stage", cr, State{Stage: "requested"}, Request{Transition: "deploy", Note: "x"}, ana, never, RefuseStage, ""},
		{"viewer", cr, State{Stage: "requested"}, Request{Transition: "plan"}, viewer, never, RefuseRole, ""},
		{"plan", cr, State{Stage: "requested", CreatedBy: "ana"}, Request{Transition: "plan"}, ana, never, "", "planned"},
		{"approval by the requester", cr, State{Stage: "planned", CreatedBy: "ana"}, Request{Transition: "approve"}, ana, never, RefuseApproval, ""},
		{"approval by the requester, other case", cr, State{Stage: "planned", CreatedBy: "ANA"}, Request{Transition: "approve"}, ana, never, RefuseApproval, ""},
		{"approval with sign-in off", cr, State{Stage: "planned", CreatedBy: "ana"}, Request{Transition: "approve"}, local, never, RefuseApproval, ""},
		{"second approval by the same person", cr, State{Stage: "planned", CreatedBy: "ana", Approvers: []string{"bo"}}, Request{Transition: "approve"}, bo, never, RefuseApproval, ""},
		{"approval by another person", cr, State{Stage: "planned", CreatedBy: "ana"}, Request{Transition: "approve"}, bo, never, "", "approved"},
		{"missing evidence", cr, State{Stage: "approved"}, Request{Transition: "issue", Note: "done"}, ana, never, RefuseField, ""},
		{"evidence of blanks", cr, State{Stage: "approved"}, Request{Transition: "issue", Evidence: "   "}, ana, never, RefuseField, ""},
		{"evidence given", cr, State{Stage: "approved"}, Request{Transition: "issue", Evidence: "CHG-1042"}, ana, never, "", "issued"},
		{"blocked by a prerequisite", cr, State{Stage: "issued", Unfinished: []int64{4, 9}}, Request{Transition: "deploy", Note: "rolled"}, ana, never, RefuseBlocked, ""},
		{"a prerequisite does not block planning", cr, State{Stage: "requested", Unfinished: []int64{4}}, Request{Transition: "plan"}, ana, never, "", "planned"},
		{"cancel needs a note", cr, State{Stage: "deployed"}, Request{Transition: "cancel"}, ana, never, RefuseField, ""},
		{"cancel is not blocked", cr, State{Stage: "deployed", Unfinished: []int64{4}}, Request{Transition: "cancel", Note: "not needed"}, ana, never, "", "cancelled"},
		{"verification fails", cr, State{Stage: "deployed"}, Request{Transition: "verify"}, ana,
			func() Verification { return Verification{Status: NotVerified, Detail: "scan 8 still presents it"} }, RefuseNotVerified, ""},
		{"verification waits", cr, State{Stage: "deployed"}, Request{Transition: "verify"}, ana,
			func() Verification { return Verification{Status: Waiting, Detail: "no scan since"} }, RefuseNotVerified, ""},
		{"verification passes", cr, State{Stage: "deployed"}, Request{Transition: "verify"}, ana, verified, "", "verified"},
		{"exception needs an admin", tls, State{Stage: "requested"}, Request{Transition: "accept-risk", Note: "legacy", Until: &future}, ana, never, RefuseRole, ""},
		{"exception needs an end date", tls, State{Stage: "requested"}, Request{Transition: "accept-risk", Note: "legacy"}, admin, never, RefuseField, ""},
		{"exception in the past", tls, State{Stage: "requested"}, Request{Transition: "accept-risk", Note: "legacy", Until: &past}, admin, never, RefuseUntil, ""},
		{"exception", tls, State{Stage: "requested"}, Request{Transition: "accept-risk", Note: "legacy", Until: &future}, admin, never, "", "risk-accepted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, to, v, err := tc.tmpl.Check(tc.st, tc.req, tc.act, now, tc.ver)
			if got := code(err); got != tc.want {
				t.Fatalf("refusal %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == "" && to.ID != tc.stage {
				t.Fatalf("entered %q, want %q", to.ID, tc.stage)
			}
			if tc.want == RefuseNotVerified && (v == nil || v.Status == Verified) {
				t.Fatalf("a refused verification must return what it found: %+v", v)
			}
			if err != nil && strings.TrimSpace(err.Error()) == "" {
				t.Fatal("a refusal must say why")
			}
		})
	}
}

// A customised template keeps the guarantees: renaming the verified stage does not let work into it
// without verification, because validation refuses such a template before it can be used.
func TestACustomTemplateCannotSkipVerification(t *testing.T) {
	x := mustTemplate(t, "certificate-renewal")
	x.ID, x.Title = "fast-renewal", "Fast renewal"
	x.Transitions = append(x.Transitions, Transition{ID: "shortcut", Label: "Mark verified", From: []string{"deployed"}, To: "verified"})
	if err := x.Validate(); err == nil || !strings.Contains(err.Error(), "without requiring verification") {
		t.Fatalf("a shortcut into the verified stage was accepted: %v", err)
	}
}

func TestMarkerHelpers(t *testing.T) {
	for m, want := range map[string]bool{MarkVerified: true, MarkComplete: true, MarkCancelled: true, MarkExecuted: false, MarkException: false, "": false} {
		if Finished(m) != want {
			t.Errorf("Finished(%q) = %v", m, !want)
		}
	}
	for m, want := range map[string]bool{MarkExecuted: true, MarkReported: true, MarkVerified: false, MarkApproved: false} {
		if Baseline(m) != want {
			t.Errorf("Baseline(%q) = %v", m, !want)
		}
	}
	if got := workList([]int64{3, 4, 5}); got != "work #3, #4 and #5" {
		t.Errorf("workList = %q", got)
	}
}
