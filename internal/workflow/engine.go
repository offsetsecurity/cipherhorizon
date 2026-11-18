package workflow

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Verification statuses: what the product's own evidence says about a change (ADR-0021 §5).
const (
	Verified      = "verified"       // the evidence shows the change in effect
	NotVerified   = "not-verified"   // the evidence shows it is not
	Waiting       = "waiting"        // there is no evidence yet (no scan since the change, or an incomplete one)
	NotVerifiable = "not-verifiable" // the product cannot observe this subject the way it would need to
)

// Verification is the product's answer, with what it rests on.
type Verification struct {
	Status string    `json:"status"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
	// Since is the baseline: the moment the change was recorded as made.
	Since *time.Time `json:"since,omitempty"`
	// Evidence names the scans or uploads it read, e.g. "scan 42".
	Evidence []string `json:"evidence,omitempty"`
}

// Actor is who asks for a transition.
type Actor struct {
	Name string
	Role string // admin, analyst, viewer
	// Person is true for a signed-in account; false for the anonymous local operator and the
	// automation token, which cannot be told apart from anyone else using them.
	Person bool
}

// State is what the engine needs to know about a piece of work.
type State struct {
	Stage     string
	CreatedBy string
	Approvers []string
	// Unfinished lists the prerequisites that are neither verified, complete nor cancelled.
	Unfinished []int64
}

// Request is a transition the caller asks for, with the fields they gave.
type Request struct {
	Transition string
	Note       string
	Evidence   string
	Until      *time.Time
}

// Refusal is why a transition was not made. Code is stable for clients; Message is for people.
type Refusal struct {
	Code    string
	Message string
}

func (r *Refusal) Error() string { return r.Message }

// Refusal codes.
const (
	RefuseUnknown     = "unknown-transition"
	RefuseStage       = "wrong-stage"
	RefuseRole        = "role"
	RefuseApproval    = "approval"
	RefuseField       = "missing-field"
	RefuseUntil       = "until"
	RefuseBlocked     = "blocked"
	RefuseNotVerified = "not-verified"
)

func refuse(code, format string, a ...any) *Refusal {
	return &Refusal{Code: code, Message: fmt.Sprintf(format, a...)}
}

// MaxException is the longest an accepted risk or a wait may run before someone looks at it again.
const MaxException = 366 * 24 * time.Hour

// doneMarkers are the markers that say the change was made or the work is done: work cannot enter them
// while a prerequisite is unfinished.
var doneMarkers = map[string]bool{MarkExecuted: true, MarkReported: true, MarkVerified: true, MarkComplete: true}

// Finished says whether a stage marker counts as finished for the work that depends on it.
func Finished(marker string) bool {
	return marker == MarkVerified || marker == MarkComplete || marker == MarkCancelled
}

// Baseline says whether entering a stage with this marker resets the verification baseline.
func Baseline(marker string) bool { return marker == MarkExecuted || marker == MarkReported }

// Check decides whether req may be applied to work in state st by act, at now. verify is called only
// when the transition needs verification, and its result is returned so the caller can record it.
// It returns the transition and the stage it enters.
func (t *Template) Check(st State, req Request, act Actor, now time.Time, verify func() Verification) (Transition, Stage, *Verification, error) {
	tr, ok := t.Transition(req.Transition)
	if !ok {
		return Transition{}, Stage{}, nil, refuse(RefuseUnknown, "%q is not a transition of the %s workflow", req.Transition, t.Title)
	}
	to, _ := t.Stage(tr.To)
	if !slices.Contains(tr.From, st.Stage) {
		from, _ := t.Stage(st.Stage)
		return tr, to, nil, refuse(RefuseStage, "%s is not possible from %s", tr.Label, labelOr(from.Label, st.Stage))
	}
	switch {
	case act.Role == "viewer" || act.Role == "":
		return tr, to, nil, refuse(RefuseRole, "your account can view only")
	case tr.Role == RoleAdmin && act.Role != RoleAdmin:
		return tr, to, nil, refuse(RefuseRole, "only an administrator can %s", strings.ToLower(tr.Label))
	}
	for _, f := range tr.Require {
		var missing bool
		switch f {
		case FieldNote:
			missing = strings.TrimSpace(req.Note) == ""
		case FieldEvidence:
			missing = strings.TrimSpace(req.Evidence) == ""
		case FieldUntil:
			missing = req.Until == nil
		}
		if missing {
			return tr, to, nil, refuse(RefuseField, "%s needs %s", tr.Label, fieldWords[f])
		}
	}
	if req.Until != nil && !req.Until.After(now) {
		return tr, to, nil, refuse(RefuseUntil, "the end date must be in the future")
	}
	if req.Until != nil && req.Until.After(now.Add(MaxException)) {
		return tr, to, nil, refuse(RefuseUntil, "an exception ends within a year; it can be renewed when it does")
	}
	if tr.Approval {
		switch {
		case !act.Person:
			return tr, to, nil, refuse(RefuseApproval, "an approval must be given by a signed-in person; with sign-in off, or with the automation token, nobody can be told apart (turn sign-in on, or use a workflow without approvals)")
		case strings.EqualFold(act.Name, st.CreatedBy):
			return tr, to, nil, refuse(RefuseApproval, "the person who requested this work cannot approve it")
		case slices.ContainsFunc(st.Approvers, func(a string) bool { return strings.EqualFold(a, act.Name) }):
			return tr, to, nil, refuse(RefuseApproval, "you have already approved this work; another person must")
		}
	}
	if doneMarkers[to.Marker] && len(st.Unfinished) > 0 {
		return tr, to, nil, refuse(RefuseBlocked, "this work waits for %s first", workList(st.Unfinished))
	}
	if !tr.Verify {
		return tr, to, nil, nil
	}
	v := verify()
	if v.Status != Verified {
		return tr, to, &v, refuse(RefuseNotVerified, "not verified: %s", v.Detail)
	}
	return tr, to, &v, nil
}

var fieldWords = map[string]string{FieldNote: "a note", FieldEvidence: "evidence (a change ticket, a log or a link)", FieldUntil: "an end date"}

func labelOr(label, id string) string {
	if label != "" {
		return label
	}
	return id
}

func workList(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("#%d", id))
	}
	if len(parts) == 1 {
		return "work " + parts[0]
	}
	return "work " + strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}
