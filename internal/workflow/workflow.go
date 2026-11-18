// Package workflow runs tracked work through a workflow template that is data (ADR-0021). A template
// lists stages and the transitions between them; the engine checks a transition against the template,
// the caller and the state of the work, and enforces the rules a template cannot switch off: a stage
// marked verified is entered only on the product's own verification, a stage marked approved only by a
// different signed-in person, an exception only with a reason and an end date, and nothing is marked
// done while a prerequisite is unfinished.
//
// The package is pure: no store, no network, no clock of its own.
package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Markers: what a stage means, whatever it is called. Lists and metrics read markers, never stage names.
const (
	MarkRequested = "requested" // the work exists; nothing has been decided or changed
	MarkApproved  = "approved"  // a second person approved the change
	MarkExecuted  = "executed"  // the change was made (the verification baseline)
	MarkReported  = "reported"  // the change was reported successful by whoever made it (also a baseline)
	MarkVerified  = "verified"  // the product's own evidence shows the change in effect
	MarkComplete  = "complete"  // closed as done (verified or not)
	MarkException = "exception" // a risk accepted until a date
	MarkCancelled = "cancelled" // closed as not done
)

// Subject kinds: what a piece of work is about.
const (
	SubjectFinding     = "finding"     // one finding on one endpoint or host
	SubjectCertificate = "certificate" // one certificate, by SHA-256 fingerprint
	SubjectReadiness   = "readiness"   // an endpoint that should reach a readiness level
	SubjectEndpoint    = "endpoint"    // an endpoint, with no measurable target
	SubjectSystem      = "system"      // a system
)

// Roles a transition may require. A viewer never changes anything (the server refuses it before this
// package is asked).
const (
	RoleAnalyst = "analyst"
	RoleAdmin   = "admin"
)

// Fields a transition may require from the caller.
const (
	FieldNote     = "note"     // why, in words
	FieldEvidence = "evidence" // a reference: a change ticket, a log, a link
	FieldUntil    = "until"    // an end date (an exception's)
)

var (
	markers     = map[string]bool{"": true, MarkRequested: true, MarkApproved: true, MarkExecuted: true, MarkReported: true, MarkVerified: true, MarkComplete: true, MarkException: true, MarkCancelled: true}
	subjects    = map[string]bool{SubjectFinding: true, SubjectCertificate: true, SubjectReadiness: true, SubjectEndpoint: true, SubjectSystem: true}
	verifiable  = map[string]bool{SubjectFinding: true, SubjectCertificate: true, SubjectReadiness: true}
	roles       = map[string]bool{"": true, RoleAnalyst: true, RoleAdmin: true}
	fields      = map[string]bool{FieldNote: true, FieldEvidence: true, FieldUntil: true}
	terminalMks = map[string]bool{MarkComplete: true, MarkCancelled: true}
	idRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
)

// Limits on a template's size.
const (
	MaxStages      = 20
	MaxTransitions = 60
	MaxBytes       = 64 << 10
)

// Template is a workflow: its stages (the first is where work starts) and its transitions.
type Template struct {
	ID       string   `json:"id"`
	Version  int      `json:"version"`
	Title    string   `json:"title"`
	Purpose  string   `json:"purpose"`
	Subjects []string `json:"subjects"`
	// Target is the readiness level the workflow is for (3: hybrid key exchange, 4: a post-quantum
	// certificate); work under it cannot aim lower. 0 for workflows with no level.
	Target      int          `json:"target,omitempty"`
	Stages      []Stage      `json:"stages"`
	Transitions []Transition `json:"transitions"`
}

// Stage is one place work can be.
type Stage struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Marker   string `json:"marker,omitempty"`
	Terminal bool   `json:"terminal,omitempty"`
}

// Transition moves work from one of From to To.
type Transition struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	From  []string `json:"from"`
	To    string   `json:"to"`
	// Role is the least role that may make it: analyst (the default) or admin.
	Role string `json:"role,omitempty"`
	// Require lists the fields the caller must give: note, evidence, until.
	Require []string `json:"require,omitempty"`
	// Approval makes it an approval: a signed-in person who did not request the work and has not
	// approved it already.
	Approval bool `json:"approval,omitempty"`
	// Verify allows it only when the product's own verification says verified.
	Verify bool `json:"verify,omitempty"`
}

// Parse reads a template strictly (unknown fields are refused) and validates it.
func Parse(b []byte) (*Template, error) {
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("a template is at most %d bytes", MaxBytes)
	}
	var t Template
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	if dec.More() {
		return nil, errors.New("template: one JSON object only")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}

// Stage returns the stage with this id.
func (t *Template) Stage(id string) (Stage, bool) {
	for _, s := range t.Stages {
		if s.ID == id {
			return s, true
		}
	}
	return Stage{}, false
}

// Transition returns the transition with this id.
func (t *Template) Transition(id string) (Transition, bool) {
	for _, tr := range t.Transitions {
		if tr.ID == id {
			return tr, true
		}
	}
	return Transition{}, false
}

// Initial is the stage new work starts in.
func (t *Template) Initial() Stage { return t.Stages[0] }

// From lists the transitions that leave a stage, in template order.
func (t *Template) From(stage string) []Transition {
	var out []Transition
	for _, tr := range t.Transitions {
		if slices.Contains(tr.From, stage) {
			out = append(out, tr)
		}
	}
	return out
}

// Applies says whether the template may be used for a subject kind.
func (t *Template) Applies(subject string) bool { return slices.Contains(t.Subjects, subject) }

// Verifies says whether any transition of the template needs verification.
func (t *Template) Verifies() bool {
	for _, tr := range t.Transitions {
		if tr.Verify {
			return true
		}
	}
	return false
}

// Validate checks the template against every rule of ADR-0021 and returns all the problems found.
func (t *Template) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	label := func(where, v string, max int) {
		switch {
		case strings.TrimSpace(v) == "":
			bad("%s: label is empty", where)
		case len(v) > max:
			bad("%s: label is longer than %d characters", where, max)
		case strings.ContainsAny(v, "\x00\r\n\t<>"):
			bad("%s: label contains a control character or angle bracket", where)
		}
	}
	if !idRE.MatchString(t.ID) {
		bad("id %q: lower-case letters, digits and hyphens, starting with a letter, at most 40", t.ID)
	}
	if t.Version < 1 {
		bad("version must be 1 or more")
	}
	label("title", t.Title, 80)
	if len(t.Purpose) > 400 || strings.ContainsAny(t.Purpose, "\x00\r\n<>") {
		bad("purpose: at most 400 characters, one line, no angle brackets")
	}
	if len(t.Subjects) == 0 {
		bad("subjects: name at least one of finding, certificate, readiness, endpoint, system")
	}
	for _, s := range t.Subjects {
		if !subjects[s] {
			bad("subject %q is not one of finding, certificate, readiness, endpoint, system", s)
		}
	}
	if t.Target != 0 && (t.Target < 1 || t.Target > 4 || !slices.Contains(t.Subjects, SubjectReadiness)) {
		bad("target is a readiness level from 1 to 4, for a workflow whose subjects include readiness")
	}
	if len(t.Stages) == 0 || len(t.Stages) > MaxStages {
		bad("a template has 1 to %d stages", MaxStages)
		return errors.Join(errs...)
	}
	if len(t.Transitions) > MaxTransitions {
		bad("a template has at most %d transitions", MaxTransitions)
	}

	stages := map[string]Stage{}
	for i, s := range t.Stages {
		where := fmt.Sprintf("stage %d (%s)", i, s.ID)
		if !idRE.MatchString(s.ID) {
			bad("%s: id must be lower-case letters, digits and hyphens", where)
		}
		if _, dup := stages[s.ID]; dup {
			bad("%s: duplicate stage", where)
		}
		stages[s.ID] = s
		label(where, s.Label, 60)
		if !markers[s.Marker] {
			bad("%s: marker %q is not one of requested, approved, executed, reported, verified, complete, exception, cancelled", where, s.Marker)
		}
		if s.Terminal && !terminalMks[s.Marker] {
			bad("%s: a terminal stage is marked complete or cancelled", where)
		}
		if !s.Terminal && terminalMks[s.Marker] {
			bad("%s: a stage marked %s must be terminal", where, s.Marker)
		}
		if i == 0 && s.Marker != MarkRequested {
			bad("%s: the first stage is where work starts and is marked requested", where)
		}
		if i > 0 && s.Marker == MarkRequested {
			bad("%s: only the first stage is marked requested", where)
		}
	}

	ids := map[string]bool{}
	into := map[string][]Transition{}
	for i, tr := range t.Transitions {
		where := fmt.Sprintf("transition %d (%s)", i, tr.ID)
		if !idRE.MatchString(tr.ID) {
			bad("%s: id must be lower-case letters, digits and hyphens", where)
		}
		if ids[tr.ID] {
			bad("%s: duplicate transition", where)
		}
		ids[tr.ID] = true
		label(where, tr.Label, 60)
		to, ok := stages[tr.To]
		if !ok {
			bad("%s: goes to %q, which is not a stage", where, tr.To)
		}
		if len(tr.From) == 0 {
			bad("%s: leaves from no stage", where)
		}
		for _, f := range tr.From {
			s, ok := stages[f]
			switch {
			case !ok:
				bad("%s: leaves from %q, which is not a stage", where, f)
			case s.Terminal:
				bad("%s: leaves from %q, which is terminal", where, f)
			case f == tr.To:
				bad("%s: goes from %q to itself", where, f)
			}
		}
		if !roles[tr.Role] {
			bad("%s: role %q is not analyst or admin", where, tr.Role)
		}
		for _, f := range tr.Require {
			if !fields[f] {
				bad("%s: required field %q is not one of note, evidence, until", where, f)
			}
		}
		if !ok {
			continue
		}
		into[tr.To] = append(into[tr.To], tr)
		// The rules a template cannot switch off.
		if to.Marker == MarkVerified && !tr.Verify {
			bad("%s: enters %q, marked verified, without requiring verification", where, to.ID)
		}
		if tr.Verify && to.Marker != MarkVerified && to.Marker != MarkComplete {
			bad("%s: requires verification but enters %q, which is marked neither verified nor complete", where, to.ID)
		}
		if to.Marker == MarkApproved && !tr.Approval {
			bad("%s: enters %q, marked approved, without being an approval", where, to.ID)
		}
		if to.Marker == MarkException && (!slices.Contains(tr.Require, FieldNote) || !slices.Contains(tr.Require, FieldUntil)) {
			bad("%s: enters an exception without requiring a note and an end date (until)", where)
		}
		if slices.Contains(tr.Require, FieldUntil) && to.Marker != MarkException {
			bad("%s: asks for an end date but does not enter an exception", where)
		}
	}
	if t.Verifies() {
		for _, s := range t.Subjects {
			if !verifiable[s] {
				bad("subject %q cannot be verified by the product, yet the template has a transition that requires verification", s)
			}
		}
	}

	// Every stage is reachable from the first, every stage that is not terminal can reach a terminal
	// stage, and an exception can be left (so expired risk acceptance can be reopened).
	reach := map[string]bool{t.Stages[0].ID: true}
	for changed := true; changed; {
		changed = false
		for _, tr := range t.Transitions {
			if reach[tr.To] {
				continue
			}
			for _, f := range tr.From {
				if reach[f] {
					reach[tr.To], changed = true, true
					break
				}
			}
		}
	}
	ends := map[string]bool{}
	for _, s := range t.Stages {
		if s.Terminal {
			ends[s.ID] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, tr := range t.Transitions {
			if !ends[tr.To] {
				continue
			}
			for _, f := range tr.From {
				if !ends[f] {
					ends[f], changed = true, true
				}
			}
		}
	}
	for _, s := range t.Stages {
		if !reach[s.ID] {
			bad("stage %q cannot be reached from %q", s.ID, t.Stages[0].ID)
		}
		if !ends[s.ID] {
			bad("stage %q never leads to a terminal stage", s.ID)
		}
		if s.Marker == MarkException && len(t.From(s.ID)) == 0 {
			bad("stage %q is an exception that can never be reopened", s.ID)
		}
	}
	if len(ends) == 0 || !slices.ContainsFunc(t.Stages, func(s Stage) bool { return s.Terminal }) {
		bad("a template has at least one terminal stage")
	}
	return errors.Join(errs...)
}
