// Package policy is the catalog of standards documents and the dated milestones the product acts on
// (ADR-0022). It is data, embedded from catalog.json and validated when it loads: a document has a
// status, a date, an address and the place it was transcribed from, and nothing that deprecates,
// disallows or requires anything rests on a draft.
//
// The checks that judge a scan against a standard's clauses stay code in internal/eval; this package
// holds only facts about documents.
package policy

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed catalog.json
var catalogJSON []byte

// Document statuses.
const (
	StatusFinal      = "final"
	StatusDraft      = "draft"
	StatusWithdrawn  = "withdrawn"
	StatusSuperseded = "superseded"
)

// Milestone effects.
const (
	EffectDeprecated  = "deprecated"
	EffectDisallowed  = "disallowed"
	EffectRequired    = "required"
	EffectRecommended = "recommended"
)

// Milestone relations to their date: "after" the end of the day, or "by" the end of the day.
const (
	RelationAfter = "after"
	RelationBy    = "by"
)

// Scopes say whom a milestone binds.
const (
	ScopeGeneral       = "general"
	ScopeUSFederal     = "us-federal"
	ScopeUSFederalHVA  = "us-federal-hva"
	maxText            = 600
	maxProvenance      = 300
	maxCatalogEntities = 500
)

// Catalog is the whole catalog.
type Catalog struct {
	Version    string      `json:"version"`
	About      string      `json:"about"`
	Documents  []Document  `json:"documents"`
	Milestones []Milestone `json:"milestones"`
	Profiles   []Profile   `json:"profiles"`
}

// Document is one published (or draft) standard or guidance document.
type Document struct {
	ID         string `json:"id"`
	Publisher  string `json:"publisher"`
	Identifier string `json:"identifier"`
	Title      string `json:"title"`
	Status     string `json:"status"`
	// Published is the publication date as YYYY-MM-DD, YYYY-MM, or empty when not recorded.
	Published  string   `json:"published"`
	URL        string   `json:"url"`
	Families   []string `json:"families"`
	Notes      string   `json:"notes,omitempty"`
	Provenance string   `json:"provenance"`
}

// Milestone is one dated statement of a document.
type Milestone struct {
	ID           string   `json:"id"`
	Document     string   `json:"document"`
	Clause       string   `json:"clause"`
	Text         string   `json:"text"`
	Effect       string   `json:"effect"`
	Relation     string   `json:"relation"`
	Date         string   `json:"date"`
	Families     []string `json:"families"`
	StrengthBits int      `json:"strengthBits,omitempty"`
	Scope        string   `json:"scope"`
	Provenance   string   `json:"provenance"`
}

// Profile is a named set of milestones an organisation follows.
type Profile struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	About      string   `json:"about"`
	Milestones []string `json:"milestones"`
}

// Day is the milestone's date at 00:00 UTC.
func (m Milestone) Day() time.Time {
	t, err := time.Parse(time.DateOnly, m.Date)
	if err != nil {
		return time.Time{} // unreachable for a validated catalog
	}
	return t
}

// Cutoff is the last instant the milestone's date covers: 23:59:59 UTC of that day. "Deprecated after
// 2030" means after the cut-off of 31 December 2030; "required by 2 January 2030" means by its cut-off.
func (m Milestone) Cutoff() time.Time {
	return m.Day().Add(24*time.Hour - time.Second)
}

var (
	loadOnce sync.Once
	loaded   *Catalog
	loadErr  error
)

// Default is the embedded catalog. It panics if the embedded file is invalid, which a test rules out.
func Default() *Catalog {
	loadOnce.Do(func() { loaded, loadErr = Parse(catalogJSON) })
	if loadErr != nil {
		panic("policy: embedded catalog is invalid: " + loadErr.Error())
	}
	return loaded
}

// Raw is the embedded catalog's bytes, served as they are.
func Raw() []byte { return catalogJSON }

// Milestone returns the milestone with this id.
func (c *Catalog) Milestone(id string) (Milestone, bool) {
	for _, m := range c.Milestones {
		if m.ID == id {
			return m, true
		}
	}
	return Milestone{}, false
}

// MustMilestone returns the milestone with this id or panics: for the evaluation's fixed references,
// which a test checks resolve.
func (c *Catalog) MustMilestone(id string) Milestone {
	m, ok := c.Milestone(id)
	if !ok {
		panic("policy: no milestone " + id)
	}
	return m
}

// Document returns the document with this id.
func (c *Catalog) Document(id string) (Document, bool) {
	for _, d := range c.Documents {
		if d.ID == id {
			return d, true
		}
	}
	return Document{}, false
}

// Parse reads and validates a catalog.
func Parse(b []byte) (*Catalog, error) {
	var c Catalog
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

var (
	idRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,79}$`)
	dateRE    = regexp.MustCompile(`^\d{4}-\d{2}(-\d{2})?$`)
	familyRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,23}$`)
	statuses  = map[string]bool{StatusFinal: true, StatusDraft: true, StatusWithdrawn: true, StatusSuperseded: true}
	effects   = map[string]bool{EffectDeprecated: true, EffectDisallowed: true, EffectRequired: true, EffectRecommended: true}
	relations = map[string]bool{RelationAfter: true, RelationBy: true}
	scopes    = map[string]bool{ScopeGeneral: true, ScopeUSFederal: true, ScopeUSFederalHVA: true}
)

// Validate checks every rule ADR-0022 names and returns all the problems it finds.
func (c *Catalog) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if strings.TrimSpace(c.Version) == "" {
		bad("catalog: no version")
	}
	if len(c.Documents)+len(c.Milestones)+len(c.Profiles) > maxCatalogEntities {
		bad("catalog: more than %d entries", maxCatalogEntities)
	}
	text := func(where, field, v string, max int, required bool) {
		if required && strings.TrimSpace(v) == "" {
			bad("%s: %s is empty", where, field)
		}
		if len(v) > max {
			bad("%s: %s is longer than %d characters", where, field, max)
		}
		if strings.ContainsAny(v, "\x00\r\n\t") {
			bad("%s: %s contains a control character", where, field)
		}
	}
	families := func(where string, fs []string) {
		for _, f := range fs {
			if !familyRE.MatchString(f) {
				bad("%s: family %q is not a family name", where, f)
			}
		}
	}

	docs := map[string]Document{}
	for i, d := range c.Documents {
		where := fmt.Sprintf("document %d (%s)", i, d.ID)
		if !idRE.MatchString(d.ID) {
			bad("%s: id is not a lower-case identifier", where)
		}
		if _, dup := docs[d.ID]; dup {
			bad("%s: duplicate id", where)
		}
		docs[d.ID] = d
		if !statuses[d.Status] {
			bad("%s: status %q is not one of final, draft, withdrawn, superseded", where, d.Status)
		}
		if d.Published != "" && !validDate(d.Published) {
			bad("%s: published %q is not YYYY-MM-DD or YYYY-MM", where, d.Published)
		}
		if u, err := url.Parse(d.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			bad("%s: url must be an https address", where)
		}
		text(where, "publisher", d.Publisher, 80, true)
		text(where, "identifier", d.Identifier, 120, true)
		text(where, "title", d.Title, 200, true)
		text(where, "notes", d.Notes, maxText, false)
		text(where, "provenance", d.Provenance, maxProvenance, true)
		families(where, d.Families)
	}

	ms := map[string]bool{}
	for i, m := range c.Milestones {
		where := fmt.Sprintf("milestone %d (%s)", i, m.ID)
		if !idRE.MatchString(m.ID) {
			bad("%s: id is not a lower-case identifier", where)
		}
		if ms[m.ID] {
			bad("%s: duplicate id", where)
		}
		ms[m.ID] = true
		d, ok := docs[m.Document]
		switch {
		case !ok:
			bad("%s: document %q is not in the catalog", where, m.Document)
		case d.Status != StatusFinal && m.Effect != EffectRecommended:
			bad("%s: a %s milestone cannot rest on a %s document (%s)", where, m.Effect, d.Status, d.ID)
		}
		if !effects[m.Effect] {
			bad("%s: effect %q is not one of deprecated, disallowed, required, recommended", where, m.Effect)
		}
		if !relations[m.Relation] {
			bad("%s: relation %q is not after or by", where, m.Relation)
		}
		if _, err := time.Parse(time.DateOnly, m.Date); err != nil {
			bad("%s: date %q is not YYYY-MM-DD", where, m.Date)
		}
		if !scopes[m.Scope] {
			bad("%s: scope %q is not one of general, us-federal, us-federal-hva", where, m.Scope)
		}
		if m.StrengthBits < 0 || m.StrengthBits > 512 {
			bad("%s: strengthBits out of range", where)
		}
		text(where, "clause", m.Clause, 80, false)
		text(where, "text", m.Text, maxText, true)
		text(where, "provenance", m.Provenance, maxProvenance, true)
		families(where, m.Families)
	}

	ps := map[string]bool{}
	for i, p := range c.Profiles {
		where := fmt.Sprintf("profile %d (%s)", i, p.ID)
		if !idRE.MatchString(p.ID) {
			bad("%s: id is not a lower-case identifier", where)
		}
		if ps[p.ID] {
			bad("%s: duplicate id", where)
		}
		ps[p.ID] = true
		text(where, "title", p.Title, 120, true)
		text(where, "about", p.About, maxText, false)
		if len(p.Milestones) == 0 {
			bad("%s: lists no milestones", where)
		}
		for _, id := range p.Milestones {
			if !ms[id] {
				bad("%s: milestone %q is not in the catalog", where, id)
			}
		}
	}
	return errors.Join(errs...)
}

func validDate(s string) bool {
	if !dateRE.MatchString(s) {
		return false
	}
	layout := time.DateOnly
	if len(s) == len("2006-01") {
		layout = "2006-01"
	}
	_, err := time.Parse(layout, s)
	return err == nil
}
