// Package evidence is the platform-neutral record of what a host collector saw,
// and the rules that stop a report claiming more than was seen.
//
// It is the middle of a pipeline (see docs/decisions/ADR-0001):
//
//	sensors (OS-specific)  ->  Batch of Observations + Coverage
//	Graph (normalise)      ->  one node per thing, all its observations kept
//	derive                 ->  cited, rule-made facts, each naming its inputs
//	cbom projection        ->  CycloneDX 1.6
//
// This package imports no operating-system package and no CycloneDX type, so
// nothing platform-specific can leak past a sensor. Its central rule is
// mechanical: no relationship may claim more than the weakest evidence it rests
// on (see Class and CheckGraph).
package evidence

// Stream says who observed a record. A record made by a host collector is host
// evidence even when it is about network activity; a record made by `tls scan`
// is network evidence. They are joined only by a labelled assessment (ADR-0006).
type Stream string

// The streams.
const (
	StreamHost    Stream = "host"
	StreamNetwork Stream = "network"
)

// Origin says whether a record was seen or worked out.
type Origin string

// The origins. A derived record must name the observations it rests on.
const (
	OriginObserved Origin = "observed"
	OriginDerived  Origin = "derived"
)

// Rung is the kind of statement an observation makes.
type Rung string

// The claim rungs. See Class for how they compare.
const (
	RungPresent     Rung = "present"     // an artefact exists here
	RungProvisioned Rung = "provisioned" // the host holds key/certificate material (metadata only)
	RungCapable     Rung = "capable"     // the artefact can perform an algorithm
	RungPolicy      Rung = "policy"      // configuration permits or forbids something
	RungBound       Rung = "bound"       // an application is linked/configured to use something
	RungLoaded      Rung = "loaded"      // a running process has it mapped
	RungExercised   Rung = "exercised"   // an operation was observed (network stream; never host)
)

// CapableKind distinguishes asking the running system from applying cited knowledge.
type CapableKind string

// The capable kinds.
const (
	CapableProbed CapableKind = "probed" // the running system was asked
	CapableMapped CapableKind = "mapped" // cited knowledge applied to a present artefact
)

// Direction is the effect of a policy. Unspecified means defaults apply: it is
// never the same as "none".
type Direction string

// The policy directions.
const (
	DirPermits     Direction = "permits"
	DirForbids     Direction = "forbids"
	DirUnspecified Direction = "unspecified"
)

// BindingKind says how an application is tied to a library or material.
type BindingKind string

// The binding kinds. Every one means "could use", never "uses".
const (
	BindStaticImport    BindingKind = "static-import"
	BindPackageDepends  BindingKind = "package-depends"
	BindServiceConfig   BindingKind = "service-config"
	BindDynamicLoadHint BindingKind = "dynamic-load-hint"
)

// Outcome is what a sensor can say about a thing. Absence is earned, not assumed.
type Outcome string

// The outcomes.
const (
	OutcomeObserved        Outcome = "observed"
	OutcomeConfirmedAbsent Outcome = "confirmed-absent" // only from an authoritative method that completed
	OutcomeUnknown         Outcome = "unknown"          // the sensor could not see
)

// Claim is what an observation asserts. Only the field that goes with Rung is set.
type Claim struct {
	Rung      Rung        `json:"rung"`
	Capable   CapableKind `json:"capable,omitempty"`
	Direction Direction   `json:"direction,omitempty"`
	Binding   BindingKind `json:"binding,omitempty"`
}

// Subject is what an observation is about.
type Subject struct {
	Kind string `json:"kind"`
	// Key is canonical: the same thing seen by two methods has the same Key, so
	// the graph merges them. See the key constructors in keys.go.
	Key  string `json:"key"`
	Name string `json:"name,omitempty"`
	// Attrs is allow-listed per Kind (AllowedAttrs). Nothing free-form.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Relation is an edge from an observation's subject to another subject.
type Relation struct {
	Kind  string `json:"kind"`
	To    string `json:"to"` // Subject.Key
	Claim Claim  `json:"claim"`
}

// UnknownReason explains an OutcomeUnknown.
type UnknownReason struct {
	Code   string `json:"code"` // one of the Unknown* constants
	Detail string `json:"detail,omitempty"`
}

// The unknown reasons.
const (
	UnknownPermission  = "permission"
	UnknownBudget      = "budget"
	UnknownUnsupported = "unsupported"
	UnknownStubbed     = "stubbed-source" // a source that fails silently returned a suspect result
	UnknownError       = "error"
)

// Source says where on the host an observation came from.
type Source struct {
	Kind     string `json:"kind"`     // file, registry, api, database, procfs
	Location string `json:"location"` // host-relative, forward-slash, user names tokenised
}

// KnowledgeRef names the cited knowledge a derived fact applies.
type KnowledgeRef struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Citations []string `json:"citations,omitempty"`
}

// Observation is one fact, or one derived fact. It is immutable once Finish has
// given it an ID.
type Observation struct {
	ID        string          `json:"id"`
	Stream    Stream          `json:"stream"`
	Origin    Origin          `json:"origin"`
	Subject   Subject         `json:"subject"`
	Claim     Claim           `json:"claim"`
	Outcome   Outcome         `json:"outcome"`
	Unknown   *UnknownReason  `json:"unknown,omitempty"`
	Relations []Relation      `json:"relations,omitempty"`
	Method    string          `json:"method"`
	Source    Source          `json:"source"`
	Privilege string          `json:"privilege"`
	BasedOn   []string        `json:"basedOn,omitempty"`
	Knowledge *KnowledgeRef   `json:"knowledge,omitempty"`
	Downgrade *QualityLowered `json:"qualityOverride,omitempty"`
}

// QualityLowered lowers an observation's method quality, with a reason. It can
// only lower: a fact may never claim more reliability than its method has.
type QualityLowered struct {
	To     Quality `json:"to"`
	Reason string  `json:"reason"`
}

// Coverage records what a sensor attempted and what it could not see. It is
// part of the evidence, not a log: silence must never read as safety.
type Coverage struct {
	Sensor string            `json:"sensor"`
	Method string            `json:"method"`
	Scope  string            `json:"scope"`
	Status CoverageStatus    `json:"status"`
	Reason string            `json:"reason,omitempty"`
	Limits map[string]string `json:"limits,omitempty"` // budgets that applied and, if hit, the counts
	Unseen []string          `json:"unseen,omitempty"` // named blind spots for this scope
	// Denied counts locations that could not be read for lack of permission, and
	// is what lets a run say "elevated privileges may reveal more".
	Denied int `json:"denied,omitempty"`
}

// CoverageStatus is how completely a sensor covered its scope.
type CoverageStatus string

// The coverage statuses.
const (
	CoverageComplete CoverageStatus = "complete"
	CoveragePartial  CoverageStatus = "partial"
	CoverageSkipped  CoverageStatus = "skipped"
	CoverageDenied   CoverageStatus = "denied"
	CoverageFailed   CoverageStatus = "failed"
)

// Batch is what one sensor returns. A partial Batch with an error is valid:
// partial beats none.
type Batch struct {
	Observations []Observation
	Coverage     []Coverage
}

// Host identifies the machine the evidence is about.
type Host struct {
	Name string
	// ID is a salted hash of the platform machine id. The raw id is never
	// emitted. Empty when the platform offers none.
	ID        string
	OSFamily  string
	OSVersion string
	Arch      string
	// PrivilegeTier is the highest tier the run used: "user" or "admin".
	PrivilegeTier string
}
