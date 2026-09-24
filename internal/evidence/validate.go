package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Subject kinds.
const (
	KindPackage   = "package"
	KindArtefact  = "artefact"
	KindAlgorithm = "algorithm"
)

// AllowedAttrs is the allow-list of attributes per subject kind (ADR-0005).
// A sensor may not put anything else on a subject: free-form host data is how
// secrets and hostile strings would travel.
var AllowedAttrs = map[string]map[string]bool{
	KindPackage:   set("name", "version", "arch", "distro", "family", "kind"),
	KindArtefact:  set("path", "size", "fileVersion", "productName", "family", "kind", "arch", "peValid"),
	KindAlgorithm: set(),
}

func set(ss ...string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// Limits on host-supplied strings. They are attacker-controlled and are carried
// as data, never interpreted; the limits bound what a hostile host can make a
// report carry.
const (
	maxAttrLen = 1024
	maxNameLen = 512
	maxKeyLen  = 2048
)

var (
	streams    = set(string(StreamHost), string(StreamNetwork))
	origins    = set(string(OriginObserved), string(OriginDerived))
	rungs      = set(string(RungPresent), string(RungProvisioned), string(RungCapable), string(RungPolicy), string(RungBound), string(RungLoaded), string(RungExercised))
	outcomes   = set(string(OutcomeObserved), string(OutcomeConfirmedAbsent), string(OutcomeUnknown))
	privileges = set("user", "admin", "debug")
	unknowns   = set(UnknownPermission, UnknownBudget, UnknownUnsupported, UnknownStubbed, UnknownError)
)

// Finish computes the observation's deterministic ID from its content. Call it
// last: any later change invalidates the ID and Validate says so.
func Finish(o *Observation) {
	o.ID = computeID(*o)
}

func computeID(o Observation) string {
	o.ID = ""
	// encoding/json sorts map keys, so this encoding is canonical.
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return "obs:" + hex.EncodeToString(sum[:12])
}

// Validate checks one observation against the contract. It does not resolve
// BasedOn (the Graph does that).
func Validate(o Observation) error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if o.ID != computeID(o) {
		fail("id %q does not match the content (call Finish last)", o.ID)
	}
	if !streams[string(o.Stream)] {
		fail("unknown stream %q", o.Stream)
	}
	if !origins[string(o.Origin)] {
		fail("unknown origin %q", o.Origin)
	}
	if !privileges[o.Privilege] {
		fail("unknown privilege tier %q", o.Privilege)
	}

	m, ok := LookupMethod(o.Method)
	q, qerr := QualityOf(o)
	switch {
	case !ok:
		fail("unknown method %q", o.Method)
	case qerr != nil:
		errs = append(errs, qerr)
	}

	// Subject.
	if o.Subject.Key == "" || len(o.Subject.Key) > maxKeyLen {
		fail("subject key empty or over %d bytes", maxKeyLen)
	}
	if len(o.Subject.Name) > maxNameLen {
		fail("subject name over %d bytes", maxNameLen)
	}
	allowed, kindKnown := AllowedAttrs[o.Subject.Kind]
	if !kindKnown {
		fail("unknown subject kind %q", o.Subject.Kind)
	}
	for k, v := range o.Subject.Attrs {
		if kindKnown && !allowed[k] {
			fail("attribute %q is not allowed on a %s subject", k, o.Subject.Kind)
		}
		if len(v) > maxAttrLen || !utf8.ValidString(v) {
			fail("attribute %q is over %d bytes or not UTF-8", k, maxAttrLen)
		}
	}

	// Claim.
	if err := validateClaim(o.Claim); err != nil {
		fail("claim: %v", err)
	}
	if o.Stream == StreamHost && o.Claim.Rung == RungExercised {
		fail("a host collector never produces an %q claim: observed use is network evidence (ADR-0006)", RungExercised)
	}
	for i, r := range o.Relations {
		if r.Kind == "" || r.To == "" {
			fail("relation %d needs a kind and a target", i)
		}
		if err := validateClaim(r.Claim); err != nil {
			fail("relation %d claim: %v", i, err)
		}
		if ClassOf(r.Claim) > ClassOf(o.Claim) {
			fail("relation %d claims %s but its observation is only %s", i, ClassOf(r.Claim), ClassOf(o.Claim))
		}
	}

	// Outcome.
	if !outcomes[string(o.Outcome)] {
		fail("unknown outcome %q", o.Outcome)
	}
	switch o.Outcome {
	case OutcomeUnknown:
		if o.Unknown == nil || !unknowns[o.Unknown.Code] {
			fail("an unknown outcome needs a valid reason")
		}
	case OutcomeConfirmedAbsent:
		if ok && q != QualityAuthoritative {
			fail("confirmed-absent needs an authoritative method; %s is %s", m.ID, q)
		}
		fallthrough
	default:
		if o.Unknown != nil {
			fail("only an unknown outcome carries a reason")
		}
	}

	// Origin.
	switch o.Origin {
	case OriginDerived:
		if len(o.BasedOn) == 0 {
			fail("a derived fact must name the observations it rests on")
		}
	case OriginObserved:
		if len(o.BasedOn) != 0 {
			fail("an observed fact cannot have BasedOn")
		}
		if o.Source.Kind == "" || o.Source.Location == "" {
			fail("an observation needs a source")
		}
	}
	if o.Claim.Rung == RungCapable && o.Claim.Capable == CapableMapped && (o.Knowledge == nil || o.Knowledge.ID == "") {
		fail("a mapped capability must cite the knowledge it applies")
	}
	if strings.ContainsAny(o.Source.Location, "\\\x00\r\n") {
		fail("source location must be a normalised, forward-slash path")
	}

	return errors.Join(errs...)
}

func validateClaim(c Claim) error {
	if !rungs[string(c.Rung)] {
		return fmt.Errorf("unknown rung %q", c.Rung)
	}
	if (c.Rung == RungCapable) != (c.Capable != "") {
		return errors.New("capable kind is set exactly when the rung is capable")
	}
	if c.Rung == RungCapable && c.Capable != CapableProbed && c.Capable != CapableMapped {
		return fmt.Errorf("unknown capable kind %q", c.Capable)
	}
	if (c.Rung == RungPolicy) != (c.Direction != "") {
		return errors.New("direction is set exactly when the rung is policy")
	}
	if c.Rung == RungPolicy && c.Direction != DirPermits && c.Direction != DirForbids && c.Direction != DirUnspecified {
		return fmt.Errorf("unknown direction %q", c.Direction)
	}
	if (c.Rung == RungBound) != (c.Binding != "") {
		return errors.New("binding kind is set exactly when the rung is bound")
	}
	return nil
}
