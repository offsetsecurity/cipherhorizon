package evidence

import (
	"fmt"
	"sort"
)

// Quality is how reliably a method establishes what it claims. It is declared
// once per method, not guessed per fact. No numeric confidence is used: nothing
// here has been calibrated, and a number would suggest precision we lack
// (ADR-0002).
type Quality string

// The qualities, strongest first.
const (
	QualityAuthoritative Quality = "authoritative" // a complete authoritative source was parsed, or the system was asked
	QualityParsed        Quality = "parsed"        // a file or structure was parsed in a stable format
	QualityHeuristic     Quality = "heuristic"     // a name or pattern match
	QualitySampled       Quality = "sampled"       // a runtime observation that may miss
)

// rank orders the qualities for lowering. Sampled is the weakest.
func (q Quality) rank() int {
	switch q {
	case QualityAuthoritative:
		return 3
	case QualityParsed:
		return 2
	case QualityHeuristic:
		return 1
	}
	return 0
}

// Sufficient reports whether the quality may support a derived capability:
// authoritative or parsed. A name match alone may not.
func (q Quality) Sufficient() bool { return q == QualityAuthoritative || q == QualityParsed }

// Method is a named, versioned way of sensing, declared once.
type Method struct {
	ID      string
	Version string
	// Sensor is the name of the sensor that uses the method; it is what a
	// component's cipherhorizon:collector property reports.
	Sensor string
	// Technique is a value of CycloneDX 1.6's closed evidence-technique list.
	Technique string
	Quality   Quality
	// MinPrivilege is the lowest tier the method works at: "user" or "admin".
	MinPrivilege string
	// SecretProximity is "none", or "adjacent" when the method works near key
	// material and so needs extra review and tests (ADR-0005).
	SecretProximity string
}

// Method IDs.
const (
	MethodDpkgStatus = "debian.dpkg.status@1"
	MethodFSWalkName = "fs.walk.filename@1"
	MethodPEVersion  = "pe.version-info@1"
	MethodKnowledge  = "knowledge.mapping@1"
)

var methods = map[string]Method{
	MethodDpkgStatus: {ID: MethodDpkgStatus, Version: "1", Sensor: "apt", Technique: "manifest-analysis", Quality: QualityAuthoritative, MinPrivilege: "user", SecretProximity: "none"},
	MethodFSWalkName: {ID: MethodFSWalkName, Version: "1", Sensor: "pe-files", Technique: "filename", Quality: QualityHeuristic, MinPrivilege: "user", SecretProximity: "none"},
	MethodPEVersion:  {ID: MethodPEVersion, Version: "1", Sensor: "pe-files", Technique: "binary-analysis", Quality: QualityParsed, MinPrivilege: "user", SecretProximity: "none"},
	MethodKnowledge:  {ID: MethodKnowledge, Version: "1", Sensor: "knowledge", Technique: "other", Quality: QualityAuthoritative, MinPrivilege: "user", SecretProximity: "none"},
}

// LookupMethod returns the declared method.
func LookupMethod(id string) (Method, bool) {
	m, ok := methods[id]
	return m, ok
}

// Methods lists the declared methods, sorted by ID.
func Methods() []Method {
	out := make([]Method, 0, len(methods))
	for _, m := range methods {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// QualityOf is an observation's effective method quality: the method's own,
// unless the observation lowers it.
func QualityOf(o Observation) (Quality, error) {
	m, ok := LookupMethod(o.Method)
	if !ok {
		return "", fmt.Errorf("evidence: unknown method %q", o.Method)
	}
	if o.Downgrade != nil {
		if o.Downgrade.To.rank() > m.Quality.rank() {
			return "", fmt.Errorf("evidence: observation raises quality of %s from %s to %s; it may only lower it", o.Method, m.Quality, o.Downgrade.To)
		}
		return o.Downgrade.To, nil
	}
	return m.Quality, nil
}
