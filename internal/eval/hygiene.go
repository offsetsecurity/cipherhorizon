package eval

// TLS hygiene is this product's own measure of how well an endpoint is configured.
//
// It is deliberately simple and is derived from nothing but the cited findings on
// the same result: every point taken off is traceable to a finding, and every
// finding carries its sources. The numbers below are this project's own choice;
// they are not a standard and are not taken from any other scanner's rating.
//
// Post-quantum findings (category "pqc") are never counted here. Readiness is a
// separate question, reported separately, so that a well-configured classical
// endpoint is not marked down twice.

// Points taken off the score by one finding of each severity.
var severityPoints = map[Severity]int{Critical: 40, High: 20, Medium: 10, Low: 4, Info: 0}

// The ceilings: a result cannot score above these while such a finding is present.
const (
	ceilingCritical = 29 // any critical finding: at most "Failing"
	ceilingHigh     = 74 // any high finding: at most "Fair"
)

// The bands, best first. A score belongs to the first band whose minimum it reaches. Their words
// are this scale's alone (UX-REVIEW-010 U-1): Strong and Weak belong to suite strength (PRD-010).
var bands = []struct {
	Min  int
	Name string
}{
	{90, "Excellent"}, {75, "Good"}, {55, "Fair"}, {30, "Poor"}, {0, "Failing"},
}

// oldBands are the names the bands had before PRD-011, which evaluations stored then still carry.
var oldBands = map[string]string{"Strong": "Excellent", "Sound": "Good", "Weak": "Poor", "Broken": "Failing"}

// BandName is a band's current name: an evaluation stored before PRD-011 says the old one.
func BandName(band string) string {
	if n, ok := oldBands[band]; ok {
		return n
	}
	return band
}

// BandNotRated is the band of a result that could not be rated.
const BandNotRated = "Not rated"

// BandFor names the band of a score.
func BandFor(score int) string {
	if score < 0 {
		return BandNotRated
	}
	for _, b := range bands {
		if score >= b.Min {
			return b.Name
		}
	}
	return "Failing"
}

// BandRank orders bands from worst (0) to best; Not rated is below Failing. An old name ranks as
// its new one.
func BandRank(band string) int {
	band = BandName(band)
	for i, b := range bands {
		if b.Name == band {
			return len(bands) - i
		}
	}
	return 0
}

// Deduction is one finding's effect on the score.
type Deduction struct {
	Finding  string   `json:"finding"` // rule ID, e.g. CIPHER.RC4
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Points   int      `json:"points"`
}

// Ceiling records a cap that applied because of the worst finding present.
type Ceiling struct {
	Score  int    `json:"score"`
	Reason string `json:"reason"`
}

// Hygiene is the rating of one result.
type Hygiene struct {
	Score       int         `json:"score"` // 0 to 100, or -1 when not rated
	Band        string      `json:"band"`
	Deductions  []Deduction `json:"deductions"`
	Ceiling     *Ceiling    `json:"ceiling"` // nil when no ceiling applied
	NotMeasured []string    `json:"notMeasured"`
	Methodology string      `json:"methodology"`
}

const hygieneMethodology = "TLS hygiene score: start at 100 and take off points for each finding on this result " +
	"(critical 40, high 20, medium 10, low 4, info 0). Post-quantum findings are not counted; readiness is reported separately. " +
	"Each distinct problem counts once. A critical finding limits the score to 29 (Failing) and a high finding to 74 (Fair). " +
	"Bands: Excellent 90 and above, Good 75, Fair 55, Poor 30, Failing below. " +
	"The weights are this project's own choice, not a standard, and are not derived from any other scanner's rating."

func computeHygiene(c *ctx, findings []Finding) Hygiene {
	h := Hygiene{Deductions: []Deduction{}, Methodology: hygieneMethodology}
	h.NotMeasured = []string{
		"Certificate revocation status.",
		"Active exploit probes (Heartbleed, ROBOT, CCS injection, ...): not implemented; only weaknesses inferable from what is enabled are counted.",
	}
	if c.rep.HSTS == nil {
		h.NotMeasured = append(h.NotMeasured,
			"HTTP Strict Transport Security: not checked on this scan (the opt-in --http-checks flag was off).")
	}

	anyProtocol := false
	for _, ok := range c.supported {
		if ok {
			anyProtocol = true
		}
	}
	if !anyProtocol {
		h.Score, h.Band = -1, BandNotRated
		h.NotMeasured = append(h.NotMeasured, "No protocol version was accepted, so the endpoint could not be rated.")
		return h
	}

	scoreFindings(&h, findings)
	return h
}

// scoreFindings applies the arithmetic shared by every protocol's hygiene score: one deduction
// per distinct problem at its worst severity, the ceilings, and the band.
func scoreFindings(h *Hygiene, findings []Finding) {
	// Each distinct problem counts once, at its worst severity: the findings arrive worst first,
	// so the first instance of a rule is the one that counts (two certificates with the same
	// fault are one problem, not two).
	score, worst := 100, Info
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Category == "pqc" || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		if p := severityPoints[f.Severity]; p > 0 {
			score -= p
			h.Deductions = append(h.Deductions, Deduction{Finding: f.ID, Title: f.Title, Severity: f.Severity, Points: p})
		}
		if f.Severity.Rank() < worst.Rank() {
			worst = f.Severity
		}
	}
	switch worst {
	case Critical:
		h.Ceiling = &Ceiling{Score: ceilingCritical, Reason: "a critical finding is present"}
	case High:
		h.Ceiling = &Ceiling{Score: ceilingHigh, Reason: "a high-severity finding is present"}
	}
	if h.Ceiling != nil && score > h.Ceiling.Score {
		score = h.Ceiling.Score
	} else {
		h.Ceiling = nil // the ceiling only matters when it changed the outcome
	}
	if score < 0 {
		score = 0
	}
	h.Score, h.Band = score, BandFor(score)
}
