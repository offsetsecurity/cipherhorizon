package eval

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Standards (PRD-017). A standard is a named, dated, published requirement set that a TLS
// endpoint or an SSH server can be checked against: NIST SP 800-52 Rev. 2, BSI TR-02102-2,
// RFC 9325 (BCP 195), and so on. Each requirement is one clause of the document, transcribed
// from the document itself with its section number, and judged from the data a scan already
// holds. Nothing here probes; a requirement a scan cannot see is "not assessed", never "met".
//
// The verdicts are a view over the same facts the findings rest on, so a standard and a finding
// can never disagree about what the server offered. The scales stay the product's own (readiness,
// hygiene); a standard's verdict is the standard's.

// Requirement statuses.
const (
	ReqMet           = "met"
	ReqNotMet        = "not-met"
	ReqNotAssessed   = "not-assessed"   // the scan holds no evidence either way
	ReqNotApplicable = "not-applicable" // there is nothing to judge (no CBC suites for a CBC rule)
)

// Standard verdicts.
const (
	StdMeets       = "meets"
	StdFails       = "does-not-meet"
	StdNotAssessed = "not-assessed"
)

// Requirement levels. A "must" is the document's shall / MUST / "not recommended" for a thing
// the document forbids; a "should" is a recommendation. A standard is met when no must fails.
const (
	LevelMust   = "must"
	LevelShould = "should"
)

// Standard is one published requirement set.
type Standard struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Publisher string `json:"publisher"`
	Edition   string `json:"edition"`
	Protocol  string `json:"protocol"` // "tls" | "ssh"
	URL       string `json:"url"`
	// Scope says, in one sentence, who the document binds and what it is for.
	Scope string `json:"scope"`
	// Requirements are the clauses this program judges.
	Requirements []Requirement `json:"requirements"`
	// NotAssessed names what the document requires that a network scan cannot see, so a
	// "meets" is read for what it is.
	NotAssessed []string `json:"notAssessed,omitempty"`
}

// Requirement is one clause.
type Requirement struct {
	ID     string `json:"id"`
	Clause string `json:"clause"`
	Text   string `json:"text"`
	Level  string `json:"level"`
	check  func(*tlsCheck) Verdict
	sshChk func(*sshCheck) Verdict
}

// Verdict is one requirement's result on one scan.
type Verdict struct {
	Status string
	Detail string
}

func met(detail string) Verdict         { return Verdict{ReqMet, detail} }
func notMet(detail string) Verdict      { return Verdict{ReqNotMet, detail} }
func notAssessed(detail string) Verdict { return Verdict{ReqNotAssessed, detail} }
func notApplicable(d string) Verdict    { return Verdict{ReqNotApplicable, d} }

// StandardResult is how one scan measures against one standard.
type StandardResult struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Publisher string `json:"publisher"`
	Edition   string `json:"edition"`
	Protocol  string `json:"protocol"`
	URL       string `json:"url"`
	Scope     string `json:"scope"`
	// Verdict is meets, does-not-meet or not-assessed (nothing could be judged).
	Verdict string `json:"verdict"`
	// MustFailures and ShouldFailures count the clauses not met at each level.
	MustFailures   int `json:"mustFailures"`
	ShouldFailures int `json:"shouldFailures"`
	Met            int `json:"met"`
	NotAssessed    int `json:"notAssessed"`
	NotApplicable  int `json:"notApplicable"`

	Requirements []RequirementResult `json:"requirements"`
	Limits       []string            `json:"limits,omitempty"`
}

// RequirementResult is one clause's result.
type RequirementResult struct {
	ID     string `json:"id"`
	Clause string `json:"clause"`
	Text   string `json:"text"`
	Level  string `json:"level"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Standards lists every standard this program carries, TLS first, in the order the pages show them.
func Standards() []*Standard {
	out := append([]*Standard(nil), tlsStandards...)
	return append(out, sshStandards...)
}

// StandardsFor lists the standards for a protocol ("tls" or "ssh").
func StandardsFor(protocol string) []*Standard {
	if protocol == ProtocolSSH {
		return append([]*Standard(nil), sshStandards...)
	}
	return append([]*Standard(nil), tlsStandards...)
}

// StandardByID finds a standard.
func StandardByID(id string) (*Standard, bool) {
	for _, s := range Standards() {
		if s.ID == id {
			return s, true
		}
	}
	return nil, false
}

// StandardsSummary is the compact form stored with a scan for lists and filters: standard id
// to verdict.
func StandardsSummary(ev Evaluation) map[string]string {
	if len(ev.Standards) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, s := range ev.Standards {
		out[s.ID] = s.Verdict
	}
	return out
}

func (s *Standard) result() StandardResult {
	return StandardResult{ID: s.ID, Title: s.Title, Publisher: s.Publisher, Edition: s.Edition, Protocol: s.Protocol,
		URL: s.URL, Scope: s.Scope, Requirements: []RequirementResult{}, Limits: s.NotAssessed}
}

func (r *StandardResult) add(req Requirement, v Verdict) {
	r.Requirements = append(r.Requirements, RequirementResult{ID: req.ID, Clause: req.Clause, Text: req.Text, Level: req.Level, Status: v.Status, Detail: v.Detail})
	switch v.Status {
	case ReqMet:
		r.Met++
	case ReqNotMet:
		if req.Level == LevelShould {
			r.ShouldFailures++
		} else {
			r.MustFailures++
		}
	case ReqNotApplicable:
		r.NotApplicable++
	default:
		r.NotAssessed++
	}
}

func (r *StandardResult) close() {
	switch {
	case r.MustFailures > 0:
		r.Verdict = StdFails
	case r.Met == 0 && r.ShouldFailures == 0:
		r.Verdict = StdNotAssessed
	default:
		r.Verdict = StdMeets
	}
}

// evaluateTLSStandards judges a TLS report against every TLS standard.
func evaluateTLSStandards(c *ctx) []StandardResult {
	tc := &tlsCheck{ctx: c}
	var out []StandardResult
	for _, s := range tlsStandards {
		r := s.result()
		for _, req := range s.Requirements {
			r.add(req, req.check(tc))
		}
		r.close()
		out = append(out, r)
	}
	return out
}

// evaluateSSHStandards judges an SSH report against every SSH standard.
func evaluateSSHStandards(c *sshCtx) []StandardResult {
	sc := &sshCheck{sshCtx: c}
	var out []StandardResult
	for _, s := range sshStandards {
		r := s.result()
		for _, req := range s.Requirements {
			r.add(req, req.sshChk(sc))
		}
		r.close()
		out = append(out, r)
	}
	return out
}

// ---- TLS: the facts a requirement reads ------------------------------------------------------

// tlsCheck is the evaluation context with the views the TLS requirements need.
type tlsCheck struct {
	*ctx
}

// stageRan says whether a stage produced evidence. Reports before stages were recorded are taken
// at their word when they hold data.
func (t *tlsCheck) stageRan(name string) bool {
	if len(t.rep.Stages) == 0 {
		return true
	}
	for _, s := range t.rep.Stages {
		if s.Name == name {
			return s.Outcome == tlsprobe.OutcomeDone
		}
	}
	return false
}

// supportedVersions lists the protocol versions the server answered, highest first.
func (t *tlsCheck) supportedVersions() []string {
	var out []string
	for _, v := range []string{"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"} {
		if t.supported[v] {
			out = append(out, v)
		}
	}
	return out
}

func (t *tlsCheck) anyVersion() bool { return len(t.supportedVersions()) > 0 }

// pre13 says whether any version before TLS 1.3 is supported.
func (t *tlsCheck) pre13() bool {
	for _, v := range t.supportedVersions() {
		if v != "TLSv1.3" {
			return true
		}
	}
	return false
}

// versionsNotAllowed is not-met when a listed version is supported, naming them.
func (t *tlsCheck) versionsNotAllowed(forbidden ...string) Verdict {
	if !t.stageRan(tlsprobe.StageProtocols) {
		return notAssessed("the protocol-version stage did not run")
	}
	var seen []string
	for _, v := range forbidden {
		if t.supported[v] {
			seen = append(seen, v)
		}
	}
	if len(seen) > 0 {
		return notMet(strings.Join(seen, ", ") + " accepted")
	}
	if !t.anyVersion() {
		return notAssessed("no protocol version answered")
	}
	return met("none of " + strings.Join(forbidden, ", ") + " is accepted")
}

// versionRequired is met when v is supported.
func (t *tlsCheck) versionRequired(v string) Verdict {
	if !t.stageRan(tlsprobe.StageProtocols) {
		return notAssessed("the protocol-version stage did not run")
	}
	if t.supported[v] {
		return met(v + " is supported")
	}
	if t.inconclusive(v) {
		return notAssessed("the " + v + " probe was inconclusive")
	}
	return notMet(v + " is not supported")
}

func suiteNames(ss []tlsprobe.SuiteResult) string {
	var out []string
	seen := map[string]bool{}
	for _, s := range ss {
		if seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		if len(out) == 4 {
			out = append(out, fmt.Sprintf("and %d more", len(ss)-4))
			break
		}
		out = append(out, s.Name)
	}
	return strings.Join(out, ", ")
}

// noSuite is not-met when any accepted suite, on any version, matches pred.
func (t *tlsCheck) noSuite(pred func(tlsprobe.SuiteResult) bool, what, pass string) Verdict {
	if !t.stageRan(tlsprobe.StageSuites) {
		return notAssessed("the cipher-suite stage did not run")
	}
	var hit []tlsprobe.SuiteResult
	for _, s := range t.suites {
		if pred(s) {
			hit = append(hit, s)
		}
	}
	if len(hit) > 0 {
		return notMet(fmt.Sprintf("%s: %s", what, suiteNames(hit)))
	}
	if len(t.suites) == 0 {
		return notAssessed("no cipher suite was enumerated")
	}
	return met(pass)
}

// suitesOnly is not-met when a version accepts a suite outside allowed. Versions absent from
// allowed are not judged here (a versions rule covers them).
func (t *tlsCheck) suitesOnly(allowed map[string][]string, source string) Verdict {
	if !t.stageRan(tlsprobe.StageSuites) {
		return notAssessed("the cipher-suite stage did not run")
	}
	var bad []tlsprobe.SuiteResult
	judged := 0
	for v, names := range allowed {
		ok := map[string]bool{}
		for _, n := range names {
			ok[n] = true
		}
		for _, s := range t.byVersion[v] {
			judged++
			if !ok[s.Name] {
				bad = append(bad, s)
			}
		}
	}
	if len(bad) > 0 {
		return notMet(fmt.Sprintf("accepted but not in %s: %s", source, suiteNames(bad)))
	}
	if judged == 0 {
		return notAssessed("no cipher suite was enumerated for a version the list covers")
	}
	return met(fmt.Sprintf("every accepted suite is in %s", source))
}

func groupNameList(gs []tlsprobe.GroupResult) string {
	var out []string
	for _, g := range gs {
		if !contains(out, g.Name) {
			out = append(out, g.Name)
		}
	}
	return strings.Join(out, ", ")
}

// groupsOnly is not-met when a group outside allowed is accepted (any version).
func (t *tlsCheck) groupsOnly(allowed []string, source string) Verdict {
	if !t.stageRan(tlsprobe.StageKeyExchange) {
		return notAssessed("the key-exchange stage did not run")
	}
	ok := map[string]bool{}
	for _, n := range allowed {
		ok[strings.ToLower(n)] = true
	}
	var bad []tlsprobe.GroupResult
	for _, g := range t.rep.Groups {
		if !ok[strings.ToLower(g.Name)] {
			bad = append(bad, g)
		}
	}
	if len(bad) > 0 {
		return notMet("accepted but not in " + source + ": " + groupNameList(bad))
	}
	if len(t.rep.Groups) == 0 {
		return notAssessed("no key-exchange group was enumerated")
	}
	return met("every accepted group is in " + source + ": " + groupNameList(t.rep.Groups))
}

// hasGroup says whether a named group is accepted.
func (t *tlsCheck) hasGroup(names ...string) (string, bool) {
	for _, g := range t.rep.Groups {
		for _, n := range names {
			if strings.EqualFold(g.Name, n) {
				return g.Name, true
			}
		}
	}
	return "", false
}

// dheSuites says whether any finite-field DHE suite is accepted.
func (t *tlsCheck) dheSuites() bool {
	for _, s := range t.suites {
		if s.Kx == "DHE" || s.Kx == "DHE_PSK" {
			return true
		}
	}
	return false
}

// minDH is the DHE prime size rule.
func (t *tlsCheck) minDH(bits int) Verdict {
	if !t.dheSuites() {
		if t.stageRan(tlsprobe.StageSuites) {
			return notApplicable("no finite-field DHE suite is accepted")
		}
		return notAssessed("the cipher-suite stage did not run")
	}
	if t.rep.DH == nil {
		return notAssessed("the DHE parameters were not read")
	}
	if t.rep.DH.PrimeBits < bits {
		return notMet(fmt.Sprintf("the DHE prime is %d bits", t.rep.DH.PrimeBits))
	}
	return met(fmt.Sprintf("the DHE prime is %d bits", t.rep.DH.PrimeBits))
}

// curveBits is the size of a named elliptic-curve group, 0 when it is not an elliptic curve.
func curveBits(name string) int {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "mlkem"), strings.Contains(n, "kyber"), strings.HasPrefix(n, "ffdhe"):
		return 0
	case n == "x25519":
		return 255
	case n == "x448":
		return 448
	case strings.HasPrefix(n, "secp"), strings.HasPrefix(n, "brainpoolp"), strings.HasPrefix(n, "sect"):
		digits := strings.TrimLeft(strings.TrimPrefix(strings.TrimPrefix(n, "secp"), "brainpoolp"), "sect")
		var b int
		for _, ch := range digits {
			if ch < '0' || ch > '9' {
				break
			}
			b = b*10 + int(ch-'0')
		}
		return b
	}
	return 0
}

// minCurve is not-met when an elliptic-curve group under bits is accepted.
func (t *tlsCheck) minCurve(bits int) Verdict {
	if !t.stageRan(tlsprobe.StageKeyExchange) {
		return notAssessed("the key-exchange stage did not run")
	}
	var bad []tlsprobe.GroupResult
	curves := 0
	for _, g := range t.rep.Groups {
		if b := curveBits(g.Name); b > 0 {
			curves++
			if b < bits {
				bad = append(bad, g)
			}
		}
	}
	if len(bad) > 0 {
		return notMet(fmt.Sprintf("curves under %d bits accepted: %s", bits, groupNameList(bad)))
	}
	if curves == 0 {
		return notApplicable("no elliptic-curve group is accepted")
	}
	return met(fmt.Sprintf("every accepted curve is %d bits or more", bits))
}

// feature reads a hello-extension fact; nil means not observed.
func (t *tlsCheck) feature(v *bool, want bool, yes, no, none string) Verdict {
	if !t.stageRan(tlsprobe.StageFeatures) {
		return notAssessed("the features stage did not run")
	}
	if v == nil {
		return notAssessed(none)
	}
	if *v == want {
		return met(yes)
	}
	return notMet(no)
}

// cbcSuites says whether any CBC suite is accepted.
func (t *tlsCheck) cbcSuites() bool {
	for _, s := range t.suites {
		if s.Mode == "CBC" {
			return true
		}
	}
	return false
}

// etmWhenCBC: CBC suites only together with encrypt_then_mac.
func (t *tlsCheck) etmWhenCBC() Verdict {
	if !t.stageRan(tlsprobe.StageSuites) {
		return notAssessed("the cipher-suite stage did not run")
	}
	if !t.cbcSuites() {
		return notApplicable("no CBC suite is accepted")
	}
	f := t.rep.Features.EncryptThenMAC
	switch {
	case !t.stageRan(tlsprobe.StageFeatures) || f == nil:
		return notAssessed("CBC suites are accepted and encrypt_then_mac was not observed")
	case *f:
		return met("CBC suites are accepted and the server negotiates encrypt_then_mac")
	}
	return notMet("CBC suites are accepted without encrypt_then_mac")
}

// serverOrder: the server enforces its own cipher-suite order on every version that has a choice.
func (t *tlsCheck) serverOrder() Verdict {
	judged, bad := 0, []string{}
	for _, v := range t.supportedVersions() {
		if len(t.byVersion[v]) < 2 {
			continue
		}
		switch pref(t.rep, v, "suites") {
		case "server":
			judged++
		case "client", "mixed":
			judged++
			bad = append(bad, v)
		}
	}
	if judged == 0 {
		return notAssessed("no version accepted two suites, so preference could not be observed")
	}
	if len(bad) > 0 {
		return notMet("the client's order decides on " + strings.Join(bad, ", "))
	}
	return met("the server's order decides")
}

// leaves lists every served leaf a named client can get (dual certificates included). A report
// from before chain analysis (tls-report/1) has no analysed chains; its raw certificate results
// are wrapped so the clauses that need only the leaf's fields are still judged, the way the
// certificate rules judge them. Clauses that need the served DER read ch.served == nil as
// "not assessed".
func (t *tlsCheck) leaves() []*chain {
	var out []*chain
	for _, ch := range t.chains {
		if !ch.cr.NoSNI && len(ch.cr.Chain) > 0 {
			out = append(out, ch)
		}
	}
	if len(out) > 0 || !t.legacy {
		return out
	}
	for _, cr := range t.rep.Certificates {
		if cr.NoSNI || len(cr.Chain) == 0 {
			continue
		}
		ch := &chain{cr: cr, view: ChainView{Source: cr.Source, Names: NamesView{Host: t.rep.Target.Host}}}
		if cr.Trusted {
			ch.trustedBy = []string{"the scanning machine's store"}
		}
		if cr.NameMatches && len(cr.Chain[0].DNSNames)+len(cr.Chain[0].IPAddresses) > 0 {
			ch.view.Names.MatchedBy = "a subjectAltName"
		}
		out = append(out, ch)
	}
	return out
}

// legacyChain says a wrapped tls-report/1 chain holds no served DER, staple or SCTs.
func legacyChain(ch *chain) bool { return ch.served == nil }

// certs runs fn over every served leaf; the first not-met wins, else the first met.
func (t *tlsCheck) certs(fn func(ch *chain, leaf tlsprobe.CertInfo) Verdict) Verdict {
	if !t.stageRan(tlsprobe.StageCerts) {
		return notAssessed("the certificate stage did not run")
	}
	ls := t.leaves()
	if len(ls) == 0 {
		return notAssessed("no certificate was read")
	}
	var first *Verdict
	for _, ch := range ls {
		v := fn(ch, ch.cr.Chain[0])
		if v.Status == ReqNotMet {
			return v
		}
		if first == nil {
			first = &v
		}
	}
	return *first
}

// keyWords names a key: "RSA 2048", "ECDSA P-256".
func keyWords(k tlsprobe.KeyInfo) string {
	switch {
	case k.Curve != "":
		return k.Algorithm + " " + k.Curve
	case k.Bits > 0:
		return fmt.Sprintf("%s %d", k.Algorithm, k.Bits)
	}
	return k.Algorithm
}

// curveNamed says whether a certificate curve is one of the named ones, in any spelling.
func curveNamed(curve string, names ...string) bool {
	c := canonCurve(curve)
	for _, n := range names {
		if canonCurve(n) == c {
			return true
		}
	}
	return false
}

func canonCurve(s string) string {
	switch strings.ToLower(strings.ReplaceAll(s, "-", "")) {
	case "p256", "secp256r1", "prime256v1", "nistp256":
		return "p256"
	case "p384", "secp384r1", "nistp384":
		return "p384"
	case "p521", "secp521r1", "nistp521":
		return "p521"
	case "brainpoolp256r1", "brainpoolp256r1tls13":
		return "bp256"
	case "brainpoolp384r1", "brainpoolp384r1tls13":
		return "bp384"
	case "brainpoolp512r1", "brainpoolp512r1tls13":
		return "bp512"
	}
	return strings.ToLower(s)
}

// sigHash classifies a certificate signature algorithm's hash: "sha2", "weak" (SHA-1, MD5, MD2),
// "pq" (ML-DSA, SLH-DSA), "eddsa" or "".
func sigHash(name string) string {
	n := strings.ToLower(strings.ReplaceAll(name, "-", ""))
	switch {
	case strings.Contains(n, "mldsa"), strings.Contains(n, "slhdsa"):
		return "pq"
	case strings.Contains(n, "ed25519"), strings.Contains(n, "ed448"):
		return "eddsa"
	case strings.Contains(n, "sha256"), strings.Contains(n, "sha384"), strings.Contains(n, "sha512"), strings.Contains(n, "sha3"):
		return "sha2"
	case strings.Contains(n, "sha1"), strings.Contains(n, "md5"), strings.Contains(n, "md2"):
		return "weak"
	}
	return ""
}

// certSignedSHA2 is the "signature hash from the SHA-2 family" rule.
func (t *tlsCheck) certSignedSHA2() Verdict {
	return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
		switch sigHash(leaf.SignatureAlg.Name) {
		case "sha2":
			return met("signed with " + leaf.SignatureAlg.Name)
		case "pq":
			return met("signed with a post-quantum algorithm, " + leaf.SignatureAlg.Name)
		case "eddsa":
			return met("signed with " + leaf.SignatureAlg.Name + " (SHA-512 inside)")
		case "weak":
			return notMet("signed with " + leaf.SignatureAlg.Name)
		}
		return notAssessed("signature algorithm " + leaf.SignatureAlg.Name + " not classified")
	})
}

// certKeyAtLeast is the key-size rule: RSA at least rsaBits, elliptic curves at least ecBits.
func (t *tlsCheck) certKeyAtLeast(rsaBits, ecBits int) Verdict {
	return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
		k := leaf.PublicKey
		switch k.Algorithm {
		case "RSA", "DSA":
			if k.Bits < rsaBits {
				return notMet(keyWords(k) + fmt.Sprintf(" (under %d bits)", rsaBits))
			}
		case "ECDSA", "Ed25519", "Ed448":
			b := k.Bits
			if b == 0 {
				b = curveBits(k.Curve)
			}
			if b > 0 && b < ecBits {
				return notMet(keyWords(k) + fmt.Sprintf(" (under %d bits)", ecBits))
			}
		case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
			return met(keyWords(k) + " (post-quantum)")
		default:
			if strings.HasPrefix(k.Algorithm, "ML-DSA") || strings.HasPrefix(k.Algorithm, "SLH-DSA") {
				return met(keyWords(k) + " (post-quantum)")
			}
			return notAssessed(keyWords(k) + " not classified")
		}
		return met(keyWords(k))
	})
}

// certValidityAtMost is the lifetime rule, in days, for certificates issued from a date on.
func (t *tlsCheck) certValidityAtMost(days int, from time.Time) Verdict {
	return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
		if !from.IsZero() && leaf.NotBefore.Before(from) {
			return notApplicable(fmt.Sprintf("issued %s, before the rule applies", leaf.NotBefore.Format("2006-01-02")))
		}
		d := int(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24)
		if d > days {
			return notMet(fmt.Sprintf("valid for %d days", d))
		}
		return met(fmt.Sprintf("valid for %d days", d))
	})
}

// certTrusted is the "trusted certificate" rule: a bundled public store or the operator's anchors
// validate the chain at the evaluation time.
func (t *tlsCheck) certTrusted() Verdict {
	return t.certs(func(ch *chain, leaf tlsprobe.CertInfo) Verdict {
		if ch.expired || t.now.After(leaf.NotAfter) {
			return notMet("the certificate expired on " + leaf.NotAfter.Format("2006-01-02"))
		}
		if t.now.Before(leaf.NotBefore) {
			return notMet("the certificate is not yet valid")
		}
		switch {
		case len(ch.trustedBy) > 0:
			return met("trusted by " + strings.Join(ch.trustedBy, " and "))
		case ch.private:
			return met("trusted by your CA bundle")
		}
		return notMet("no root store or CA bundle trusts the chain")
	})
}

// certEKUServerAuth: the leaf carries extended key usage with serverAuth (or none at all, which
// RFC 5280 reads as any use).
func (t *tlsCheck) certEKUServerAuth() Verdict {
	return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
		if len(leaf.ExtKeyUsage) == 0 {
			return notMet("no extended key usage extension")
		}
		if contains(leaf.ExtKeyUsage, "serverAuth") || contains(leaf.ExtKeyUsage, "any") {
			return met("extended key usage includes serverAuth")
		}
		return notMet("extended key usage lacks serverAuth: " + strings.Join(leaf.ExtKeyUsage, ", "))
	})
}

// certHasSAN: the leaf names the host in a subjectAltName.
func (t *tlsCheck) certHasSAN() Verdict {
	return t.certs(func(ch *chain, leaf tlsprobe.CertInfo) Verdict {
		if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
			return notMet("no subjectAltName")
		}
		if ch.view.Names.MatchedBy != "" {
			return met("subjectAltName names the host (" + ch.view.Names.MatchedBy + ")")
		}
		return notMet("the subjectAltName does not name " + ch.view.Names.Host)
	})
}

// certRevocationSource: the leaf names where its revocation status is published.
func (t *tlsCheck) certRevocationSource(needOCSP bool) Verdict {
	return t.certs(func(_ *chain, leaf tlsprobe.CertInfo) Verdict {
		switch {
		case len(leaf.OCSPServers) > 0:
			return met("an OCSP responder is named (authorityInfoAccess)")
		case needOCSP:
			return notMet("no OCSP responder is named in the certificate")
		case len(leaf.CRLPoints) > 0:
			return met("a CRL distribution point is named")
		}
		return notMet("neither an OCSP responder nor a CRL is named")
	})
}

// chainComplete: the served chain reaches an issuer the stores hold, in order, without extras.
func (t *tlsCheck) chainComplete() Verdict {
	return t.certs(func(ch *chain, _ tlsprobe.CertInfo) Verdict {
		if legacyChain(ch) {
			return notAssessed("the scan predates chain analysis; scan again")
		}
		if ch.view.Served.Missing != nil && ch.view.Served.Missing.Likely == "intermediate" {
			return notMet("an intermediate is missing: " + ch.view.Served.Missing.IssuerDN)
		}
		for _, is := range ch.view.Served.Issues {
			if is.Kind == "order" {
				return notMet("the served chain is out of order")
			}
		}
		return met("the served chain is complete and in order")
	})
}

// ocspStapled: a stapled OCSP response rides on the handshake.
func (t *tlsCheck) ocspStapled() Verdict {
	if !t.stageRan(tlsprobe.StageCerts) {
		return notAssessed("the certificate stage did not run")
	}
	for _, ch := range t.leaves() {
		if o := ch.view.OCSP; o != nil && o.Present {
			return met("a stapled OCSP response was served")
		}
	}
	if f := t.rep.Features.OCSPStapling; f != nil && *f {
		return met("the server accepts status_request")
	}
	if t.rep.Features.OCSPStapling == nil && (len(t.leaves()) == 0 || t.legacy) {
		return notAssessed("no handshake recorded a stapled response")
	}
	return notMet("no stapled OCSP response was served")
}

// ctProof: the certificate carries SCTs (embedded, in the handshake or in the staple).
func (t *tlsCheck) ctProof() Verdict {
	return t.certs(func(ch *chain, leaf tlsprobe.CertInfo) Verdict {
		if legacyChain(ch) && !leaf.EmbeddedSCTs {
			return notAssessed("the scan predates SCT collection; scan again")
		}
		if len(ch.view.SCTs) > 0 || leaf.EmbeddedSCTs {
			return met(fmt.Sprintf("%d signed certificate timestamp(s)", max(len(ch.view.SCTs), 1)))
		}
		return notMet("no signed certificate timestamp")
	})
}

// hstsAtLeast: HTTPS endpoints send Strict-Transport-Security with max-age of at least seconds.
func (t *tlsCheck) hstsAtLeast(seconds int64) Verdict {
	if t.rep.Target.StartTLS != "" {
		return notApplicable("not an HTTPS endpoint")
	}
	if !t.stageRan(tlsprobe.StageHTTP) {
		return notAssessed("the HTTP check did not run")
	}
	h := t.rep.HSTSHeader
	switch {
	case h == nil && t.rep.HSTS != nil && !*t.rep.HSTS, h == nil && t.rep.HSTS == nil:
		return notMet("no Strict-Transport-Security header")
	case h == nil:
		return notAssessed("the header was seen but not parsed by this scan version")
	case h.MaxAge == nil:
		return notMet("the header has no max-age")
	case *h.MaxAge < seconds:
		return notMet(fmt.Sprintf("max-age is %d seconds", *h.MaxAge))
	}
	return met(fmt.Sprintf("max-age is %d seconds", *h.MaxAge))
}

// hybridPQ: a standardised post-quantum hybrid group is accepted.
func (t *tlsCheck) hybridPQ(names ...string) Verdict {
	if !t.stageRan(tlsprobe.StageKeyExchange) {
		return notAssessed("the key-exchange stage did not run")
	}
	for _, g := range t.rep.Groups {
		if !g.PQ || g.Obsolete {
			continue
		}
		if len(names) == 0 {
			return met(g.Name + " is accepted")
		}
		for _, n := range names {
			if strings.EqualFold(g.Name, n) {
				return met(g.Name + " is accepted")
			}
		}
	}
	if len(names) > 0 {
		return notMet("none of " + strings.Join(names, ", ") + " is accepted")
	}
	return notMet("no post-quantum group is accepted")
}

// schemesAccepted lists the TLS 1.3 signature schemes the signature stage proved accepted.
func (t *tlsCheck) schemesAccepted() ([]string, bool) {
	s := t.rep.Signatures
	if s == nil || !s.Conclusive() {
		return nil, false
	}
	var out []string
	for _, sc := range s.Accepted() {
		out = append(out, sc.Name)
	}
	sort.Strings(out)
	return out, true
}

// ---- SSH: the facts a requirement reads ------------------------------------------------------

// sshCheck is the SSH evaluation context with the views the SSH requirements need.
type sshCheck struct {
	*sshCtx
}

func (s *sshCheck) listed() bool { return s.rep.Algorithms != nil }

// onlyFrom is not-met when a name of kind is offered that is not in allowed.
func (s *sshCheck) onlyFrom(kind string, allowed []string, source string) Verdict {
	if !s.listed() {
		return notAssessed("the server's algorithm lists were not read")
	}
	ok := map[string]bool{}
	for _, n := range allowed {
		ok[n] = true
	}
	var bad []string
	offered := s.offeredOf(kind)
	for _, n := range offered {
		if !ok[n] {
			bad = append(bad, n)
		}
	}
	if len(bad) > 0 {
		return notMet("offered but not in " + source + ": " + strings.Join(bad, ", "))
	}
	if len(offered) == 0 {
		return notApplicable("nothing of this kind is offered")
	}
	return met("every " + kind + " offered is in " + source)
}

// firstIs is met when the server's most preferred name of kind is one of names.
func (s *sshCheck) firstIs(kind string, names []string) Verdict {
	if !s.listed() {
		return notAssessed("the server's algorithm lists were not read")
	}
	offered := s.offeredOf(kind)
	if len(offered) == 0 {
		return notApplicable("nothing of this kind is offered")
	}
	if contains(names, offered[0]) {
		return met(offered[0] + " is listed first")
	}
	return notMet(offered[0] + " is listed first")
}

// rsaKeysAtLeast: every RSA host key fetched is at least bits.
func (s *sshCheck) rsaKeysAtLeast(bits int) Verdict {
	rsa := 0
	for _, k := range s.rep.HostKeys {
		if k.Algorithm != "RSA" {
			continue
		}
		rsa++
		if k.Bits < bits {
			return notMet(fmt.Sprintf("an RSA host key of %d bits", k.Bits))
		}
	}
	if rsa == 0 {
		for _, n := range s.alg.HostKey {
			if strings.HasPrefix(n, "rsa-sha2") || strings.HasPrefix(n, "ssh-rsa") {
				return notAssessed("RSA host keys are offered but none was fetched")
			}
		}
		return notApplicable("no RSA host key")
	}
	return met(fmt.Sprintf("every RSA host key is %d bits or more", bits))
}
