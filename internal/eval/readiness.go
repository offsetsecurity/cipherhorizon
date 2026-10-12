package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Readiness levels. This scale is the product's own (PRD-001 section 7); the
// facts each level rests on are cited, the scale is not a standard.
const (
	LevelUndetermined = -1 // the scan could not establish TLS 1.3 support
	LevelNotReady     = 0  // no TLS 1.3, so no post-quantum key exchange is possible
	LevelExposed      = 1  // TLS 1.3 but only classical key exchange
	LevelHybridAvail  = 2  // a standardised hybrid group is supported, not negotiated by a current client
	LevelHybridNeg    = 3  // a current client negotiates a standardised hybrid group
	LevelPQAuth       = 4  // level 3 plus a post-quantum certificate
)

var levelLabels = map[int]string{
	LevelUndetermined: "Undetermined",
	LevelNotReady:     "Not ready",
	LevelExposed:      "Exposed",
	LevelHybridAvail:  "Hybrid available",
	LevelHybridNeg:    "Hybrid negotiated",
	LevelPQAuth:       "PQ-authenticated",
}

// LevelLabel names a readiness level.
func LevelLabel(l int) string { return levelLabels[l] }

// Dimension is one facet of readiness.
type Dimension struct {
	Status    string     `json:"status"`
	Detail    string     `json:"detail"`
	Evidence  Evidence   `json:"evidence"`
	Citations []Citation `json:"citations"`
}

// Readiness is the post-quantum readiness of an endpoint.
type Readiness struct {
	Level   int    `json:"level"`
	Label   string `json:"label"`
	Summary string `json:"summary"`
	// HNDLExposed: traffic recorded today with a current client would be readable by a
	// future quantum computer, because the key exchange negotiated is classical.
	HNDLExposed bool `json:"hndlExposed"`

	KeyEstablishment Dimension `json:"keyEstablishment"`
	Authentication   Dimension `json:"authentication"`
	Symmetric        Dimension `json:"symmetric"`

	// PQGroups are the standardised post-quantum groups the server accepts;
	// ObsoletePQGroups are pre-standard draft groups, which do not count.
	PQGroups         []string `json:"pqGroups"`
	ObsoletePQGroups []string `json:"obsoletePqGroups"`

	NextSteps []string   `json:"nextSteps"`
	Citations []Citation `json:"citations"`
}

func assessReadiness(c *ctx) Readiness {
	rep := c.rep
	tls13 := c.supported["TLSv1.3"]

	var pq, obsolete, classical []tlsprobe.GroupResult
	for _, g := range rep.Groups {
		if g.Version != "TLSv1.3" {
			continue
		}
		switch {
		case g.PQ && g.Obsolete:
			obsolete = append(obsolete, g)
		case g.PQ:
			pq = append(pq, g)
		default:
			classical = append(classical, g)
		}
	}

	n := rep.Negotiated
	negotiated := n != nil && n.Version != ""
	negotiatedPQ := negotiated && n.PQ && n.Version == "TLSv1.3"

	r := Readiness{PQGroups: groupNames(pq), ObsoletePQGroups: groupNames(obsolete)}
	keyEv := Observed

	switch {
	case !tls13 && c.inconclusive("TLSv1.3"):
		r.Level = LevelUndetermined
	case !tls13:
		r.Level = LevelNotReady
	case negotiatedPQ:
		r.Level = LevelHybridNeg
	case len(pq) == 0:
		r.Level = LevelExposed
	case negotiated:
		r.Level = LevelHybridAvail
	default:
		// No handshake data: fall back to the server's own preference, and say so.
		keyEv = Inferred
		if pref(rep, "TLSv1.3", "groups") == "server" && len(rep.Groups) > 0 && rep.Groups[0].Version == "TLSv1.3" && rep.Groups[0].PQ && !rep.Groups[0].Obsolete {
			r.Level = LevelHybridNeg
		} else {
			r.Level = LevelHybridAvail
		}
	}
	if r.Level == LevelHybridNeg && (hasPQCertificate(rep) || len(pqSchemes(rep)) > 0) {
		r.Level = LevelPQAuth
	}
	r.Label = LevelLabel(r.Level)
	r.HNDLExposed = r.Level >= LevelNotReady && r.Level < LevelHybridNeg // undetermined is not "exposed"

	// Key establishment.
	ke := Dimension{Evidence: keyEv, Citations: []Citation{citRFC10024, citIANAGroups, citHNDL}}
	switch r.Level {
	case LevelUndetermined:
		ke.Status, ke.Evidence = "undetermined", NotMeasured
		ke.Detail = "TLS 1.3 support could not be established (the probe was inconclusive); re-scan."
	case LevelNotReady:
		ke.Status = "unavailable"
		ke.Detail = "TLS 1.3 is not supported. Post-quantum key exchange exists in TLS only as TLS 1.3 groups (RFC 10024)."
	case LevelExposed:
		ke.Status = "classical"
		ke.Detail = "TLS 1.3 groups accepted: " + orNone(groupNames(classical)) + ". None is post-quantum."
		if len(obsolete) > 0 {
			ke.Detail += " Obsolete pre-standard draft groups (" + strings.Join(groupNames(obsolete), ", ") + ") are accepted but do not count."
		}
	case LevelHybridAvail:
		ke.Status = "hybrid-available"
		ke.Detail = "Supports " + strings.Join(groupNames(pq), ", ") + "."
		if negotiated {
			ke.Detail += " A current client (Go crypto/tls, which offers the hybrid first) negotiated " + n.Group + " instead."
		} else {
			ke.Detail += " Whether a current client negotiates it could not be tested."
		}
	default:
		ke.Status = "hybrid-negotiated"
		if negotiatedPQ {
			ke.Detail = "A current client negotiated " + n.Group + " by default."
		} else {
			ke.Detail = "The server's most-preferred group is " + rep.Groups[0].Name + " (inferred from its preference order)."
		}
	}
	r.KeyEstablishment = ke

	r.Authentication = authDimension(rep)
	r.Symmetric = symmetricDimension(c)
	r.Summary, r.NextSteps = narrative(r.Level)
	r.Citations = []Citation{citHNDL, citRFC10024, citFIPS203, citIR8547, citOpenSSL35, citGoMLKEM}
	return r
}

func narrative(level int) (string, []string) {
	switch level {
	case LevelUndetermined:
		return "The scan could not tell whether TLS 1.3 is supported, so readiness is unknown.",
			[]string{"Re-run the scan; check the endpoint is reachable and the scan was not cut short."}
	case LevelNotReady:
		return "No TLS 1.3, so no post-quantum key exchange is possible. Recorded traffic is exposed to harvest-now-decrypt-later.",
			[]string{
				"Enable TLS 1.3: post-quantum key exchange in TLS exists only in TLS 1.3 (RFC 10024).",
				"Then enable the standardised hybrid group X25519MLKEM768.",
			}
	case LevelExposed:
		return "TLS 1.3, but only classical key exchange. Traffic recorded today could be decrypted by a future quantum computer.",
			[]string{
				"Enable the standardised hybrid group X25519MLKEM768 (RFC 10024). Library support: OpenSSL 3.5 or later, Go 1.24 or later (crypto/tls).",
				"Put it ahead of the classical groups in the server's group preference.",
			}
	case LevelHybridAvail:
		return "A standardised hybrid group is supported, but a current client does not negotiate it.",
			[]string{"Move the hybrid group to the top of the server's group preference so clients that offer it get it."}
	case LevelHybridNeg:
		return "A current client negotiates a standardised hybrid key exchange: recorded traffic is protected against harvest-now-decrypt-later.",
			[]string{"Keep the hybrid group enabled and preferred.", "Track post-quantum certificates (ML-DSA, FIPS 204) as CAs and clients support them."}
	default:
		return "Hybrid key exchange and a post-quantum certificate.",
			[]string{"Maintain; retain classical fallback only while clients require it."}
	}
}

func authDimension(rep *tlsprobe.Report) Dimension {
	d := Dimension{Citations: []Citation{citIR8547, citFIPS204}}
	if len(rep.Certificates) == 0 {
		d.Status, d.Evidence = "unknown", NotMeasured
		d.Detail = "No certificate was retrieved, so authentication algorithms are unknown."
		return d
	}
	seen := map[string]bool{}
	var algs []string
	pq := false
	for _, cr := range rep.Certificates {
		leaf, ok := leafOf(cr)
		if !ok {
			continue
		}
		k := leaf.PublicKey
		label := k.Algorithm
		if k.Bits > 0 {
			label += fmt.Sprintf(" %d-bit", k.Bits)
		}
		if k.Curve != "" {
			label += " " + k.Curve
		}
		if !seen[label] {
			seen[label] = true
			algs = append(algs, label)
		}
		if strings.HasPrefix(k.Algorithm, "ML-DSA") || strings.HasPrefix(k.Algorithm, "SLH-DSA") {
			pq = true
		}
	}
	sort.Strings(algs)
	d.Evidence = Observed
	if pq {
		d.Status = "post-quantum"
		d.Detail = "Certificate key algorithm(s): " + strings.Join(algs, ", ") + "."
		return d
	}
	// The certificate a default client got is classical, but the signature stage may have shown
	// the server also holds a post-quantum key (PRD-008 REQ-PQS-5).
	if names := pqSchemes(rep); len(names) > 0 {
		d.Status = "post-quantum"
		d.Detail = "The server accepted " + strings.Join(names, ", ") + " when it was the only signature scheme offered, so it holds a post-quantum key for it. " +
			"The certificate a default client received uses " + strings.Join(algs, ", ") + "."
		return d
	}
	d.Status = "classical"
	d.Detail = "Certificate key algorithm(s): " + strings.Join(algs, ", ") +
		". All are quantum-vulnerable signatures; this matters for future forgery, not for recorded traffic."
	return d
}

func symmetricDimension(c *ctx) Dimension {
	d := Dimension{Evidence: Observed, Citations: []Citation{citNISTCategories}}
	if len(c.suites) == 0 {
		d.Status, d.Evidence = "unknown", NotMeasured
		d.Detail = "No cipher suites were enumerated."
		return d
	}
	minBits, none := 0, false
	for _, s := range c.suites {
		if s.Cipher == "NULL" {
			none = true
			continue
		}
		if minBits == 0 || s.KeyBits < minBits {
			minBits = s.KeyBits
		}
	}
	switch {
	case none:
		d.Status = "inadequate"
		d.Detail = "The server accepts suites with no encryption at all."
	case minBits < 128:
		d.Status = "inadequate"
		d.Detail = fmt.Sprintf("The weakest accepted cipher has a %d-bit key; NIST's post-quantum categories start at AES-128.", minBits)
	default:
		d.Status = "adequate"
		d.Detail = fmt.Sprintf("Every accepted cipher has a key of at least %d bits (AES-128 is NIST category 1).", minBits)
	}
	return d
}

func pqcFindings(r Readiness) []Finding {
	var out []Finding
	add := func(id, title string, sev Severity, ev Evidence, detail, remed string, cites ...Citation) {
		out = append(out, Finding{ID: id, Title: title, Severity: sev, Category: "pqc", Detail: detail,
			Evidence: ev, Citations: cites, Remediation: remed})
	}
	switch r.Level {
	case LevelNotReady:
		add("PQC.NO-PQ-POSSIBLE", "No post-quantum key exchange is possible (no TLS 1.3)", Medium, Observed,
			r.KeyEstablishment.Detail, r.NextSteps[0], citRFC10024, citHNDL)
	case LevelExposed:
		add("PQC.HNDL-EXPOSED", "Traffic is exposed to harvest-now-decrypt-later", Medium, r.KeyEstablishment.Evidence,
			r.KeyEstablishment.Detail, r.NextSteps[0], citHNDL, citRFC10024, citFIPS203, citOpenSSL35, citGoMLKEM)
	case LevelHybridAvail:
		add("PQC.HYBRID-NOT-NEGOTIATED", "A hybrid group is supported but not negotiated by default", Low, r.KeyEstablishment.Evidence,
			r.KeyEstablishment.Detail, r.NextSteps[0], citRFC10024, citIANAGroups)
	}
	if len(r.ObsoletePQGroups) > 0 {
		add("PQC.OBSOLETE-DRAFT-GROUP", "Obsolete pre-standard post-quantum groups are accepted", Low, Registry,
			"Accepted: "+strings.Join(r.ObsoletePQGroups, ", ")+". IANA marks these OBSOLETE; RFC 10024 supersedes them.",
			"Remove the draft groups and enable the standardised X25519MLKEM768.", citIANAGroups, citRFC10024)
	}
	if r.Authentication.Status == "classical" {
		add("PQC.CLASSICAL-AUTH", "Certificates use classical (quantum-vulnerable) signatures", Info, Observed,
			r.Authentication.Detail, "No action needed yet: post-quantum certificates are not broadly available. Track ML-DSA (FIPS 204) support in your CA and clients.",
			citIR8547, citFIPS204)
	}
	if r.Symmetric.Status == "inadequate" {
		add("PQC.SYMMETRIC-INADEQUATE", "Symmetric ciphers below the post-quantum baseline are accepted", Medium, Observed,
			r.Symmetric.Detail, "Remove ciphers with keys under 128 bits.", citNISTCategories)
	}
	return out
}

func groupNames(gs []tlsprobe.GroupResult) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

func pref(rep *tlsprobe.Report, version, subject string) string {
	for _, p := range rep.Preference {
		if p.Version == version && p.Subject == subject {
			return p.Order
		}
	}
	return ""
}

// pqSchemes names the post-quantum signature schemes the signature stage proved accepted (only
// when its control hello was refused, so the answers mean something).
func pqSchemes(rep *tlsprobe.Report) []string {
	var out []string
	for _, s := range rep.Signatures.Accepted() {
		if s.PQ {
			out = append(out, s.Algorithm)
		}
	}
	return out
}

func hasPQCertificate(rep *tlsprobe.Report) bool {
	for _, cr := range rep.Certificates {
		if leaf, ok := leafOf(cr); ok &&
			(strings.HasPrefix(leaf.PublicKey.Algorithm, "ML-DSA") || strings.HasPrefix(leaf.PublicKey.Algorithm, "SLH-DSA")) {
			return true
		}
	}
	return false
}
