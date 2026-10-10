package server

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

var fingerprintRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// certView is a certificate as the API shows it: its public attributes, its role, and the
// cited findings that apply to it. The graph has no key material to show.
type certView struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	Serial      string `json:"serial,omitempty"`
	DNSNames    string `json:"dnsNames,omitempty"`
	KeyAlg      string `json:"keyAlgorithm"`
	KeyBits     *int   `json:"keyBits"`
	Curve       string `json:"curve,omitempty"`
	SigAlg      string `json:"signatureAlgorithm"`
	// Extension facts a tls-report/2 recorded (PRD-004 REQ-TCRT-7); empty when no source had them.
	KeyUsage     string    `json:"keyUsage,omitempty"`
	ExtKeyUsage  string    `json:"extKeyUsage,omitempty"`
	PolicyClass  string    `json:"policyClass,omitempty"`
	LifetimeDays string    `json:"lifetimeDays,omitempty"`
	Wildcards    string    `json:"wildcards,omitempty"`
	CNOnly       bool      `json:"cnOnly,omitempty"`
	NotBefore    *string   `json:"notBefore"`
	NotAfter     *string   `json:"notAfter"`
	DaysLeft     *int      `json:"daysLeft"`
	Current      bool      `json:"current"`
	Places       int       `json:"places"`
	Systems      int       `json:"systems"`
	Origins      []string  `json:"origins"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`

	Findings []certFindingBrief `json:"findings"`
	// KeyLengthNote says why a key size is absent: the graph never guesses one.
	KeyLengthNote string `json:"keyLengthNote,omitempty"`
}

type certFindingBrief struct {
	ID       string        `json:"id"`
	Severity eval.Severity `json:"severity"`
	Title    string        `json:"title"`
}

func factsOf(c store.CertificateRow) eval.CertificateFacts { return c.Facts() }

func viewCert(c store.CertificateRow, now time.Time) (certView, []eval.Finding) {
	f := factsOf(c)
	findings := eval.EvaluateCertificate(f, now)
	v := certView{
		Fingerprint: c.Fingerprint, Name: c.Name, Role: c.Role(), Subject: c.Attrs["subject"], Issuer: c.Attrs["issuer"],
		Serial: c.Attrs["serial"], DNSNames: c.Attrs["dnsNames"], KeyAlg: c.Attrs["keyAlg"], Curve: c.Attrs["curve"], SigAlg: c.Attrs["sigAlg"],
		Current: c.Current, Places: c.Places, Systems: c.Systems, Origins: c.Origins, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
		Findings: []certFindingBrief{},
		KeyUsage: c.Attrs["keyUsage"], ExtKeyUsage: c.Attrs["extKeyUsage"], PolicyClass: c.Attrs["policyClass"],
		LifetimeDays: c.Attrs["lifetimeDays"], Wildcards: c.Attrs["wildcards"], CNOnly: c.Attrs["cnOnly"] == "true",
	}
	if f.KeyBits > 0 {
		v.KeyBits = &f.KeyBits
	} else {
		v.KeyLengthNote = "no source recorded a key size for this certificate"
	}
	if !f.NotBefore.IsZero() {
		s := f.NotBefore.UTC().Format(time.RFC3339)
		v.NotBefore = &s
	}
	if !f.NotAfter.IsZero() {
		s := f.NotAfter.UTC().Format(time.RFC3339)
		v.NotAfter = &s
		d := int(f.NotAfter.Sub(now).Hours() / 24)
		v.DaysLeft = &d
	}
	for _, fd := range findings {
		v.Findings = append(v.Findings, certFindingBrief{ID: fd.ID, Severity: fd.Severity, Title: fd.Title})
	}
	return v, findings
}

// anchorSummary counts a class of CA certificates (roots, or intermediates) instead of
// listing them: a machine carries hundreds, and none is a finding on its own.
type anchorSummary struct {
	Count          int `json:"count"`
	Current        int `json:"current"`
	Expired        int `json:"expired"`
	Expiring90Days int `json:"expiring90Days"`
	WeakKey        int `json:"weakKey"`
	WeakSignature  int `json:"weakSignature"`
	OutlivesPQC    int `json:"outlivesPqcDeprecation"`
}

func (a *anchorSummary) add(c certView) {
	a.Count++
	if c.Current {
		a.Current++
	}
	if c.DaysLeft != nil && *c.DaysLeft < 0 {
		a.Expired++
	} else if c.DaysLeft != nil && *c.DaysLeft <= 90 {
		a.Expiring90Days++
	}
	for _, f := range c.Findings {
		switch f.ID {
		case "CERT.WEAK-KEY":
			a.WeakKey++
		case "CERT.WEAK-SIGNATURE":
			a.WeakSignature++
		case "CERT.PQ-OUTLIVES-DEPRECATION":
			a.OutlivesPQC++
		}
	}
}

// listCertificates returns end-entity certificates one by one and summarises the CA
// certificates (REQ-CERT-5), with any change to a host's set of roots.
func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	rows, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	all := r.URL.Query().Get("include") == "all"
	onlyCurrent := r.URL.Query().Get("current") == "1"

	items := []certView{}
	anchors := map[string]*anchorSummary{"root": {}, "intermediate": {}}
	for _, c := range rows {
		v, _ := viewCert(c, now)
		if a, isCA := anchors[v.Role]; isCA {
			a.add(v)
			if !all {
				continue
			}
		}
		if onlyCurrent && !v.Current {
			continue
		}
		items = append(items, v)
	}
	sort.SliceStable(items, func(i, j int) bool {
		wi, wj := worstRank(items[i]), worstRank(items[j])
		if wi != wj {
			return wi < wj
		}
		di, dj := 1<<30, 1<<30
		if items[i].DaysLeft != nil {
			di = *items[i].DaysLeft
		}
		if items[j].DaysLeft != nil {
			dj = *items[j].DaysLeft
		}
		if di != dj {
			return di < dj
		}
		return items[i].Fingerprint < items[j].Fingerprint
	})
	changes, err := s.cfg.Store.RootSetChanges()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"certificates":   items,
		"trustAnchors":   anchors,
		"rootSetChanges": changes,
		"generatedAt":    now.UTC().Format(time.RFC3339),
		"note":           "End-entity certificates are listed; roots and intermediates are summarised. Add include=all to list them.",
	})
}

func worstRank(v certView) int {
	w := 5
	for _, f := range v.Findings {
		if r := f.Severity.Rank(); r < w {
			w = r
		}
	}
	return w
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if !fingerprintRE.MatchString(fp) {
		writeErr(w, http.StatusBadRequest, "a certificate is identified by its 64-digit SHA-256 fingerprint")
		return
	}
	fp = strings.ToLower(fp)
	rows, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	for _, c := range rows {
		if c.Fingerprint != fp {
			continue
		}
		v, findings := viewCert(c, s.cfg.Now())
		places, _, err := s.cfg.Store.CertificatePlaces(fp)
		if err != nil {
			storeErr(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"certificate": v, "findingDetails": findings, "places": places})
		return
	}
	writeErr(w, http.StatusNotFound, "not found")
}

func (s *Server) systemCertificates(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetSystem(id); err != nil {
		storeErr(w, err)
		return
	}
	obs, err := s.cfg.Store.SystemObservations(id, true)
	if err != nil {
		storeErr(w, err)
		return
	}
	rows, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	byFP := map[string]store.CertificateRow{}
	for _, c := range rows {
		byFP[c.Fingerprint] = c
	}
	seen := map[string]bool{}
	now := s.cfg.Now()
	out := []certView{}
	anchors := map[string]*anchorSummary{"root": {}, "intermediate": {}}
	for _, o := range obs {
		if o.Entity.Kind != "certificate" {
			continue
		}
		fp := strings.TrimPrefix(o.Entity.Key, "cert:")
		if seen[fp] {
			continue
		}
		seen[fp] = true
		c, ok := byFP[fp]
		if !ok {
			continue
		}
		v, _ := viewCert(c, now)
		if a, isCA := anchors[v.Role]; isCA {
			a.add(v)
			continue
		}
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return worstRank(out[i]) < worstRank(out[j]) })
	writeJSON(w, 200, map[string]any{"certificates": out, "trustAnchors": anchors})
}
