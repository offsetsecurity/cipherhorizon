package eval

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Input is everything evaluation reads besides the report. The zero value
// (with Now set) evaluates against the bundled root stores and nothing else.
type Input struct {
	Now time.Time
	// Stores are the public root stores; nil means the bundled ones
	// (refdata.Stores). A store-less evaluation is possible with an empty,
	// non-nil slice.
	Stores []*pki.Store
	// Anchors are the operator's private CA certificates (server-wide bundle
	// plus the system's own), as one unconstrained store; nil when none.
	Anchors *pki.Store
	// SSLv2Keys maps a public-key SHA-256 (SPKI) to the other endpoints in the
	// estate whose latest scan accepted SSLv2 while serving that key.
	SSLv2Keys map[string][]string
	// SSHBaseline is the id of the baseline an SSH server is judged against; empty means
	// BaselineDefault.
	SSHBaseline string
	// Distrust lists keys and certificates no path should rely on; nil means the bundled
	// list (refdata.Distrust). A listed key is reported on the path it sits on, never used
	// to stop evaluating it.
	Distrust *pki.Distrust
}

// ChainView is the evaluation's reading of one served chain: how it was
// served, who trusts it, which names it covers, its lifetime against the limit,
// its stapled OCSP response and its SCTs.
type ChainView struct {
	Source   string            `json:"source"`
	NoSNI    bool              `json:"noSni,omitempty"`
	Leaf     string            `json:"leaf"` // SHA-256
	Served   ServedView        `json:"served"`
	Trust    []pki.StoreResult `json:"trust"`
	Private  *pki.StoreResult  `json:"private,omitempty"`
	OS       *pki.StoreResult  `json:"os,omitempty"`
	Public   bool              `json:"public"` // trusted, or distrusted only by a constraint, by a bundled store
	Names    NamesView         `json:"names"`
	Lifetime LifetimeView      `json:"lifetime"`
	OCSP     *OCSPView         `json:"ocsp,omitempty"`
	SCTs     []SCTView         `json:"scts"`
	// Revocation sources the certificate names; T1 never contacts them.
	OCSPURLs []string `json:"ocspUrls,omitempty"`
	CRLURLs  []string `json:"crlUrls,omitempty"`
	Error    string   `json:"error,omitempty"` // the chain could not be analysed
}

// ServedView is the chain as the server sent it.
type ServedView struct {
	Order     []string    `json:"order"` // SHA-256 of each served certificate, in served order
	Path      []int       `json:"path"`  // served indexes on the path from the leaf up
	Issues    []pki.Issue `json:"issues,omitempty"`
	SizeBytes int         `json:"sizeBytes"`
	// Missing names the issuer the server should have sent, when it did not.
	Missing *MissingView `json:"missing,omitempty"`
	// ExpiresFirst lists served-path positions that expire before the leaf.
	ExpiresFirst []int `json:"expiresFirst,omitempty"`
}

// MissingView describes the issuer the served path stops short of.
type MissingView struct {
	IssuerDN string   `json:"issuer"`
	AIA      []string `json:"aia,omitempty"` // caIssuers URLs, not fetched
	// Likely is "intermediate" when the served path stops at a certificate that
	// names where its issuer can be downloaded (AIA caIssuers, as public CAs'
	// leaves do): a server that forgot its intermediate. It is "root" when the
	// path already ends at a CA certificate, or the leaf names no issuer URL (a
	// leaf signed straight by a root): then the unknown issuer is most likely a
	// root no store holds, which servers do not send anyway.
	Likely string `json:"likely"`
}

// NamesView says which names were checked against which SANs (RFC 9525).
type NamesView struct {
	Host      string   `json:"host"`
	Checked   []string `json:"checked"` // the SANs, "DNS:x" / "IP:y"
	MatchedBy string   `json:"matchedBy,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// LifetimeView compares the validity period with the limit in force when the
// certificate was issued.
type LifetimeView struct {
	Days        int    `json:"days"`
	LimitDays   int    `json:"limitDays,omitempty"`
	LimitSource string `json:"limitSource,omitempty"`
	Applies     bool   `json:"applies"` // only publicly trusted certificates are held to the limit
}

// OCSPView is the stapled OCSP response.
type OCSPView struct {
	Present     bool      `json:"present"`
	Error       string    `json:"error,omitempty"`    // unreadable or not usable
	Response    string    `json:"response,omitempty"` // outer responseStatus
	Status      string    `json:"status,omitempty"`   // good | revoked | unknown
	RevokedAt   time.Time `json:"revokedAt,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	ThisUpdate  time.Time `json:"thisUpdate,omitempty"`
	NextUpdate  time.Time `json:"nextUpdate,omitempty"`
	ProducedAt  time.Time `json:"producedAt,omitempty"`
	Responder   string    `json:"responder,omitempty"`
	Signature   string    `json:"signature,omitempty"` // valid | invalid | unsupported | no-issuer
	Delegated   bool      `json:"delegated,omitempty"`
	ForThisCert bool      `json:"forThisCert"`
}

// SCTView is one SCT and where it came from.
type SCTView struct {
	Source    string    `json:"source"` // embedded | tls | ocsp
	LogID     string    `json:"logId"`  // base64
	LogName   string    `json:"logName,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	SigAlg    string    `json:"signatureAlgorithm,omitempty"`
}

// chain is one CertResult with everything evaluation derived from it.
type chain struct {
	cr     tlsprobe.CertResult
	served *pki.Served // nil on legacy reports or when the DER is missing
	view   ChainView

	trustedBy []string // bundled store names that trust it
	failing   []string // bundled store names that do not
	private   bool     // trusted by the operator's anchors
	expired   bool     // every validation failed only on time
	missing   bool
	ocsp      *pki.SingleResponse
}

var crlReasons = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged",
	4: "superseded", 5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise"}

var sigAlgNames = map[[2]uint8]string{
	{4, 3}: "ECDSA-SHA256", {5, 3}: "ECDSA-SHA384", {6, 3}: "ECDSA-SHA512",
	{4, 1}: "RSA-SHA256", {5, 1}: "RSA-SHA384", {6, 1}: "RSA-SHA512", {8, 7}: "Ed25519",
}

// analyseChains builds the PKI view of every served chain of a tls-report/2.
func (c *ctx) analyseChains() {
	stores := c.in.Stores
	all := append([]*pki.Store(nil), stores...)
	if c.in.Anchors != nil {
		all = append(all, c.in.Anchors)
	}
	host := c.rep.Target.Host
	for _, cr := range c.rep.Certificates {
		ch := &chain{cr: cr, view: ChainView{Source: cr.Source, NoSNI: cr.NoSNI, Trust: []pki.StoreResult{}, SCTs: []SCTView{}}}
		c.chains = append(c.chains, ch)
		if len(cr.Chain) == 0 {
			ch.view.Error = "no certificate"
			continue
		}
		ch.view.Leaf = cr.Chain[0].SHA256
		ch.view.OCSPURLs, ch.view.CRLURLs = cr.Chain[0].OCSPServers, cr.Chain[0].CRLPoints
		var der [][]byte
		for _, ci := range cr.Chain {
			b, err := base64.StdEncoding.DecodeString(ci.DER)
			if err != nil || len(b) == 0 {
				der = nil
				break
			}
			der = append(der, b)
		}
		if der == nil {
			ch.view.Error = "the report does not carry this chain's certificates"
			continue
		}
		s, err := pki.AnalyzeServed(der)
		if err != nil {
			ch.view.Error = err.Error()
			continue
		}
		ch.served = s
		leaf := s.Leaf()
		for _, x := range s.Certs {
			if x != nil {
				ch.view.Served.Order = append(ch.view.Served.Order, pki.Fingerprint(x))
			} else {
				ch.view.Served.Order = append(ch.view.Served.Order, "")
			}
		}
		ch.view.Served.Path, ch.view.Served.Issues, ch.view.Served.SizeBytes = s.Path, s.Issues, s.SizeBytes
		ch.view.Served.ExpiresFirst = s.ExpiresFirst()
		if m, dn, aia := s.MissingIssuer(all...); m {
			likely := "intermediate"
			if top := s.Top(); (top != leaf && top.IsCA) || len(aia) == 0 {
				likely = "root"
			}
			ch.missing = likely == "intermediate"
			ch.view.Served.Missing = &MissingView{IssuerDN: dn, AIA: aia, Likely: likely}
		}

		// SCTs from all three sources first: Chrome's constraint needs their times.
		ch.collectSCTs(c)
		var times []time.Time
		for _, v := range ch.view.SCTs {
			times = append(times, v.Timestamp)
		}

		expiredOnly := true
		for _, st := range stores {
			r := pki.Validate(s, st, c.now, times, c.in.Distrust)
			ch.view.Trust = append(ch.view.Trust, r)
			switch {
			case r.Trusted:
				ch.trustedBy = append(ch.trustedBy, st.Name)
				ch.view.Public = true
				expiredOnly = false
			case r.Distrust != "":
				ch.failing = append(ch.failing, st.Name)
				ch.view.Public = true
				expiredOnly = false
			case r.ExpiredOnly:
				ch.failing = append(ch.failing, st.Name)
				ch.view.Public = true
			default:
				ch.failing = append(ch.failing, st.Name)
				expiredOnly = false
			}
		}
		if c.in.Anchors != nil {
			r := pki.Validate(s, c.in.Anchors, c.now, times, c.in.Distrust)
			r.Store = "your CA bundle"
			ch.view.Private = &r
			ch.private = r.Trusted
			if r.Trusted {
				expiredOnly = false
			}
		}
		if len(ch.trustedBy) > 0 || ch.private {
			ch.missing, ch.view.Served.Missing = false, nil
		}
		ch.expired = expiredOnly && len(stores) > 0 && ch.view.Public
		if c.in.Anchors != nil && ch.view.Private.ExpiredOnly {
			ch.expired = true
		}
		if cr.Trusted || cr.TrustError != "" {
			ch.view.OS = &pki.StoreResult{Store: "this machine", Trusted: cr.Trusted, Error: cr.TrustError}
		}

		// Names (RFC 9525): the SANs, never the CN.
		nv := NamesView{Host: host}
		for _, n := range leaf.DNSNames {
			nv.Checked = append(nv.Checked, "DNS:"+n)
		}
		for _, ip := range leaf.IPAddresses {
			nv.Checked = append(nv.Checked, "IP:"+ip.String())
		}
		if by, err := pki.NameMatch(leaf, host); err != nil {
			nv.Error = err.Error()
		} else {
			nv.MatchedBy = by
		}
		ch.view.Names = nv

		lv := LifetimeView{Days: cr.Chain[0].LifetimeDays, Applies: ch.view.Public}
		if lv.Days == 0 {
			lv.Days = lifetimeDays(leaf.NotBefore, leaf.NotAfter)
		}
		if d, ok := refdata.MaxLifetime(leaf.NotBefore); ok {
			lv.LimitDays, lv.LimitSource = d, refdata.LifetimeSourceLabel
		}
		ch.view.Lifetime = lv

		ch.readStaple(c, s)
	}
}

func lifetimeDays(nb, na time.Time) int {
	if na.Before(nb) {
		return 0
	}
	secs := na.Sub(nb).Seconds() + 1
	d := int(secs / 86400)
	if float64(d)*86400 < secs {
		d++
	}
	return d
}

func (ch *chain) addSCT(source string, s pki.SCT) {
	v := SCTView{Source: source, LogID: base64.StdEncoding.EncodeToString(s.LogID[:]), Timestamp: s.Timestamp,
		SigAlg: sigAlgNames[[2]uint8{s.HashAlg, s.SigAlg}]}
	if l, ok := refdata.LookupCTLog(s.LogID[:]); ok {
		v.LogName, v.Operator = l.Name, l.Operator
	}
	ch.view.SCTs = append(ch.view.SCTs, v)
}

func (ch *chain) collectSCTs(c *ctx) {
	if scts, err := pki.EmbeddedSCTs(ch.served.Leaf()); err == nil {
		for _, s := range scts {
			ch.addSCT("embedded", s)
		}
	}
	for _, b64 := range ch.cr.TLSSCTs {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		if s, err := pki.ParseSCT(b); err == nil {
			ch.addSCT("tls", s)
		}
	}
	// OCSP SCTs are added by readStaple.
	_ = c
}

// issuerOf finds the leaf's issuer: served, or an anchor in any store.
func (c *ctx) issuerOf(s *pki.Served) *x509.Certificate {
	if i := s.IssuerOf(); i != nil {
		return i
	}
	leaf := s.Leaf()
	stores := append([]*pki.Store(nil), c.in.Stores...)
	if c.in.Anchors != nil {
		stores = append(stores, c.in.Anchors)
	}
	for _, st := range stores {
		for _, r := range st.Certificates() {
			if pki.Issued(r, leaf) {
				return r
			}
		}
	}
	return nil
}

func (ch *chain) readStaple(c *ctx, s *pki.Served) {
	if ch.cr.OCSPStaple == "" {
		return
	}
	v := &OCSPView{Present: true}
	ch.view.OCSP = v
	b, err := base64.StdEncoding.DecodeString(ch.cr.OCSPStaple)
	if err != nil {
		v.Error = "the stapled response is not valid base64 in the report"
		return
	}
	o, err := pki.ParseOCSP(b)
	if err != nil {
		v.Error = "the stapled response could not be read: " + err.Error()
		return
	}
	v.Response = o.Status
	if o.Status != "successful" {
		v.Error = "the responder answered " + o.Status + " instead of a status"
		return
	}
	v.ProducedAt = o.ProducedAt
	v.Responder = o.ResponderName
	if v.Responder == "" && len(o.ResponderKeyHash) > 0 {
		v.Responder = "key hash " + hex.EncodeToString(o.ResponderKeyHash)
	}
	issuer := c.issuerOf(s)
	sig, by := o.VerifySignature(issuer)
	v.Signature, v.Delegated = sig, by != nil
	r, ok := o.Match(s.Leaf(), issuer)
	v.ForThisCert = ok
	if !ok {
		return
	}
	ch.ocsp = r
	v.Status, v.ThisUpdate, v.NextUpdate = r.Status, r.ThisUpdate, r.NextUpdate
	if r.Status == "revoked" {
		v.RevokedAt = r.RevokedAt
		if r.Reason >= 0 {
			v.Reason = crlReasons[r.Reason]
		}
	}
	for _, sct := range r.SCTs {
		ch.addSCT("ocsp", sct)
	}
}

// label names a chain in a finding's detail.
func (ch *chain) label() string {
	l, _ := leafOf(ch.cr)
	return certLabel(ch.cr, l)
}

// storeList renders store names for a sentence.
func storeList(names []string) string {
	switch len(names) {
	case 0:
		return "none"
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func (ch *chain) trustSummary() string {
	var parts []string
	for _, r := range ch.view.Trust {
		switch {
		case r.Trusted:
			parts = append(parts, r.Store+": trusted")
		case r.Distrust != "":
			parts = append(parts, r.Store+": "+r.Distrust)
		default:
			parts = append(parts, r.Store+": "+r.Error)
		}
	}
	if p := ch.view.Private; p != nil {
		switch {
		case p.Trusted:
			parts = append(parts, "your CA bundle: trusted")
		case p.Distrust != "":
			parts = append(parts, "your CA bundle: "+p.Distrust)
		default:
			parts = append(parts, "your CA bundle: "+p.Error)
		}
	}
	return strings.Join(parts, "; ")
}

func fmtDate(t time.Time) string { return t.UTC().Format("2006-01-02") }
