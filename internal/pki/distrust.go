package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// Kinds of distrust-list entry.
const (
	// KindKeyCompromise: the private key is public or recoverable, so anyone can sign as this CA.
	KindKeyCompromise = "key-compromise"
	// KindCADistrust: root programs have blocked the certificate, though its key is not known to be public.
	KindCADistrust = "ca-distrust"
)

// Listed is what a distrust list says about one key: what it is, why it is listed and where that
// is published. An entry is a fact about the key, not a verdict on a path: evaluation reports it
// and carries on.
type Listed struct {
	Name     string   `json:"name"`     // the CA's name, for display
	Kind     string   `json:"kind"`     // KindKeyCompromise | KindCADistrust
	Incident string   `json:"incident"` // incident id, e.g. "emudhra-2026-10"
	Title    string   `json:"title"`    // the incident's title
	Since    string   `json:"since"`    // YYYY-MM-DD the problem became public
	Summary  string   `json:"summary"`
	Sources  []string `json:"sources"`
}

// Phrase describes the entry in a clause: "whose private key is public (title, since)".
func (l Listed) Phrase() string {
	what := "whose private key is public"
	if l.Kind == KindCADistrust {
		what = "which root programs have blocked"
	}
	return fmt.Sprintf("%s (%s, %s)", what, l.Title, l.Since)
}

// Distrust is a list of keys and certificates no path should rely on, matched by the SHA-256 of
// the SubjectPublicKeyInfo (one entry covers every certificate for that key: the original, its
// cross-signs and any reissue) or of the certificate's DER. A nil *Distrust matches nothing.
type Distrust struct {
	bySPKI map[string]Listed
	byCert map[string]Listed
}

// NewDistrust returns an empty list.
func NewDistrust() *Distrust {
	return &Distrust{bySPKI: map[string]Listed{}, byCert: map[string]Listed{}}
}

// Add lists a key (spki, lower-case hex, may be empty) and certificates (lower-case hex SHA-256 of
// DER) under l.
func (d *Distrust) Add(spki string, certs []string, l Listed) {
	if spki != "" {
		d.bySPKI[spki] = l
	}
	for _, c := range certs {
		d.byCert[c] = l
	}
}

// Len is the number of distinct keys and certificates listed.
func (d *Distrust) Len() int {
	if d == nil {
		return 0
	}
	return len(d.bySPKI) + len(d.byCert)
}

// LookupHashes matches by certificate SHA-256 and/or SPKI SHA-256 (lower-case hex; either may be
// empty), for certificates known only by their facts.
func (d *Distrust) LookupHashes(certSHA, spkiSHA string) (Listed, bool) {
	if d == nil {
		return Listed{}, false
	}
	if spkiSHA != "" {
		if l, ok := d.bySPKI[spkiSHA]; ok {
			return l, true
		}
	}
	if certSHA != "" {
		if l, ok := d.byCert[certSHA]; ok {
			return l, true
		}
	}
	return Listed{}, false
}

// Lookup matches a parsed certificate.
func (d *Distrust) Lookup(c *x509.Certificate) (Listed, bool) {
	if d == nil || c == nil {
		return Listed{}, false
	}
	return d.LookupHashes(Fingerprint(c), SPKIFingerprint(c))
}

// SPKIFingerprint is the lower-case hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// ListedOn is one listed certificate found on a path.
type ListedOn struct {
	Position int    `json:"position"` // 0 = leaf, counting up the path
	SHA256   string `json:"sha256"`
	Listed
}

// ListedOnPath returns every listed certificate on a path (leaf first).
func (d *Distrust) ListedOnPath(path []*x509.Certificate) []ListedOn {
	var out []ListedOn
	for i, c := range path {
		if l, ok := d.Lookup(c); ok {
			out = append(out, ListedOn{Position: i, SHA256: Fingerprint(c), Listed: l})
		}
	}
	return out
}

// Limits on path building over hostile input: a served chain is at most MaxServedCerts long, and
// these keep a crafted set of cross-signs from exploding the search.
const (
	maxPathLen = 8
	maxPaths   = 16
)

// Paths returns every path from the served leaf to a root in store along which each signature
// verifies under its issuer's key and the names chain, leaf first, root last. The served
// certificates are the only intermediates (no AIA fetching). No validity period, key usage,
// name constraint, root-program constraint or distrust list is applied: Paths answers "is there
// a cryptographic path?", and evaluation reports the rest as findings on that path. It exists
// because crypto/x509 silently drops paths through keys it has hardcoded as distrusted, which
// would hide the very path an evaluation has to show.
func Paths(s *Served, store *Store) [][]*x509.Certificate {
	if s == nil || store == nil || s.Leaf() == nil {
		return nil
	}
	inters := s.Intermediates()
	var out [][]*x509.Certificate
	var walk func(path []*x509.Certificate)
	walk = func(path []*x509.Certificate) {
		if len(out) >= maxPaths {
			return
		}
		cur := path[len(path)-1]
		if _, ok := store.bySHA[Fingerprint(cur)]; ok {
			out = append(out, append([]*x509.Certificate(nil), path...))
			return
		}
		if len(path) >= maxPathLen {
			return
		}
		for _, r := range store.roots {
			if !onPath(path, r.cert) && Issued(r.cert, cur) {
				walk(append(path, r.cert))
			}
		}
		for _, c := range inters {
			if !onPath(path, c) && Issued(c, cur) {
				walk(append(path, c))
			}
		}
	}
	walk([]*x509.Certificate{s.Leaf()})
	return out
}

func onPath(path []*x509.Certificate, c *x509.Certificate) bool {
	for _, p := range path {
		if p.Equal(c) {
			return true
		}
	}
	return false
}
