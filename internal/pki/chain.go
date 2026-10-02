package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
)

// MaxServedCerts bounds the chain a server can make us analyse.
const MaxServedCerts = 16

// Issue kinds found in a served chain (RFC 8446 §4.4.2, RFC 5246 §7.4.2).
const (
	IssueOrder     = "order"     // a certificate does not certify the one before it
	IssueRoot      = "root"      // a self-signed root was sent (harmless, wasted bytes)
	IssueDuplicate = "duplicate" // the same certificate was sent twice
	IssueUnrelated = "unrelated" // a certificate on no path from the leaf
	IssueUnparsed  = "unparsed"  // a certificate that does not parse
)

// Issue is one problem with how a chain was served.
type Issue struct {
	Kind   string `json:"kind"`
	Index  int    `json:"index"` // position in the served order, 0 = leaf
	Detail string `json:"detail"`
}

// Served is the analysis of a chain exactly as the server sent it.
type Served struct {
	// Certs are the parsed certificates in served order; an entry is nil when
	// that certificate did not parse.
	Certs []*x509.Certificate
	// Path is the served indexes on the certification path from the leaf
	// upwards, following issuer signatures among the served certificates.
	Path      []int
	Issues    []Issue
	SizeBytes int
}

// AnalyzeServed parses and analyses a served chain (leaf first). It fails only
// when there is no leaf it can parse.
func AnalyzeServed(der [][]byte) (*Served, error) {
	if len(der) == 0 {
		return nil, errors.New("pki: empty chain")
	}
	if len(der) > MaxServedCerts {
		der = der[:MaxServedCerts]
	}
	s := &Served{}
	seen := map[string]int{}
	for i, d := range der {
		s.SizeBytes += len(d)
		c, err := x509.ParseCertificate(d)
		if err != nil {
			if i == 0 {
				return nil, fmt.Errorf("pki: leaf: %w", err)
			}
			s.Certs = append(s.Certs, nil)
			s.Issues = append(s.Issues, Issue{Kind: IssueUnparsed, Index: i, Detail: err.Error()})
			continue
		}
		fp := Fingerprint(c)
		if j, dup := seen[fp]; dup {
			s.Certs = append(s.Certs, nil)
			s.Issues = append(s.Issues, Issue{Kind: IssueDuplicate, Index: i, Detail: fmt.Sprintf("same certificate as position %d", j)})
			continue
		}
		seen[fp] = i
		s.Certs = append(s.Certs, c)
	}

	// Follow issuer signatures upward from the leaf through the served set.
	used := map[int]bool{0: true}
	s.Path = []int{0}
	for cur := 0; !selfSigned(s.Certs[cur]); {
		next := -1
		for j, c := range s.Certs {
			if c != nil && !used[j] && Issued(c, s.Certs[cur]) {
				next = j
				break
			}
		}
		if next < 0 {
			break
		}
		used[next] = true
		s.Path = append(s.Path, next)
		cur = next
	}

	for pos, idx := range s.Path {
		if pos > 0 && idx != pos {
			s.Issues = append(s.Issues, Issue{Kind: IssueOrder, Index: idx,
				Detail: fmt.Sprintf("the issuer of position %d was sent at position %d", s.Path[pos-1], idx)})
			break
		}
	}
	if last := s.Path[len(s.Path)-1]; last != 0 && selfSigned(s.Certs[last]) {
		s.Issues = append(s.Issues, Issue{Kind: IssueRoot, Index: last, Detail: "a self-signed root was sent; clients ignore it"})
	}
	for i, c := range s.Certs {
		if c != nil && !used[i] {
			s.Issues = append(s.Issues, Issue{Kind: IssueUnrelated, Index: i, Detail: "not on the path from the leaf"})
		}
	}
	return s, nil
}

// Leaf is the first served certificate.
func (s *Served) Leaf() *x509.Certificate { return s.Certs[0] }

// Intermediates are every parsed served certificate except the leaf, for path
// building.
func (s *Served) Intermediates() []*x509.Certificate {
	var out []*x509.Certificate
	for _, c := range s.Certs[1:] {
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

// Top is the highest certificate on the served path.
func (s *Served) Top() *x509.Certificate { return s.Certs[s.Path[len(s.Path)-1]] }

// IssuerOf returns the served certificate that issued the leaf, if any.
func (s *Served) IssuerOf() *x509.Certificate {
	if len(s.Path) > 1 {
		return s.Certs[s.Path[1]]
	}
	return nil
}

// ExpiresFirst lists the served-path certificates above the leaf whose notAfter
// is before the leaf's: the chain breaks before the leaf does.
func (s *Served) ExpiresFirst() []int {
	var out []int
	leaf := s.Leaf()
	for _, i := range s.Path[1:] {
		if s.Certs[i].NotAfter.Before(leaf.NotAfter) {
			out = append(out, i)
		}
	}
	return out
}

// MissingIssuer reports whether the top of the served path is neither a root
// nor issued by any anchor in the stores: an intermediate the server should
// have sent is missing. When it is, the issuer's name and the top
// certificate's AIA caIssuers URLs are returned.
func (s *Served) MissingIssuer(stores ...*Store) (missing bool, issuerDN string, aia []string) {
	top := s.Top()
	if selfSigned(top) {
		return false, "", nil
	}
	for _, st := range stores {
		if st == nil {
			continue
		}
		for _, r := range st.roots {
			if Issued(r.cert, top) || bytes.Equal(r.cert.Raw, top.Raw) {
				return false, "", nil
			}
		}
	}
	return true, top.Issuer.String(), top.IssuingCertificateURL
}

// Issued reports whether parent issued child: the names chain and the signature
// verifies.
func Issued(parent, child *x509.Certificate) bool {
	return bytes.Equal(parent.RawSubject, child.RawIssuer) && child.CheckSignatureFrom(parent) == nil
}

// selfSigned checks the signature with the certificate's own key, without
// CheckSignatureFrom's CA requirements, so a self-signed leaf counts too.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// SelfSigned reports whether c is signed by its own key under its own name.
func SelfSigned(c *x509.Certificate) bool { return selfSigned(c) }
