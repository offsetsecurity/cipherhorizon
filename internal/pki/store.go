// Package pki holds the certificate-path logic the TLS evaluation needs: the
// analysis of a served chain, path validation per anchor set (with the
// constraints root programs apply), certificate-name matching, and decoders for
// a stapled OCSP response and an SCT list.
//
// It is pure: it never touches the network, never reads the clock (the time is
// always an argument) and never reads a store. Every decoder bounds its input
// and is fuzzed.
package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// Root is one trust anchor with the constraints its root program applies.
type Root struct {
	SHA256 string // lower-case hex SHA-256 of DER
	DER    []byte
	// DistrustAfter is Mozilla's "Distrust for TLS After Date": a leaf whose
	// notBefore is after it is not trusted through this root. Zero means none.
	DistrustAfter time.Time
	// SCTNotAfter is Chrome's sct_not_after: a leaf is trusted through this root
	// only with an SCT timestamped at or before it. Zero means none.
	SCTNotAfter time.Time
	// PermittedDNS are DNS-name constraints a root program applies to this root
	// on top of the certificate's own (for example "tr").
	PermittedDNS []string
}

// Store is a named set of trust anchors: a bundled root-program snapshot or an
// operator's private CA bundle.
type Store struct {
	Name     string // "Mozilla", "Chrome", "private"
	Snapshot string // date of the snapshot, empty for private anchors
	// Constrained marks a root-program store whose constraints are applied.
	Constrained bool
	roots       []parsedRoot
	pool        *x509.CertPool
	bySHA       map[string]int
}

type parsedRoot struct {
	Root
	cert *x509.Certificate
}

// NewStore parses every root. A root that does not parse, or whose SHA256 does
// not match its DER, is an error: a store is never silently smaller than its
// source.
func NewStore(name, snapshot string, constrained bool, roots []Root) (*Store, error) {
	s := &Store{Name: name, Snapshot: snapshot, Constrained: constrained, pool: x509.NewCertPool(), bySHA: map[string]int{}}
	for _, r := range roots {
		sum := sha256.Sum256(r.DER)
		fp := hex.EncodeToString(sum[:])
		if r.SHA256 != "" && r.SHA256 != fp {
			return nil, fmt.Errorf("pki: store %s: root %s: fingerprint does not match its DER", name, r.SHA256)
		}
		r.SHA256 = fp
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			return nil, fmt.Errorf("pki: store %s: root %s: %w", name, fp, err)
		}
		if _, dup := s.bySHA[fp]; dup {
			continue
		}
		s.bySHA[fp] = len(s.roots)
		s.roots = append(s.roots, parsedRoot{Root: r, cert: c})
		s.pool.AddCert(c)
	}
	return s, nil
}

// Len is the number of distinct roots.
func (s *Store) Len() int { return len(s.roots) }

// Root returns the root with this fingerprint.
func (s *Store) Root(sha string) (Root, bool) {
	i, ok := s.bySHA[sha]
	if !ok {
		return Root{}, false
	}
	return s.roots[i].Root, true
}

// Certificates returns the parsed roots, in source order.
func (s *Store) Certificates() []*x509.Certificate {
	out := make([]*x509.Certificate, len(s.roots))
	for i, r := range s.roots {
		out[i] = r.cert
	}
	return out
}

// Fingerprint is the lower-case hex SHA-256 of a certificate's DER.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
