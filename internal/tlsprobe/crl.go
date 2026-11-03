package tlsprobe

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
)

// CRLFetcher retrieves a CRL by URL; *revocation.Fetcher is the implementation.
type CRLFetcher interface {
	Get(ctx context.Context, url string) (*revocation.Fetched, error)
}

// Bounds on the CRL step, which follows addresses a target's certificates name.
const (
	maxCRLURLsPerCert = 4
	crlStageBudget    = 90 * time.Second
)

var probesCRL = "fetched the CRL each certificate on the served path names (plain HTTP to the CA's CRL server, never the target; private and loopback addresses refused unless allowed), checked its signature against the certificate's issuer, its scope and its dates, and looked up the certificate's serial; no OCSP responder is contacted"

// crlChecks fills CertResult.CRL for every chain: each certificate on the
// served path, leaf first, is checked against a CRL it names, signed by the
// next certificate up (or, for the top, by an issuer from opts.CRLIssuers). A
// self-signed root, or a served cross-sign of a known anchor, ends the walk: roots
// are not revoked, and nothing above an anchor is on the path clients trust. A CRL that
// cannot answer gives an unknown result, and the next URL is tried. A
// certificate seen in several chains is checked once.
func (p *prober) crlChecks(ctx context.Context, certs []CertResult) {
	ctx, cancel := context.WithTimeout(ctx, crlStageBudget)
	defer cancel()
	done := map[string][]pki.CRLResult{}
	// A served certificate with the name and key of a known anchor (a cross-signed copy of a
	// root) is where clients' paths end: roots are not revoked, and what is above it is off the
	// path they trust.
	anchors := map[string]bool{}
	for _, r := range p.opts.CRLIssuers {
		anchors[string(r.RawSubject)+"\x00"+pki.SPKIFingerprint(r)] = true
	}
	for i := range certs {
		cr := &certs[i]
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
			continue
		}
		s, err := pki.AnalyzeServed(der)
		if err != nil {
			continue
		}
		for pos, idx := range s.Path {
			c := s.Certs[idx]
			if pki.SelfSigned(c) || (pos > 0 && anchors[string(c.RawSubject)+"\x00"+pki.SPKIFingerprint(c)]) {
				break
			}
			fp := pki.Fingerprint(c)
			if prev, ok := done[fp]; ok {
				for _, r := range prev {
					r.Position = idx
					cr.CRL = append(cr.CRL, r)
				}
				continue
			}
			var issuer *x509.Certificate
			if pos+1 < len(s.Path) {
				issuer = s.Certs[s.Path[pos+1]]
			} else {
				for _, r := range p.opts.CRLIssuers {
					if pki.Issued(r, c) {
						issuer = r
						break
					}
				}
			}
			res := p.crlFor(ctx, c, issuer)
			for j := range res {
				res[j].Position, res[j].SHA256 = idx, fp
			}
			done[fp] = res
			cr.CRL = append(cr.CRL, res...)
		}
	}
}

// crlFor checks one certificate against the CRLs it names, stopping at the
// first that answers.
func (p *prober) crlFor(ctx context.Context, c, issuer *x509.Certificate) []pki.CRLResult {
	var urls []string
	for _, u := range c.CRLDistributionPoints {
		if strings.HasPrefix(strings.ToLower(u), "http://") {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		if !c.IsCA && len(c.CRLDistributionPoints) == 0 {
			return nil // an end-entity certificate may rely on OCSP alone; nothing to look up
		}
		why := "the certificate names no CRL distribution point"
		if len(c.CRLDistributionPoints) > 0 {
			why = "the certificate names no http CRL address (only " + strings.Join(c.CRLDistributionPoints, ", ") + ")"
		}
		return []pki.CRLResult{{Status: pki.CRLUnknown, Problem: why}}
	}
	if len(urls) > maxCRLURLsPerCert {
		urls = urls[:maxCRLURLsPerCert]
	}
	var out []pki.CRLResult
	for _, u := range urls {
		p.progress("checking the CRL at " + u)
		f, err := p.opts.CRL.Get(ctx, u)
		if err != nil {
			out = append(out, pki.CRLResult{URL: u, Status: pki.CRLUnknown, Problem: err.Error()})
			continue
		}
		r := pki.JudgeCRL(f.List, u, c, issuer, p.opts.Now())
		r.FetchedAt, r.Size, r.CRLSHA256 = f.FetchedAt, f.Size, f.SHA256
		out = append(out, r)
		if r.Status != pki.CRLUnknown {
			break
		}
	}
	return out
}
