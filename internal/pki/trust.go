package pki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

// StoreResult is the outcome of validating one served chain against one
// anchor set.
type StoreResult struct {
	Store    string `json:"store"`
	Snapshot string `json:"snapshot,omitempty"`
	Trusted  bool   `json:"trusted"`
	// Path is the validated chain, leaf first, by SHA-256; the last entry is the
	// anchor. Empty when nothing validated.
	Path []string `json:"path,omitempty"`
	// Error says why nothing validated; Distrust says which root-program
	// constraint, or which listed key, stopped a path that exists.
	Error    string `json:"error,omitempty"`
	Distrust string `json:"distrust,omitempty"`
	// Listed are the certificates on Path that the distrust list names. Path is
	// then the signature-valid path through them: the evaluation reports it
	// rather than losing it.
	Listed []ListedOn `json:"listed,omitempty"`
	// ExpiredOnly is set when the path validates except that a certificate on it
	// is outside its validity at the evaluation time: the expiry finding covers
	// it, so "untrusted" is not raised a second time.
	ExpiredOnly bool `json:"expiredOnly,omitempty"`
}

// Validate builds a path from the served leaf to an anchor in store, using the
// served certificates as the only intermediates (no AIA fetching, no system
// pool), for TLS server authentication at now. sctTimes are the timestamps of
// every SCT seen for the leaf (embedded, TLS, OCSP); they decide Chrome's
// sct_not_after constraint.
//
// dl is the distrust list (nil for none). It applies to every store, private
// ones included: a path through a listed key is reported as distrusted, with the
// path and the listed certificates, whatever crypto/x509 did with it (Go 1.27.3
// and later drop such paths silently, older versions accept them).
func Validate(s *Served, store *Store, now time.Time, sctTimes []time.Time, dl *Distrust) StoreResult {
	res := StoreResult{Store: store.Name, Snapshot: store.Snapshot}
	inter := x509.NewCertPool()
	for _, c := range s.Intermediates() {
		inter.AddCert(c)
	}
	verify := func(at time.Time) ([][]*x509.Certificate, error) {
		return s.Leaf().Verify(x509.VerifyOptions{Roots: store.pool, Intermediates: inter, CurrentTime: at,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	}
	chains, err := verify(now)
	if err != nil {
		// A path that exists but runs through a listed key: say so and show it,
		// instead of the bare error crypto/x509 gives when it drops such a path.
		if dl.Len() > 0 {
			for _, p := range Paths(s, store) {
				if on := dl.ListedOnPath(p); len(on) > 0 {
					res.Distrust, res.Listed, res.Path = listedReason(on), on, chainSHAs(p)
					return res
				}
			}
		}
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired {
			// Would the path hold while every certificate on it was valid?
			if at, ok := validWindow(s); ok {
				if c2, err2 := verify(at); err2 == nil {
					res.ExpiredOnly = true
					res.Error = "a certificate on the path is outside its validity period"
					res.Path = chainSHAs(c2[0])
					return res
				}
			}
		}
		res.Error = describeVerifyError(err)
		return res
	}
	var reasons []string
	var listed []ListedOn
	var listedPath []*x509.Certificate
	for _, ch := range chains {
		root := ch[len(ch)-1]
		r, ok := store.Root(Fingerprint(root))
		if !ok {
			continue
		}
		if on := dl.ListedOnPath(ch); len(on) > 0 {
			reasons = append(reasons, listedReason(on))
			if listed == nil {
				listed, listedPath = on, ch
			}
			continue
		}
		if why := constraintFailure(r, s.Leaf(), sctTimes); why != "" && store.Constrained {
			reasons = append(reasons, why)
			continue
		}
		res.Trusted, res.Path = true, chainSHAs(ch)
		return res
	}
	if len(reasons) == 0 {
		res.Error = "no path to a root in this store"
		return res
	}
	res.Distrust = strings.Join(dedupe(reasons), "; ")
	res.Path = chainSHAs(chains[0])
	if listed != nil {
		res.Path, res.Listed = chainSHAs(listedPath), listed
	}
	return res
}

// listedReason says which listed certificates a path goes through.
func listedReason(on []ListedOn) string {
	parts := make([]string, 0, len(on))
	for _, l := range on {
		parts = append(parts, fmt.Sprintf("%q %s", l.Name, l.Phrase()))
	}
	return "the path goes through " + strings.Join(parts, " and ")
}

// constraintFailure applies a root program's constraints to a leaf.
func constraintFailure(r Root, leaf *x509.Certificate, sctTimes []time.Time) string {
	if !r.DistrustAfter.IsZero() && leaf.NotBefore.After(r.DistrustAfter) {
		return fmt.Sprintf("the root is distrusted for certificates issued after %s, and this one was issued %s",
			r.DistrustAfter.Format("2006-01-02"), leaf.NotBefore.UTC().Format("2006-01-02"))
	}
	if !r.SCTNotAfter.IsZero() {
		ok := false
		for _, t := range sctTimes {
			if !t.After(r.SCTNotAfter) {
				ok = true
			}
		}
		if len(sctTimes) == 0 {
			ok = !leaf.NotBefore.After(r.SCTNotAfter)
		}
		if !ok {
			return fmt.Sprintf("the root is trusted only for certificates logged by %s", r.SCTNotAfter.Format("2006-01-02"))
		}
	}
	if len(r.PermittedDNS) > 0 {
		for _, n := range leaf.DNSNames {
			if !withinAny(n, r.PermittedDNS) {
				return fmt.Sprintf("the root is limited to names under %s, and the certificate names %s", strings.Join(r.PermittedDNS, ", "), n)
			}
		}
	}
	return ""
}

func withinAny(name string, permitted []string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, p := range permitted {
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

// validWindow returns a moment at which every certificate on the served path
// is valid, if there is one.
func validWindow(s *Served) (time.Time, bool) {
	var from, to time.Time
	for i, idx := range s.Path {
		c := s.Certs[idx]
		if i == 0 || c.NotBefore.After(from) {
			from = c.NotBefore
		}
		if i == 0 || c.NotAfter.Before(to) {
			to = c.NotAfter
		}
	}
	if !from.Before(to) {
		return time.Time{}, false
	}
	return from.Add(to.Sub(from) / 2), true
}

func describeVerifyError(err error) string {
	var ua x509.UnknownAuthorityError
	var inv x509.CertificateInvalidError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &ua):
		return "no path to a root in this store"
	case errors.As(err, &inv):
		switch inv.Reason {
		case x509.Expired:
			return "a certificate on the path is outside its validity period"
		case x509.IncompatibleUsage:
			return "the certificate is not valid for TLS server authentication (extended key usage)"
		case x509.CANotAuthorizedForThisName:
			return "a name constraint on the path excludes this certificate"
		case x509.NotAuthorizedToSign:
			return "a certificate on the path is not a CA but signed another"
		case x509.TooManyIntermediates:
			return "the path is longer than a CA on it allows"
		}
		return inv.Error()
	case errors.As(err, &hn):
		return hn.Error()
	}
	return err.Error()
}

func chainSHAs(ch []*x509.Certificate) []string {
	out := make([]string, len(ch))
	for i, c := range ch {
		out[i] = Fingerprint(c)
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// NameMatch checks the host against the leaf's DNS and IP SANs; the CN is never
// used (RFC 9525). MatchedBy names the SAN that matched.
func NameMatch(leaf *x509.Certificate, host string) (matchedBy string, err error) {
	if err := leaf.VerifyHostname(host); err != nil {
		return "", err
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, ip := range leaf.IPAddresses {
		if ip.String() == h || "["+ip.String()+"]" == h {
			return "IP:" + ip.String(), nil
		}
	}
	for _, n := range leaf.DNSNames {
		ln := strings.ToLower(strings.TrimSuffix(n, "."))
		if ln == h {
			return "DNS:" + n, nil
		}
		if strings.HasPrefix(ln, "*.") {
			if i := strings.IndexByte(h, '.'); i > 0 && h[i+1:] == ln[2:] {
				return "DNS:" + n, nil
			}
		}
	}
	return "", nil
}
