package certinfo_test

import (
	"crypto/x509"
	"slices"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/certinfo"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
)

func TestExtensionFacts(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{PermittedDNS: []string{"example.test"}})
	nb := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	leaf := root.Leaf(t, pkitest.LeafOpts{
		DNS: []string{"*.example.test", "example.test"}, NotBefore: nb, NotAfter: nb.Add(47*24*time.Hour - time.Second),
		EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, MustStaple: true,
		RSAExponent: 3, Policies: []string{"2.23.140.1.2.2"},
	})
	f := certinfo.Describe(leaf)
	if !slices.Equal(f.ExtKeyUsage, []string{"serverAuth", "clientAuth"}) {
		t.Errorf("EKU %v", f.ExtKeyUsage)
	}
	if !f.OCSPMustStaple || f.RSAExponent != 3 || f.PolicyClass != "OV" || f.LifetimeDays != 47 {
		t.Errorf("must-staple %v exponent %d class %s lifetime %d", f.OCSPMustStaple, f.RSAExponent, f.PolicyClass, f.LifetimeDays)
	}
	if !slices.Equal(f.Wildcards, []string{"*.example.test"}) || f.CNOnly {
		t.Errorf("wildcards %v cnOnly %v", f.Wildcards, f.CNOnly)
	}
	if f.BasicConstraints == nil || f.BasicConstraints.CA || len(f.SPKISHA256) != 64 {
		t.Errorf("basic constraints %+v spki %q", f.BasicConstraints, f.SPKISHA256)
	}

	r := certinfo.Describe(root.Cert)
	if r.BasicConstraints == nil || !r.BasicConstraints.CA || r.NameConstraints == nil || !slices.Equal(r.NameConstraints.Permitted, []string{"example.test"}) {
		t.Errorf("root: %+v %+v", r.BasicConstraints, r.NameConstraints)
	}
	if r.PolicyClass != "unknown" || r.RSAExponent != 0 {
		t.Errorf("root class %s exponent %d", r.PolicyClass, r.RSAExponent)
	}

	cn := certinfo.Describe(root.Leaf(t, pkitest.LeafOpts{CN: "only.test", DNS: []string{}}))
	if !cn.CNOnly {
		t.Error("CN-only certificate not flagged")
	}
	// A TLS Feature extension listing something other than status_request is not must-staple.
	if f := certinfo.Describe(root.Leaf(t, pkitest.LeafOpts{})); f.OCSPMustStaple {
		t.Error("plain leaf flagged must-staple")
	}
}
