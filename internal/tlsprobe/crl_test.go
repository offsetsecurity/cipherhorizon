package tlsprobe_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// fakeCRLs serves CRLs by URL and counts requests.
type fakeCRLs struct {
	mu    sync.Mutex
	lists map[string]*x509.RevocationList
	calls map[string]int
}

func (f *fakeCRLs) Get(_ context.Context, url string) (*revocation.Fetched, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[url]++
	rl, ok := f.lists[url]
	if !ok {
		return nil, errors.New("fetching the CRL failed: connection refused")
	}
	return &revocation.Fetched{List: rl, SHA256: strings.Repeat("ab", 32), Size: len(rl.Raw), FetchedAt: time.Now().UTC()}, nil
}

func crlTarget(t *testing.T) (*testserver.Server, *pkitest.CA, *fakeCRLs) {
	t.Helper()
	root := pkitest.NewRoot(t, "CRL Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "CRL Intermediate", pkitest.CAOpts{CRL: []string{"http://crl.test/root.crl"}})
	now := time.Now()
	tc := inter.TLS(t, pkitest.LeafOpts{CN: "127.0.0.1", IPs: nil, DNS: []string{"leaf.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		CRL: []string{"ldap://ldap.test/cn=x", "http://crl.test/int.crl"}}, inter.Cert)
	fake := &fakeCRLs{calls: map[string]int{}, lists: map[string]*x509.RevocationList{
		"http://crl.test/int.crl": inter.CRL(t, nil, now.Add(-time.Hour), now.Add(7*24*time.Hour)),
		"http://crl.test/root.crl": root.CRL(t, []x509.RevocationListEntry{{SerialNumber: inter.Cert.SerialNumber, RevocationTime: now.Add(-48 * time.Hour), ReasonCode: 2}},
			now.Add(-time.Hour), now.Add(7*24*time.Hour)),
	}}
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{tc}})
	return srv, root, fake
}

// TestCRLStageChecksTheWholePath: with lookups on, the leaf is checked against its issuer's CRL
// and the intermediate against the root's; the root itself is not checked; a certificate served
// in several chains is fetched once; only the http address is used.
func TestCRLStageChecksTheWholePath(t *testing.T) {
	srv, root, fake := crlTarget(t)
	o := opts()
	o.CRL, o.CRLIssuers = fake, []*x509.Certificate{root.Cert}
	rep := scan(t, srv, o)
	if !rep.CRLLookups {
		t.Fatal("CRLLookups not set")
	}
	rev := stageMap(rep)["revocation"]
	if rev.Outcome != tlsprobe.OutcomeDone || !strings.Contains(strings.Join(rev.Probes, " "), "fetched the CRL") {
		t.Errorf("revocation stage %+v", rev)
	}
	if len(rep.Certificates) == 0 {
		t.Fatal("no certificates")
	}
	for _, cr := range rep.Certificates {
		if len(cr.CRL) != 2 {
			t.Fatalf("%s: %d CRL results: %+v", cr.Source, len(cr.CRL), cr.CRL)
		}
		leaf, in := cr.CRL[0], cr.CRL[1]
		if leaf.Position != 0 || leaf.Status != pki.CRLGood || leaf.Signature != pki.CRLSigValid || leaf.URL != "http://crl.test/int.crl" || leaf.SHA256 != cr.Chain[0].SHA256 {
			t.Errorf("%s leaf: %+v", cr.Source, leaf)
		}
		if in.Position != 1 || in.Status != pki.CRLRevoked || in.Reason != "cACompromise" || in.Issuer != pki.Fingerprint(root.Cert) {
			t.Errorf("%s intermediate: %+v", cr.Source, in)
		}
	}
	for u, n := range fake.calls {
		if n != 1 {
			t.Errorf("%s fetched %d times", u, n)
		}
	}
}

func TestCRLStageWithoutIssuerOrServer(t *testing.T) {
	srv, _, fake := crlTarget(t)
	delete(fake.lists, "http://crl.test/int.crl")
	o := opts()
	o.CRL = fake // no CRLIssuers: the root that signs the intermediate's CRL is unknown
	rep := scan(t, srv, o)
	cr := rep.Certificates[0]
	if len(cr.CRL) != 2 {
		t.Fatalf("%+v", cr.CRL)
	}
	if r := cr.CRL[0]; r.Status != pki.CRLUnknown || !strings.Contains(r.Problem, "connection refused") {
		t.Errorf("unreachable CRL: %+v", r)
	}
	if r := cr.CRL[1]; r.Status != pki.CRLUnknown || r.Signature != pki.CRLSigNoIssuer {
		t.Errorf("no issuer: %+v", r)
	}
}

// Off by default: no CRL is fetched and the report says lookups did not happen.
func TestCRLStageOffByDefault(t *testing.T) {
	srv, _, _ := crlTarget(t)
	rep := scan(t, srv, opts())
	if rep.CRLLookups || len(rep.Certificates) == 0 || len(rep.Certificates[0].CRL) != 0 {
		t.Errorf("lookups off, yet: %v %+v", rep.CRLLookups, rep.Certificates)
	}
	if rev := stageMap(rep)["revocation"]; !strings.Contains(rev.Reason, "CRL lookups are off") {
		t.Errorf("revocation stage %+v", rev)
	}
}

// A served cross-signed copy of a known root ends the walk: the root is the anchor clients use,
// so the cross-sign's CRL (whose issuer may be unknown) is not looked up.
func TestCRLStageStopsAtAServedAnchor(t *testing.T) {
	root := pkitest.NewRoot(t, "CRL Root", pkitest.CAOpts{})
	other := pkitest.NewRoot(t, "Old Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "CRL Intermediate", pkitest.CAOpts{CRL: []string{"http://crl.test/root.crl"}})
	cross := other.CrossSign(t, root, pkitest.CAOpts{CRL: []string{"http://crl.test/old.crl"}})
	now := time.Now()
	tc := inter.TLS(t, pkitest.LeafOpts{DNS: []string{"leaf.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		CRL: []string{"http://crl.test/int.crl"}}, inter.Cert, cross)
	fake := &fakeCRLs{calls: map[string]int{}, lists: map[string]*x509.RevocationList{
		"http://crl.test/int.crl":  inter.CRL(t, nil, now.Add(-time.Hour), now.Add(24*time.Hour)),
		"http://crl.test/root.crl": root.CRL(t, nil, now.Add(-time.Hour), now.Add(24*time.Hour)),
	}}
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{tc}})
	o := opts()
	o.CRL, o.CRLIssuers = fake, []*x509.Certificate{root.Cert}
	rep := scan(t, srv, o)
	cr := rep.Certificates[0]
	if len(cr.CRL) != 2 || cr.CRL[0].Status != pki.CRLGood || cr.CRL[1].Status != pki.CRLGood {
		t.Errorf("results %+v", cr.CRL)
	}
	if fake.calls["http://crl.test/old.crl"] != 0 {
		t.Error("the cross-sign's CRL was fetched")
	}
}
