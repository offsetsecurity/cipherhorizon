package pki_test

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
)

// emudhraG3C is the SPKI SHA-256 of "EM OV TLS CA - G3C", whose P-384 private key is 4.
const emudhraG3C = "63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8"

var compromised = pki.Listed{Name: "Weak CA", Kind: pki.KindKeyCompromise, Incident: "test-incident",
	Title: "test CA keys recoverable", Since: "2026-10-17", Sources: []string{"https://example.test/"}}

// weakChain is root -> intermediate with private key 4 on P-384 -> leaf: the
// shape of the eMudhra compromise, with our own root.
func weakChain(t *testing.T) (root, inter *pkitest.CA) {
	t.Helper()
	root = pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	inter = root.IntermediateWithKey(t, "Weak CA", pkitest.CAOpts{}, pkitest.SmallScalarKey(t, elliptic.P384(), 4))
	return root, inter
}

// TestSmallScalarKeyIsTheRealKey pins the fixture to the incident: a P-384 key
// with private scalar 4 has exactly the public key of the real eMudhra CA.
func TestSmallScalarKeyIsTheRealKey(t *testing.T) {
	_, inter := weakChain(t)
	if got := pki.SPKIFingerprint(inter.Cert); got != emudhraG3C {
		t.Fatalf("d=4 on P-384 gives SPKI %s, want %s", got, emudhraG3C)
	}
}

// TestDistrustedKeyIsReportedNotDropped is the P0 build guard: on any Go
// version (Go 1.27.3+ silently drops the path, older ones accept it) the
// result says the store does not trust the chain, says why, and keeps the
// whole signature-valid path with the listed certificate's position.
func TestDistrustedKeyIsReportedNotDropped(t *testing.T) {
	root, inter := weakChain(t)
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	dl := pki.NewDistrust()
	dl.Add(emudhraG3C, nil, compromised)

	for _, constrained := range []bool{true, false} {
		st := store(t, "S", constrained, rootOf(root))
		r := pki.Validate(analyze(t, leaf, inter.Cert), st, epoch, nil, dl)
		if r.Trusted {
			t.Errorf("constrained=%v: a path through a listed key was trusted: %+v", constrained, r)
		}
		if !strings.Contains(r.Distrust, `"Weak CA" whose private key is public (test CA keys recoverable, 2026-10-17)`) {
			t.Errorf("constrained=%v: reason %q", constrained, r.Distrust)
		}
		if len(r.Path) != 3 || r.Path[1] != pki.Fingerprint(inter.Cert) || r.Path[2] != pki.Fingerprint(root.Cert) {
			t.Errorf("constrained=%v: path lost: %v", constrained, r.Path)
		}
		if len(r.Listed) != 1 || r.Listed[0].Position != 1 || r.Listed[0].Incident != "test-incident" {
			t.Errorf("constrained=%v: listed %+v", constrained, r.Listed)
		}
		if r.Error != "" {
			t.Errorf("constrained=%v: the raw verifier error leaked: %q", constrained, r.Error)
		}
	}

	// The same chain with no list: whatever crypto/x509 decides, nothing is invented.
	r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "S", true, rootOf(root)), epoch, nil, nil)
	if r.Distrust != "" || len(r.Listed) != 0 {
		t.Errorf("no list, yet listed: %+v", r)
	}
}

// TestDistrustByCertificateFingerprint covers entries known only by certificate hash.
func TestDistrustByCertificateFingerprint(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "Blocked CA", pkitest.CAOpts{})
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	dl := pki.NewDistrust()
	l := compromised
	l.Kind, l.Name = pki.KindCADistrust, "Blocked CA"
	dl.Add("", []string{pki.Fingerprint(inter.Cert)}, l)
	r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "S", true, rootOf(root)), epoch, nil, dl)
	if r.Trusted || !strings.Contains(r.Distrust, "which root programs have blocked") || len(r.Path) != 3 {
		t.Errorf("certificate-hash entry: %+v", r)
	}
	if _, ok := dl.LookupHashes(pki.Fingerprint(inter.Cert), ""); !ok {
		t.Error("LookupHashes by certificate")
	}
	var nilList *pki.Distrust
	if _, ok := nilList.Lookup(inter.Cert); ok || nilList.Len() != 0 {
		t.Error("a nil list matched")
	}
}

// TestPathsFollowsCrossSigns: the same key under two issuers gives one path per
// root, and the list (matched by key) catches both.
func TestPathsFollowsCrossSigns(t *testing.T) {
	rootA := pkitest.NewRoot(t, "Root A", pkitest.CAOpts{})
	rootB := pkitest.NewRoot(t, "Root B", pkitest.CAOpts{})
	inter := rootA.IntermediateWithKey(t, "Weak CA", pkitest.CAOpts{}, pkitest.SmallScalarKey(t, elliptic.P384(), 4))
	cross := rootB.CrossSign(t, inter, pkitest.CAOpts{})
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	s := analyze(t, leaf, inter.Cert, cross)

	paths := pki.Paths(s, store(t, "Both", true, rootOf(rootA), rootOf(rootB)))
	if len(paths) != 2 {
		t.Fatalf("%d paths, want 2", len(paths))
	}
	dl := pki.NewDistrust()
	dl.Add(emudhraG3C, nil, compromised)
	for _, p := range paths {
		if on := dl.ListedOnPath(p); len(on) != 1 || on[0].Position != 1 {
			t.Errorf("path %v: listed %+v", p, on)
		}
	}
	// Only root B: the path goes through the cross-sign.
	r := pki.Validate(s, store(t, "B", true, rootOf(rootB)), epoch, nil, dl)
	if r.Trusted || len(r.Path) != 3 || r.Path[1] != pki.Fingerprint(cross) {
		t.Errorf("via the cross-sign: %+v", r)
	}
	// A root nothing chains to gives no path.
	if p := pki.Paths(s, store(t, "Else", true, rootOf(pkitest.NewRoot(t, "Else", pkitest.CAOpts{})))); len(p) != 0 {
		t.Errorf("paths to an unrelated root: %d", len(p))
	}
}
