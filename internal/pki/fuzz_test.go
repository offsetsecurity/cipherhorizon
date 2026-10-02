package pki_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
)

func FuzzParseOCSP(f *testing.F) {
	for _, n := range []string{"ocsp-good", "ocsp-revoked", "ocsp-unknown", "ocsp-delegated", "ocsp-trylater"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n+".der")); err == nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {

		o, err := pki.ParseOCSP(b)
		if err != nil {
			return
		}
		if o.Status == "successful" && len(o.Responses) == 0 {
			t.Fatal("successful response without single responses")
		}
		for _, r := range o.Responses {
			if r.Serial == nil {
				t.Fatal("nil serial")
			}
		}
		_, _ = o.VerifySignature(nil)
	})
}

func FuzzParseSCTList(f *testing.F) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f.Add(pkitest.SCTList([]pkitest.SCTSpec{{Timestamp: ts}}))
	f.Add(pkitest.SCTList([]pkitest.SCTSpec{{Timestamp: ts}, {LogID: [32]byte{9}, Timestamp: ts}}))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		scts, err := pki.ParseSCTList(b)
		if err != nil {
			return
		}
		if len(scts) > pki.MaxSCTs {
			t.Fatalf("%d SCTs", len(scts))
		}
		for _, s := range scts {
			if len(s.Signature) > len(b) || len(s.Extensions) > len(b) {
				t.Fatal("field longer than input")
			}
		}
	})
}

// FuzzServedChain feeds random byte sequences, split into "certificates", to
// the chain analysis.
func FuzzServedChain(f *testing.F) {
	f.Add([]byte("a"), []byte("b"), []byte("c"))
	root := pkitest.NewRoot(f, "Root", pkitest.CAOpts{})
	inter := root.Intermediate(f, "Inter", pkitest.CAOpts{})
	leaf := inter.Leaf(f, pkitest.LeafOpts{})
	f.Add(leaf.Raw, inter.Cert.Raw, root.Cert.Raw)
	f.Add(leaf.Raw, root.Cert.Raw, inter.Cert.Raw)
	f.Add(leaf.Raw, leaf.Raw, inter.Cert.Raw[:40])
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		s, err := pki.AnalyzeServed([][]byte{a, b, c})
		if err != nil {
			return
		}
		if len(s.Path) == 0 || s.Path[0] != 0 {
			t.Fatalf("path %v", s.Path)
		}
		_ = s.ExpiresFirst()
		_, _, _ = s.MissingIssuer()
	})
}
