package pki_test

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
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

// FuzzJudgeCRL feeds hostile CRLs (a scan fetches them from addresses a target's certificates
// name) through the parser and the judgement: no panic, and an answer is one of the three
// statuses, with "good" or "revoked" only under a valid signature.
func FuzzJudgeCRL(f *testing.F) {
	for _, n := range []string{"int-revoked", "int-empty", "root-revoked", "int-partition", "int-delta", "bad"} {
		if b, err := os.ReadFile(filepath.Join("testdata", "crl", n+".crl")); err == nil {
			f.Add(b)
		}
	}
	leaf, inter := crlCert(f, "leaf"), crlCert(f, "int")
	f.Fuzz(func(t *testing.T, b []byte) {
		rl, err := x509.ParseRevocationList(b)
		if err != nil {
			return
		}
		r := pki.JudgeCRL(rl, "http://crl.pki.test/int.crl", leaf, inter, crlAt)
		switch r.Status {
		case pki.CRLGood, pki.CRLRevoked:
			if r.Signature != pki.CRLSigValid {
				t.Fatalf("%s without a valid signature: %+v", r.Status, r)
			}
		case pki.CRLUnknown:
			if r.Problem == "" {
				t.Fatal("unknown without a reason")
			}
		default:
			t.Fatalf("status %q", r.Status)
		}
	})
}
