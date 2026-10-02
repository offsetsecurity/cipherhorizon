package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
)

// TestWriteOracleFixtures writes the served-chain fixtures and this package's
// trust verdict for each, for testing/pki/oracle.sh to check against
// `openssl verify` (QA-PLAN-004 §1, T1-M2). It runs only when PKI_ORACLE_DIR
// is set. Root-program constraints (distrust-after, sct_not_after, program
// name constraints) are not certificate contents, so OpenSSL cannot judge
// them; those fixtures are covered by TestValidate instead.
func TestWriteOracleFixtures(t *testing.T) {
	dir := os.Getenv("PKI_ORACLE_DIR")
	if dir == "" {
		t.Skip("PKI_ORACLE_DIR not set")
	}
	root := pkitest.NewRoot(t, "Oracle Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "Oracle Intermediate", pkitest.CAOpts{})
	other := pkitest.NewRoot(t, "Unrelated Root", pkitest.CAOpts{})
	expiredInter := root.Intermediate(t, "Expired Intermediate", pkitest.CAOpts{NotBefore: epoch.AddDate(-2, 0, 0), NotAfter: epoch.AddDate(0, 0, -1)})
	constrained := root.Intermediate(t, "Constrained Intermediate", pkitest.CAOpts{PermittedDNS: []string{"example.test"}})
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	cases := []struct {
		name   string
		served []*x509.Certificate
		at     time.Time
	}{
		{"clean", []*x509.Certificate{leaf, inter.Cert}, epoch},
		{"missing-intermediate", []*x509.Certificate{leaf}, epoch},
		{"wrong-order", []*x509.Certificate{leaf, root.Cert, inter.Cert}, epoch},
		{"root-included", []*x509.Certificate{leaf, inter.Cert, root.Cert}, epoch},
		{"duplicate", []*x509.Certificate{leaf, inter.Cert, inter.Cert}, epoch},
		{"unrelated-extra", []*x509.Certificate{leaf, inter.Cert, other.Cert}, epoch},
		{"leaf-expired", []*x509.Certificate{leaf, inter.Cert}, leaf.NotAfter.AddDate(0, 0, 1)},
		{"leaf-not-yet-valid", []*x509.Certificate{leaf, inter.Cert}, leaf.NotBefore.AddDate(0, 0, -1)},
		{"intermediate-expired", []*x509.Certificate{expiredInter.Leaf(t, pkitest.LeafOpts{NotBefore: epoch.AddDate(0, -2, 0)}), expiredInter.Cert}, epoch},
		{"client-auth-only", []*x509.Certificate{inter.Leaf(t, pkitest.LeafOpts{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}), inter.Cert}, epoch},
		{"no-eku", []*x509.Certificate{inter.Leaf(t, pkitest.LeafOpts{NoEKU: true}), inter.Cert}, epoch},
		{"name-constraint-ok", []*x509.Certificate{constrained.Leaf(t, pkitest.LeafOpts{DNS: []string{"www.example.test"}}), constrained.Cert}, epoch},
		{"name-constraint-violated", []*x509.Certificate{constrained.Leaf(t, pkitest.LeafOpts{DNS: []string{"www.other.test"}}), constrained.Cert}, epoch},
		{"self-signed-leaf", []*x509.Certificate{other.Leaf(t, pkitest.LeafOpts{})}, epoch},
		{"wrong-root-in-store", []*x509.Certificate{leaf, inter.Cert}, epoch},
	}
	store, err := pki.NewStore("oracle", "", false, []pki.Root{{DER: root.Cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := pki.NewStore("oracle-other", "", false, []pki.Root{{DER: other.Cert.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		d := filepath.Join(dir, c.name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		st, anchor := store, root.Cert
		if c.name == "wrong-root-in-store" {
			st, anchor = otherStore, other.Cert
		}
		writePEM(t, filepath.Join(d, "anchors.pem"), anchor)
		writePEM(t, filepath.Join(d, "leaf.pem"), c.served[0])
		writePEM(t, filepath.Join(d, "untrusted.pem"), c.served[1:]...)
		s, err := pki.AnalyzeServed(pkitest.DER(c.served...))
		if err != nil {
			t.Fatal(err)
		}
		r := pki.Validate(s, st, c.at, nil)
		verdict := "untrusted"
		if r.Trusted {
			verdict = "trusted"
		}
		meta := fmt.Sprintf("%s %d\n", verdict, c.at.Unix())
		if err := os.WriteFile(filepath.Join(d, "expect"), []byte(meta), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writePEM(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
