package pki_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/pki"
	"github.com/example/cipherhorizon/internal/pki/pkitest"
)

var epoch = pkitest.Epoch

func store(t *testing.T, name string, constrained bool, roots ...pki.Root) *pki.Store {
	t.Helper()
	s, err := pki.NewStore(name, "2026-06-01", constrained, roots)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rootOf(ca *pkitest.CA) pki.Root { return pki.Root{DER: ca.Cert.Raw} }

func analyze(t *testing.T, certs ...*x509.Certificate) *pki.Served {
	t.Helper()
	s, err := pki.AnalyzeServed(pkitest.DER(certs...))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func kinds(s *pki.Served) string {
	var k []string
	for _, i := range s.Issues {
		k = append(k, i.Kind)
	}
	return strings.Join(k, ",")
}

func TestServedChain(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "Inter", pkitest.CAOpts{})
	inter2 := root.Intermediate(t, "Inter Two", pkitest.CAOpts{})
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	other := pkitest.NewRoot(t, "Unrelated", pkitest.CAOpts{})

	cases := []struct {
		name   string
		certs  []*x509.Certificate
		issues string
		path   int
	}{
		{"clean", []*x509.Certificate{leaf, inter.Cert}, "", 2},
		{"root included", []*x509.Certificate{leaf, inter.Cert, root.Cert}, "root", 3},
		{"wrong order", []*x509.Certificate{leaf, root.Cert, inter.Cert}, "order,root", 3},
		{"duplicate", []*x509.Certificate{leaf, inter.Cert, inter.Cert}, "duplicate", 2},
		{"unrelated", []*x509.Certificate{leaf, inter.Cert, other.Cert}, "unrelated", 2},
		{"sibling intermediate", []*x509.Certificate{leaf, inter2.Cert, inter.Cert}, "order,unrelated", 2},
		{"leaf only", []*x509.Certificate{leaf}, "", 1},
	}
	for _, c := range cases {
		s := analyze(t, c.certs...)
		if got := kinds(s); got != c.issues {
			t.Errorf("%s: issues %q, want %q (%+v)", c.name, got, c.issues, s.Issues)
		}
		if len(s.Path) != c.path {
			t.Errorf("%s: path %v, want length %d", c.name, s.Path, c.path)
		}
		size := 0
		for _, x := range c.certs {
			size += len(x.Raw)
		}
		if s.SizeBytes != size {
			t.Errorf("%s: size %d, want %d (REQ-TCHN-6)", c.name, s.SizeBytes, size)
		}
	}

	st := store(t, "Test", true, rootOf(root))
	if m, _, _ := analyze(t, leaf, inter.Cert).MissingIssuer(st); m {
		t.Error("complete chain reported a missing issuer")
	}
	m, dn, _ := analyze(t, leaf).MissingIssuer(st)
	if !m || !strings.Contains(dn, "Inter") {
		t.Errorf("leaf-only chain: missing=%v issuer=%q", m, dn)
	}
	// An intermediate issued directly by a root in a store is complete.
	direct := root.Leaf(t, pkitest.LeafOpts{})
	if m, _, _ := analyze(t, direct).MissingIssuer(st); m {
		t.Error("leaf issued by the root reported a missing issuer")
	}
	// A self-signed leaf is not "missing an intermediate".
	if m, _, _ := analyze(t, other.Cert).MissingIssuer(st); m {
		t.Error("self-signed certificate reported a missing issuer")
	}
	if _, err := pki.AnalyzeServed([][]byte{[]byte("junk")}); err == nil {
		t.Error("unparseable leaf accepted")
	}
	if s, err := pki.AnalyzeServed([][]byte{leaf.Raw, []byte("junk"), inter.Cert.Raw}); err != nil || kinds(s) != "unparsed,order" {
		t.Errorf("unparseable intermediate: %v %q", err, kinds(s))
	}
}

func TestExpiresFirst(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	short := root.Intermediate(t, "Short", pkitest.CAOpts{NotAfter: epoch.AddDate(0, 0, 10)})
	leaf := short.Leaf(t, pkitest.LeafOpts{})
	if got := analyze(t, leaf, short.Cert).ExpiresFirst(); len(got) != 1 || got[0] != 1 {
		t.Errorf("ExpiresFirst = %v", got)
	}
	long := root.Intermediate(t, "Long", pkitest.CAOpts{})
	if got := analyze(t, long.Leaf(t, pkitest.LeafOpts{}), long.Cert).ExpiresFirst(); len(got) != 0 {
		t.Errorf("ExpiresFirst = %v", got)
	}
}

func TestValidate(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	inter := root.Intermediate(t, "Inter", pkitest.CAOpts{})
	leaf := inter.Leaf(t, pkitest.LeafOpts{})
	now := epoch

	plain := store(t, "Plain", true, rootOf(root))
	if r := pki.Validate(analyze(t, leaf, inter.Cert), plain, now, nil); !r.Trusted || len(r.Path) != 3 {
		t.Errorf("clean chain: %+v", r)
	}
	if r := pki.Validate(analyze(t, leaf), plain, now, nil); r.Trusted || r.Error == "" {
		t.Errorf("missing intermediate validated (no AIA allowed): %+v", r)
	}
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Empty", true, rootOf(pkitest.NewRoot(t, "Else", pkitest.CAOpts{}))), now, nil); r.Trusted {
		t.Errorf("trusted by a store without its root: %+v", r)
	}

	// Mozilla-style distrust after a date.
	distrusted := rootOf(root)
	distrusted.DistrustAfter = leaf.NotBefore.Add(-48 * time.Hour)
	r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Mozilla", true, distrusted), now, nil)
	if r.Trusted || !strings.Contains(r.Distrust, "distrusted for certificates issued after") {
		t.Errorf("distrust-after ignored: %+v", r)
	}
	// Unconstrained (private) stores do not apply constraints.
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "private", false, distrusted), now, nil); !r.Trusted {
		t.Errorf("private store applied a constraint: %+v", r)
	}
	// Issued on the cut-off date itself: still trusted.
	onDay := rootOf(root)
	onDay.DistrustAfter = leaf.NotBefore
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Mozilla", true, onDay), now, nil); !r.Trusted {
		t.Errorf("issued on the cut-off: %+v", r)
	}

	// Chrome-style sct_not_after.
	sctRoot := rootOf(root)
	sctRoot.SCTNotAfter = leaf.NotBefore.Add(-time.Hour)
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Chrome", true, sctRoot), now, []time.Time{leaf.NotBefore}); r.Trusted || r.Distrust == "" {
		t.Errorf("late SCT accepted: %+v", r)
	}
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Chrome", true, sctRoot), now, []time.Time{leaf.NotBefore, sctRoot.SCTNotAfter}); !r.Trusted {
		t.Errorf("one SCT in time should satisfy the constraint: %+v", r)
	}
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Chrome", true, sctRoot), now, nil); r.Trusted {
		t.Errorf("no SCTs and notBefore after the limit: %+v", r)
	}

	// Root-program name constraints.
	named := rootOf(root)
	named.PermittedDNS = []string{"tr"}
	if r := pki.Validate(analyze(t, leaf, inter.Cert), store(t, "Mozilla", true, named), now, nil); r.Trusted {
		t.Errorf("name constraint ignored: %+v", r)
	}
	trLeaf := inter.Leaf(t, pkitest.LeafOpts{DNS: []string{"www.example.com.tr"}})
	if r := pki.Validate(analyze(t, trLeaf, inter.Cert), store(t, "Mozilla", true, named), now, nil); !r.Trusted {
		t.Errorf("name inside the constraint: %+v", r)
	}

	// Expired: the path holds, only time is wrong.
	if r := pki.Validate(analyze(t, leaf, inter.Cert), plain, leaf.NotAfter.Add(time.Hour), nil); r.Trusted || !r.ExpiredOnly {
		t.Errorf("expired leaf: %+v", r)
	}
	// No serverAuth.
	client := inter.Leaf(t, pkitest.LeafOpts{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if r := pki.Validate(analyze(t, client, inter.Cert), plain, now, nil); r.Trusted || !strings.Contains(r.Error, "server authentication") {
		t.Errorf("clientAuth-only leaf: %+v", r)
	}
}

func TestNameMatch(t *testing.T) {
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	leaf := root.Leaf(t, pkitest.LeafOpts{CN: "cn-only.test", DNS: []string{"*.example.test", "exact.test"}})
	for host, want := range map[string]string{
		"a.example.test": "DNS:*.example.test", "EXACT.test": "DNS:exact.test",
	} {
		got, err := pki.NameMatch(leaf, host)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", host, got, err)
		}
	}
	for _, host := range []string{"example.test", "a.b.example.test", "cn-only.test"} {
		if _, err := pki.NameMatch(leaf, host); err == nil {
			t.Errorf("%s matched", host)
		}
	}
}

func TestSCTList(t *testing.T) {
	ts := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	specs := []pkitest.SCTSpec{{LogID: [32]byte{1}, Timestamp: ts}, {LogID: [32]byte{2}, Timestamp: ts.Add(time.Hour)}}
	scts, err := pki.ParseSCTList(pkitest.SCTList(specs))
	if err != nil || len(scts) != 2 || scts[1].LogID[0] != 2 || !scts[0].Timestamp.Equal(ts) {
		t.Fatalf("round trip: %+v %v", scts, err)
	}
	root := pkitest.NewRoot(t, "Root", pkitest.CAOpts{})
	leaf := root.Leaf(t, pkitest.LeafOpts{SCTs: specs})
	if e, err := pki.EmbeddedSCTs(leaf); err != nil || len(e) != 2 {
		t.Errorf("embedded: %v %v", e, err)
	}
	good := pkitest.SCTList(specs)
	for name, b := range map[string][]byte{
		"empty":           nil,
		"total too long":  append([]byte{0xff, 0xff}, good[2:]...),
		"entry overrun":   {0, 3, 0, 9, 0},
		"truncated sct":   {0, 4, 0, 2, 0, 0},
		"trailing sig":    append(append([]byte(nil), good...), 0),
		"bad version":     func() []byte { b := append([]byte(nil), good...); b[4] = 1; return b }(),
		"zero-length sct": {0, 2, 0, 0},
	} {
		if _, err := pki.ParseSCTList(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	many := make([]pkitest.SCTSpec, pki.MaxSCTs+1)
	if _, err := pki.ParseSCTList(pkitest.SCTList(many)); err == nil {
		t.Error("more than MaxSCTs accepted")
	}
}

// ---- OCSP, against OpenSSL-made fixtures ------------------------------------------

func readCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readOCSP(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".der"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// oracle reads the fields OpenSSL printed for a response (`openssl ocsp -resp_text`).
func oracle(t *testing.T, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	re := regexp.MustCompile(`^\s+(Cert Status|Serial Number|This Update|Next Update|Revocation Time|Revocation Reason|Hash Algorithm|Issuer Name Hash|Issuer Key Hash|Produced At): (.*)$`)
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		if m := re.FindStringSubmatch(l); m != nil {
			if _, dup := out[m[1]]; !dup {
				out[m[1]] = strings.TrimSpace(m[2])
			}
		}
	}
	return out
}

func opensslTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse("Jan _2 15:04:05 2006 MST", s)
	if err != nil {
		t.Fatalf("oracle time %q: %v", s, err)
	}
	return v
}

func TestOCSPAgainstOpenSSL(t *testing.T) {
	issuer := readCert(t, "int.pem")
	leaf := readCert(t, "leaf.pem")
	other := readCert(t, "other.pem")
	for _, name := range []string{"ocsp-good", "ocsp-revoked", "ocsp-unknown", "ocsp-other", "ocsp-delegated"} {
		o, err := pki.ParseOCSP(readOCSP(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := oracle(t, name)
		if o.Status != "successful" || len(o.Responses) != 1 {
			t.Fatalf("%s: %+v", name, o)
		}
		r := o.Responses[0]
		if !strings.EqualFold(r.Serial.Text(16), want["Serial Number"]) {
			t.Errorf("%s: serial %s, OpenSSL %s", name, r.Serial.Text(16), want["Serial Number"])
		}
		if r.Status != want["Cert Status"] {
			t.Errorf("%s: status %s, OpenSSL %s", name, r.Status, want["Cert Status"])
		}
		if !r.ThisUpdate.Equal(opensslTime(t, want["This Update"])) || !r.NextUpdate.Equal(opensslTime(t, want["Next Update"])) {
			t.Errorf("%s: this/next %v %v, OpenSSL %s %s", name, r.ThisUpdate, r.NextUpdate, want["This Update"], want["Next Update"])
		}
		if !o.ProducedAt.Equal(opensslTime(t, want["Produced At"])) {
			t.Errorf("%s: producedAt %v", name, o.ProducedAt)
		}
		if !strings.EqualFold(want["Hash Algorithm"], strings.ReplaceAll(r.HashAlg, "-", "")) {
			t.Errorf("%s: hash %s, OpenSSL %s", name, r.HashAlg, want["Hash Algorithm"])
		}
		if r.Status == "revoked" {
			if !r.RevokedAt.Equal(opensslTime(t, want["Revocation Time"])) || r.Reason != 1 || !strings.HasPrefix(want["Revocation Reason"], "keyCompromise") {
				t.Errorf("%s: revoked %v reason %d, OpenSSL %s %s", name, r.RevokedAt, r.Reason, want["Revocation Time"], want["Revocation Reason"])
			}
		}
		target := leaf
		if name == "ocsp-other" {
			target = other
		}
		if _, ok := o.Match(target, issuer); !ok {
			t.Errorf("%s: does not match its own certificate", name)
		}
		if name == "ocsp-other" {
			if _, ok := o.Match(leaf, issuer); ok {
				t.Errorf("%s: a staple for another certificate matched the leaf", name)
			}
		}
		sig, by := o.VerifySignature(issuer)
		if sig != pki.SigValid {
			t.Errorf("%s: signature %s", name, sig)
		}
		if (name == "ocsp-delegated") != (by != nil) {
			t.Errorf("%s: delegated responder = %v", name, by)
		}
	}
}

func TestOCSPTamperedAndHostile(t *testing.T) {
	issuer := readCert(t, "int.pem")
	good := readOCSP(t, "ocsp-good")
	o, _ := pki.ParseOCSP(good)
	if sig, _ := o.VerifySignature(issuer); sig != pki.SigValid {
		t.Fatalf("baseline signature %s", sig)
	}
	// Flip a bit inside the signed tbsResponseData (the serial's last byte sits there).
	tampered := append([]byte(nil), good...)
	i := strings.Index(string(tampered), "\x02\x02\x10\x01") // INTEGER 0x1001
	if i < 0 {
		t.Fatal("serial not found in fixture")
	}
	tampered[i+3] ^= 0x01
	o2, err := pki.ParseOCSP(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if sig, _ := o2.VerifySignature(issuer); sig != pki.SigInvalid {
		t.Errorf("tampered response: signature %s", sig)
	}
	if sig, _ := o.VerifySignature(nil); sig != pki.SigNoIssuer {
		t.Errorf("no issuer: %s", sig)
	}
	// A different CA's key does not verify it.
	if sig, _ := o.VerifySignature(readCert(t, "root.pem")); sig != pki.SigInvalid {
		t.Errorf("wrong issuer: %s", sig)
	}

	tl, err := pki.ParseOCSP(readOCSP(t, "ocsp-trylater"))
	if err != nil || tl.Status != "tryLater" || len(tl.Responses) != 0 {
		t.Errorf("tryLater: %+v %v", tl, err)
	}
	for name, b := range map[string][]byte{
		"empty":        nil,
		"trailing":     append(append([]byte(nil), good...), 0),
		"truncated":    good[:len(good)-5],
		"too long":     make([]byte, pki.MaxOCSPBytes+1),
		"bad status":   {0x30, 0x03, 0x0a, 0x01, 0x04},
		"not sequence": {0x04, 0x00},
	} {
		if _, err := pki.ParseOCSP(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMustStapleFixture(t *testing.T) {
	c := readCert(t, "leaf-muststaple.pem")
	found := false
	for _, e := range c.Extensions {
		if e.Id.String() == "1.3.6.1.5.5.7.1.24" {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture lacks the TLS Feature extension")
	}
}
