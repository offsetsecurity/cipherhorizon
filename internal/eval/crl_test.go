package eval_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The CRL fixtures are OpenSSL's (testing/pki/make-crl.sh); the results are what the scanner's
// CRL step records: pki.JudgeCRL over each fetched CRL.

var crlEvalAt = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func crlPEM(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pki", "testdata", "crl", name+".pem"))
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

func judged(t *testing.T, crl, url string, pos int, subject, issuer *x509.Certificate) pki.CRLResult {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pki", "testdata", "crl", crl+".crl"))
	if err != nil {
		t.Fatal(err)
	}
	rl, err := x509.ParseRevocationList(b)
	if err != nil {
		t.Fatal(err)
	}
	r := pki.JudgeCRL(rl, url, subject, issuer, crlEvalAt)
	r.Position, r.SHA256 = pos, pki.Fingerprint(subject)
	return r
}

// crlEval evaluates leaf+int from the CRL fixture PKI with the given CRL results, against a
// store holding the fixture root.
func crlEval(t *testing.T, lookups bool, results ...pki.CRLResult) eval.Evaluation {
	t.Helper()
	root, inter, leaf := crlPEM(t, "root"), crlPEM(t, "int"), crlPEM(t, "leaf")
	st, err := pki.NewStore("Mozilla", "2026-06-01", true, []pki.Root{{DER: root.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	cr := chainResult("tls-default", leaf, inter)
	cr.CRL = results
	rep := v2(cr)
	rep.Target = tlsprobe.Target{Host: "leaf.test", Port: 443, SNI: "leaf.test"}
	rep.CRLLookups = lookups
	return eval.EvaluateWith(rep, eval.Input{Now: crlEvalAt, Stores: []*pki.Store{st}})
}

// crlEvals fire every CRL rule (for the rule matrix).
func crlEvals(t *testing.T) []eval.Evaluation {
	root, inter, leaf := crlPEM(t, "root"), crlPEM(t, "int"), crlPEM(t, "leaf")
	stale := pki.CRLResult{Position: 1, SHA256: pki.Fingerprint(inter), URL: "http://crl.pki.test/root.crl", Status: pki.CRLGood,
		Signature: pki.CRLSigValid, NextUpdate: crlEvalAt.AddDate(0, 0, -3)}
	return []eval.Evaluation{
		crlEval(t, true, judged(t, "int-revoked", "http://crl.pki.test/int.crl", 0, leaf, inter), judged(t, "root-revoked", "http://crl.pki.test/root.crl", 1, inter, root)),
		crlEval(t, true, judged(t, "bad", "http://crl.pki.test/int.crl", 0, leaf, inter), stale),
	}
}

func findingsOf(ev eval.Evaluation, id string) []eval.Finding {
	var out []eval.Finding
	for _, f := range ev.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func checkResult(ev eval.Evaluation, id string) string {
	for _, c := range ev.Checks {
		if c.ID == id {
			return c.Result
		}
	}
	return ""
}

// TestRevokedChainIsAFindingNotAGate: a leaf on its issuer's CRL and an intermediate on the
// root's CRL are each reported, with reason and date; the chain is still trusted by the store
// (revocation is a status beside trust) and every other rule still ran.
func TestRevokedChainIsAFindingNotAGate(t *testing.T) {
	ev := crlEvals(t)[0]
	rv := findingsOf(ev, "REV.REVOKED")
	if len(rv) != 1 || rv[0].Severity != eval.Critical || !rv[0].Availability {
		t.Fatalf("REV.REVOKED: %+v", rv)
	}
	for _, want := range []string{"the leaf is revoked (keyCompromise) since 2026-05-01", `intermediate "CipherHorizon CRL Test Intermediate" is revoked (cACompromise) since 2026-05-15`,
		"its private key is reported compromised", "everything below it on the chain", "http://crl.pki.test/root.crl"} {
		if !strings.Contains(rv[0].Detail, want) {
			t.Errorf("detail lacks %q: %s", want, rv[0].Detail)
		}
	}
	if tr := ev.PKI[0].Trust; len(tr) != 1 || !tr[0].Trusted {
		t.Errorf("revocation changed the trust verdict: %+v", tr)
	}
	if len(findingsOf(ev, "REV.UNKNOWN")) != 0 || checkResult(ev, "REV.UNKNOWN") != "not-found" {
		t.Errorf("a revoked answer is an answer: %+v", findingsOf(ev, "REV.UNKNOWN"))
	}
	if checkResult(ev, "PROTO.TLS10") == "" || checkResult(ev, "CERT.EXPIRING") == "" {
		t.Error("other checks did not run")
	}
}

func TestBadSignatureStaleAndUnknown(t *testing.T) {
	ev := crlEvals(t)[1]
	if f := findingsOf(ev, "REV.CRL-BAD-SIGNATURE"); len(f) != 1 || !strings.Contains(f[0].Detail, "for the leaf does not verify") {
		t.Errorf("bad signature: %+v", f)
	}
	if f := findingsOf(ev, "REV.CRL-STALE"); len(f) != 1 || !strings.Contains(f[0].Detail, "due to be replaced on 2026-09-28") {
		t.Errorf("stale: %+v", f)
	}
	if f := findingsOf(ev, "REV.UNKNOWN"); len(f) != 1 || !strings.Contains(f[0].Detail, "the leaf: http://crl.pki.test/int.crl: the CRL's signature does not verify") {
		t.Errorf("unknown: %+v", f)
	}
	if len(findingsOf(ev, "REV.REVOKED")) != 0 {
		t.Error("an unverified CRL revoked something")
	}
}

// TestCurrentCRLVouchesForTheLeaf: a good, signed, current CRL for the leaf makes revocation
// known, without a staple.
func TestCurrentCRLVouchesForTheLeaf(t *testing.T) {
	inter, leaf := crlPEM(t, "int"), crlPEM(t, "leaf")
	ev := crlEval(t, true, judged(t, "int-empty", "http://crl.pki.test/int.crl", 0, leaf, inter))
	for _, s := range ev.Sections {
		if s.ID == eval.SecRevocation && s.Status == eval.StatusUnknown {
			t.Errorf("a current CRL should vouch: %+v", s)
		}
	}
	for _, id := range []string{"REV.REVOKED", "REV.CRL-BAD-SIGNATURE", "REV.CRL-STALE", "REV.UNKNOWN"} {
		if r := checkResult(ev, id); r != "not-found" {
			t.Errorf("%s: %s", id, r)
		}
	}
	// Lookups off: the same chain's CRL checks are not checked, and the section says why.
	off := crlEval(t, false)
	for _, id := range []string{"REV.REVOKED", "REV.UNKNOWN"} {
		if r := checkResult(off, id); r != "not-checked" {
			t.Errorf("lookups off, %s: %s", id, r)
		}
	}
	for _, s := range off.Sections {
		if s.ID == eval.SecRevocation && s.Status == eval.StatusUnknown && !strings.Contains(s.Reason, "CRL lookups were off") {
			t.Errorf("lookups off, section: %+v", s)
		}
	}
}
