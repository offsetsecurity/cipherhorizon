package eval_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/pki"
	"github.com/offsetsecurity/cipherhorizon/internal/pki/pkitest"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The T1 rules need tls-report/2 data: raw certificates, staples, SCTs. These
// fixtures follow QA-PLAN-004 §3. The "public" stores are synthetic stores
// holding the test root, so no real CA is involved.

var epoch = pkitest.Epoch

// t1Rules are the rules added in eval/3 (the matrix asserts each one).
var t1Rules = []string{
	"CERT.CHAIN-INCOMPLETE", "CERT.CHAIN-ORDER", "CERT.CHAIN-EXTRA", "CERT.INTERMEDIATE-EXPIRES", "CERT.LIFETIME",
	"CERT.NO-SERVERAUTH", "CERT.CLIENTAUTH-EKU", "CERT.PARTIAL-TRUST", "CERT.WEAK-EXPONENT",
	"OCSP.REVOKED", "OCSP.MISMATCH", "OCSP.STALE", "OCSP.UNKNOWN", "OCSP.MUST-STAPLE-MISSING", "OCSP.NO-STAPLE",
	"CT.NO-SCTS", "KX.DH-COMMON-PRIME", "HTTP.HSTS-DISABLED", "HTTP.HSTS-SHORT", "HTTP.HSTS-INVALID",
	"HTTP.HSTS-NO-SUBDOMAINS", "CIPHER.CBC", "VULN.DROWN-SHARED-KEY", "CERT.UNTRUSTED",
}

type pkiFix struct {
	root, inter *pkitest.CA
	stores      []*pki.Store
}

var sctOK = []pkitest.SCTSpec{{LogID: [32]byte{1}, Timestamp: epoch.AddDate(0, -1, 0)}}

func newPKI(t *testing.T) *pkiFix {
	t.Helper()
	root := pkitest.NewRoot(t, "Test Root", pkitest.CAOpts{})
	f := &pkiFix{root: root, inter: root.Intermediate(t, "Test Intermediate", pkitest.CAOpts{})}
	for _, n := range []string{"Mozilla", "Chrome"} {
		s, err := pki.NewStore(n, "2026-06-01", true, []pki.Root{{DER: root.Cert.Raw}})
		if err != nil {
			t.Fatal(err)
		}
		f.stores = append(f.stores, s)
	}
	return f
}

func chainResult(source string, certs ...*x509.Certificate) tlsprobe.CertResult {
	cr := tlsprobe.CertResult{Source: source, NameMatches: true}
	for _, c := range certs {
		cr.Chain = append(cr.Chain, tlsprobe.DescribeCertificate(c))
	}
	return cr
}

func doneStages() []tlsprobe.Stage {
	var out []tlsprobe.Stage
	for _, n := range tlsprobe.StageNames {
		out = append(out, tlsprobe.Stage{Name: n, Outcome: tlsprobe.OutcomeDone, Probes: []string{"x"}})
	}
	return out
}

func fullHSTS() *tlsprobe.HSTSResult {
	return tlsprobe.ParseHSTS([]string{"max-age=31536000; includeSubDomains"})
}

// v2 is the modern endpoint as a tls-report/2 with the given chains.
func v2(chains ...tlsprobe.CertResult) *tlsprobe.Report {
	rep := modern()
	rep.SchemaVersion = tlsprobe.SchemaVersion
	rep.Target = tlsprobe.Target{Host: "leaf.test", Port: 443, SNI: "leaf.test"}
	rep.Certificates = chains
	rep.Stages = doneStages()
	rep.HSTSHeader = fullHSTS()
	v := true
	rep.HSTS = &v
	return rep
}

func evalAt(rep *tlsprobe.Report, at time.Time, stores []*pki.Store) eval.Evaluation {
	return eval.EvaluateWith(rep, eval.Input{Now: at, Stores: stores})
}

// t1IDs returns the T1 rule IDs that fired, sorted.
func t1IDs(ev eval.Evaluation) []string {
	want := map[string]bool{}
	for _, id := range t1Rules {
		want[id] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range ev.Findings {
		if want[f.ID] && !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f.ID)
		}
	}
	sort.Strings(out)
	return out
}

func findID(ev eval.Evaluation, id string) []eval.Finding {
	var out []eval.Finding
	for _, f := range ev.Findings {
		if f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func expect(t *testing.T, name string, ev eval.Evaluation, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := t1IDs(ev); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s: T1 findings %v, want %v", name, got, want)
	}
}

// ---- OpenSSL-made fixtures (internal/pki/testdata) ------------------------------

func osslCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pki", "testdata", name))
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

func osslStaple(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pki", "testdata", name+".der"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// osslAt is a moment inside the fixtures' OCSP validity (thisUpdate is when
// make-ocsp.sh ran; nextUpdate a week later).
func osslAt(t *testing.T) time.Time {
	t.Helper()
	o, err := pki.ParseOCSP(osslStaple(t, "ocsp-good"))
	if err != nil {
		t.Fatal(err)
	}
	return o.Responses[0].ThisUpdate.Add(time.Hour)
}

func osslStore(t *testing.T) []*pki.Store {
	t.Helper()
	s, err := pki.NewStore("Mozilla", "test", true, []pki.Root{{DER: osslCert(t, "root.pem").Raw}})
	if err != nil {
		t.Fatal(err)
	}
	return []*pki.Store{s}
}

func stapled(t *testing.T, leafFile string, staple []byte) *tlsprobe.Report {
	cr := chainResult("tls-default", osslCert(t, leafFile), osslCert(t, "int.pem"))
	if staple != nil {
		cr.OCSPStaple = base64.StdEncoding.EncodeToString(staple)
	}
	return v2(cr)
}

// ---- the matrix -------------------------------------------------------------------

func TestT1ChainMatrix(t *testing.T) {
	f := newPKI(t)
	in := f.inter.Cert
	// The AIA URL matters: an issuer the certificate says can be downloaded is still missing (nothing is fetched).
	clean := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, AIA: []string{"http://ca.test/inter.der"}})

	ev := evalAt(v2(chainResult("tls-default", clean, in)), epoch, f.stores)
	expect(t, "clean", ev)
	if v := ev.PKI[0]; !v.Public || len(v.Trust) != 2 || !v.Trust[0].Trusted || v.Names.MatchedBy != "DNS:leaf.test" || len(v.SCTs) != 1 || v.SCTs[0].Source != "embedded" {
		t.Errorf("clean view: %+v", v)
	}

	ev = evalAt(v2(chainResult("tls-default", clean)), epoch, f.stores)
	expect(t, "missing intermediate", ev, "CERT.CHAIN-INCOMPLETE", "CERT.UNTRUSTED")
	if fs := findID(ev, "CERT.CHAIN-INCOMPLETE"); len(fs) != 1 || !fs[0].Availability || !strings.Contains(fs[0].Detail, "Test Intermediate") {
		t.Errorf("missing intermediate: %+v", fs)
	}

	wrong := v2(chainResult("tls-default", clean, f.root.Cert, in))
	ev = evalAt(wrong, epoch, f.stores)
	expect(t, "wrong order (TLS 1.3 server)", ev, "CERT.CHAIN-ORDER", "CERT.CHAIN-EXTRA")
	if fs := findID(ev, "CERT.CHAIN-ORDER"); fs[0].Severity != eval.Low {
		t.Errorf("order on a TLS 1.3 server: %s", fs[0].Severity)
	}
	wrong.Protocols, wrong.Negotiated = protocols("TLSv1.2"), &tlsprobe.Negotiated{Version: "TLSv1.2"}
	if fs := findID(evalAt(wrong, epoch, f.stores), "CERT.CHAIN-ORDER"); len(fs) != 1 || fs[0].Severity != eval.Medium {
		t.Errorf("order on a TLS 1.2-only server: %+v", fs)
	}

	expect(t, "root included", evalAt(v2(chainResult("tls-default", clean, in, f.root.Cert)), epoch, f.stores), "CERT.CHAIN-EXTRA")
	expect(t, "duplicate", evalAt(v2(chainResult("tls-default", clean, in, in)), epoch, f.stores), "CERT.CHAIN-EXTRA")
	other := pkitest.NewRoot(t, "Unrelated", pkitest.CAOpts{})
	expect(t, "unrelated", evalAt(v2(chainResult("tls-default", clean, in, other.Cert)), epoch, f.stores), "CERT.CHAIN-EXTRA")

	short := f.root.Intermediate(t, "Short Intermediate", pkitest.CAOpts{NotAfter: epoch.AddDate(0, 0, 20)})
	expect(t, "intermediate expires first",
		evalAt(v2(chainResult("tls-default", short.Leaf(t, pkitest.LeafOpts{SCTs: sctOK}), short.Cert)), epoch, f.stores),
		"CERT.INTERMEDIATE-EXPIRES")

	noSA := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	ev = evalAt(v2(chainResult("tls-default", noSA, in)), epoch, f.stores)
	if !contains(t1IDs(ev), "CERT.NO-SERVERAUTH") {
		t.Errorf("no serverAuth: %v", t1IDs(ev))
	}

	both := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}})
	expect(t, "public clientAuth", evalAt(v2(chainResult("tls-default", both, in)), epoch, f.stores), "CERT.CLIENTAUTH-EKU")

	e3 := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, RSAExponent: 3})
	expect(t, "RSA e=3", evalAt(v2(chainResult("tls-default", e3, in)), epoch, f.stores), "CERT.WEAK-EXPONENT")

	// Lifetimes (REQ-TCRT-3/4).
	nb := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	long := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, NotBefore: nb, NotAfter: nb.AddDate(0, 0, 398)})
	ev = evalAt(v2(chainResult("tls-default", long, in)), epoch, f.stores)
	expect(t, "398 days issued after 2026-03-15", ev, "CERT.LIFETIME")
	if v := ev.PKI[0].Lifetime; v.LimitDays != 200 || !v.Applies {
		t.Errorf("lifetime view %+v", v)
	}
	nb47 := epoch.AddDate(0, 0, -27)
	short47 := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, NotBefore: nb47, NotAfter: nb47.Add(47*24*time.Hour - time.Second)})
	ev = evalAt(v2(chainResult("tls-default", short47, in)), epoch, f.stores)
	expect(t, "47 days with 20 left", ev)
	if len(findID(ev, "CERT.EXPIRING")) != 0 {
		t.Error("a 47-day certificate with 20 days left raised CERT.EXPIRING")
	}

	// CT (REQ-TCT-3).
	bare := f.inter.Leaf(t, pkitest.LeafOpts{})
	expect(t, "public without SCTs", evalAt(v2(chainResult("tls-default", bare, in)), epoch, f.stores), "CT.NO-SCTS")
	viaTLS := chainResult("tls-default", bare, in)
	viaTLS.TLSSCTs = []string{base64.StdEncoding.EncodeToString(pkitest.SCT(sctOK[0]))}
	ev = evalAt(v2(viaTLS), epoch, f.stores)
	expect(t, "SCT in the TLS extension", ev)
	if s := ev.PKI[0].SCTs; len(s) != 1 || s[0].Source != "tls" {
		t.Errorf("TLS SCT view %+v", s)
	}
}

func TestT1TrustMatrix(t *testing.T) {
	f := newPKI(t)
	in := f.inter.Cert
	leaf := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK})

	// Trusted by one of two stores.
	other, _ := pki.NewStore("Chrome", "2026-06-01", true, []pki.Root{{DER: pkitest.NewRoot(t, "Else", pkitest.CAOpts{}).Cert.Raw}})
	ev := evalAt(v2(chainResult("tls-default", leaf, in)), epoch, []*pki.Store{f.stores[0], other})
	expect(t, "one of two stores", ev, "CERT.PARTIAL-TRUST")
	if fs := findID(ev, "CERT.PARTIAL-TRUST"); !strings.Contains(fs[0].Detail, "trusted by Mozilla, not by Chrome") {
		t.Errorf("partial trust detail: %s", fs[0].Detail)
	}

	// Mozilla distrust-after.
	moz, _ := pki.NewStore("Mozilla", "2026-06-01", true, []pki.Root{{DER: f.root.Cert.Raw, DistrustAfter: leaf.NotBefore.AddDate(0, 0, -1)}})
	ev = evalAt(v2(chainResult("tls-default", leaf, in)), epoch, []*pki.Store{moz, f.stores[1]})
	expect(t, "distrusted after", ev, "CERT.PARTIAL-TRUST")
	if fs := findID(ev, "CERT.PARTIAL-TRUST"); !strings.Contains(fs[0].Detail, "distrusted for certificates issued after") {
		t.Errorf("distrust detail: %s", fs[0].Detail)
	}

	// A private CA: untrusted without the bundle; trusted by it, and exempt
	// from the lifetime and CT rules, with it.
	priv := pkitest.NewRoot(t, "Corp Root", pkitest.CAOpts{})
	nb := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	pleaf := priv.Leaf(t, pkitest.LeafOpts{NotBefore: nb, NotAfter: nb.AddDate(2, 0, 0)})
	rep := v2(chainResult("tls-default", pleaf))
	// A leaf signed straight by the root names no issuer URL: the root is unknown, not an
	// intermediate missing (badssl.com superfish, preact-cli).
	expect(t, "private CA without the bundle", evalAt(rep, epoch, f.stores), "CERT.UNTRUSTED")
	anchors, _ := pki.NewStore("private", "", false, []pki.Root{{DER: priv.Cert.Raw}})
	ev = eval.EvaluateWith(rep, eval.Input{Now: epoch, Stores: f.stores, Anchors: anchors})
	expect(t, "private CA with the bundle", ev)
	if p := ev.PKI[0].Private; p == nil || !p.Trusted || ev.PKI[0].Public {
		t.Errorf("private view %+v public=%v", p, ev.PKI[0].Public)
	}

	// A private chain served correctly (leaf and intermediate; the root is never
	// sent) is untrusted, not "missing an intermediate".
	pinter := priv.Intermediate(t, "Corp Issuing", pkitest.CAOpts{})
	ev = evalAt(v2(chainResult("tls-default", pinter.Leaf(t, pkitest.LeafOpts{}), pinter.Cert)), epoch, f.stores)
	expect(t, "private chain with its intermediate", ev, "CERT.UNTRUSTED")
	if m := ev.PKI[0].Served.Missing; m == nil || m.Likely != "root" {
		t.Errorf("missing view %+v", m)
	}
	if fs := findID(ev, "CERT.UNTRUSTED"); !strings.Contains(fs[0].Detail, "either a private CA") {
		t.Errorf("untrusted detail: %s", fs[0].Detail)
	}

	// Expired: CERT.EXPIRED, not also UNTRUSTED.
	ev = evalAt(v2(chainResult("tls-default", leaf, in)), leaf.NotAfter.AddDate(0, 0, 2), f.stores)
	if len(findID(ev, "CERT.EXPIRED")) != 1 || len(findID(ev, "CERT.UNTRUSTED")) != 0 {
		t.Errorf("expired: %v", t1IDs(ev))
	}

	// The no-SNI chain is information, never the endpoint's certificate. Shaped like
	// www.google.com: a trusted chain with SNI, and without SNI a self-signed placeholder
	// for another name (here also expired). Nothing about it is scored or put first.
	placeholderCA := pkitest.NewRoot(t, "invalid2.invalid", pkitest.CAOpts{})
	placeholder := placeholderCA.Leaf(t, pkitest.LeafOpts{CN: "invalid2.invalid", DNS: []string{"invalid2.invalid"},
		NotBefore: epoch.AddDate(0, -6, 0), NotAfter: epoch.AddDate(0, 0, -1)})
	nosni := chainResult("no-sni", placeholder)
	nosni.NoSNI, nosni.NameMatches = true, false
	withSNI := v2(chainResult("tls-default", leaf, in))
	base := evalAt(withSNI, epoch, f.stores)
	both := v2(chainResult("tls-default", leaf, in), nosni)
	ev = evalAt(both, epoch, f.stores)
	for _, id := range []string{"CERT.EXPIRED", "CERT.UNTRUSTED", "CERT.NAME-MISMATCH", "CERT.CHAIN-INCOMPLETE", "CT.NO-SCTS"} {
		if len(findID(ev, id)) != 0 {
			t.Errorf("the no-SNI placeholder raised %s", id)
		}
	}
	note := findID(ev, "CERT.NO-SNI-DIFFERENT")
	if len(note) != 1 || note[0].Severity != eval.Info || !strings.Contains(note[0].Detail, "invalid2.invalid") ||
		!strings.Contains(note[0].Detail, "not trusted") || !strings.Contains(note[0].Detail, "expired") {
		t.Errorf("no-SNI note: %+v", note)
	}
	if ev.Hygiene.Score != base.Hygiene.Score || strings.Join(ev.FixFirst, ",") != strings.Join(base.FixFirst, ",") {
		t.Errorf("the no-SNI chain changed the score (%d vs %d) or Fix first (%v vs %v)", ev.Hygiene.Score, base.Hygiene.Score, ev.FixFirst, base.FixFirst)
	}
	if len(ev.PKI) != 2 || !ev.PKI[1].NoSNI {
		t.Errorf("PKI views: %d", len(ev.PKI))
	}

	// A served cross-signed root: the store validates the path through its own copy of the
	// root, so the cross-signer's absence is not reported as a missing or unknown issuer.
	oldRoot := pkitest.NewRoot(t, "Old Root", pkitest.CAOpts{})
	crossCert := crossSign(t, oldRoot, f.root)
	ev = evalAt(v2(chainResult("tls-default", leaf, in, crossCert)), epoch, f.stores)
	if v := ev.PKI[0]; !v.Trust[0].Trusted || v.Served.Missing != nil {
		t.Errorf("cross-signed root: trusted=%v missing=%+v", v.Trust[0].Trusted, v.Served.Missing)
	}
	if len(findID(ev, "CERT.UNTRUSTED")) != 0 || len(findID(ev, "CERT.CHAIN-INCOMPLETE")) != 0 {
		t.Errorf("cross-signed root raised trust findings: %v", t1IDs(ev))
	}
}

// crossSign issues a certificate for subject's name and key, signed by issuer: a cross-sign.
func crossSign(t *testing.T, issuer, subject *pkitest.CA) *x509.Certificate {
	t.Helper()
	tmpl := *subject.Cert
	tmpl.Raw, tmpl.RawTBSCertificate, tmpl.Signature, tmpl.AuthorityKeyId = nil, nil, nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, issuer.Cert, subject.Cert.PublicKey, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestT1RevocationMatrix(t *testing.T) {
	at := osslAt(t)
	st := osslStore(t)
	revocation := func(ev eval.Evaluation) []string {
		var out []string
		for _, id := range t1IDs(ev) {
			if strings.HasPrefix(id, "OCSP.") {
				out = append(out, id)
			}
		}
		return out
	}
	cases := []struct {
		name, leaf, staple string
		at                 time.Time
		want               string
	}{
		{"staple good", "leaf.pem", "ocsp-good", at, ""},
		{"staple good, delegated responder", "leaf.pem", "ocsp-delegated", at, ""},
		{"staple revoked", "leaf.pem", "ocsp-revoked", at, "OCSP.REVOKED"},
		{"staple after nextUpdate", "leaf.pem", "ocsp-good", at.AddDate(0, 0, 10), "OCSP.STALE"},
		{"staple for another certificate", "leaf.pem", "ocsp-other", at, "OCSP.MISMATCH"},
		{"staple unknown", "leaf.pem", "ocsp-unknown", at, "OCSP.UNKNOWN"},
		{"staple tryLater", "leaf.pem", "ocsp-trylater", at, "OCSP.MISMATCH"},
		{"must-staple without a staple", "leaf-muststaple.pem", "", at, "OCSP.MUST-STAPLE-MISSING"},
		{"OCSP URL, no staple", "leaf.pem", "", at, "OCSP.NO-STAPLE"},
	}
	for _, c := range cases {
		var b []byte
		if c.staple != "" {
			b = osslStaple(t, c.staple)
		}
		ev := evalAt(stapled(t, c.leaf, b), c.at, st)
		if got := strings.Join(revocation(ev), ","); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if c.name == "staple good" {
			o := ev.PKI[0].OCSP
			if o == nil || o.Status != "good" || o.Signature != pki.SigValid || !o.ForThisCert {
				t.Errorf("good view %+v", o)
			}
		}
		if c.name == "staple revoked" {
			if fs := findID(ev, "OCSP.REVOKED"); fs[0].Severity != eval.Critical || !fs[0].Availability || !strings.Contains(fs[0].Detail, "keyCompromise") {
				t.Errorf("revoked: %+v", fs)
			}
		}
	}

	// Tampered: the signed bytes changed, so the signature no longer verifies.
	good := osslStaple(t, "ocsp-good")
	tampered := append([]byte(nil), good...)
	i := strings.Index(string(tampered), "2026")
	if i < 0 {
		t.Fatal("producedAt not found")
	}
	if tampered[i+13] == '0' {
		tampered[i+13] = '1'
	} else {
		tampered[i+13] = '0'
	}
	ev := evalAt(stapled(t, "leaf.pem", tampered), at, st)
	if fs := findID(ev, "OCSP.MISMATCH"); len(fs) != 1 || !strings.Contains(fs[0].Detail, "signature") {
		t.Errorf("tampered: %+v", fs)
	}

	// A CRL-only certificate with no staple raises nothing (REQ-TREV-4).
	f := newPKI(t)
	crl := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK, CRL: []string{"http://crl.test/c.crl"}})
	expect(t, "CRL only", evalAt(v2(chainResult("tls-default", crl, f.inter.Cert)), epoch, f.stores))
}

func TestT1HTTPKeyExchangeAndVulnerabilities(t *testing.T) {
	f := newPKI(t)
	leaf := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK})
	base := func() *tlsprobe.Report { return v2(chainResult("tls-default", leaf, f.inter.Cert)) }
	for _, c := range []struct {
		name   string
		header []string
		want   []string
	}{
		{"absent", []string{}, []string{"HTTP.NO-HSTS"}},
		{"max-age=0", []string{"max-age=0"}, []string{"HTTP.HSTS-DISABLED"}},
		{"short", []string{"max-age=600; includeSubDomains"}, []string{"HTTP.HSTS-SHORT"}},
		{"duplicate", []string{"max-age=31536000; includeSubDomains", "max-age=1"}, []string{"HTTP.HSTS-INVALID"}},
		{"invalid", []string{"max-age=x"}, []string{"HTTP.HSTS-INVALID"}},
		{"no subdomains", []string{"max-age=31536000"}, []string{"HTTP.HSTS-NO-SUBDOMAINS"}},
		{"full", []string{"max-age=63072000; includeSubDomains; preload"}, nil},
	} {
		rep := base()
		rep.HSTSHeader = tlsprobe.ParseHSTS(c.header)
		ev := evalAt(rep, epoch, f.stores)
		var got []string
		for _, f := range ev.Findings {
			if strings.HasPrefix(f.ID, "HTTP.") {
				got = append(got, f.ID)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("HSTS %s: %v, want %v", c.name, got, c.want)
		}
	}

	// DH: an RFC 7919 group is named, not a finding; Oakley group 2 is Logjam.
	rep := base()
	rep.DH = &tlsprobe.DHResult{PrimeBits: 2048, PrimeSHA256: "9cd3b7f336872f46c09428d1bbc19877a4d440512cda8d1c1cf0cd6e33698966"}
	if ids := t1IDs(evalAt(rep, epoch, f.stores)); contains(ids, "KX.DH-COMMON-PRIME") {
		t.Errorf("ffdhe2048 flagged: %v", ids)
	}
	rep.DH = &tlsprobe.DHResult{PrimeBits: 1024, PrimeSHA256: "3f35a3f5f6c4376a744acad409bb22f8d897f949d2311d885adaa890981b67a0"}
	ev := evalAt(rep, epoch, f.stores)
	fs := findID(ev, "KX.DH-COMMON-PRIME")
	if len(fs) != 1 || !contains(fs[0].Labels, "Logjam") || !strings.Contains(fs[0].Detail, "Oakley Group 2") {
		t.Errorf("Oakley 2: %+v", fs)
	}
	if a := attack(ev, "Logjam"); a.Status != "exposed" {
		t.Errorf("Logjam attack view %+v", a)
	}

	// DROWN across the estate.
	key := tlsprobe.DescribeCertificate(leaf).SPKISHA256
	ev = eval.EvaluateWith(base(), eval.Input{Now: epoch, Stores: f.stores, SSLv2Keys: map[string][]string{key: {"legacy.test:443"}}})
	if fs := findID(ev, "VULN.DROWN-SHARED-KEY"); len(fs) != 1 || !strings.Contains(fs[0].Detail, "legacy.test:443") {
		t.Errorf("DROWN: %+v", fs)
	}
	if a := attack(ev, "DROWN"); a.Status != "exposed" {
		t.Errorf("DROWN attack view %+v", a)
	}
	for _, name := range []string{"Heartbleed", "ROBOT", "CCS injection", "Ticketbleed", "Padding oracles"} {
		if a := attack(ev, name); a.Status != "not-tested" || a.Why == "" {
			t.Errorf("%s: %+v", name, a)
		}
	}
}

func attack(ev eval.Evaluation, name string) eval.AttackView {
	for _, a := range ev.Vulnerabilities {
		if a.Name == name {
			return a
		}
	}
	return eval.AttackView{}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestSectionsAndFixFirst(t *testing.T) {
	f := newPKI(t)
	leaf := f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK})
	rep := v2(chainResult("tls-default", leaf)) // missing intermediate: high + availability
	rep.Protocols = protocols("TLSv1.3", "TLSv1.2", "TLSv1.0")
	for i := range rep.Stages {
		if rep.Stages[i].Name == tlsprobe.StageHTTP {
			rep.Stages[i] = tlsprobe.Stage{Name: tlsprobe.StageHTTP, Outcome: tlsprobe.OutcomeSkipped, ReasonCode: tlsprobe.ReasonOptionOff, Reason: "off"}
		}
	}
	rep.HSTSHeader, rep.HSTS = nil, nil
	ev := evalAt(rep, epoch, f.stores)

	if len(ev.Sections) != len(eval.SectionOrder) {
		t.Fatalf("sections %+v", ev.Sections)
	}
	st := map[string]eval.Section{}
	for i, s := range ev.Sections {
		if s.ID != eval.SectionOrder[i] {
			t.Errorf("section %d is %s", i, s.ID)
		}
		st[s.ID] = s
	}
	if st["certificates"].Status != eval.StatusProblem || st["protocols"].Status != eval.StatusAttention {
		t.Errorf("statuses: certificates %s, protocols %s", st["certificates"].Status, st["protocols"].Status)
	}
	if h := st["http"]; h.Status != eval.StatusNotChecked || h.ReasonCode != tlsprobe.ReasonOptionOff {
		t.Errorf("http %+v", h)
	}
	if len(ev.FixFirst) == 0 || ev.FixFirst[0] != "CERT.CHAIN-INCOMPLETE" && ev.FixFirst[0] != "CERT.UNTRUSTED" {
		t.Errorf("fix first %v", ev.FixFirst)
	}
	if len(ev.FixFirst) > 3 {
		t.Errorf("fix first has %d entries", len(ev.FixFirst))
	}
	for _, fd := range ev.Findings {
		if fd.Section == "" {
			t.Errorf("%s has no section", fd.ID)
		}
	}
	if len(ev.ReferenceData) != 5 {
		t.Errorf("reference data %+v", ev.ReferenceData)
	}

	// A legacy (tls-report/1) report: revocation not collected, nothing breaks.
	legacy := modern()
	legacy.SchemaVersion = tlsprobe.SchemaVersion1
	lev := eval.Evaluate(legacy, now)
	if !lev.LegacyReport {
		t.Error("legacy report not marked")
	}
	for _, s := range lev.Sections {
		if s.ID == "revocation" && (s.Status != eval.StatusNotCollected || s.ReasonCode != tlsprobe.ReasonLegacy) {
			t.Errorf("legacy revocation %+v", s)
		}
	}
}

// TestLabelsDoNotChangeHygiene: an attack is a label on its finding, never a
// second finding, so the score is what the findings alone give.
func TestLabelsDoNotChangeHygiene(t *testing.T) {
	ev := eval.Evaluate(terrible(), now)
	seen := map[string]bool{}
	points := 0
	for _, f := range ev.Findings {
		if f.Category == "pqc" || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		points += map[eval.Severity]int{eval.Critical: 40, eval.High: 20, eval.Medium: 10, eval.Low: 4}[f.Severity]
	}
	sum := 0
	for _, d := range ev.Hygiene.Deductions {
		sum += d.Points
	}
	if sum != points {
		t.Errorf("deductions %d, findings %d", sum, points)
	}
	known := map[string]bool{}
	for _, id := range eval.RuleIDs() {
		known[id] = true
	}
	labelled := 0
	for _, f := range ev.Findings {
		labelled += len(f.Labels)
		if !known[f.ID] && !strings.HasPrefix(f.ID, "PQC.") {
			t.Errorf("finding %s is not a published rule (a label became a finding?)", f.ID)
		}
	}
	if labelled == 0 {
		t.Error("the worst-case endpoint carries no attack labels")
	}
}

// t1Firing evaluates enough tls-report/2 fixtures that every T1 rule fires at
// least once; TestEveryRuleFiresAndIsCited checks the union.
func t1Firing(t *testing.T) []eval.Evaluation {
	f := newPKI(t)
	in := f.inter.Cert
	leaf := f.inter.Leaf(t, pkitest.LeafOpts{})
	nb := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	short := f.root.Intermediate(t, "Short", pkitest.CAOpts{NotAfter: epoch.AddDate(0, 0, 20)})
	other, _ := pki.NewStore("Chrome", "x", true, []pki.Root{{DER: pkitest.NewRoot(t, "Else", pkitest.CAOpts{}).Cert.Raw}})
	rep := v2(
		chainResult("a", leaf),
		chainResult("b", f.inter.Leaf(t, pkitest.LeafOpts{}), f.root.Cert, in),
		chainResult("c", short.Leaf(t, pkitest.LeafOpts{}), short.Cert),
		chainResult("d", f.inter.Leaf(t, pkitest.LeafOpts{NotBefore: nb, NotAfter: nb.AddDate(0, 0, 398)}), in),
		chainResult("e", f.inter.Leaf(t, pkitest.LeafOpts{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}), in),
		chainResult("f", f.inter.Leaf(t, pkitest.LeafOpts{EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}), in),
		chainResult("g", f.inter.Leaf(t, pkitest.LeafOpts{RSAExponent: 3}), in),
	)
	ph := chainResult("no-sni", pkitest.NewRoot(t, "Placeholder", pkitest.CAOpts{}).Cert)
	ph.NoSNI = true
	rep.Certificates = append(rep.Certificates, ph)
	rep.DH = &tlsprobe.DHResult{PrimeBits: 1024, PrimeSHA256: "3f35a3f5f6c4376a744acad409bb22f8d897f949d2311d885adaa890981b67a0"}
	rep.Suites = append(rep.Suites, suite("TLSv1.2", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", "RSA", "AES", "CBC", 128, 128, false, true))
	rep.HSTSHeader = tlsprobe.ParseHSTS([]string{"max-age=0", "max-age=1"})
	key := rep.Certificates[0].Chain[0].SPKISHA256
	out := []eval.Evaluation{eval.EvaluateWith(rep, eval.Input{Now: epoch, Stores: []*pki.Store{f.stores[0], other},
		SSLv2Keys: map[string][]string{key: {"old.test:443"}}})}
	for _, h := range [][]string{{"max-age=0"}, {"max-age=60"}, {"max-age=31536000"}} {
		r := v2(chainResult("tls-default", f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK}), in))
		r.HSTSHeader = tlsprobe.ParseHSTS(h)
		out = append(out, evalAt(r, epoch, f.stores))
	}
	at, st := osslAt(t), osslStore(t)
	for _, c := range []struct {
		leaf, staple string
		at           time.Time
	}{{"leaf.pem", "ocsp-revoked", at}, {"leaf.pem", "ocsp-other", at}, {"leaf.pem", "ocsp-unknown", at},
		{"leaf.pem", "ocsp-good", at.AddDate(0, 0, 10)}, {"leaf-muststaple.pem", "", at}, {"leaf.pem", "", at}} {
		var b []byte
		if c.staple != "" {
			b = osslStaple(t, c.staple)
		}
		out = append(out, evalAt(stapled(t, c.leaf, b), c.at, st))
	}
	// A root whose private key is public, and DH moduli that are not prime or not safe primes.
	sf := pkitest.NewRoot(t, "Superfish, Inc.", pkitest.CAOpts{})
	out = append(out, evalAt(v2(chainResult("tls-default", sf.Leaf(t, pkitest.LeafOpts{}))), epoch, f.stores))
	no, yes := false, true
	for _, d := range []*tlsprobe.DHResult{{PrimeBits: 2048, Suite: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", IsPrime: &no},
		{PrimeBits: 2048, Suite: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", IsPrime: &yes, SafePrime: &no}} {
		r := v2(chainResult("tls-default", leaf, in))
		r.DH = d
		out = append(out, evalAt(r, epoch, f.stores))
	}
	return out
}

// QA of real scans (badssl.com revoked): with no stapled response vouching for the certificate,
// and the CA never contacted, revocation is "unknown", never "good"; its checks still count as run.
// A good, verified staple makes it good.
func TestRevocationIsUnknownWithoutAStaple(t *testing.T) {
	f := newPKI(t)
	sectionOf := func(ev eval.Evaluation) eval.Section {
		for _, s := range ev.Sections {
			if s.ID == eval.SecRevocation {
				return s
			}
		}
		return eval.Section{}
	}
	ev := evalAt(v2(chainResult("tls-default", f.inter.Leaf(t, pkitest.LeafOpts{SCTs: sctOK}), f.inter.Cert)), epoch, f.stores)
	if s := sectionOf(ev); s.Status != eval.StatusUnknown || s.ReasonCode != "not-contacted" || !strings.Contains(s.Reason, "not known") {
		t.Errorf("no staple: section %+v", s)
	}
	for _, c := range ev.Checks {
		if c.Section == eval.SecRevocation && c.Result == "not-checked" {
			t.Errorf("check %s reads not-checked; it ran", c.ID)
		}
	}
	good := evalAt(stapled(t, "leaf.pem", osslStaple(t, "ocsp-good")), osslAt(t), osslStore(t))
	if s := sectionOf(good); s.Status == eval.StatusUnknown {
		t.Errorf("good staple: section %+v", s)
	}
}

// QA of real scans (badssl.com superfish): a chain to a root whose private key is public is that
// finding, critical and failing clients, not also "untrusted" for the same reason.
func TestCompromisedRootIsItsOwnFinding(t *testing.T) {
	f := newPKI(t)
	sf := pkitest.NewRoot(t, "eDellRoot", pkitest.CAOpts{})
	ev := evalAt(v2(chainResult("tls-default", sf.Leaf(t, pkitest.LeafOpts{}))), epoch, f.stores)
	fs := findID(ev, "CERT.COMPROMISED-ROOT")
	if len(fs) != 1 || fs[0].Severity != eval.Critical || !fs[0].Availability || !strings.Contains(fs[0].Detail, "eDellRoot") {
		t.Fatalf("compromised root: %+v", fs)
	}
	if len(findID(ev, "CERT.UNTRUSTED")) != 0 || len(findID(ev, "CERT.CHAIN-INCOMPLETE")) != 0 {
		t.Errorf("also untrusted or incomplete: %v", t1IDs(ev))
	}
}
