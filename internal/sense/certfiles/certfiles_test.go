package certfiles

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io/fs"
	"math/big"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
)

// ---- fixtures ------------------------------------------------------------------------------------

type certSpec struct {
	cn        string
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	isCA      bool
}

func mkCert(t *testing.T, spec certSpec, pub crypto.PublicKey, signer crypto.Signer) []byte {
	t.Helper()
	if spec.notBefore.IsZero() {
		spec.notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if spec.notAfter.IsZero() {
		spec.notAfter = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: spec.cn},
		NotBefore: spec.notBefore, NotAfter: spec.notAfter, DNSNames: spec.dns,
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: spec.isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

var (
	keyOnce sync.Once
	rsaKey  *rsa.PrivateKey
	ecKey   *ecdsa.PrivateKey
)

func keys(t *testing.T) (*rsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			t.Fatal(err)
		}
		if ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	})
	return rsaKey, ecKey
}

// A private key with a recognisable body, so a test can prove none of it travels.
type canary struct {
	pem     []byte
	der     []byte
	b64Body string
}

func newCanary(t *testing.T, label string) canary {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return canary{pem: pemOf(label, der), der: der, b64Body: base64.StdEncoding.EncodeToString(der)}
}

// leaks reports where a canary's bytes appear in s: raw, base64 (whole and in a long
// slice) or hex.
func (c canary) leaks(s string) bool {
	if strings.Contains(s, string(c.der)) || strings.Contains(s, c.b64Body) || strings.Contains(s, hex.EncodeToString(c.der)) {
		return true
	}
	return len(c.b64Body) > 24 && strings.Contains(s, c.b64Body[10:34])
}

// logFS records every path opened or read, so a test can prove a file was never touched.
type logFS struct {
	fstest.MapFS
	mu     sync.Mutex
	opened []string
}

func (l *logFS) Open(name string) (fs.File, error) {
	l.note(name)
	return l.MapFS.Open(name)
}

func (l *logFS) ReadFile(name string) ([]byte, error) {
	l.note(name)
	return l.MapFS.ReadFile(name)
}

func (l *logFS) note(name string) {
	l.mu.Lock()
	l.opened = append(l.opened, name)
	l.mu.Unlock()
}

func (l *logFS) wasOpened(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, o := range l.opened {
		if o == name {
			return true
		}
	}
	return false
}

func collect(t *testing.T, fsys fs.FS) evidence.Batch {
	t.Helper()
	s := New(sense.Env{FS: fsys, OS: "linux", Tier: "user"})
	if ok, err := s.Detect(context.Background()); err != nil || !ok {
		t.Fatalf("Detect = %v, %v", ok, err)
	}
	b, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Whatever the sensor emits must satisfy the evidence contract.
	g := evidence.NewGraph(evidence.Host{Name: "h", OSFamily: "linux", PrivilegeTier: "user"})
	if err := g.AddBatch(b); err != nil {
		t.Fatalf("the batch breaks the evidence contract: %v", err)
	}
	return b
}

func certObs(b evidence.Batch) []evidence.Observation {
	var out []evidence.Observation
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindCertificate {
			out = append(out, o)
		}
	}
	return out
}

func limit(b evidence.Batch, k string) string { return b.Coverage[0].Limits[k] }

// ---- tests ---------------------------------------------------------------------------------------

// REQ-CERT-2, REQ-CERT-3: certificates are found in the trust store and service
// directories, with key algorithm, size and curve, once per place they are found.
func TestFindsCertificatesInTrustStoreAndServiceDirs(t *testing.T) {
	rk, ek := keys(t)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaDER := mkCert(t, certSpec{cn: "rsa.example.test", dns: []string{"rsa.example.test", "www.example.test"}}, &rk.PublicKey, rk)
	ecDER := mkCert(t, certSpec{cn: "ec.example.test", isCA: true}, &ek.PublicKey, ek)
	edDER := mkCert(t, certSpec{cn: "ed.example.test"}, edPub, edPriv)

	bundle := append(append(pemOf("CERTIFICATE", rsaDER), pemOf("CERTIFICATE", ecDER)...), pemOf("CERTIFICATE", edDER)...)
	fsys := fstest.MapFS{
		"etc/ssl/certs/ca-certificates.crt":        {Data: bundle},
		"etc/ssl/certs/rsa.pem":                    {Data: pemOf("CERTIFICATE", rsaDER)},
		"usr/share/ca-certificates/mozilla/ec.crt": {Data: pemOf("CERTIFICATE", ecDER)},
		"etc/ssl/certs/5ad8a5d6.0":                 {Data: []byte("/usr/share/ca-certificates/mozilla/ec.crt"), Mode: fs.ModeSymlink},
		"etc/pki/tls/certs/ed.cer":                 {Data: edDER}, // bare DER
		"etc/nginx/ssl/site.pem":                   {Data: append(pemOf("CERTIFICATE", rsaDER), newCanary(t, "PRIVATE KEY").pem...)},
		"usr/share/ca-certificates/mozilla/README": {Data: []byte("not a certificate")},
		"etc/ssl/certs/notes.txt":                  {Data: pemOf("CERTIFICATE", rsaDER)}, // wrong extension: not read
	}
	b := collect(t, fsys)
	obs := certObs(b)

	// rsa: bundle, rsa.pem, nginx site.pem = 3 places; ec: bundle, mozilla/ec.crt, and the hashed link = 3; ed: bundle, ed.cer = 2
	if len(obs) != 8 {
		t.Fatalf("%d certificate observations, want 8:\n%s", len(obs), locations(obs))
	}
	byKey := map[string]int{}
	for _, o := range obs {
		byKey[o.Subject.Key]++
		if o.Claim.Rung != evidence.RungProvisioned || o.Stream != evidence.StreamHost || o.Method != evidence.MethodCertFile {
			t.Errorf("%s: rung %s stream %s method %s", o.Subject.Key, o.Claim.Rung, o.Stream, o.Method)
		}
	}
	if len(byKey) != 3 {
		t.Errorf("%d distinct certificates, want 3", len(byKey))
	}

	find := func(cn string) evidence.Observation {
		for _, o := range obs {
			if strings.Contains(o.Subject.Attrs["subject"], cn) {
				return o
			}
		}
		t.Fatalf("no observation for %s", cn)
		return evidence.Observation{}
	}
	rsaObs, ecObs, edObs := find("rsa.example.test"), find("ec.example.test"), find("ed.example.test")
	if a := rsaObs.Subject.Attrs; a["keyAlg"] != "RSA" || a["keyBits"] != "2048" || a["dnsNames"] != "rsa.example.test,www.example.test" || a["isCA"] != "false" {
		t.Errorf("rsa attrs = %v", a)
	}
	if a := ecObs.Subject.Attrs; a["keyAlg"] != "ECDSA" || a["curve"] != "P-256" || a["keyBits"] != "256" || a["isCA"] != "true" || a["selfSigned"] != "true" {
		t.Errorf("ec attrs = %v", a)
	}
	if a := edObs.Subject.Attrs; a["keyAlg"] != "Ed25519" || a["keyBits"] != "256" {
		t.Errorf("ed attrs = %v", a)
	}
	// The key is the same one a TLS scan uses for the same certificate.
	want := evidence.CertificateKey(rsaObs.Subject.Attrs["sha256"])
	if rsaObs.Subject.Key != want {
		t.Errorf("key %q, want %q", rsaObs.Subject.Key, want)
	}
	// The certificate whose file also holds a key says so; the others cannot say.
	for _, o := range obs {
		got := o.Source.Attrs["privateKey"]
		wantPK := "unknown"
		if o.Source.Location == "etc/nginx/ssl/site.pem" {
			wantPK = "yes"
		}
		if got != wantPK {
			t.Errorf("%s privateKey = %q, want %q", o.Source.Location, got, wantPK)
		}
	}
	// The hashed link is reported at the link's own name.
	found := false
	for _, o := range obs {
		found = found || o.Source.Location == "etc/ssl/certs/5ad8a5d6.0"
	}
	if !found {
		t.Errorf("the hashed link is not reported at its own name:\n%s", locations(obs))
	}
	if limit(b, "linksFollowed") != "1" || limit(b, "linksRefused") != "0" {
		t.Errorf("links followed/refused = %s/%s", limit(b, "linksFollowed"), limit(b, "linksRefused"))
	}
}

func locations(obs []evidence.Observation) string {
	var sb strings.Builder
	for _, o := range obs {
		sb.WriteString("  " + o.Source.Location + "  " + o.Subject.Attrs["subject"] + "\n")
	}
	return sb.String()
}

// REQ-CERT-4, SR-06: no private key is opened by name, decoded, stored or reported. The
// canary keys have recognisable bodies; none of them may appear anywhere in the output.
func TestNoKeyMaterialIsReadOrReported(t *testing.T) {
	rk, _ := keys(t)
	certDER := mkCert(t, certSpec{cn: "real.example.test"}, &rk.PublicKey, rk)

	cKeyFile := newCanary(t, "PRIVATE KEY")       // in server.key
	cPrivkey := newCanary(t, "PRIVATE KEY")       // letsencrypt privkey.pem
	cPKCS8 := newCanary(t, "PRIVATE KEY")         // a .pem whose name looks harmless but holds only a key
	cEnc := newCanary(t, "ENCRYPTED PRIVATE KEY") // encrypted
	cRSA := newCanary(t, "RSA PRIVATE KEY")
	cEC := newCanary(t, "EC PRIVATE KEY")
	cCombined := newCanary(t, "PRIVATE KEY")
	cUnderKeyName := newCanary(t, "PRIVATE KEY")
	cBundle := newCanary(t, "PRIVATE KEY")
	all := []canary{cKeyFile, cPrivkey, cPKCS8, cEnc, cRSA, cEC, cCombined, cUnderKeyName, cBundle}

	fsys := &logFS{MapFS: fstest.MapFS{
		"etc/ssl/certs/real.crt":                   {Data: pemOf("CERTIFICATE", certDER)},
		"etc/ssl/private/server.key":               {Data: cKeyFile.pem},
		"etc/nginx/ssl/server.key":                 {Data: cKeyFile.pem},
		"etc/ssl/certs/backup.p12":                 {Data: []byte("PKCS12 canary")},
		"etc/ssl/certs/store.jks":                  {Data: []byte("JKS canary")},
		"etc/letsencrypt/live/example/privkey.pem": {Data: cPrivkey.pem},
		"etc/ssl/certs/key.pem":                    {Data: cUnderKeyName.pem},
		"etc/ssl/certs/site-key.pem":               {Data: cUnderKeyName.pem},
		"etc/ssl/certs/server.pem":                 {Data: cPKCS8.pem}, // harmless name, key content: opened, never decoded
		"etc/ssl/certs/enc.pem":                    {Data: cEnc.pem},
		"etc/ssl/certs/rsa.pem":                    {Data: cRSA.pem},
		"etc/ssl/certs/ec.pem":                     {Data: cEC.pem},
		"etc/ssl/certs/combined.pem":               {Data: append(append(pemOf("CERTIFICATE", certDER), cCombined.pem...), pemOf("CERTIFICATE", certDER)...)},
		"etc/ssl/certs/ca-bundle.crt":              {Data: append(append(cBundle.pem, pemOf("CERTIFICATE", certDER)...), []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n")...)},
		"etc/ssl/certs/linked.0":                   {Data: []byte("/etc/ssl/private/server.key"), Mode: fs.ModeSymlink},
		"etc/ssl/certs/linked-to-a-key-name.crt":   {Data: []byte("etc/ssl/certs/key.pem"), Mode: fs.ModeSymlink},
	}}
	b := collect(t, fsys)

	// Names that announce a key are never opened, and neither is anything under private/.
	for _, name := range []string{
		"etc/ssl/private/server.key", "etc/nginx/ssl/server.key", "etc/ssl/certs/backup.p12", "etc/ssl/certs/store.jks",
		"etc/letsencrypt/live/example/privkey.pem", "etc/ssl/certs/key.pem", "etc/ssl/certs/site-key.pem",
	} {
		if fsys.wasOpened(name) {
			t.Errorf("%s was opened", name)
		}
	}
	if fsys.wasOpened("etc/ssl/private") {
		t.Error("the private directory was entered")
	}
	if n := limit(b, "keyFilesNotOpened"); n == "0" || n == "" {
		t.Errorf("keyFilesNotOpened = %q, want the key files counted", n)
	}

	// Nothing of any key appears in any output.
	raw, _ := json.Marshal(b)
	for i, c := range all {
		if c.leaks(string(raw)) {
			t.Errorf("canary %d leaked into the batch", i)
		}
	}
	for _, o := range b.Observations {
		for _, s := range append([]string{o.Subject.Name, o.Subject.Key, o.Source.Location}, mapValues(o.Subject.Attrs)...) {
			if strings.Contains(s, "PRIVATE KEY") {
				t.Errorf("a key label appears in %q", s)
			}
		}
	}

	// The certificate in the combined file is reported (and its key noted); the key blocks were
	// counted but never decoded; a key-only file yields no certificate.
	var combined, pkcs8Files int
	for _, o := range certObs(b) {
		if o.Source.Location == "etc/ssl/certs/combined.pem" {
			combined++
			if o.Source.Attrs["privateKey"] != "yes" {
				t.Errorf("combined.pem privateKey = %q, want yes", o.Source.Attrs["privateKey"])
			}
		}
		if strings.HasSuffix(o.Source.Location, "server.pem") || strings.HasSuffix(o.Source.Location, "enc.pem") {
			pkcs8Files++
		}
	}
	if combined != 1 {
		t.Errorf("combined.pem yielded %d observations, want 1 (two identical blocks are one certificate at one place)", combined)
	}
	if pkcs8Files != 0 {
		t.Error("a file holding only a key produced a certificate")
	}
	if kb := limit(b, "keyBlocksSkipped"); kb == "0" || kb == "" {
		t.Errorf("keyBlocksSkipped = %q", kb)
	}
	// Key blocks were never fed to certificate parsing: had one been decoded, the parse would have failed and been counted.
	if n := limit(b, "unparseableCertificates"); n != "" {
		t.Errorf("unparseableCertificates = %s: a key block reached the certificate parser", n)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// SR-16 / ENG-HANDOFF-002 DN-4: links are followed once, only inside the host root, only to
// regular files, only through real directories.
func TestSymbolicLinkRules(t *testing.T) {
	rk, _ := keys(t)
	der := mkCert(t, certSpec{cn: "linked.example.test"}, &rk.PublicKey, rk)
	pemBytes := pemOf("CERTIFICATE", der)
	link := func(target string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink}
	}

	fsys := fstest.MapFS{
		"usr/share/ca-certificates/mozilla/good.crt": {Data: pemBytes},
		"etc/ssl/certs/ok-relative.pem":              link("../../../usr/share/ca-certificates/mozilla/good.crt"),
		"etc/ssl/certs/ok-absolute.pem":              link("/usr/share/ca-certificates/mozilla/good.crt"),
		"etc/ssl/certs/escape.pem":                   link("../../../../../../etc/shadow"),
		"etc/ssl/certs/missing.pem":                  link("/nonexistent/file.crt"),
		"etc/ssl/certs/loop-a.pem":                   link("loop-b.pem"),
		"etc/ssl/certs/loop-b.pem":                   link("loop-a.pem"),
		"etc/ssl/certs/chain.pem":                    link("ok-relative.pem"), // a link to a link
		"etc/ssl/certs/dir.pem":                      link("/usr/share/ca-certificates/mozilla"),
		"etc/ssl/certs/viadir.pem":                   link("/etc/ssl/linkdir/real.crt"),
		"etc/ssl/linkdir":                            link("/usr/share/ca-certificates/mozilla"),
		"etc/ssl/certs/dotdot.pem":                   link(".."),
		"etc/ssl/certs/empty.pem":                    link(""),
	}
	b := collect(t, fsys)
	obs := certObs(b)
	got := map[string]bool{}
	for _, o := range obs {
		got[o.Source.Location] = true
	}
	for _, want := range []string{"etc/ssl/certs/ok-relative.pem", "etc/ssl/certs/ok-absolute.pem"} {
		if !got[want] {
			t.Errorf("%s (a good link) was not followed:\n%s", want, locations(obs))
		}
	}
	for _, refused := range []string{"escape", "missing", "loop-a", "loop-b", "chain", "dir", "viadir", "dotdot", "empty"} {
		if got["etc/ssl/certs/"+refused+".pem"] {
			t.Errorf("%s.pem was followed", refused)
		}
	}
	if limit(b, "linksFollowed") != "2" || limit(b, "linksRefused") != "9" {
		t.Errorf("links followed/refused = %s/%s, want 2/9", limit(b, "linksFollowed"), limit(b, "linksRefused"))
	}
	if b.Coverage[0].Status != evidence.CoveragePartial || b.Coverage[0].Reason != evidence.UnknownUnsupported {
		t.Errorf("coverage = %s/%s: refused links must make the result partial, not silently complete", b.Coverage[0].Status, b.Coverage[0].Reason)
	}
}

// SR-02, SR-17: attacker-chosen certificate text is cleaned and bounded, and a hostile
// path is skipped and counted rather than aborting the inventory.
func TestHostileTextIsCleanedAndBounded(t *testing.T) {
	_, ek := keys(t)
	hostile := "evil<img src=x onerror=alert(1)>\x1b[31m\u202e" + strings.Repeat("A", 3000)
	der := mkCert(t, certSpec{cn: hostile, dns: []string{"a.test"}}, &ek.PublicKey, ek)
	fsys := fstest.MapFS{
		"etc/ssl/certs/hostile.crt":   {Data: pemOf("CERTIFICATE", der)},
		"etc/ssl/certs/bad\nname.crt": {Data: pemOf("CERTIFICATE", der)},
		"etc/ssl/certs/bad\x00.pem":   {Data: pemOf("CERTIFICATE", der)},
	}
	b := collect(t, fsys) // collect fails the test if the batch breaks the evidence contract
	obs := certObs(b)
	if len(obs) != 1 {
		t.Fatalf("%d observations, want 1 (the two hostile names are skipped)", len(obs))
	}
	for k, v := range obs[0].Subject.Attrs {
		if len(v) > maxAttrLen || strings.ContainsAny(v, "\x00\x1b") {
			t.Errorf("attribute %s not cleaned: %.60q", k, v)
		}
	}
	if len(obs[0].Subject.Name) > maxNameLen {
		t.Errorf("name is %d bytes", len(obs[0].Subject.Name))
	}
	if limit(b, "skippedUnsafeNames") != "2" {
		t.Errorf("skippedUnsafeNames = %q, want 2", limit(b, "skippedUnsafeNames"))
	}
	if b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("status = %s: a skipped file must make coverage partial", b.Coverage[0].Status)
	}
}

// Malformed input is counted, never fatal, and never partly decoded into something.
func TestMalformedInputIsCountedNotFatal(t *testing.T) {
	rk, _ := keys(t)
	good := pemOf("CERTIFICATE", mkCert(t, certSpec{cn: "good.example.test"}, &rk.PublicKey, rk))
	notACert := pemOf("CERTIFICATE", []byte{0x30, 0x03, 0x02, 0x01, 0x05})
	fsys := fstest.MapFS{
		"etc/ssl/certs/good.crt":       {Data: good},
		"etc/ssl/certs/garbage.crt":    {Data: []byte("-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n")},
		"etc/ssl/certs/notacert.crt":   {Data: notACert},
		"etc/ssl/certs/unterminated":   {Data: []byte("x")},
		"etc/ssl/certs/open-ended.pem": {Data: []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")},
		"etc/ssl/certs/empty.pem":      {Data: nil},
		"etc/ssl/certs/binary.der":     {Data: []byte{0x30, 0x82, 0xff, 0xff, 0x00}},
		"etc/ssl/certs/label.pem":      {Data: []byte("-----BEGIN " + strings.Repeat("X", 200) + "-----\nAAAA\n-----END X-----\n")},
	}
	b := collect(t, fsys)
	if n := len(certObs(b)); n != 1 {
		t.Errorf("%d certificates, want only the good one", n)
	}
	if b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("status = %s, want partial", b.Coverage[0].Status)
	}
	if limit(b, "unparseableCertificates") == "" || limit(b, "malformedBlocks") == "" {
		t.Errorf("limits = %v: the problems must be counted", b.Coverage[0].Limits)
	}
}

// SR-01-style bounds: a directory tree and a file cannot make the run unbounded.
func TestBudgetsAreEnforcedAndReported(t *testing.T) {
	rk, _ := keys(t)
	pemBytes := pemOf("CERTIFICATE", mkCert(t, certSpec{cn: "x.example.test"}, &rk.PublicKey, rk))

	// too many entries
	fsys := fstest.MapFS{}
	for i := 0; i < 50; i++ {
		fsys["etc/ssl/certs/f"+string(rune('a'+i%26))+string(rune('a'+i/26))+".crt"] = &fstest.MapFile{Data: pemBytes}
	}
	old := maxEntries
	maxEntries = 10
	defer func() { maxEntries = old }()
	b := collect(t, fsys)
	if b.Coverage[0].Status != evidence.CoveragePartial || b.Coverage[0].Reason != evidence.UnknownBudget {
		t.Errorf("entry budget: %s/%s, want partial/budget", b.Coverage[0].Status, b.Coverage[0].Reason)
	}
	maxEntries = old

	// a file over the size cap is not opened
	big := &logFS{MapFS: fstest.MapFS{"etc/ssl/certs/huge.crt": {Data: make([]byte, maxFileSize+1)}}}
	b = collect(t, big)
	if big.wasOpened("etc/ssl/certs/huge.crt") || limit(b, "oversizedFilesNotOpened") != "1" {
		t.Errorf("oversized file: opened=%v limit=%q", big.wasOpened("etc/ssl/certs/huge.crt"), limit(b, "oversizedFilesNotOpened"))
	}

	// more certificates in one file than the per-file cap
	var many []byte
	for i := 0; i < maxCertsPerFile+5; i++ {
		many = append(many, pemBytes...)
	}
	b = collect(t, fstest.MapFS{"etc/ssl/certs/many.crt": {Data: many}})
	if b.Coverage[0].Status != evidence.CoveragePartial || b.Coverage[0].Reason != evidence.UnknownBudget {
		t.Errorf("per-file cap: %s/%s", b.Coverage[0].Status, b.Coverage[0].Reason)
	}
}

func TestDetectAndDeterminism(t *testing.T) {
	rk, _ := keys(t)
	pemBytes := pemOf("CERTIFICATE", mkCert(t, certSpec{cn: "x.example.test"}, &rk.PublicKey, rk))
	fsys := fstest.MapFS{"etc/ssl/certs/a.crt": {Data: pemBytes}, "etc/ssl/certs/b.crt": {Data: pemBytes}}

	if ok, _ := New(sense.Env{FS: fsys, OS: "windows"}).Detect(context.Background()); ok {
		t.Error("the Linux file sensor claims a Windows host")
	}
	if ok, _ := New(sense.Env{FS: fstest.MapFS{"etc/hostname": {Data: []byte("x")}}, OS: "linux"}).Detect(context.Background()); ok {
		t.Error("detected certificates on a host with no searched directory")
	}
	a, b := collect(t, fsys), collect(t, fsys)
	if len(a.Observations) != len(b.Observations) || len(a.Observations) != 2 {
		t.Fatalf("%d and %d observations, want 2 and 2", len(a.Observations), len(b.Observations))
	}
	for i := range a.Observations {
		if a.Observations[i].ID != b.Observations[i].ID {
			t.Errorf("observation %d differs between runs", i)
		}
	}
	if _, err := sense.Default.New(Name, sense.Env{FS: fsys, OS: "linux"}); err != nil {
		t.Errorf("the sensor is not registered or its Info is invalid: %v", err)
	}
	if _, err := sense.Default.New(Name, sense.Env{}); err == nil {
		t.Error("a nil filesystem was accepted")
	}
}

func TestClassify(t *testing.T) {
	for name, want := range map[string][2]bool{
		"a.crt": {true, false}, "b.PEM": {true, false}, "c.cer": {true, false}, "d.der": {true, false}, "5ad8a5d6.0": {true, false},
		"monkey.crt": {true, false}, "turkey-cert.pem": {true, false},
		"server.key": {false, true}, "privkey.pem": {false, true}, "site-key.pem": {false, true}, "key.pem": {false, true},
		"private.crt": {false, true}, "a.p12": {false, true}, "b.pfx": {false, true}, "c.jks": {false, true}, "d.keystore": {false, true},
		"my_secret.pem": {false, true}, "x.pk8": {false, true},
		"README": {false, false}, "notes.txt": {false, false},
	} {
		if maybe, isKey := classify(name); maybe != want[0] || isKey != want[1] {
			t.Errorf("classify(%q) = %v,%v, want %v,%v", name, maybe, isKey, want[0], want[1])
		}
	}
}
