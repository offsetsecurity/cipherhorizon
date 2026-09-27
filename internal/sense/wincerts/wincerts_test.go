package wincerts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/sense"
	"github.com/example/cipherhorizon/internal/winapi"
)

// fake is a certificate-store API with canned answers.
type fake struct {
	native bool
	stores map[string]result
	delay  map[string]time.Duration
	mu     sync.Mutex
	calls  []string
}

func key(loc winapi.StoreLocation, name string) string { return string(loc) + "/" + name }

func (f *fake) Native() bool { return f.native }

func (f *fake) CertStore(loc winapi.StoreLocation, name string) ([]winapi.StoreCert, int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, key(loc, name))
	f.mu.Unlock()
	if d := f.delay[key(loc, name)]; d > 0 {
		time.Sleep(d)
	}
	r := f.stores[key(loc, name)]
	return r.certs, r.skipped, r.err
}

func mk(t *testing.T, cn string, ca bool, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: ca, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: []string{"a.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func live(api winapi.CertStoreAPI) *Sensor {
	return New(sense.Env{OS: "windows", Tier: "user", Live: true}, api)
}

func collect(t *testing.T, s *Sensor) evidence.Batch {
	t.Helper()
	b, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g := evidence.NewGraph(evidence.Host{Name: "h", OSFamily: "windows", PrivilegeTier: "user"})
	if err := g.AddBatch(b); err != nil {
		t.Fatalf("the batch breaks the evidence contract: %v", err)
	}
	return b
}

func TestDetectRunsOnlyForALiveWindowsHost(t *testing.T) {
	api := &fake{native: true}
	for name, tc := range map[string]struct {
		env  sense.Env
		api  winapi.CertStoreAPI
		want bool
	}{
		"live windows":      {sense.Env{OS: "windows", Live: true}, api, true},
		"a --root override": {sense.Env{OS: "windows", Live: false}, api, false},
		"linux":             {sense.Env{OS: "linux", Live: true}, api, false},
		"a non-native fake": {sense.Env{OS: "windows", Live: true}, &fake{native: false}, false},
	} {
		got, err := New(tc.env, tc.api).Detect(context.Background())
		if err != nil || got != tc.want {
			t.Errorf("%s: Detect = %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

// REQ-CERT-1: one observation per certificate per store, at the provisioned rung, with the
// key algorithm and size, and the store named as the place.
func TestEachCertificateInEachStoreIsAnObservation(t *testing.T) {
	root := mk(t, "Example Root", true, time.Now().Add(20*365*24*time.Hour))
	leaf := mk(t, "machine.example.test", false, time.Now().Add(90*24*time.Hour))
	api := &fake{native: true, stores: map[string]result{
		key(winapi.LocalMachine, "Root"): {certs: []winapi.StoreCert{{DER: root, PrivateKey: "no"}}},
		key(winapi.LocalMachine, "MY"):   {certs: []winapi.StoreCert{{DER: leaf, PrivateKey: "yes"}}},
		key(winapi.CurrentUser, "Root"):  {certs: []winapi.StoreCert{{DER: root, PrivateKey: "no"}, {DER: root, PrivateKey: "no"}}}, // a duplicate in one store
		key(winapi.CurrentUser, "CA"):    {},
	}}
	b := collect(t, live(api))
	if len(b.Observations) != 3 {
		t.Fatalf("%d observations, want 3 (root in two stores, leaf in one; the duplicate is one sighting)", len(b.Observations))
	}
	byLoc := map[string]evidence.Observation{}
	for _, o := range b.Observations {
		byLoc[o.Source.Location+"|"+o.Subject.Attrs["subject"]] = o
		if o.Claim.Rung != evidence.RungProvisioned || o.Method != evidence.MethodCertStore || o.Stream != evidence.StreamHost || o.Source.Kind != "api" {
			t.Errorf("%s: %s %s %s %s", o.Source.Location, o.Claim.Rung, o.Method, o.Stream, o.Source.Kind)
		}
	}
	my := byLoc["cert-store:LocalMachine/MY|CN=machine.example.test"]
	if my.Source.Attrs["privateKey"] != "yes" || my.Subject.Attrs["keyAlg"] != "ECDSA" || my.Subject.Attrs["keyBits"] != "256" || my.Subject.Attrs["curve"] != "P-256" {
		t.Errorf("machine certificate = %+v / %v", my.Subject.Attrs, my.Source.Attrs)
	}
	lmRoot := byLoc["cert-store:LocalMachine/Root|CN=Example Root"]
	if lmRoot.Source.Attrs["privateKey"] != "no" || lmRoot.Subject.Attrs["isCA"] != "true" || lmRoot.Subject.Attrs["selfSigned"] != "true" {
		t.Errorf("root = %+v / %v", lmRoot.Subject.Attrs, lmRoot.Source.Attrs)
	}
	if _, ok := byLoc["cert-store:CurrentUser/Root|CN=Example Root"]; !ok {
		t.Error("the current user's copy of the root is missing")
	}
	if b.Coverage[0].Status != evidence.CoverageComplete {
		t.Errorf("coverage = %s/%s", b.Coverage[0].Status, b.Coverage[0].Reason)
	}
}

// ADR-0016: only allow-listed stores are ever asked for, whatever else is on the machine.
func TestOnlyAllowListedStoresAreRequested(t *testing.T) {
	api := &fake{native: true}
	collect(t, live(api))
	if len(api.calls) != 12 {
		t.Errorf("%d store reads, want 12 (6 stores x 2 locations): %v", len(api.calls), api.calls)
	}
	for _, c := range api.calls {
		loc, name, _ := strings.Cut(c, "/")
		if !winapi.ValidStore(winapi.StoreLocation(loc), name) {
			t.Errorf("the sensor asked for %s, which is not on the allow-list", c)
		}
		if name == "Disallowed" {
			t.Error("the Disallowed store was read")
		}
	}
	if winapi.ValidStore("LocalMachine", "Disallowed") || winapi.ValidStore("Somewhere", "Root") || winapi.ValidStore("LocalMachine", "") || winapi.ValidStore("LocalMachine", "Root\\..") {
		t.Error("ValidStore accepts something it should not")
	}
}

// A store that cannot be read costs that store, not the run, and the result says so.
func TestAStoreThatFailsMakesTheResultPartialNotFatal(t *testing.T) {
	c := mk(t, "ok.example.test", false, time.Now().Add(48*time.Hour))
	api := &fake{native: true, stores: map[string]result{
		key(winapi.LocalMachine, "Root"): {err: &winapi.StatusError{Call: "CertOpenStore", Code: 5}},
		key(winapi.LocalMachine, "MY"):   {certs: []winapi.StoreCert{{DER: c, PrivateKey: "unknown"}}},
	}}
	b := collect(t, live(api))
	if len(b.Observations) != 1 {
		t.Errorf("%d observations, want the one readable store's", len(b.Observations))
	}
	cov := b.Coverage[0]
	if cov.Status != evidence.CoveragePartial || cov.Reason != evidence.UnknownPermission || cov.Denied != 1 {
		t.Errorf("access denied: %s/%s denied=%d, want partial/permission/1", cov.Status, cov.Reason, cov.Denied)
	}

	api.stores[key(winapi.CurrentUser, "CA")] = result{err: &winapi.StatusError{Call: "CertEnumCertificatesInStore", Code: 0x8007000E}}
	b = collect(t, live(api))
	if b.Coverage[0].Reason != evidence.UnknownError || b.Coverage[0].Limits["storesFailed"] != "1" {
		t.Errorf("a failing store: %s / %v", b.Coverage[0].Reason, b.Coverage[0].Limits)
	}
}

func TestAStalledStoreIsGivenUpOn(t *testing.T) {
	old := callTimeout
	callTimeout = 50 * time.Millisecond
	defer func() { callTimeout = old }()
	c := mk(t, "ok.example.test", false, time.Now().Add(48*time.Hour))
	api := &fake{native: true,
		stores: map[string]result{key(winapi.LocalMachine, "MY"): {certs: []winapi.StoreCert{{DER: c}}}},
		delay:  map[string]time.Duration{key(winapi.LocalMachine, "Root"): 300 * time.Millisecond},
	}
	b := collect(t, live(api))
	if len(b.Observations) != 1 || b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("%d observations, coverage %s: a stalled store must not stop the run or read as complete", len(b.Observations), b.Coverage[0].Status)
	}
}

// SR-06: whatever a store holds, only certificates come out. A key blob in a store is not
// parsed as a certificate, is not reported, and none of its bytes travel.
func TestNothingButCertificatesComesOut(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
	canary := base64.StdEncoding.EncodeToString(keyDER)
	good := mk(t, "good.example.test", false, time.Now().Add(48*time.Hour))
	api := &fake{native: true, stores: map[string]result{
		key(winapi.LocalMachine, "MY"): {certs: []winapi.StoreCert{
			{DER: keyDER, PrivateKey: "yes"}, {DER: []byte{1, 2, 3}}, {DER: nil}, {DER: good, PrivateKey: "maybe"},
		}},
	}}
	b := collect(t, live(api))
	if len(b.Observations) != 1 {
		t.Fatalf("%d observations, want only the certificate", len(b.Observations))
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), canary) || strings.Contains(string(raw), canary[8:32]) {
		t.Error("key bytes appear in the output")
	}
	if got := b.Observations[0].Source.Attrs["privateKey"]; got != "unknown" {
		t.Errorf("an invalid private-key answer became %q, want unknown", got)
	}
	if b.Coverage[0].Limits["unparseableCertificates"] != "3" || b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("coverage = %v %s: what could not be read must be counted", b.Coverage[0].Limits, b.Coverage[0].Status)
	}
	// Only allow-listed attributes ever appear.
	for k := range b.Observations[0].Subject.Attrs {
		if !evidence.AllowedAttrs[evidence.KindCertificate][k] {
			t.Errorf("attribute %s is not allowed", k)
		}
	}
}

func TestSkippedCertificatesMakeCoveragePartial(t *testing.T) {
	c := mk(t, "ok.example.test", false, time.Now().Add(48*time.Hour))
	api := &fake{native: true, stores: map[string]result{key(winapi.CurrentUser, "Root"): {certs: []winapi.StoreCert{{DER: c}}, skipped: 4}}}
	b := collect(t, live(api))
	if b.Coverage[0].Status != evidence.CoveragePartial || b.Coverage[0].Reason != evidence.UnknownBudget || b.Coverage[0].Limits["skippedOversizedOrOverCap"] != "4" {
		t.Errorf("coverage = %+v", b.Coverage[0])
	}
}

func TestHostileCertificateTextIsCleaned(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "evil<script>\x1b[31m\u202e" + strings.Repeat("A", 4000)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	b := collect(t, live(&fake{native: true, stores: map[string]result{key(winapi.LocalMachine, "MY"): {certs: []winapi.StoreCert{{DER: der}}}}}))
	if len(b.Observations) != 1 {
		t.Fatalf("%d observations", len(b.Observations))
	}
	for k, v := range b.Observations[0].Subject.Attrs {
		if len(v) > maxAttrLen || strings.ContainsAny(v, "\x1b\x00") {
			t.Errorf("attribute %s not cleaned", k)
		}
	}
}

func TestCancellationStopsTheRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := live(&fake{native: true}).Collect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestRegistrationAndInfo(t *testing.T) {
	reg := sense.NewRegistry()
	if err := Register(reg, &fake{native: true}); err != nil {
		t.Fatal(err)
	}
	s, err := reg.New(Name, sense.Env{OS: "windows", Live: true})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := evidence.LookupMethod(s.Info().Methods[0])
	if !ok || m.SecretProximity != "adjacent" || m.Sensor != Name {
		t.Errorf("method = %+v: reading certificate stores must be declared adjacent to secrets", m)
	}
}

// Off Windows the real API is a stub that says it is not native, so the sensor is never detected.
func TestTheStubIsNeverDetected(t *testing.T) {
	if winapi.NewCertStore().Native() {
		t.Skip("this is Windows: the real implementation is native")
	}
	if got, _ := New(sense.Env{OS: "windows", Live: true}, winapi.NewCertStore()).Detect(context.Background()); got {
		t.Error("the non-Windows stub was detected")
	}
}
