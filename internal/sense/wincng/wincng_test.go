package wincng

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/knowledge"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
)

const primitive = "Microsoft Primitive Provider"

// fake is a Windows that says exactly what a test tells it to, and records what it was asked.
type fake struct {
	mu sync.Mutex

	native     bool
	algorithms map[uint32][]Algorithm // by operation class
	registered []string
	providers  map[string][]string // algorithm -> providers
	ksps       []StorageProvider
	kspAlgs    map[string][]Algorithm
	csps       []CSP
	accepts    map[string]bool // "ML-KEM/768" -> accepted; "ML-KEM/" -> opens

	failing map[string]error // method name -> error
	delay   map[string]time.Duration

	opened []string // storage providers opened
	probed []string // "alg/set" asked
}

func (f *fake) Native() bool { return f.native }

func (f *fake) check(method string) error {
	if d := f.delay[method]; d > 0 {
		time.Sleep(d)
	}
	return f.failing[method]
}

func (f *fake) Algorithms(op uint32) ([]Algorithm, int, error) {
	if err := f.check("Algorithms"); err != nil {
		return nil, 0, err
	}
	return f.algorithms[op], 0, nil
}
func (f *fake) AlgorithmProviders(alg string) ([]string, int, error) {
	if err := f.check("AlgorithmProviders"); err != nil {
		return nil, 0, err
	}
	return f.providers[alg], 0, nil
}
func (f *fake) RegisteredProviders() ([]string, int, error) {
	if err := f.check("RegisteredProviders"); err != nil {
		return nil, 0, err
	}
	return f.registered, 0, nil
}
func (f *fake) StorageProviders() ([]StorageProvider, int, error) {
	if err := f.check("StorageProviders"); err != nil {
		return nil, 0, err
	}
	return f.ksps, 0, nil
}
func (f *fake) StorageProviderAlgorithms(name string, _ uint32) ([]Algorithm, int, error) {
	f.mu.Lock()
	f.opened = append(f.opened, name)
	f.mu.Unlock()
	if err := f.check("StorageProviderAlgorithms"); err != nil {
		return nil, 0, err
	}
	return f.kspAlgs[name], 0, nil
}
func (f *fake) CSPs() ([]CSP, int, error) {
	if err := f.check("CSPs"); err != nil {
		return nil, 0, err
	}
	return f.csps, 0, nil
}
func (f *fake) Probe(alg, set string) (bool, error) {
	f.mu.Lock()
	f.probed = append(f.probed, alg+"/"+set)
	f.mu.Unlock()
	if err := f.check("Probe"); err != nil {
		return false, err
	}
	return f.accepts[alg+"/"+set], nil
}

// windows11 is a small but realistic Windows: the values are taken from the real machine.
func windows11() *fake {
	return &fake{
		native: true,
		algorithms: map[uint32][]Algorithm{
			OpCipher:            {{Name: "AES", Ops: OpCipher}, {Name: "3DES", Ops: OpCipher}, {Name: "RC4", Ops: OpCipher}},
			OpHash:              {{Name: "SHA1", Ops: OpHash}, {Name: "SHA256", Ops: OpHash}, {Name: "MD5", Ops: OpHash}},
			OpAsymmetricEncrypt: {{Name: "RSA", Ops: OpAsymmetricEncrypt}},
			OpSignature:         {{Name: "ECDSA_P256", Ops: OpSignature}, {Name: "ECDSA_P384", Ops: OpSignature}, {Name: "ML-DSA", Ops: OpSignature}},
			OpKeyDerivation:     {{Name: "PBKDF2", Ops: OpKeyDerivation}},
		},
		registered: []string{primitive, "Microsoft Software Key Storage Provider", "Microsoft Platform Crypto Provider"},
		providers: map[string][]string{
			"AES": {primitive}, "3DES": {primitive}, "RC4": {primitive}, "SHA1": {primitive}, "SHA256": {primitive}, "MD5": {primitive},
			"RSA": {primitive}, "ECDSA_P256": {primitive}, "ECDSA_P384": {primitive}, "ML-DSA": {primitive}, "PBKDF2": {primitive},
			"ML-KEM": {primitive},
		},
		ksps: []StorageProvider{{Name: "Microsoft Software Key Storage Provider"}, {Name: "Microsoft Platform Crypto Provider"}, {Name: "Microsoft Smart Card Key Storage Provider"}},
		kspAlgs: map[string][]Algorithm{
			"Microsoft Software Key Storage Provider": {{Name: "RSA", Ops: OpAsymmetricEncrypt}, {Name: "ECDSA_P256", Ops: OpSignature}},
		},
		csps: []CSP{{Name: "Microsoft Base Cryptographic Provider v1.0", Type: 1}, {Name: "Microsoft Enhanced RSA and AES Cryptographic Provider", Type: 24}},
		accepts: map[string]bool{
			"ML-KEM/": true, "ML-KEM/512": true, "ML-KEM/768": true, "ML-KEM/1024": true,
			"ML-DSA/": true, "ML-DSA/44": true, "ML-DSA/65": true, "ML-DSA/87": true,
		},
	}
}

func live() sense.Env { return sense.Env{OS: "windows", Tier: "user", Live: true} }

func collect(t *testing.T, api API) (evidence.Batch, error) {
	t.Helper()
	b, err := New(live(), api).Collect(context.Background())
	for _, o := range b.Observations {
		if verr := evidence.Validate(o); verr != nil {
			t.Errorf("invalid observation: %v", verr)
		}
	}
	return b, err
}

func providersOf(b evidence.Batch) map[string]evidence.Observation {
	out := map[string]evidence.Observation{}
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindProvider {
			out[o.Subject.Name] = o
		}
	}
	return out
}

func edgesOf(b evidence.Batch) map[string][]string { // algorithm -> providers
	out := map[string][]string{}
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindAlgorithm {
			out[o.Subject.Name] = append(out[o.Subject.Name], o.Relations[0].To)
		}
	}
	return out
}

func TestDetectRequiresALiveWindowsHostAndTheRealAPI(t *testing.T) {
	for name, tc := range map[string]struct {
		env    sense.Env
		native bool
		want   bool
	}{
		"live windows, real API":   {sense.Env{OS: "windows", Live: true}, true, true},
		"windows fixture (--root)": {sense.Env{OS: "windows", Live: false}, true, false},
		"linux host":               {sense.Env{OS: "linux", Live: true}, true, false},
		"stub API (not Windows)":   {sense.Env{OS: "windows", Live: true}, false, false},
	} {
		got, err := New(tc.env, &fake{native: tc.native}).Detect(context.Background())
		if err != nil || got != tc.want {
			t.Errorf("%s: Detect = %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

func TestProvidersAreInventoriedWithTheirKind(t *testing.T) {
	b, err := collect(t, windows11())
	if err != nil {
		t.Fatal(err)
	}
	p := providersOf(b)
	for name, kind := range map[string]string{
		primitive: "cng", "Microsoft Software Key Storage Provider": "cng+ksp", "Microsoft Platform Crypto Provider": "cng+ksp",
		"Microsoft Smart Card Key Storage Provider": "ksp", "Microsoft Base Cryptographic Provider v1.0": "csp",
	} {
		o, ok := p[name]
		if !ok {
			t.Errorf("provider %q missing", name)
			continue
		}
		if got := o.Subject.Attrs["providerKind"]; got != kind {
			t.Errorf("%s: kind %q, want %q", name, got, kind)
		}
		if o.Claim.Rung != evidence.RungPresent {
			t.Errorf("%s: a provider is present, nothing more: %+v", name, o.Claim)
		}
		if q, _ := evidence.QualityOf(o); q != evidence.QualityAuthoritative {
			t.Errorf("%s: quality %s; the system was asked, so authoritative", name, q)
		}
	}
	if csp := p["Microsoft Enhanced RSA and AES Cryptographic Provider"]; csp.Subject.Attrs["cspType"] != "24" {
		t.Errorf("csp type = %q", csp.Subject.Attrs["cspType"])
	}
}

func TestRegisteredAlgorithmsBecomeProbedCapabilityOfTheirProvider(t *testing.T) {
	b, _ := collect(t, windows11())
	e := edgesOf(b)
	pk := evidence.ProviderKey("cng", primitive)
	for _, id := range []string{"AES", "3DES", "RC4", "SHA-1", "SHA-256", "MD5", "RSA", "ECDSA"} {
		if !contains(e[id], pk) {
			t.Errorf("%s is not attributed to the primitive provider: %v", id, e[id])
		}
	}
	// ECDSA_P256 and ECDSA_P384 are one catalogue algorithm and one edge, not two.
	n := 0
	for _, o := range b.Observations {
		if o.Subject.Name == "ECDSA" && o.Method == evidence.MethodCNGAlgorithms {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d ECDSA edges from the primitive provider, want 1", n)
	}
	// An identifier with no catalogue entry gets no edge, but is named on its provider.
	if _, has := e["PBKDF2"]; has {
		t.Error("an unmapped identifier became an algorithm")
	}
	if algs := providersOf(b)[primitive].Subject.Attrs["algorithms"]; !strings.Contains(algs, "PBKDF2") || !strings.Contains(algs, "ECDSA_P384") {
		t.Errorf("provider algorithm list = %q; every registered identifier should be named", algs)
	}
	for _, o := range b.Observations {
		if o.Subject.Kind != evidence.KindAlgorithm {
			continue
		}
		if o.Claim.Rung != evidence.RungCapable || o.Claim.Capable != evidence.CapableProbed || o.Origin != evidence.OriginObserved {
			t.Errorf("%s: claim %+v origin %s; want observed capable/probed", o.Subject.Name, o.Claim, o.Origin)
		}
		if evidence.ClassOf(o.Claim) != evidence.E0Existence {
			t.Errorf("%s: a registered algorithm is existence, not use", o.Subject.Name)
		}
	}
}

// Loading a provider runs its code, so only the in-box software provider is ever opened.
func TestOnlyTheAllowListedStorageProviderIsOpened(t *testing.T) {
	f := windows11()
	b, _ := collect(t, f)
	if !reflect.DeepEqual(f.opened, []string{"Microsoft Software Key Storage Provider"}) {
		t.Fatalf("opened %v; only the in-box software provider may be opened", f.opened)
	}
	p := providersOf(b)
	if p["Microsoft Software Key Storage Provider"].Subject.Attrs["opened"] != "true" {
		t.Error("the opened provider is not marked opened")
	}
	for _, name := range []string{"Microsoft Platform Crypto Provider", "Microsoft Smart Card Key Storage Provider"} {
		if p[name].Subject.Attrs["opened"] != "false" {
			t.Errorf("%s: opened = %q, want false", name, p[name].Subject.Attrs["opened"])
		}
	}
	// The algorithms the opened provider offered are attributed to it.
	if !contains(edgesOf(b)["RSA"], evidence.ProviderKey("cng", "Microsoft Software Key Storage Provider")) {
		t.Error("the opened storage provider's algorithms were not attributed to it")
	}
}

func TestAHostileProviderNamedLikeAnAllowedOneIsNotOpened(t *testing.T) {
	f := windows11()
	f.ksps = []StorageProvider{{Name: "Microsoft Software Key Storage Provider "}, {Name: "microsoft software key storage provider"}, {Name: "Vendor HSM KSP"}}
	_, _ = collect(t, f)
	if len(f.opened) != 0 {
		t.Errorf("opened %v; a lookalike or third-party name must never match the allow-list", f.opened)
	}
}

// Probing generates an ephemeral key pair, so it is limited to the post-quantum
// families and to the fixed parameter sets.
func TestOnlyPostQuantumParameterSetsAreProbed(t *testing.T) {
	f := windows11()
	_, _ = collect(t, f)
	allowed := map[string]bool{"ML-KEM/": true, "ML-DSA/": true}
	for _, p := range knowledge.CNGProbes {
		allowed[p.Algorithm+"/"+p.ParamSet] = true
	}
	for _, c := range f.probed {
		if !allowed[c] {
			t.Errorf("probed %q, which is not on the fixed list", c)
		}
	}
	if len(f.probed) != 2+len(knowledge.CNGProbes) {
		t.Errorf("%d probes: %v", len(f.probed), f.probed)
	}
}

func TestConfirmedParameterSetsBecomeCatalogueAlgorithms(t *testing.T) {
	b, _ := collect(t, windows11())
	e := edgesOf(b)
	pk := evidence.ProviderKey("cng", primitive)
	for _, id := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if !contains(e[id], pk) {
			t.Errorf("%s not confirmed on the primitive provider: %v", id, e[id])
		}
	}
	if _, has := e["ML-KEM"]; has {
		t.Error("the family was emitted although its parameter sets were confirmed")
	}
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindAlgorithm && strings.HasPrefix(o.Subject.Name, "ML-") && o.Method != evidence.MethodCNGProbe {
			t.Errorf("%s came from %s, not the probe", o.Subject.Name, o.Method)
		}
	}
}

func TestOnlyTheAcceptedParameterSetsAreReported(t *testing.T) {
	f := windows11()
	f.accepts = map[string]bool{"ML-KEM/": true, "ML-KEM/768": true, "ML-DSA/": true} // ML-DSA opens; no parameter set accepted
	b, _ := collect(t, f)
	e := edgesOf(b)
	if _, has := e["ML-KEM-768"]; !has {
		t.Error("ML-KEM-768 was accepted and should be reported")
	}
	for _, id := range []string{"ML-KEM-512", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if _, has := e[id]; has {
			t.Errorf("%s was refused and must not be reported", id)
		}
	}
	// Opened but no parameter set confirmed: the family, and only the family.
	if !contains(e["ML-DSA"], evidence.ProviderKey("cng", primitive)) {
		t.Errorf("the ML-DSA family should be reported when no parameter set is confirmed: %v", e["ML-DSA"])
	}
}

func TestNoProviderMeansNoAttribution(t *testing.T) {
	f := windows11()
	f.providers["ML-KEM"] = nil
	b, _ := collect(t, f)
	for id := range edgesOf(b) {
		if strings.HasPrefix(id, "ML-KEM") {
			t.Errorf("%s was attributed although no provider was reported", id)
		}
	}
}

func TestHostileNamesAreSkippedAndReported(t *testing.T) {
	f := windows11()
	f.registered = append(f.registered, "evil\x00name", "line\nbreak", strings.Repeat("A", MaxName+50), "")
	f.csps = append(f.csps, CSP{Name: "bad\x1b[31mred", Type: 1})
	b, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindProvider && !evidence.SafeText(o.Subject.Name, MaxName) {
			t.Errorf("an unsafe provider name was carried: %q", o.Subject.Name)
		}
	}
	if b.Coverage[0].Status != evidence.CoveragePartial || b.Coverage[0].Limits["namesSkipped"] == "" {
		t.Errorf("hostile names must make the coverage partial and be counted: %+v", b.Coverage[0])
	}
}

func TestOneFailedCallIsPartialNotFatal(t *testing.T) {
	f := windows11()
	f.failing = map[string]error{"CSPs": &StatusError{Call: "CryptEnumProvidersW", Code: 5}}
	b, err := collect(t, f)
	if err != nil {
		t.Fatalf("a single failed call must not fail the run: %v", err)
	}
	c := b.Coverage[0]
	if c.Status != evidence.CoveragePartial || c.Limits["failedCalls"] != "1" || !strings.Contains(c.Limits["firstFailure"], "0x00000005") {
		t.Errorf("coverage = %+v", c)
	}
	if len(providersOf(b)) == 0 {
		t.Error("the providers that could be read were dropped")
	}
	for _, p := range providersOf(b) {
		if p.Subject.Attrs["providerKind"] == "csp" {
			t.Error("a legacy provider appeared although its enumeration failed")
		}
	}
}

func TestEverythingFailingIsAnError(t *testing.T) {
	f := &fake{native: true, failing: map[string]error{}}
	for _, m := range []string{"Algorithms", "AlgorithmProviders", "RegisteredProviders", "StorageProviders", "CSPs", "Probe"} {
		f.failing[m] = ErrUnsupported
	}
	b, err := collect(t, f)
	if err == nil {
		t.Fatal("a run in which nothing could be read must be an error")
	}
	if b.Coverage[0].Status != evidence.CoverageFailed {
		t.Errorf("status = %s", b.Coverage[0].Status)
	}
}

func TestAStalledCallIsBoundedByTheTimeout(t *testing.T) {
	old := callTimeout
	callTimeout = 80 * time.Millisecond
	t.Cleanup(func() { callTimeout = old })
	f := windows11()
	f.delay = map[string]time.Duration{"RegisteredProviders": 5 * time.Second}
	start := time.Now()
	b, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("the run took %v; a stalled call must not stall it", time.Since(start))
	}
	c := b.Coverage[0]
	if c.Status != evidence.CoveragePartial || !strings.Contains(c.Limits["firstFailure"], "timed out") {
		t.Errorf("coverage = %+v", c)
	}
}

func TestCancellationReturnsWhatWasReadWithAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(live(), windows11()).Collect(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestAProviderAlgorithmListIsBounded(t *testing.T) {
	f := windows11()
	var many []Algorithm
	for i := 0; i < 500; i++ {
		many = append(many, Algorithm{Name: fmt.Sprintf("ALGORITHM-NUMBER-%03d", i), Ops: OpHash})
	}
	f.algorithms[OpHash] = many
	for _, a := range many {
		f.providers[a.Name] = []string{primitive}
	}
	b, _ := collect(t, f)
	if n := len(providersOf(b)[primitive].Subject.Attrs["algorithms"]); n > maxAlgorithmsLen {
		t.Errorf("algorithm list is %d bytes, cap is %d", n, maxAlgorithmsLen)
	}
	if b.Coverage[0].Limits["algorithmListsTruncated"] == "" || b.Coverage[0].Status != evidence.CoveragePartial {
		t.Errorf("a truncated list must be reported: %+v", b.Coverage[0])
	}
}

func TestOutputIsDeterministicAndCoverageNamesTheBlindSpots(t *testing.T) {
	a, _ := collect(t, windows11())
	b, _ := collect(t, windows11())
	ids := func(x evidence.Batch) []string {
		var out []string
		for _, o := range x.Observations {
			out = append(out, o.ID)
		}
		return out
	}
	if !reflect.DeepEqual(ids(a), ids(b)) || !sort.StringsAreSorted(providerKeys(a)) {
		t.Error("output is not deterministic or not sorted")
	}
	joined := strings.Join(a.Coverage[0].Unseen, "|")
	for _, want := range []string{"not opened", "loading it", "policy", "keys held by any provider"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the blind spots do not mention %q", want)
		}
	}
	if a.Coverage[0].Status != evidence.CoverageComplete {
		t.Errorf("a clean run is complete: %+v", a.Coverage[0])
	}
}

func TestRegisteredAndValid(t *testing.T) {
	if err := New(live(), windows11()).Info().Validate(); err != nil {
		t.Error(err)
	}
}

func providerKeys(b evidence.Batch) []string {
	var out []string
	for _, o := range b.Observations {
		if o.Subject.Kind == evidence.KindProvider {
			out = append(out, o.Subject.Key)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
