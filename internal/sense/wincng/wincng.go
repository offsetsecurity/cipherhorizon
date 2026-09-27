// Package wincng is the sensor for the cryptography Windows itself provides: the CNG
// algorithm registry and primitive providers, key storage providers (KSPs) and legacy
// cryptographic service providers (CSPs). Unlike the file sensor it does not infer
// capability from a file's name and version; it ASKS the operating system what is
// registered, which is a stronger kind of evidence (`capable`, `probed`).
//
// The sensor itself knows nothing about Windows: every call goes through the API in
// internal/winapi, so the logic here is tested anywhere with a fake. Security rules
// (ADR-0013): no subprocess and no network; no key, certificate or secret is opened or
// enumerated; a key storage provider is OPENED (which loads its code) only if it is on
// the in-box allow-list in internal/knowledge; a parameter set is probed only for the
// two post-quantum families; and it runs only for a live Windows host.
package wincng

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/knowledge"
	"github.com/example/cipherhorizon/internal/sense"
)

const (
	// Name is the sensor's registry name.
	Name = "windows-cng"
	// Version is the version of this sensor's behaviour.
	Version = "0.1.0"

	maxCommentLen    = 256
	maxAlgorithmsLen = 1000 // bytes of the provider's algorithm list carried as one attribute
)

// callTimeout bounds one call into Windows. A provider that stalls must not stall the
// run; a variable only so a test can shorten it.
var callTimeout = 15 * time.Second

func init() {
	sense.Register(Name, func(env sense.Env) (sense.Sensor, error) { return New(env, NewAPI()), nil })
}

// Register adds the sensor to reg, asking api. Production uses the package's init
// (the real Windows API); tests register a fake.
func Register(reg *sense.Registry, api API) error {
	return reg.Register(Name, func(env sense.Env) (sense.Sensor, error) { return New(env, api), nil })
}

// Sensor implements sense.Sensor.
type Sensor struct {
	api  API
	env  sense.Env
	tier string
}

var _ sense.Sensor = (*Sensor)(nil)

// New returns a sensor that asks api about the host described by env.
func New(env sense.Env, api API) *Sensor {
	tier := env.Tier
	if tier == "" {
		tier = hostinfo.TierUser
	}
	return &Sensor{api: api, env: env, tier: tier}
}

// Info implements sense.Sensor.
func (*Sensor) Info() sense.Info {
	return sense.Info{Name: Name, Version: Version, Methods: []string{
		evidence.MethodCNGProviders, evidence.MethodCNGAlgorithms, evidence.MethodKSPProviders,
		evidence.MethodKSPAlgorithms, evidence.MethodCSPProviders, evidence.MethodCNGProbe,
	}}
}

// Detect reports whether Windows can be asked about THIS machine. The sensor asks the
// running operating system, so it runs only for a live Windows host: never for a
// mounted disk, a `--root` override, an image or a test fixture, where the answers
// would describe the wrong machine.
func (s *Sensor) Detect(context.Context) (bool, error) {
	return s.env.OS == "windows" && s.env.Live && s.api.Native(), nil
}

var unseen = []string{
	"key storage providers other than the in-box software provider (Platform/TPM, Smart Card, Passport, Pluton, and any third-party or hardware provider): listed by name and not opened, because opening one loads its code, so the algorithms they offer are not enumerated",
	"legacy cryptographic service providers: listed by name and type only; asking one for its algorithms means loading it",
	"which provider or algorithm any application actually uses, and which algorithms are enabled for TLS or other protocols (policy is not collected by this version)",
	"keys held by any provider (never collected); the certificates in the system stores are the certificate sensor's business",
	"algorithms that only a third-party provider adds",
	"that Windows offers an algorithm does not mean it is approved, enabled or configured for use",
}

// provider is one registered provider being assembled before it is emitted.
type provider struct {
	name      string
	namespace string // "cng" or "csp"
	cng, ksp  bool
	csp       bool
	comment   string
	cspType   uint32
	openable  bool
	opened    bool
	algs      map[string]bool
}

type edge struct{ algorithm, provider, method string }

type run struct {
	s         *Sensor
	ctx       context.Context
	providers map[string]*provider
	edges     map[edge]bool
	native    map[string]bool // every registered algorithm identifier

	ok, calls  int
	failed     []string
	skipped    int // names the API returned that were unusable
	unsafeName int
	truncated  int
	probes     int
	probesOK   int
	kspOpened  int
}

// Collect asks Windows and returns what it says.
func (s *Sensor) Collect(ctx context.Context) (evidence.Batch, error) {
	r := &run{s: s, ctx: ctx, providers: map[string]*provider{}, edges: map[edge]bool{}, native: map[string]bool{}}

	r.registered()
	r.storage()
	r.algorithms()
	r.storageAlgorithms()
	r.probe()
	r.legacy()

	batch := r.emit()
	cov := r.coverage()
	batch.Coverage = []evidence.Coverage{cov}
	if err := ctx.Err(); err != nil {
		batch.Coverage[0].Status, batch.Coverage[0].Reason = evidence.CoveragePartial, evidence.UnknownBudget
		return batch, fmt.Errorf("%s: %w", Name, err)
	}
	if r.calls > 0 && r.ok == 0 {
		return batch, fmt.Errorf("%s: no call to Windows succeeded (%s)", Name, strings.Join(r.failed, "; "))
	}
	return batch, nil
}

// within runs one call into Windows with a deadline, so a stalled provider cannot
// stall the run. The goroutine of a call that times out is abandoned; the process is
// short-lived and the call holds nothing this run needs.
func within[T any](r *run, what string, f func() (T, int, error)) (T, bool) {
	var zero T
	if r.ctx.Err() != nil {
		return zero, false
	}
	r.calls++
	type result struct {
		v       T
		skipped int
		err     error
	}
	ch := make(chan result, 1)
	go func() {
		v, sk, err := f()
		ch <- result{v, sk, err}
	}()
	select {
	case res := <-ch:
		r.skipped += res.skipped
		if res.err != nil {
			r.failed = append(r.failed, what+": "+briefErr(res.err))
			return zero, false
		}
		r.ok++
		return res.v, true
	case <-time.After(callTimeout):
		r.failed = append(r.failed, what+": timed out")
		return zero, false
	case <-r.ctx.Done():
		return zero, false
	}
}

func briefErr(err error) string {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Error()
	}
	if errors.Is(err, ErrUnsupported) {
		return "not available on this Windows"
	}
	return "failed"
}

// usable applies the sensor's own check to a name before it is used at all.
func (r *run) usable(name string) bool {
	if name == "" || !evidence.SafeText(name, MaxName) {
		r.unsafeName++
		return false
	}
	return true
}

func (r *run) provider(namespace, name string) *provider {
	key := evidence.ProviderKey(namespace, name)
	p, ok := r.providers[key]
	if !ok {
		p = &provider{name: name, namespace: namespace, algs: map[string]bool{}}
		r.providers[key] = p
	}
	return p
}

func (r *run) registered() {
	names, ok := within(r, "registered CNG providers", func() ([]string, int, error) { return r.s.api.RegisteredProviders() })
	if !ok {
		return
	}
	for _, n := range names {
		if r.usable(n) {
			r.provider("cng", n).cng = true
		}
	}
}

func (r *run) storage() {
	list, ok := within(r, "key storage providers", func() ([]StorageProvider, int, error) { return r.s.api.StorageProviders() })
	if !ok {
		return
	}
	for _, k := range list {
		if !r.usable(k.Name) {
			continue
		}
		p := r.provider("cng", k.Name)
		p.ksp = true
		p.openable = knowledge.OpenableStorageProviders[k.Name]
		if evidence.SafeText(k.Comment, maxCommentLen) {
			p.comment = k.Comment
		}
	}
}

// algorithms lists the registered identifiers per operation class, then asks who
// provides each one.
func (r *run) algorithms() {
	for _, op := range []uint32{OpCipher, OpHash, OpAsymmetricEncrypt, OpSecretAgreement, OpSignature, OpRNG, OpKeyDerivation} {
		list, ok := within(r, fmt.Sprintf("algorithm registry (class %#x)", op), func() ([]Algorithm, int, error) { return r.s.api.Algorithms(op) })
		if !ok {
			continue
		}
		for _, a := range list {
			if r.usable(a.Name) {
				r.native[a.Name] = true
			}
		}
	}
	for _, name := range sortedKeys(r.native) {
		provs, ok := within(r, "providers of "+name, func() ([]string, int, error) { return r.s.api.AlgorithmProviders(name) })
		if !ok {
			continue
		}
		for _, pn := range provs {
			if !r.usable(pn) {
				continue
			}
			p := r.provider("cng", pn)
			p.cng = true
			p.algs[name] = true
			if id, ok := knowledge.CNGAlgorithm(name); ok {
				r.edges[edge{id, evidence.ProviderKey("cng", pn), evidence.MethodCNGAlgorithms}] = true
			}
		}
	}
}

// storageAlgorithms opens ONLY the allow-listed in-box key storage provider. Every
// other one is listed by name and never loaded.
func (r *run) storageAlgorithms() {
	for _, key := range sortedKeys(r.providers) {
		p := r.providers[key]
		if !p.ksp || !p.openable {
			continue
		}
		list, ok := within(r, "algorithms of "+p.name, func() ([]Algorithm, int, error) { return r.s.api.StorageProviderAlgorithms(p.name, OpAll) })
		if !ok {
			continue
		}
		p.opened = true
		r.kspOpened++
		for _, a := range list {
			if !r.usable(a.Name) {
				continue
			}
			p.algs[a.Name] = true
			if id, ok := knowledge.CNGAlgorithm(a.Name); ok {
				r.edges[edge{id, key, evidence.MethodKSPAlgorithms}] = true
			}
		}
	}
}

// probe asks Windows whether it accepts each post-quantum parameter set. It is the
// only step that performs a cryptographic operation (an ephemeral in-memory key pair,
// destroyed at once) and is limited to the fixed list in the knowledge package.
func (r *run) probe() {
	families := make([]string, 0, len(knowledge.CNGFamilies))
	for f := range knowledge.CNGFamilies {
		families = append(families, f)
	}
	sort.Strings(families)
	for _, fam := range families {
		opens, ok := within(r, "open "+fam, func() (bool, int, error) { b, err := r.s.api.Probe(fam, ""); return b, 0, err })
		if !ok || !opens {
			continue
		}
		provs, ok := within(r, "providers of "+fam, func() ([]string, int, error) { return r.s.api.AlgorithmProviders(fam) })
		if !ok || len(provs) == 0 || !r.usable(provs[0]) {
			continue // without a provider there is nothing to attribute the capability to
		}
		pkey := evidence.ProviderKey("cng", provs[0])
		p := r.provider("cng", provs[0])
		p.cng = true
		p.algs[fam] = true

		confirmed := false
		for _, pr := range knowledge.CNGProbes {
			if pr.Algorithm != fam {
				continue
			}
			r.probes++
			yes, ok := within(r, "probe "+pr.ID, func() (bool, int, error) { b, err := r.s.api.Probe(pr.Algorithm, pr.ParamSet); return b, 0, err })
			if ok && yes {
				r.probesOK++
				confirmed = true
				r.edges[edge{pr.ID, pkey, evidence.MethodCNGProbe}] = true
			}
		}
		if !confirmed {
			// The family opens but no parameter set could be confirmed: say only that.
			r.edges[edge{knowledge.CNGFamilies[fam], pkey, evidence.MethodCNGProbe}] = true
		}
	}
}

func (r *run) legacy() {
	list, ok := within(r, "legacy providers", func() ([]CSP, int, error) { return r.s.api.CSPs() })
	if !ok {
		return
	}
	for _, c := range list {
		if !r.usable(c.Name) {
			continue
		}
		p := r.provider("csp", c.Name)
		p.csp, p.cspType = true, c.Type
	}
}

func (r *run) emit() evidence.Batch {
	var b evidence.Batch
	for _, key := range sortedKeys(r.providers) {
		p := r.providers[key]
		attrs := map[string]string{"providerKind": p.kind()}
		if p.csp {
			attrs["cspType"] = strconv.FormatUint(uint64(p.cspType), 10)
		}
		if p.comment != "" {
			attrs["comment"] = p.comment
		}
		if p.ksp {
			attrs["opened"] = strconv.FormatBool(p.opened)
		}
		if list := r.algorithmList(p); list != "" {
			attrs["algorithms"] = list
		}
		method, source := evidence.MethodCNGProviders, "bcrypt.dll/BCryptEnumRegisteredProviders"
		switch {
		case p.csp:
			method, source = evidence.MethodCSPProviders, "advapi32.dll/CryptEnumProvidersW"
		case p.ksp:
			method, source = evidence.MethodKSPProviders, "ncrypt.dll/NCryptEnumStorageProviders"
		}
		o := evidence.Observation{
			Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
			Subject: evidence.Subject{Kind: evidence.KindProvider, Key: key, Name: p.name, Attrs: attrs},
			Claim:   evidence.Claim{Rung: evidence.RungPresent}, Outcome: evidence.OutcomeObserved,
			Method: method, Source: evidence.Source{Kind: "api", Location: source}, Privilege: r.s.tier,
		}
		evidence.Finish(&o)
		b.Observations = append(b.Observations, o)
	}

	edges := make([]edge, 0, len(r.edges))
	for e := range r.edges {
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		a, c := edges[i], edges[j]
		if a.algorithm != c.algorithm {
			return a.algorithm < c.algorithm
		}
		if a.provider != c.provider {
			return a.provider < c.provider
		}
		return a.method < c.method
	})
	probed := evidence.Claim{Rung: evidence.RungCapable, Capable: evidence.CapableProbed}
	for _, e := range edges {
		source := "bcrypt.dll/BCryptEnumAlgorithms"
		switch e.method {
		case evidence.MethodKSPAlgorithms:
			source = "ncrypt.dll/NCryptEnumAlgorithms"
		case evidence.MethodCNGProbe:
			source = "bcrypt.dll/BCryptOpenAlgorithmProvider"
		}
		o := evidence.Observation{
			Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
			Subject:   evidence.Subject{Kind: evidence.KindAlgorithm, Key: evidence.AlgorithmKey(e.algorithm), Name: e.algorithm},
			Claim:     probed,
			Outcome:   evidence.OutcomeObserved,
			Relations: []evidence.Relation{{Kind: "provided-by", To: e.provider, Claim: probed}},
			Method:    e.method, Source: evidence.Source{Kind: "api", Location: source}, Privilege: r.s.tier,
		}
		evidence.Finish(&o)
		b.Observations = append(b.Observations, o)
	}
	return b
}

func (p *provider) kind() string {
	switch {
	case p.csp:
		return "csp"
	case p.cng && p.ksp:
		return "cng+ksp"
	case p.ksp:
		return "ksp"
	}
	return "cng"
}

// algorithmList is the provider's registered identifiers as one bounded attribute.
func (r *run) algorithmList(p *provider) string {
	names := sortedKeys(p.algs)
	var sb strings.Builder
	for i, n := range names {
		add := len(n)
		if i > 0 {
			add++
		}
		if sb.Len()+add > maxAlgorithmsLen {
			r.truncated++
			break
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(n)
	}
	return sb.String()
}

func (r *run) coverage() evidence.Coverage {
	cov := evidence.Coverage{
		Sensor: Name, Method: evidence.MethodCNGProviders,
		Scope:  "Windows CNG algorithm registry, CNG and key storage providers, legacy providers (by name) and post-quantum parameter sets, as reported by this machine",
		Status: evidence.CoverageComplete, Unseen: unseen,
		Limits: map[string]string{
			"providers": strconv.Itoa(len(r.providers)), "registeredAlgorithms": strconv.Itoa(len(r.native)),
			"storageProvidersOpened": strconv.Itoa(r.kspOpened),
			"parameterSetsProbed":    strconv.Itoa(r.probes), "parameterSetsAccepted": strconv.Itoa(r.probesOK),
			"callTimeoutSeconds": strconv.Itoa(int(callTimeout / time.Second)),
		},
	}
	switch {
	case r.calls > 0 && r.ok == 0:
		cov.Status, cov.Reason = evidence.CoverageFailed, evidence.UnknownError
	case len(r.failed) > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownError
	case r.skipped > 0 || r.unsafeName > 0 || r.truncated > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownUnsupported
	}
	if len(r.failed) > 0 {
		cov.Limits["failedCalls"] = strconv.Itoa(len(r.failed))
		cov.Limits["firstFailure"] = evidence.Clean(r.failed[0], 200)
	}
	if n := r.skipped + r.unsafeName; n > 0 {
		cov.Limits["namesSkipped"] = strconv.Itoa(n)
	}
	if r.truncated > 0 {
		cov.Limits["algorithmListsTruncated"] = strconv.Itoa(r.truncated)
	}
	return cov
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
