// Package wincerts is the sensor for the certificates in the Windows system certificate
// stores: the machine's own certificates, the trust anchors (root and intermediate
// authorities), trusted publishers and trusted people, for the machine and for the user
// the collector runs as.
//
// It asks Windows, through internal/winapi, for each allow-listed store and describes each
// certificate from its own encoded bytes: subject, issuer, validity, key algorithm and
// size, signature algorithm, and whether a private key is associated with it. It never
// reads, opens, exports or uses a key (ADR-0005, ADR-0016; SECARCH-001 SR-06, SR-07).
//
// Like windows-cng it knows nothing about Windows itself, so the logic is tested anywhere
// with a fake, and it runs only for a live Windows host: a mounted disk or a --root
// override has no certificate stores this sensor could ask about.
package wincerts

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/example/cipherhorizon/internal/certinfo"
	"github.com/example/cipherhorizon/internal/evidence"
	"github.com/example/cipherhorizon/internal/hostinfo"
	"github.com/example/cipherhorizon/internal/sense"
	"github.com/example/cipherhorizon/internal/winapi"
)

const (
	// Name is the sensor's registry name.
	Name = "windows-certs"
	// Version is the version of this sensor's behaviour.
	Version = "0.1.0"

	maxNameLen = 512
	maxAttrLen = 1024
)

// callTimeout bounds one store read. A store that stalls must not stall the run; a
// variable only so a test can shorten it.
var callTimeout = 15 * time.Second

func init() {
	sense.Register(Name, func(env sense.Env) (sense.Sensor, error) { return New(env, winapi.NewCertStore()), nil })
}

// Register adds the sensor to reg, asking api. Production uses the package's init (the
// real Windows API); tests register a fake.
func Register(reg *sense.Registry, api winapi.CertStoreAPI) error {
	return reg.Register(Name, func(env sense.Env) (sense.Sensor, error) { return New(env, api), nil })
}

// Sensor implements sense.Sensor.
type Sensor struct {
	api  winapi.CertStoreAPI
	env  sense.Env
	tier string
}

var _ sense.Sensor = (*Sensor)(nil)

// New returns a sensor that asks api about the host described by env.
func New(env sense.Env, api winapi.CertStoreAPI) *Sensor {
	tier := env.Tier
	if tier == "" {
		tier = hostinfo.TierUser
	}
	return &Sensor{api: api, env: env, tier: tier}
}

// Info implements sense.Sensor.
func (*Sensor) Info() sense.Info {
	return sense.Info{Name: Name, Version: Version, Methods: []string{evidence.MethodCertStore}}
}

// Detect reports whether Windows can be asked about THIS machine.
func (s *Sensor) Detect(context.Context) (bool, error) {
	return s.env.OS == "windows" && s.env.Live && s.api.Native(), nil
}

var unseen = []string{
	"the Disallowed store (certificates the system explicitly distrusts) and any store not on the fixed list: My, Root, CA, TrustedPeople, TrustedPublisher and AuthRoot are read for the machine and the current user",
	"the certificate stores of other users, of services, smart cards and hardware tokens, and stores delivered by Group Policy or held outside the local registry",
	"certificates in application stores that do not use the Windows stores (Firefox and Java keep their own)",
	"private keys: never read. Whether a key is associated with a certificate is one property of the store entry; it says nothing about where the key is, whether it can be exported, or whether anyone can use it",
	"whether a certificate is trusted by a particular application or in use by any service",
}

type storeSpec struct {
	loc  winapi.StoreLocation
	name string
}

// specs is every (location, store) read, in a fixed order so output is deterministic.
func specs() []storeSpec {
	var out []storeSpec
	for _, loc := range []winapi.StoreLocation{winapi.LocalMachine, winapi.CurrentUser} {
		for _, n := range winapi.CertStoreNames {
			out = append(out, storeSpec{loc, n})
		}
	}
	return out
}

type result struct {
	certs   []winapi.StoreCert
	skipped int
	err     error
}

// Collect reads each store and returns the observations.
func (s *Sensor) Collect(ctx context.Context) (evidence.Batch, error) {
	var batch evidence.Batch
	var (
		stores, denied, failed, unparseable, skipped, certs, unsafe int
		failures                                                    []string
	)
	for _, sp := range specs() {
		if err := ctx.Err(); err != nil {
			break
		}
		r := s.read(ctx, sp)
		stores++
		skipped += r.skipped
		if r.err != nil {
			var st *winapi.StatusError
			if errors.As(r.err, &st) && (st.Code == 5 || st.Code == 0x80070005) { // ACCESS_DENIED
				denied++
			} else {
				failed++
			}
			failures = append(failures, fmt.Sprintf("%s/%s: %v", sp.loc, sp.name, r.err))
			continue
		}
		location := "cert-store:" + string(sp.loc) + "/" + sp.name
		seen := map[string]bool{}
		for _, sc := range r.certs {
			c, err := x509.ParseCertificate(sc.DER)
			if err != nil {
				unparseable++
				continue
			}
			f := certinfo.Describe(c)
			if seen[f.SHA256] {
				continue // the same certificate twice in one store is one sighting
			}
			seen[f.SHA256] = true
			o, ok := s.observation(f, location, sc.PrivateKey)
			if !ok {
				unsafe++
				continue
			}
			batch.Observations = append(batch.Observations, o)
			certs++
		}
	}

	cov := evidence.Coverage{
		Sensor: Name, Method: evidence.MethodCertStore,
		Scope:  "certificates in the MY, Root, CA, TrustedPeople, TrustedPublisher and AuthRoot system stores, for the machine and the current user",
		Status: evidence.CoverageComplete, Unseen: unseen, Denied: denied,
		Limits: map[string]string{
			"storesRead": strconv.Itoa(stores), "certificates": strconv.Itoa(certs),
			"maxCertsPerStore": strconv.Itoa(winapi.MaxCertsPerStore), "maxCertBytes": strconv.Itoa(winapi.MaxCertDER),
		},
	}
	if unparseable > 0 {
		cov.Limits["unparseableCertificates"] = strconv.Itoa(unparseable)
	}
	if skipped > 0 {
		cov.Limits["skippedOversizedOrOverCap"] = strconv.Itoa(skipped)
	}
	if unsafe > 0 {
		cov.Limits["skippedUnsafeText"] = strconv.Itoa(unsafe)
	}
	switch {
	case failed > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownError
		cov.Limits["storesFailed"] = strconv.Itoa(failed)
	case denied > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownPermission
	case skipped > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
	case unparseable > 0 || unsafe > 0:
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownUnsupported
	}
	if len(failures) > 0 {
		cov.Limits["firstFailure"] = evidence.Clean(failures[0], 200)
	}
	batch.Coverage = []evidence.Coverage{cov}
	if err := ctx.Err(); err != nil {
		cov.Status, cov.Reason = evidence.CoveragePartial, evidence.UnknownBudget
		batch.Coverage = []evidence.Coverage{cov}
		return batch, fmt.Errorf("windows-certs: %w", err)
	}
	return batch, nil
}

// read asks for one store under the call budget. A store that stalls is reported as a failure
// of that store; the goroutine it leaves behind ends when Windows answers.
func (s *Sensor) read(ctx context.Context, sp storeSpec) result {
	ch := make(chan result, 1)
	go func() {
		certs, skipped, err := s.api.CertStore(sp.loc, sp.name)
		ch <- result{certs, skipped, err}
	}()
	select {
	case r := <-ch:
		return r
	case <-time.After(callTimeout):
		return result{err: errors.New("timed out")}
	case <-ctx.Done():
		return result{err: ctx.Err()}
	}
}

func (s *Sensor) observation(f certinfo.Facts, location, privateKey string) (evidence.Observation, bool) {
	if !evidence.SafeText(location, 1024) {
		return evidence.Observation{}, false
	}
	attrs := map[string]string{
		"sha256":     f.SHA256,
		"serial":     evidence.Clean(f.SerialHex, 128),
		"subject":    evidence.Clean(f.Subject, maxAttrLen),
		"issuer":     evidence.Clean(f.Issuer, maxAttrLen),
		"notBefore":  f.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		"notAfter":   f.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		"keyAlg":     evidence.Clean(f.KeyAlgorithm, 64),
		"sigAlg":     evidence.Clean(f.SigName, 64),
		"isCA":       strconv.FormatBool(f.IsCA),
		"selfSigned": strconv.FormatBool(f.SelfSigned),
	}
	if f.KeyBits > 0 {
		attrs["keyBits"] = strconv.Itoa(f.KeyBits)
	}
	if f.Curve != "" {
		attrs["curve"] = evidence.Clean(f.Curve, 64)
	}
	if names := append(append([]string{}, f.DNSNames...), f.IPAddresses...); len(names) > 0 {
		attrs["dnsNames"] = evidence.Clean(strings.Join(names, ","), maxAttrLen)
	}
	if len(f.KeyUsage) > 0 {
		attrs["keyUsage"] = strings.Join(f.KeyUsage, ",")
	}
	for k, v := range attrs {
		if v == "" {
			delete(attrs, k)
		}
	}
	name := evidence.Clean(f.Subject, maxNameLen)
	if name == "" {
		name = f.SHA256
	}
	if privateKey != winapi.KeyYes && privateKey != winapi.KeyNo {
		privateKey = winapi.KeyUnknown
	}
	o := evidence.Observation{
		Stream: evidence.StreamHost, Origin: evidence.OriginObserved,
		Subject: evidence.Subject{Kind: evidence.KindCertificate, Key: evidence.CertificateKey(f.SHA256), Name: name, Attrs: attrs},
		Claim:   evidence.Claim{Rung: evidence.RungProvisioned}, Outcome: evidence.OutcomeObserved,
		Method: evidence.MethodCertStore, Source: evidence.Source{Kind: "api", Location: location, Attrs: map[string]string{"privateKey": privateKey}},
		Privilege: s.tier,
	}
	evidence.Finish(&o)
	return o, true
}
