//go:build windows

package wincng

import (
	"context"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
)

// The whole sensor against the real machine. Exact contents differ between Windows
// builds, so this asserts what must hold on any supported one, and that the sensor
// never opens a provider it may not.
func TestTheRealSensorOnThisMachine(t *testing.T) {
	s := New(sense.Env{OS: "windows", Tier: "user", Live: true}, NewAPI())
	if ok, err := s.Detect(context.Background()); !ok || err != nil {
		t.Fatalf("Detect = %v, %v on a live Windows host", ok, err)
	}
	b, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range b.Observations {
		if verr := evidence.Validate(o); verr != nil {
			t.Fatalf("invalid observation: %v", verr)
		}
	}
	p := providersOf(b)
	prim, ok := p["Microsoft Primitive Provider"]
	if !ok || prim.Subject.Attrs["algorithms"] == "" {
		t.Fatalf("the primitive provider is missing or lists no algorithms: %+v", prim)
	}
	e := edgesOf(b)
	pk := evidence.ProviderKey("cng", "Microsoft Primitive Provider")
	for _, id := range []string{"AES", "RSA", "SHA-256", "ECDSA"} {
		if !contains(e[id], pk) {
			t.Errorf("%s is not attributed to the primitive provider", id)
		}
	}
	opened := 0
	for name, o := range p {
		if o.Subject.Attrs["opened"] == "true" {
			opened++
			if name != "Microsoft Software Key Storage Provider" {
				t.Errorf("%s was opened; only the in-box software provider may be", name)
			}
		}
	}
	if opened > 1 {
		t.Errorf("%d providers opened", opened)
	}
	if b.Coverage[0].Status != evidence.CoverageComplete {
		t.Errorf("coverage = %+v", b.Coverage[0])
	}
}
