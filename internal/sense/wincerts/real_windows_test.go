//go:build windows

package wincerts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/evidence"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	"github.com/offsetsecurity/cipherhorizon/internal/winapi"
)

// The whole sensor against the real machine's certificate stores. Exact contents differ
// between machines, so this asserts what must hold on any Windows: the stores answer, every
// observation is valid, trusted roots have no private key, and nothing that could be key
// material is in the output.
func TestTheRealSensorOnThisMachine(t *testing.T) {
	s := New(sense.Env{OS: "windows", Tier: "user", Live: true}, winapi.NewCertStore())
	if ok, err := s.Detect(context.Background()); !ok || err != nil {
		t.Fatalf("Detect = %v, %v on a live Windows host", ok, err)
	}
	b, err := s.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g := evidence.NewGraph(evidence.Host{Name: "h", OSFamily: "windows", PrivilegeTier: "user"})
	if err := g.AddBatch(b); err != nil {
		t.Fatalf("the real output breaks the evidence contract: %v", err)
	}
	if len(b.Observations) == 0 {
		t.Fatal("no certificate observed on a Windows machine")
	}
	// A machine can hold the key of a root it made itself (CI runners and mkcert do), so one such
	// root is fine; every root claiming a key means the property query is broken.
	roots, keyed := 0, 0
	for _, o := range b.Observations {
		if strings.HasSuffix(o.Source.Location, "/Root") {
			roots++
			if o.Source.Attrs["privateKey"] == "yes" {
				keyed++
				t.Logf("a trusted root with a key association: %s", o.Subject.Name)
			}
		}
		if o.Subject.Attrs["keyAlg"] == "" || o.Subject.Attrs["notAfter"] == "" {
			t.Errorf("%s: missing key algorithm or validity", o.Subject.Name)
		}
	}
	if roots == 0 {
		t.Error("no certificate in a Root store")
	} else if keyed == roots {
		t.Error("every trusted root reports a private key; check the property query")
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "BEGIN") || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Error("armored text in the output")
	}
	t.Logf("%d observations; coverage %s/%s %v", len(b.Observations), b.Coverage[0].Status, b.Coverage[0].Reason, b.Coverage[0].Limits)
}
