package tlscbom_test

import (
	"slices"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

func withSignatures(control string, accepted ...string) *tlsprobe.Report {
	r := sampleReport()
	r.Signatures = &tlsprobe.SignatureResult{Version: "TLSv1.3", Control: control}
	for _, c := range tlsprobe.SigCandidates() {
		res := tlsprobe.SigRefused
		if slices.Contains(accepted, c.Name) {
			res = tlsprobe.SigAccepted
		}
		r.Signatures.Schemes = append(r.Signatures.Schemes, tlsprobe.SigScheme{ID: c.ID, Name: c.Name, Algorithm: c.Algorithm, PQ: c.PQ, Result: res})
	}
	return r
}

// REQ-PQS-6: the accepted signature schemes reach the endpoint CBOM, schema-valid, never as "negotiated".
func TestEndpointCBOMListsAcceptedSignatureAlgorithms(t *testing.T) {
	assets := tlscbom.FromTLSReport(withSignatures(tlsprobe.SigRefused, "mldsa65", "ecdsa_secp256r1_sha256", "ed448"))
	proto := findComponent(assets, "protocol/tls/1.3")
	if proto == nil {
		t.Fatal("no TLS 1.3 protocol component")
	}
	if got, _ := property(proto, "accepted-signature-schemes"); got != "mldsa65,ecdsa_secp256r1_sha256,ed448" {
		t.Errorf("accepted-signature-schemes = %q", got)
	}
	for _, id := range []string{"ML-DSA-65", "ECDSA"} {
		a, _ := algo.Lookup(id)
		if !slices.Contains(proto.DependsOn, a.BOMRef()) {
			t.Errorf("TLS 1.3 does not depend on %s (%s): %v", id, a.BOMRef(), proto.DependsOn)
		}
		c := findComponent(assets, a.BOMRef())
		if c == nil {
			t.Fatalf("no component for %s", id)
		}
		if _, flagged := property(c, "negotiated"); flagged && id == "ML-DSA-65" {
			t.Errorf("%s marked negotiated: accepting a scheme is not using it", id)
		}
	}
	bom, warnings := cbom.Build(assets, cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, Endpoint: "endpoint.example:443",
		Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	})
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	schematest.Validate(t, encode(t, bom))

	// An inconclusive stage adds nothing.
	assets = tlscbom.FromTLSReport(withSignatures(tlsprobe.SigAccepted, "mldsa65"))
	if _, ok := property(findComponent(assets, "protocol/tls/1.3"), "accepted-signature-schemes"); ok {
		t.Error("an inconclusive signature stage reached the CBOM")
	}
}
