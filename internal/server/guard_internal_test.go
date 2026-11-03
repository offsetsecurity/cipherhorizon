package server

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
)

// The CRL fetcher keeps its own copy of the cloud-metadata addresses (it must not import the
// server). Even with private and loopback addresses allowed it must refuse every address the
// scan guard refuses as metadata.
func TestCRLPolicyRefusesEveryMetadataAddress(t *testing.T) {
	loose := revocation.Policy{AllowPrivate: true, AllowLoopback: true}
	for _, ip := range extraBlocked {
		if err := loose.CheckIP(ip); err == nil {
			t.Errorf("the CRL policy allows %s, which the scan guard blocks", ip)
		}
	}
}
