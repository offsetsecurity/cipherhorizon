package collector_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
)

func TestCryptoAssetValidate(t *testing.T) {
	good := collector.CryptoAsset{Component: cdx.Component{BOMRef: "r", Name: "n", Type: cdx.ComponentTypeLibrary}}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid asset rejected: %v", err)
	}
	for name, c := range map[string]cdx.Component{
		"no bom-ref": {Name: "n", Type: cdx.ComponentTypeLibrary},
		"no name":    {BOMRef: "r", Type: cdx.ComponentTypeLibrary},
		"no type":    {BOMRef: "r", Name: "n"},
	} {
		if err := (collector.CryptoAsset{Component: c}).Validate(); err == nil {
			t.Errorf("%s: Validate = nil, want error", name)
		}
	}
}
