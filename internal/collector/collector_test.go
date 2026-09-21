package collector_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cbom-scan/internal/collector"
)

func TestPluginInfoValidate(t *testing.T) {
	good := collector.PluginInfo{Name: "apt", Version: "0.1.0", SourceType: collector.SourceOSPackage}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid info rejected: %v", err)
	}

	tests := map[string]collector.PluginInfo{
		"empty name":        {Name: "", Version: "1", SourceType: collector.SourceOSPackage},
		"uppercase name":    {Name: "Apt", Version: "1", SourceType: collector.SourceOSPackage},
		"underscore name":   {Name: "jvm_provider", Version: "1", SourceType: collector.SourceProvider},
		"trailing dash":     {Name: "apt-", Version: "1", SourceType: collector.SourceOSPackage},
		"leading digit":     {Name: "1apt", Version: "1", SourceType: collector.SourceOSPackage},
		"empty version":     {Name: "apt", Version: "", SourceType: collector.SourceOSPackage},
		"unknown source":    {Name: "apt", Version: "1", SourceType: "magic"},
		"empty source type": {Name: "apt", Version: "1"},
	}
	for name, info := range tests {
		t.Run(name, func(t *testing.T) {
			if err := info.Validate(); err == nil {
				t.Errorf("Validate(%+v) = nil, want error", info)
			}
		})
	}

	for _, ok := range []string{"apt", "jvm-provider", "cert-store2"} {
		info := collector.PluginInfo{Name: ok, Version: "1", SourceType: collector.SourceRuntime}
		if err := info.Validate(); err != nil {
			t.Errorf("name %q rejected: %v", ok, err)
		}
	}
}

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
