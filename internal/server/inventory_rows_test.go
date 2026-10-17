package server

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Two certificates with one subject and different keys (an ECDSA and an ML-DSA certificate for the
// same host) are two keys, each with its own status; and a merge's result never depends on the
// order it read its sources. Found by the PRD-009 journey: the shared row took either status at
// random, so the inventory's counts changed between two calls on the same data.
func TestInventoryKeysWithOneSubjectAreTwoRowsWhateverTheOrder(t *testing.T) {
	alg := func(ref, name, status string) cdx.Component {
		return cdx.Component{BOMRef: ref, Name: name, Type: cdx.ComponentTypeCryptographicAsset,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeAlgorithm, AlgorithmProperties: &cdx.CryptoAlgorithmProperties{Primitive: cdx.CryptoPrimitiveSignature}},
			Properties:       &[]cdx.Property{{Name: "cipherhorizon:pqc:status", Value: status}}}
	}
	key := func(ref string) cdx.Component {
		return cdx.Component{BOMRef: ref, Name: "CN=localhost public key", Type: cdx.ComponentTypeCryptographicAsset,
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey}}}
	}
	comps := []cdx.Component{
		alg("a/ecdsa", "ECDSA-P256", "quantum-vulnerable"), alg("a/mldsa", "ML-DSA-65", "quantum-safe"),
		key("k/1"), key("k/2"),
		// The same algorithm name reported twice with different verdicts (two sources): the worse wins.
		alg("a/x1", "Odd", "quantum-safe"), alg("a/x2", "Odd", "quantum-vulnerable"),
	}
	deps := map[string][]string{"k/1": {"a/ecdsa"}, "k/2": {"a/mldsa"}}
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5}, {3, 2, 1, 0, 5, 4}, {1, 3, 0, 5, 2, 4}} {
		cs := make([]cdx.Component, len(order))
		for i, j := range order {
			cs[i] = comps[j]
		}
		inv := &mergedInventory{bom: bomView{&cdx.BOM{Components: &cs}}, deps: deps, seenIn: map[string][]sourceLabel{}}
		keys := inventoryRows(inv, "key")
		got := map[string]bool{}
		for _, r := range keys {
			got[r.Quantum+" "+r.Detail] = true
		}
		if len(keys) != 2 || !got["quantum-vulnerable public-key · ECDSA-P256"] || !got["quantum-safe public-key · ML-DSA-65"] {
			t.Errorf("order %v: keys %+v", order, keys)
		}
		for _, r := range inventoryRows(inv, "algorithm") {
			if r.Name == "Odd" && r.Quantum != "quantum-vulnerable" {
				t.Errorf("order %v: conflicting verdicts merged to %s, want the worse", order, r.Quantum)
			}
		}
	}
}
