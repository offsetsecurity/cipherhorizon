package knowledge_test

import (
	"testing"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/knowledge"
)

// Every catalogue ID the CNG tables name must exist, or the CBOM projection would refuse the run.
func TestCNGMappingsPointAtTheCatalogue(t *testing.T) {
	for _, id := range []string{"AES", "3DES", "DES", "RC2", "RC4", "MD2", "MD4", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
		"SHA3-256", "SHA3-384", "SHA3-512", "RSA", "DSA", "DH", "ECDSA", "ECDH", "ChaCha20-Poly1305"} {
		if _, ok := algo.Lookup(id); !ok {
			t.Errorf("%s is not in the catalogue", id)
		}
	}
	for name, want := range map[string]string{"SHA1": "SHA-1", "ECDSA_P256": "ECDSA", "ECDH_P521": "ECDH", "3DES_112": "3DES", "XTS-AES": "AES"} {
		if got, ok := knowledge.CNGAlgorithm(name); !ok || got != want {
			t.Errorf("CNGAlgorithm(%q) = %q, %v; want %q", name, got, ok, want)
		}
		if _, ok := algo.Lookup(want); !ok {
			t.Errorf("mapped ID %q is not in the catalogue", want)
		}
	}
	for _, unmapped := range []string{"PBKDF2", "HKDF", "RNG", "DUALECRNG", "KMAC128", "SHAKE128", "Composite-ML-DSA", "DESX", "ML-KEM", "ML-DSA", "not-an-algorithm"} {
		if _, ok := knowledge.CNGAlgorithm(unmapped); ok {
			t.Errorf("%q must not map to a catalogue algorithm (the post-quantum families come from probes)", unmapped)
		}
	}
}

func TestCNGProbesAreDigitsOnlyAndCatalogued(t *testing.T) {
	for _, p := range knowledge.CNGProbes {
		if p.ParamSet == "" || len(p.ParamSet) > 4 {
			t.Errorf("%+v: bad parameter set", p)
		}
		for _, c := range p.ParamSet {
			if c < '0' || c > '9' {
				t.Errorf("%+v: parameter set must be digits", p)
			}
		}
		if _, ok := algo.Lookup(p.ID); !ok {
			t.Errorf("%+v: %s is not in the catalogue", p, p.ID)
		}
		if _, ok := knowledge.CNGFamilies[p.Algorithm]; !ok {
			t.Errorf("%+v: %s has no family entry", p, p.Algorithm)
		}
	}
	for fam, id := range knowledge.CNGFamilies {
		if _, ok := algo.Lookup(id); !ok {
			t.Errorf("family %s -> %s is not in the catalogue", fam, id)
		}
	}
}

// The allow-list is the security boundary for loading provider code: pin it.
func TestOnlyTheInBoxSoftwareProviderMayBeOpened(t *testing.T) {
	if len(knowledge.OpenableStorageProviders) != 1 || !knowledge.OpenableStorageProviders["Microsoft Software Key Storage Provider"] {
		t.Errorf("allow-list = %v", knowledge.OpenableStorageProviders)
	}
	for _, hardware := range []string{"Microsoft Platform Crypto Provider", "Microsoft Smart Card Key Storage Provider", "Microsoft Passport Key Storage Provider", "Microsoft Pluton Cryptographic Provider"} {
		if knowledge.OpenableStorageProviders[hardware] {
			t.Errorf("%s must never be opened", hardware)
		}
	}
}
