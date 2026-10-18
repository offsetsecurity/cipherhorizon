package algo_test

import (
	"math"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
)

// ENH-001: the strength calculations reproduce NIST's own published numbers, to the precision
// NIST prints them. If a constant or the rounding were wrong, these tables would not match.

// SP 800-56B Rev. 2 Appendix D, Table 4: modulus length → E → maximum security strength.
func TestGNFSReproducesNISTTables(t *testing.T) {
	for _, c := range []struct {
		bits     int
		e        float64
		decimals int
		strength int
	}{
		{2048, 110.1, 1, 112}, {3072, 131.97, 2, 128}, {4096, 149.73, 2, 152},
		{6144, 178.42, 2, 176}, {8192, 201.7, 1, 200},
	} {
		got := algo.GNFSEstimate(c.bits)
		p := math.Pow(10, float64(c.decimals))
		if math.Round(got*p)/p != c.e {
			t.Errorf("E(%d) = %.4f, NIST prints %v", c.bits, got, c.e)
		}
		if s := algo.IFCStrength(c.bits); s != c.strength {
			t.Errorf("IFCStrength(%d) = %d, NIST Table 4 says %d", c.bits, s, c.strength)
		}
	}
	// The calibration point: SP 800-57 Part 1 Table 2 gives 1024-bit RSA 80 bits.
	if e := algo.GNFSEstimate(1024); math.Abs(e-80) > 0.01 {
		t.Errorf("E(1024) = %.4f, want 80 (the formula's calibration)", e)
	}
	// SP 800-56A Rev. 3 Table 26: the RFC 7919 groups, by the same formula and rounding.
	for bits, want := range map[int]int{2048: 112, 3072: 128, 4096: 152, 6144: 176, 8192: 200} {
		if got := algo.FFCStrength(bits); got != want {
			t.Errorf("FFCStrength(%d) = %d, SP 800-56A Table 26 says %d", bits, got, want)
		}
	}
	// SP 800-57 Part 1 Table 2 rows below the 56B table: 1024 → 80.
	if got := algo.IFCStrength(1024); got != 80 {
		t.Errorf("IFCStrength(1024) = %d, want 80", got)
	}
	// …and k = 15360 at 256, the highest strength NIST assigns.
	if got := algo.IFCStrength(15360); got != 256 {
		t.Errorf("IFCStrength(15360) = %d, want 256", got)
	}
}

// SP 800-186 Table 1, from "one half of the bit length of n".
func TestECCStrengthReproducesSP800186(t *testing.T) {
	for curve, want := range map[string]int{
		"secp224r1": 112, "secp256r1": 128, "Curve25519": 128, "Ed25519": 128,
		"secp384r1": 192, "Curve448": 224, "Ed448": 224, "secp521r1": 256,
	} {
		got, ok := algo.CurveStrength(curve)
		if !ok || got != want {
			t.Errorf("CurveStrength(%s) = %d, %v; SP 800-186 Table 1 says %d", curve, got, ok, want)
		}
	}
	if _, ok := algo.CurveStrength("brainpoolP256r1"); ok {
		t.Error("a curve without a listed order was given a strength")
	}
}

// SP 800-57 Part 1 Tables 2 and 3.
func TestSymmetricAndHashStrengthsFollowSP80057(t *testing.T) {
	for _, c := range []struct {
		cipher string
		bits   int
		want   int
		broken bool
	}{
		{"AES", 128, 128, false}, {"AES", 256, 256, false}, {"3DES", 168, 112, false},
		{"DES", 56, 56, true}, {"RC4", 128, 56, true}, {"CHACHA20", 256, 256, false},
	} {
		got, broken := algo.SymmetricStrength(c.cipher, c.bits)
		if got != c.want || broken != c.broken {
			t.Errorf("SymmetricStrength(%s, %d) = %d, %v; want %d, %v", c.cipher, c.bits, got, broken, c.want, c.broken)
		}
	}
	for h, want := range map[string]int{"SHA-224": 112, "SHA-256": 128, "SHA-384": 192, "SHA-512": 256} {
		if got, broken := algo.HashStrength(h); got != want || broken {
			t.Errorf("HashStrength(%s) = %d, %v; Table 3 says %d", h, got, broken, want)
		}
	}
	if _, broken := algo.HashStrength("SHA-1"); !broken {
		t.Error("SHA-1 is below 80 bits for collision resistance (Table 3, footnote 74)")
	}
	for h, want := range map[string]int{"SHA-1": 128, "SHA-256": 256} {
		if got, ok := algo.HMACStrength(h); !ok || got != want {
			t.Errorf("HMACStrength(%s) = %d; Table 3 says %d", h, got, want)
		}
	}
}
