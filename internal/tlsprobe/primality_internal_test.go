package tlsprobe

import (
	"math/big"
	"testing"
)

// QA of real scans (badssl.com dh-composite, dh-small-subgroup): the DH modulus is tested for
// primality and, when prime, for being a safe prime.
func TestDHPrimality(t *testing.T) {
	ffdhe2048, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)
	notSafe := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(0))
	notSafe.Sub(notSafe, big.NewInt(1)) // 2^127 - 1 is prime; (p-1)/2 = 2^126 - 1 is not
	composite := new(big.Int).Mul(big.NewInt(1000003), big.NewInt(999983))
	for name, tc := range map[string]struct {
		p           *big.Int
		prime, safe *bool
	}{
		"ffdhe2048 (a safe prime)":  {ffdhe2048, ptrB(true), ptrB(true)},
		"2^127-1 (prime, not safe)": {notSafe, ptrB(true), ptrB(false)},
		"a composite":               {composite, ptrB(false), nil},
	} {
		ip, sp := primality(tc.p.Bytes())
		if !eqB(ip, tc.prime) || !eqB(sp, tc.safe) {
			t.Errorf("%s: prime %v safe %v", name, ip, sp)
		}
	}
}

func ptrB(b bool) *bool { return &b }

func eqB(a, b *bool) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
