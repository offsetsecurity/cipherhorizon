// Package weakkey tests one public key for the ways a key can be broken from the public half alone:
// an RSA modulus with a small factor, with two primes close together (Fermat), or with the shape
// of the Infineon RSALib defect (ROCA, CVE-2017-15361); and an elliptic-curve key whose private
// scalar is small enough to find by search, as in the 2026 eMudhra CA keys.
//
// Every positive is a proof, never a suspicion: a factor that divides the modulus, or a scalar
// that reproduces the public point. ROCA is the one exception; it is a fingerprint, with a false
// positive rate far below one in a million. The tests are pure and need no network.
package weakkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"math/big"
	"sync"
)

// Kind names a weakness.
type Kind string

// The weaknesses this package finds.
const (
	RSASmallFactor Kind = "rsa-small-factor"
	RSAClosePrimes Kind = "rsa-close-primes"
	RSAROCA        Kind = "rsa-roca"
	ECSmallScalar  Kind = "ec-small-scalar"
)

// Weakness is one way a key is broken, with the proof in words.
type Weakness struct {
	Kind   Kind   `json:"kind"`
	Detail string `json:"detail"`
}

// Tests names the tests Check runs on a key of this type; empty when it runs none (Ed25519 and
// X25519 hash and clamp the seed, so a small seed does not give a small scalar; post-quantum keys
// have no such structure).
func Tests(pub crypto.PublicKey) []Kind {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k != nil && k.N != nil && k.N.Sign() > 0 {
			return []Kind{RSASmallFactor, RSAClosePrimes, RSAROCA}
		}
	case *ecdsa.PublicKey:
		if k != nil && searchFor(k.Curve) != nil {
			return []Kind{ECSmallScalar}
		}
	}
	return nil
}

// Check runs every test that applies to the key. An empty result with len(Tests(pub)) > 0 means
// the key passed them.
func Check(pub crypto.PublicKey) []Weakness {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 {
			return nil
		}
		return checkRSA(k.N)
	case *ecdsa.PublicKey:
		if k == nil {
			return nil
		}
		return checkEC(k)
	}
	return nil
}

func checkRSA(n *big.Int) []Weakness {
	if f := smallFactor(n); f != 0 {
		// The other two tests assume a product of two large primes.
		return []Weakness{{RSASmallFactor, fmt.Sprintf("the modulus is divisible by %d", f)}}
	}
	var out []Weakness
	if p, q := fermat(n, fermatRounds); p != nil {
		out = append(out, Weakness{RSAClosePrimes, fmt.Sprintf(
			"the two primes are so close together that Fermat's method factors the modulus at once (they agree in their top %d of %d bits)",
			p.BitLen()-new(big.Int).Sub(q, p).BitLen(), p.BitLen())})
	}
	if roca(n) {
		out = append(out, Weakness{RSAROCA, "the modulus has the form Infineon's RSALib produced (ROCA, CVE-2017-15361), which can be factored at practical cost"})
	}
	return out
}

// ---- small factors ---------------------------------------------------------------------------

const smallPrimeLimit = 1 << 16

var (
	smallOnce    sync.Once
	smallPrimes  []uint32
	smallProduct *big.Int
)

func initSmall() {
	sieve := make([]bool, smallPrimeLimit)
	smallProduct = big.NewInt(1)
	// Multiply in chunks: one big multiplication per 64-bit word of primes.
	chunk := uint64(1)
	for i := 2; i < smallPrimeLimit; i++ {
		if sieve[i] {
			continue
		}
		smallPrimes = append(smallPrimes, uint32(i))
		for j := i * 2; j < smallPrimeLimit; j += i {
			sieve[j] = true
		}
		if chunk > (1<<63)/uint64(i) {
			smallProduct.Mul(smallProduct, new(big.Int).SetUint64(chunk))
			chunk = 1
		}
		chunk *= uint64(i)
	}
	smallProduct.Mul(smallProduct, new(big.Int).SetUint64(chunk))
}

// smallFactor returns the smallest prime under 65536 that divides n, or 0. A modulus that is
// itself such a prime is not reported: it has no smaller factor.
func smallFactor(n *big.Int) uint32 {
	smallOnce.Do(initSmall)
	g := new(big.Int).GCD(nil, nil, new(big.Int).Mod(smallProduct, n), n)
	if g.BitLen() <= 1 {
		return 0
	}
	var r, d big.Int
	for _, p := range smallPrimes {
		if d.SetUint64(uint64(p)); d.Cmp(n) == 0 {
			return 0
		}
		if r.Mod(n, &d).Sign() == 0 {
			return p
		}
	}
	return 0
}

// ---- Fermat ------------------------------------------------------------------------------------

// fermatRounds bounds the search. One hundred rounds find primes that agree in roughly their top
// half, which covers the keys seen in the field (a generator that takes the next prime after p);
// a correctly made key differs from its top few bits down and is never found.
const fermatRounds = 100

// fermat looks for n = (a-b)(a+b) with a just above the square root of n.
func fermat(n *big.Int, rounds int) (p, q *big.Int) {
	if n.Bit(0) == 0 {
		return nil, nil
	}
	a := new(big.Int).Sqrt(n)
	if new(big.Int).Mul(a, a).Cmp(n) == 0 {
		return a, new(big.Int).Set(a) // a perfect square: p = q
	}
	one := big.NewInt(1)
	a.Add(a, one)
	b2, b, sq := new(big.Int), new(big.Int), new(big.Int)
	for i := 0; i < rounds; i++ {
		b2.Mul(a, a)
		b2.Sub(b2, n)
		b.Sqrt(b2)
		if sq.Mul(b, b).Cmp(b2) == 0 {
			return new(big.Int).Sub(a, b), new(big.Int).Add(a, b)
		}
		a.Add(a, one)
	}
	return nil, nil
}

// ---- ROCA --------------------------------------------------------------------------------------

// rocaPrimes are the primes of the published detector (Nemec, Sys, Svenda, Klinec, Matyas: "The
// Return of Coppersmith's Attack", CCS 2017). RSALib built each prime as k*M + (65537^a mod M)
// with M a product of small primes, so the modulus, reduced by any of those primes, lies in the
// subgroup that 65537 generates. A random modulus does so for all of them with negligible chance.
var rocaPrimes = []uint32{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
	101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167}

var (
	rocaOnce sync.Once
	rocaSets [][]bool // rocaSets[i][r]: r is a power of 65537 modulo rocaPrimes[i]
)

func initROCA() {
	for _, p := range rocaPrimes {
		set := make([]bool, p)
		g := uint64(65537 % p)
		for x := uint64(1); !set[x]; x = x * g % uint64(p) {
			set[x] = true
		}
		rocaSets = append(rocaSets, set)
	}
}

func roca(n *big.Int) bool {
	rocaOnce.Do(initROCA)
	var r, d big.Int
	for i, p := range rocaPrimes {
		if !rocaSets[i][r.Mod(n, d.SetUint64(uint64(p))).Uint64()] {
			return false
		}
	}
	return true
}
