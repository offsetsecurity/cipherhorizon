package weakkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func kinds(ws []Weakness) map[Kind]bool {
	m := map[Kind]bool{}
	for _, w := range ws {
		m[w.Kind] = true
	}
	return m
}

func prime(t *testing.T, bits int) *big.Int {
	t.Helper()
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A sound key passes every test; this is the negative control for all of them.
func TestSoundKeysPass(t *testing.T) {
	for _, bits := range []int{2048, 3072} {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		if ws := Check(&k.PublicKey); len(ws) != 0 {
			t.Errorf("a fresh RSA-%d key is reported weak: %+v", bits, ws)
		}
		if len(Tests(&k.PublicKey)) != 3 {
			t.Errorf("RSA runs three tests: %v", Tests(&k.PublicKey))
		}
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if ws := Check(&k.PublicKey); len(ws) != 0 {
			t.Errorf("a fresh %s key is reported weak: %+v", c.Params().Name, ws)
		}
		if len(Tests(&k.PublicKey)) != 1 {
			t.Errorf("%s runs one test", c.Params().Name)
		}
	}
	if Tests(struct{}{}) != nil || Check(struct{}{}) != nil {
		t.Error("an unknown key type runs no test")
	}
}

func TestRSASmallFactor(t *testing.T) {
	n := new(big.Int).Mul(big.NewInt(65521), prime(t, 2040))
	ws := Check(&rsa.PublicKey{N: n, E: 65537})
	if len(ws) != 1 || ws[0].Kind != RSASmallFactor || ws[0].Detail != "the modulus is divisible by 65521" {
		t.Errorf("small factor: %+v", ws)
	}
	even := new(big.Int).Lsh(prime(t, 2047), 1)
	if ws := Check(&rsa.PublicKey{N: even, E: 65537}); len(ws) != 1 || ws[0].Detail != "the modulus is divisible by 2" {
		t.Errorf("an even modulus: %+v", ws)
	}
}

// Two primes that share their top half are what a broken generator makes (the next prime after
// p); Fermat finds them at once. Primes that differ from the top bits down are not found.
func TestRSAClosePrimes(t *testing.T) {
	p := prime(t, 1024)
	q := new(big.Int).Add(p, big.NewInt(2))
	for !q.ProbablyPrime(20) {
		q.Add(q, big.NewInt(2))
	}
	ws := Check(&rsa.PublicKey{N: new(big.Int).Mul(p, q), E: 65537})
	if !kinds(ws)[RSAClosePrimes] {
		t.Errorf("adjacent primes: %+v", ws)
	}
	sq := new(big.Int).Mul(p, p)
	if !kinds(Check(&rsa.PublicKey{N: sq, E: 65537}))[RSAClosePrimes] {
		t.Error("a perfect square is p = q")
	}
}

// rocaPrime builds a prime of the RSALib form k*M + (65537^a mod M), M the product of the
// detector's primes, as the paper describes.
func rocaPrime(t *testing.T, bits int) *big.Int {
	t.Helper()
	M := big.NewInt(1)
	for _, p := range rocaPrimes {
		M.Mul(M, big.NewInt(int64(p)))
	}
	g := big.NewInt(65537)
	free := uint(bits - M.BitLen())
	for {
		a, err := rand.Int(rand.Reader, big.NewInt(1<<30))
		if err != nil {
			t.Fatal(err)
		}
		k, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), free))
		if err != nil {
			t.Fatal(err)
		}
		k.SetBit(k, int(free)-1, 1)
		c := new(big.Int).Exp(g, a, M)
		c.Add(c, new(big.Int).Mul(k, M))
		if c.ProbablyPrime(20) {
			return c
		}
	}
}

func TestRSAROCA(t *testing.T) {
	n := new(big.Int).Mul(rocaPrime(t, 512), rocaPrime(t, 512))
	if !kinds(Check(&rsa.PublicKey{N: n, E: 65537}))[RSAROCA] {
		t.Error("a modulus of two RSALib-form primes carries the fingerprint")
	}
	// The fingerprint must not fire on ordinary keys: 200 random moduli, none flagged.
	for i := 0; i < 200; i++ {
		m := new(big.Int).Mul(prime(t, 256), prime(t, 256))
		if roca(m) {
			t.Fatalf("a random modulus matches the fingerprint: %x", m)
		}
	}
}

func TestECSmallScalar(t *testing.T) {
	for _, s := range searches {
		c := s.curve
		reach := int64(2 * s.m * s.steps)
		n := c.Params().N
		cases := []*big.Int{big.NewInt(1), big.NewInt(4), big.NewInt(int64(s.m)), big.NewInt(int64(2*s.m + 1)), big.NewInt(int64(2*s.m + 2)),
			big.NewInt(reach - 1), big.NewInt(reach / 3),
			new(big.Int).Sub(n, big.NewInt(4)), new(big.Int).Sub(n, big.NewInt(reach/5))}
		for _, d := range cases {
			x, y := c.ScalarBaseMult(d.Bytes()) //nolint:staticcheck // building a test key from a chosen scalar
			ws := Check(&ecdsa.PublicKey{Curve: c, X: x, Y: y})
			if len(ws) != 1 || ws[0].Kind != ECSmallScalar {
				t.Errorf("%s d=%s: not found: %+v", c.Params().Name, d, ws)
			}
		}
		// Well beyond the reach is not found, and not claimed.
		far := big.NewInt(reach * 4)
		x, y := c.ScalarBaseMult(far.Bytes()) //nolint:staticcheck // as above
		if ws := Check(&ecdsa.PublicKey{Curve: c, X: x, Y: y}); len(ws) != 0 {
			t.Errorf("%s: a scalar beyond the reach was reported: %+v", c.Params().Name, ws)
		}
		if Reach(c.Params().Name) == 0 {
			t.Errorf("%s has a reach", c.Params().Name)
		}
	}
	if Reach("P-256") != 32 || Reach("P-384") != 28 || Reach("P-521") != 26 || Reach("P-224") != 0 {
		t.Errorf("reach: %d %d %d", Reach("P-256"), Reach("P-384"), Reach("P-521"))
	}
	x, y := elliptic.P256().ScalarBaseMult([]byte{4}) //nolint:staticcheck // as above
	ws := Check(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if len(ws) != 1 || ws[0].Detail != "the private key is 4: a search over small numbers finds it, so anyone can sign as this key" {
		t.Errorf("the finding gives the scalar as proof: %+v", ws)
	}
}

func BenchmarkECSearchP256(b *testing.B) {
	s := searchFor(elliptic.P256())
	s.once.Do(s.init)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	x, y := k.X, k.Y //nolint:staticcheck // benchmark of the search itself
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.find(x, y)
	}
}
