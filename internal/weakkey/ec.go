package weakkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
)

// The small-scalar search is baby-step giant-step on x-coordinates: a table of x(k*G) for k up to
// m, then steps of M = 2m+1 away from the public point in both directions. A match at step j gives
// the private scalar j*M ± k, or its negative n - (j*M ± k), and the candidate is confirmed by
// multiplying it out. The reach is 2*m*steps; it is set per curve so that one key costs about
// half a second on a laptop core, since arithmetic on the larger curves is slower.
type search struct {
	curve    elliptic.Curve
	m, steps int

	once   sync.Once
	baby   map[uint64]int32 // low 64 bits of x(k*G) -> k, for k in 1..m
	sx, sy *big.Int         // M*G
	nsy    *big.Int         // the y of -(M*G)
}

var searches = []*search{
	{curve: elliptic.P256(), m: 1 << 17, steps: 1 << 14}, // |d| < 2^32
	{curve: elliptic.P384(), m: 1 << 14, steps: 1 << 13}, // |d| < 2^28
	{curve: elliptic.P521(), m: 1 << 13, steps: 1 << 12}, // |d| < 2^26
}

func searchFor(c elliptic.Curve) *search {
	if c == nil {
		return nil
	}
	for _, s := range searches {
		if s.curve == c || s.curve.Params().Name == c.Params().Name {
			return s
		}
	}
	return nil
}

// Reach is how large a private scalar (or its distance below the group order) the search finds on
// the named curve ("P-256"), as a power of two; 0 for a curve that is not searched.
func Reach(curve string) int {
	for _, s := range searches {
		if s.curve.Params().Name == curve {
			return big.NewInt(int64(2*s.m*s.steps)).BitLen() - 1
		}
	}
	return 0
}

var mask64 = new(big.Int).SetUint64(^uint64(0))

func low64(x *big.Int) uint64 { return new(big.Int).And(x, mask64).Uint64() }

// The additions below use crypto/elliptic's deprecated big.Int interface on purpose: this is a
// search over public points, where constant time does not matter, and crypto/ecdh has no point
// addition.

func (s *search) init() {
	p := s.curve.Params()
	s.baby = make(map[uint64]int32, s.m)
	x, y := p.Gx, p.Gy
	for k := 1; k <= s.m; k++ {
		s.baby[low64(x)] = int32(k)
		x, y = s.curve.Add(x, y, p.Gx, p.Gy) //nolint:staticcheck // see above
	}
	s.sx, s.sy = s.curve.ScalarBaseMult(big.NewInt(int64(2*s.m + 1)).Bytes()) //nolint:staticcheck // see above
	s.nsy = new(big.Int).Sub(p.P, s.sy)
}

// find returns the private scalar d with d*G = (qx, qy) when d, or n - d, is within reach.
func (s *search) find(qx, qy *big.Int) *big.Int {
	s.once.Do(s.init)
	p := s.curve.Params()
	step := int64(2*s.m + 1)
	confirm := func(d *big.Int) *big.Int {
		d.Mod(d, p.N)
		if d.Sign() == 0 {
			return nil
		}
		x, y := s.curve.ScalarBaseMult(d.Bytes()) //nolint:staticcheck // see above
		if x.Cmp(qx) == 0 && y.Cmp(qy) == 0 {
			return d
		}
		return nil
	}
	// at reports the scalar when the point Q - sign*j*step*G is r*G for a small r.
	at := func(x, y *big.Int, j, sign int64) *big.Int {
		if x.Sign() == 0 && y.Sign() == 0 { // the point at infinity: r = 0
			return confirm(big.NewInt(sign * j * step))
		}
		k, ok := s.baby[low64(x)]
		if !ok {
			return nil
		}
		for _, r := range []int64{int64(k), -int64(k)} {
			if d := confirm(big.NewInt(sign*j*step + r)); d != nil {
				return d
			}
		}
		return nil
	}
	if d := at(qx, qy, 0, 1); d != nil {
		return d
	}
	ax, ay := qx, qy // Q - j*step*G: d = j*step + r
	bx, by := qx, qy // Q + j*step*G: d = -j*step + r
	for j := int64(1); j <= int64(s.steps); j++ {
		ax, ay = s.curve.Add(ax, ay, s.sx, s.nsy) //nolint:staticcheck // see above
		if d := at(ax, ay, j, 1); d != nil {
			return d
		}
		bx, by = s.curve.Add(bx, by, s.sx, s.sy) //nolint:staticcheck // see above
		if d := at(bx, by, j, -1); d != nil {
			return d
		}
	}
	return nil
}

// The search costs real time, and a server sees the same key on every scan: results are kept by
// the key's hash. The cache is small and is emptied when full; a key is then searched again.
var (
	cacheMu sync.Mutex
	cache   = map[[32]byte][]Weakness{}
)

const cacheMax = 4096

func checkEC(k *ecdsa.PublicKey) []Weakness {
	s := searchFor(k.Curve)
	x, y := k.X, k.Y                                                  //nolint:staticcheck // the key's coordinates are what is searched for
	if s == nil || x == nil || y == nil || !s.curve.IsOnCurve(x, y) { //nolint:staticcheck // see above
		return nil
	}
	h := sha256.New()
	h.Write([]byte(s.curve.Params().Name))
	h.Write([]byte{0})
	h.Write(x.Bytes())
	h.Write([]byte{0})
	h.Write(y.Bytes())
	var id [32]byte
	h.Sum(id[:0])

	cacheMu.Lock()
	got, ok := cache[id]
	cacheMu.Unlock()
	if ok {
		return got
	}
	var out []Weakness
	if d := s.find(x, y); d != nil {
		words := "the private key is " + d.String()
		if below := new(big.Int).Sub(s.curve.Params().N, d); below.BitLen() < d.BitLen() {
			words = "the private key is the group order minus " + below.String()
		}
		out = []Weakness{{ECSmallScalar, fmt.Sprintf("%s: a search over small numbers finds it, so anyone can sign as this key", words)}}
	}
	cacheMu.Lock()
	if len(cache) >= cacheMax {
		cache = map[[32]byte][]Weakness{}
	}
	cache[id] = out
	cacheMu.Unlock()
	return out
}
