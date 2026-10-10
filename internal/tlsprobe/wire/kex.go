package wire

import (
	"errors"
	"fmt"
)

// KeyExchange holds what a ServerKeyExchange message discloses about the
// server's ephemeral key exchange.
type KeyExchange struct {
	// Kind is "ECDHE" or "DHE".
	Kind string

	// ECDHE: the named curve (an IANA supported-group id). ExplicitCurve is set for
	// the long-deprecated explicit-parameter forms, where no name is sent.
	CurveID       uint16
	ExplicitCurve bool

	// DHE: the size in bits of the server's prime and generator and of its public
	// value, and the prime itself (big-endian, no leading zeros) so callers can
	// recognise well-known groups.
	PrimeBits     int
	GeneratorBits int
	PublicBits    int
	Prime         []byte
}

// ParseServerKeyExchange parses the body of a ServerKeyExchange for an ephemeral
// exchange. kind is "ECDHE" or "DHE"; psk says the suite is a PSK variant, whose
// message starts with an identity hint. The signature that follows the
// parameters is not parsed.
func ParseServerKeyExchange(kind string, psk bool, body []byte) (*KeyExchange, error) {
	r := &reader{b: body}
	if psk {
		r.vec16() // psk_identity_hint
	}
	ke := &KeyExchange{Kind: kind}
	switch kind {
	case "ECDHE":
		switch ct := r.u8(); ct {
		case 3: // named_curve
			ke.CurveID = r.u16()
			r.vec8() // the server's public point
		case 1, 2: // explicit_prime, explicit_char2
			ke.ExplicitCurve = true
		default:
			if r.err == nil {
				return nil, fmt.Errorf("wire: unknown ECDH curve type %d", ct)
			}
		}
	case "DHE":
		p := r.vec16()
		g := r.vec16()
		y := r.vec16()
		ke.Prime = trimZeros(p)
		ke.PrimeBits = bitLen(p)
		ke.GeneratorBits = bitLen(g)
		ke.PublicBits = bitLen(y)
	default:
		return nil, fmt.Errorf("wire: no ServerKeyExchange parser for %q", kind)
	}
	if r.err != nil {
		return nil, fmt.Errorf("wire: ServerKeyExchange: %w", r.err)
	}
	return ke, nil
}

func trimZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return append([]byte(nil), b...)
}

// bitLen is the bit length of a big-endian unsigned integer.
func bitLen(b []byte) int {
	b = trimZeros(b)
	if len(b) == 0 {
		return 0
	}
	n := 8 * (len(b) - 1)
	for v := b[0]; v != 0; v >>= 1 {
		n++
	}
	return n
}

var errSSLv2 = errors.New("wire: malformed SSLv2 message")
