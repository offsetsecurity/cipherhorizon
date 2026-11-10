package tlsprobe

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"math/bits"
)

// chachaOpener opens ChaCha20-Poly1305 records (RFC 8439). The scan needs it for one thing: to
// read the session tickets of a TLS 1.3 connection that negotiated TLS_CHACHA20_POLY1305_SHA256.
// It only decrypts, a few hundred bytes per scan, with a key the TLS library already holds; it is
// written here, plainly and without constant-time care for the Poly1305 arithmetic, because the
// release binary links no cryptography outside the standard library (ADR-0019) and the standard
// library does not export this cipher.
type chachaOpener struct{ key [32]byte }

var errChachaAuth = errors.New("chacha20-poly1305: message authentication failed")

// Open authenticates and decrypts one message; the first argument is unused (cipher.AEAD's dst).
func (c *chachaOpener) Open(_, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 || len(ciphertext) < 16 {
		return nil, errChachaAuth
	}
	body, tag := ciphertext[:len(ciphertext)-16], ciphertext[len(ciphertext)-16:]
	var polyKey [64]byte
	chachaBlock(&c.key, 0, nonce, &polyKey)
	if subtle.ConstantTimeCompare(poly1305Tag(polyKey[:32], aad, body), tag) != 1 {
		return nil, errChachaAuth
	}
	out := make([]byte, len(body))
	var block [64]byte
	for i := 0; i < len(body); i += 64 {
		chachaBlock(&c.key, uint32(i/64)+1, nonce, &block)
		for j := i; j < len(body) && j < i+64; j++ {
			out[j] = body[j] ^ block[j-i]
		}
	}
	return out, nil
}

// chachaBlock writes one ChaCha20 keystream block (RFC 8439 section 2.3).
func chachaBlock(key *[32]byte, counter uint32, nonce []byte, out *[64]byte) {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	s[12] = counter
	for i := 0; i < 3; i++ {
		s[13+i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	w := s
	qr := func(a, b, c, d int) {
		w[a] += w[b]
		w[d] = bits.RotateLeft32(w[d]^w[a], 16)
		w[c] += w[d]
		w[b] = bits.RotateLeft32(w[b]^w[c], 12)
		w[a] += w[b]
		w[d] = bits.RotateLeft32(w[d]^w[a], 8)
		w[c] += w[d]
		w[b] = bits.RotateLeft32(w[b]^w[c], 7)
	}
	for i := 0; i < 10; i++ {
		qr(0, 4, 8, 12)
		qr(1, 5, 9, 13)
		qr(2, 6, 10, 14)
		qr(3, 7, 11, 15)
		qr(0, 5, 10, 15)
		qr(1, 6, 11, 12)
		qr(2, 7, 8, 13)
		qr(3, 4, 9, 14)
	}
	for i := range w {
		binary.LittleEndian.PutUint32(out[4*i:], w[i]+s[i])
	}
}

var poly1305Prime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))

// poly1305Tag is the AEAD's tag (RFC 8439 sections 2.5 and 2.8): Poly1305 over the padded
// additional data, the padded ciphertext and their lengths.
func poly1305Tag(key, aad, ciphertext []byte) []byte {
	pad := func(n int) []byte { return make([]byte, (16-n%16)%16) }
	msg := make([]byte, 0, len(aad)+len(ciphertext)+48)
	msg = append(msg, aad...)
	msg = append(msg, pad(len(aad))...)
	msg = append(msg, ciphertext...)
	msg = append(msg, pad(len(ciphertext))...)
	msg = binary.LittleEndian.AppendUint64(msg, uint64(len(aad)))
	msg = binary.LittleEndian.AppendUint64(msg, uint64(len(ciphertext)))

	le := func(b []byte) *big.Int { // little-endian bytes to a number
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	rb := append([]byte(nil), key[:16]...)
	rb[3] &= 15
	rb[7] &= 15
	rb[11] &= 15
	rb[15] &= 15
	rb[4] &= 252
	rb[8] &= 252
	rb[12] &= 252
	r, s := le(rb), le(key[16:32])
	acc := new(big.Int)
	for i := 0; i < len(msg); i += 16 {
		block := append(append([]byte(nil), msg[i:min(i+16, len(msg))]...), 1)
		acc.Add(acc, le(block))
		acc.Mul(acc, r)
		acc.Mod(acc, poly1305Prime)
	}
	acc.Add(acc, s)
	be := acc.Bytes()
	tag := make([]byte, 16)
	for i := 0; i < 16 && i < len(be); i++ {
		tag[i] = be[len(be)-1-i]
	}
	return tag
}
