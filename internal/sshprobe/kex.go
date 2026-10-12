package sshprobe

import (
	"crypto"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/wire"
)

// kexMethod is one key exchange the scanner can carry out as a client, up to the server's reply.
// start returns the client's value (Q_C, or the body of the mpint e) and a function that, given
// the server's value, returns K exactly as the exchange hash encodes it (an mpint, or a string for
// the ML-KEM hybrid).
type kexMethod struct {
	hash  crypto.Hash
	start func() (qc []byte, finish func(qs []byte) ([]byte, error), err error)
}

// kexMethods are the key exchanges this scanner implements. Anything else is judged from the
// server's lists alone (the report says "computed").
var kexMethods = map[string]kexMethod{
	"curve25519-sha256":             {crypto.SHA256, ecdhStart(ecdh.X25519())},
	"curve25519-sha256@libssh.org":  {crypto.SHA256, ecdhStart(ecdh.X25519())},
	"ecdh-sha2-nistp256":            {crypto.SHA256, ecdhStart(ecdh.P256())},
	"ecdh-sha2-nistp384":            {crypto.SHA384, ecdhStart(ecdh.P384())},
	"ecdh-sha2-nistp521":            {crypto.SHA512, ecdhStart(ecdh.P521())},
	"mlkem768x25519-sha256":         {crypto.SHA256, mlkemX25519Start},
	"diffie-hellman-group1-sha1":    {crypto.SHA1, modpStart(oakleyGroup2)},
	"diffie-hellman-group14-sha1":   {crypto.SHA1, modpStart(oakleyGroup14)},
	"diffie-hellman-group14-sha256": {crypto.SHA256, modpStart(oakleyGroup14)},
	"diffie-hellman-group16-sha512": {crypto.SHA512, modpStart(oakleyGroup16)},
}

// hostKeyKexOrder is the order in which an implemented key exchange is picked to fetch a host key:
// cheap classical exchanges first, the hybrid next, finite-field groups last.
var hostKeyKexOrder = []string{
	"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
	"mlkem768x25519-sha256", "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
	"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
}

func isPQKex(name string) bool {
	a, ok := registry.Lookup(registry.KindKex, name)
	return ok && a.PQ
}

// mpintK encodes a shared secret, read as a big-endian unsigned integer, as an mpint.
func mpintK(secret []byte) []byte {
	w := &wire.Builder{}
	w.MPInt(new(big.Int).SetBytes(secret))
	return w.B
}

// ecdhStart: RFC 5656 section 4 and RFC 8731 section 3: Q_C and Q_S are the public values, K is
// the shared secret as an mpint.
func ecdhStart(c ecdh.Curve) func() ([]byte, func([]byte) ([]byte, error), error) {
	return func() ([]byte, func([]byte) ([]byte, error), error) {
		priv, err := c.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return priv.PublicKey().Bytes(), func(qs []byte) ([]byte, error) {
			pub, err := c.NewPublicKey(qs)
			if err != nil {
				return nil, fmt.Errorf("the server's public value is not valid: %w", err)
			}
			s, err := priv.ECDH(pub)
			if err != nil {
				return nil, err
			}
			return mpintK(s), nil
		}, nil
	}
}

// mlkemX25519Start: mlkem768x25519-sha256 (draft-ietf-sshm-mlkem-hybrid-kex, from
// draft-kampanakis-curdle-ssh-pq-ke): Q_C is the ML-KEM-768 encapsulation key then the X25519
// value; Q_S is the ML-KEM ciphertext then the X25519 value; K = SHA-256(K_PQ || K_CL), encoded
// as a string (not an mpint).
func mlkemX25519Start() ([]byte, func([]byte) ([]byte, error), error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	qc := append(dk.EncapsulationKey().Bytes(), x.PublicKey().Bytes()...)
	return qc, func(qs []byte) ([]byte, error) {
		if len(qs) != mlkem.CiphertextSize768+32 {
			return nil, fmt.Errorf("the server's hybrid value is %d bytes, want %d", len(qs), mlkem.CiphertextSize768+32)
		}
		kpq, err := dk.Decapsulate(qs[:mlkem.CiphertextSize768])
		if err != nil {
			return nil, err
		}
		pub, err := ecdh.X25519().NewPublicKey(qs[mlkem.CiphertextSize768:])
		if err != nil {
			return nil, err
		}
		kcl, err := x.ECDH(pub)
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		h.Write(kpq)
		h.Write(kcl)
		w := &wire.Builder{}
		w.String(h.Sum(nil))
		return w.B, nil
	}, nil
}

// modpStart: RFC 4253 section 8 with g = 2: e = g^x mod p, K = f^x mod p, both mpints; f must be
// in [2, p-2].
func modpStart(pHex string) func() ([]byte, func([]byte) ([]byte, error), error) {
	p, _ := new(big.Int).SetString(pHex, 16)
	return func() ([]byte, func([]byte) ([]byte, error), error) {
		// A 512-bit exponent: this exchange only has to reach the server's reply.
		x, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 512))
		if err != nil {
			return nil, nil, err
		}
		x.Add(x, big.NewInt(2))
		e := new(big.Int).Exp(big.NewInt(2), x, p)
		return wire.MPIntBytes(e), func(fb []byte) ([]byte, error) {
			if len(fb) > 0 && fb[0]&0x80 != 0 {
				return nil, errors.New("the server's f is negative")
			}
			f := new(big.Int).SetBytes(fb)
			pm1 := new(big.Int).Sub(p, big.NewInt(1))
			if f.Cmp(big.NewInt(1)) <= 0 || f.Cmp(pm1) >= 0 {
				return nil, errors.New("the server's f is out of range")
			}
			w := &wire.Builder{}
			w.MPInt(new(big.Int).Exp(f, x, p))
			return w.B, nil
		}, nil
	}
}

// The MODP groups (RFC 2409 section 6.2, RFC 3526 sections 3 and 5). TestMODPGroupsAreThePublishedOnes
// checks each against the SHA-256 of the published prime in internal/refdata.
const (
	oakleyGroup2  = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
	oakleyGroup14 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	oakleyGroup16 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"
)

// exchangeHash computes H (RFC 4253 section 8; RFC 5656 section 4): V_C, V_S, I_C, I_S, K_S and
// the two public values as strings, then K as the method encodes it.
func exchangeHash(h crypto.Hash, vc, vs, ic, is, ks, qc, qs, k []byte) []byte {
	w := &wire.Builder{}
	for _, s := range [][]byte{vc, vs, ic, is, ks, qc, qs} {
		w.String(s)
	}
	w.B = append(w.B, k...)
	d := h.New()
	d.Write(w.B)
	return d.Sum(nil)
}
