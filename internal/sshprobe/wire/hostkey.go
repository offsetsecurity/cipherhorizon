package wire

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ssh-rsa signatures are SHA-1 by definition (RFC 4253); verified, never produced
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// PublicKey is a parsed SSH public key or certificate blob.
type PublicKey struct {
	Type      string // the blob's own type name: "ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-mldsa44-ed25519", "ssh-ed25519-cert-v01@openssh.com"
	Algorithm string // the key's family in the catalogue's words: "Ed25519", "ECDSA", "RSA", "DSA", "ML-DSA-65", "ML-DSA-44+Ed25519"
	Bits      int
	Curve     string // "P-256" ...
	PQ        bool
	// Fingerprint is OpenSSH's: "SHA256:" and the unpadded base64 of SHA-256 over the blob.
	Fingerprint string
	Cert        *Certificate

	blob []byte
	key  crypto.PublicKey // for verification; nil when the type is not one this package verifies
	// composite parts (ssh-mldsa44-ed25519)
	compMLDSA *mldsa.PublicKey
	compEd    ed25519.PublicKey
}

// Blob is the key exactly as the server sent it.
func (k *PublicKey) Blob() []byte { return k.blob }

// Certificate is the part of an OpenSSH certificate (PROTOCOL.certkeys) a report shows.
type Certificate struct {
	KeyType       string    `json:"keyType"`
	Serial        uint64    `json:"serial"`
	CertType      uint32    `json:"certType"` // 1 user, 2 host
	KeyID         string    `json:"keyId,omitempty"`
	Principals    []string  `json:"principals,omitempty"`
	ValidAfter    time.Time `json:"validAfter"`
	ValidBefore   time.Time `json:"validBefore"`
	Forever       bool      `json:"forever,omitempty"`
	CAType        string    `json:"caType"`
	CAFingerprint string    `json:"caFingerprint"`
}

// Fingerprint is OpenSSH's SHA-256 fingerprint of a key blob.
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

var curves = map[string]struct {
	name  string
	curve elliptic.Curve
	hash  crypto.Hash
}{
	"nistp256": {"P-256", elliptic.P256(), crypto.SHA256},
	"nistp384": {"P-384", elliptic.P384(), crypto.SHA384},
	"nistp521": {"P-521", elliptic.P521(), crypto.SHA512},
}

var mldsaParams = map[string]func() mldsa.Parameters{
	"ssh-mldsa-44": mldsa.MLDSA44, "ssh-mldsa-65": mldsa.MLDSA65, "ssh-mldsa-87": mldsa.MLDSA87,
}

// Composite ML-DSA-44 + Ed25519 (draft-miller-sshm-composite-sigs): the public key is the 1312-byte
// ML-DSA-44 key then the 32-byte Ed25519 key.
const (
	compositeMLDSA44Ed25519 = "ssh-mldsa44-ed25519"
	compositeMLDSA87P384    = "ssh-mldsa87-p384"
	mldsa44PublicKeySize    = 1312
	mldsa44SignatureSize    = 2420
)

// ParsePublicKey reads a public key or OpenSSH certificate blob. An unknown type is not an error:
// it is returned with its name and fingerprint, unverifiable.
func ParsePublicKey(blob []byte) (*PublicKey, error) {
	r := NewReader(blob)
	typ := Clean(string(r.String()), MaxName)
	if r.Err() != nil {
		return nil, r.Err()
	}
	k := &PublicKey{Type: typ, Fingerprint: Fingerprint(blob), blob: append([]byte(nil), blob...)}
	if base, ok := strings.CutSuffix(typ, "-cert-v01@openssh.com"); ok {
		return k, parseCertificate(k, r, base)
	}
	return k, parseKeyBody(k, r, typ)
}

// parseKeyBody reads the type-specific fields that follow the type name.
func parseKeyBody(k *PublicKey, r *Reader, typ string) error {
	switch {
	case typ == "ssh-ed25519" || typ == "sk-ssh-ed25519@openssh.com":
		pk := r.String()
		if typ == "sk-ssh-ed25519@openssh.com" {
			r.String() // application
		}
		if r.Err() != nil || len(pk) != ed25519.PublicKeySize {
			return protoErr("bad Ed25519 key")
		}
		k.Algorithm, k.Bits = "Ed25519", 256
		if typ == "ssh-ed25519" {
			k.key = ed25519.PublicKey(append([]byte(nil), pk...))
		}
	case strings.HasPrefix(typ, "ecdsa-sha2-") || strings.HasPrefix(typ, "sk-ecdsa-sha2-"):
		id := string(r.String())
		q := r.String()
		if strings.HasPrefix(typ, "sk-") {
			r.String() // application
		}
		c, ok := curves[id]
		if r.Err() != nil || !ok {
			return protoErr("bad ECDSA key (curve %q)", Clean(id, 32))
		}
		k.Algorithm, k.Curve, k.Bits = "ECDSA", c.name, c.curve.Params().BitSize
		pub, err := ecdsa.ParseUncompressedPublicKey(c.curve, q)
		if err != nil {
			return protoErr("ECDSA point not on %s", c.name)
		}
		if !strings.HasPrefix(typ, "sk-") {
			k.key = pub
		}
	case typ == "ssh-rsa":
		e, n := r.MPInt(), r.MPInt()
		if r.Err() != nil || n.Sign() == 0 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
			return protoErr("bad RSA key")
		}
		k.Algorithm, k.Bits = "RSA", n.BitLen()
		k.key = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case typ == "ssh-dss":
		p := r.MPInt()
		r.MPInt()
		r.MPInt()
		r.MPInt()
		if r.Err() != nil {
			return protoErr("bad DSA key")
		}
		k.Algorithm, k.Bits = "DSA", p.BitLen()
	case mldsaParams[typ] != nil:
		params := mldsaParams[typ]()
		pk := r.String()
		if r.Err() != nil {
			return r.Err()
		}
		key, err := mldsa.NewPublicKey(params, pk)
		if err != nil {
			return protoErr("bad %s key: %v", typ, err)
		}
		k.Algorithm, k.PQ, k.key = params.String(), true, key
	case typ == compositeMLDSA44Ed25519:
		pk := r.String()
		if r.Err() != nil || len(pk) != mldsa44PublicKeySize+ed25519.PublicKeySize {
			return protoErr("bad %s key", typ)
		}
		ml, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pk[:mldsa44PublicKeySize])
		if err != nil {
			return protoErr("bad %s key: %v", typ, err)
		}
		k.Algorithm, k.PQ = "ML-DSA-44+Ed25519", true
		k.compMLDSA, k.compEd = ml, ed25519.PublicKey(append([]byte(nil), pk[mldsa44PublicKeySize:]...))
	case typ == compositeMLDSA87P384:
		r.String()
		if r.Err() != nil {
			return r.Err()
		}
		k.Algorithm, k.PQ = "ML-DSA-87+ECDSA-P384", true // recognised, not verified
	default:
		k.Algorithm = "unknown"
	}
	return r.Err()
}

// parseCertificate reads an OpenSSH certificate (PROTOCOL.certkeys): nonce, the key fields, then
// the certificate fields and the CA's key.
func parseCertificate(k *PublicKey, r *Reader, base string) error {
	r.String() // nonce
	if err := parseKeyBody(k, r, base); err != nil {
		return err
	}
	k.key, k.compMLDSA, k.compEd = nil, nil, nil // a certificate's key is verified through the cert type, not done here
	c := &Certificate{KeyType: base}
	c.Serial = r.Uint64()
	c.CertType = r.Uint32()
	c.KeyID = Clean(string(r.String()), 128)
	pr := NewReader(r.String())
	for len(pr.Rest()) > 0 && pr.Err() == nil && len(c.Principals) < 16 {
		c.Principals = append(c.Principals, Clean(string(pr.String()), 128))
	}
	after, before := r.Uint64(), r.Uint64()
	c.ValidAfter = time.Unix(int64(min(after, 1<<62)), 0).UTC()
	if before == ^uint64(0) {
		c.Forever = true
	} else {
		c.ValidBefore = time.Unix(int64(min(before, 1<<62)), 0).UTC()
	}
	r.String() // critical options
	r.String() // extensions
	r.String() // reserved
	ca := r.String()
	r.String() // signature
	if r.Err() != nil {
		return r.Err()
	}
	c.CAFingerprint = Fingerprint(ca)
	cr := NewReader(ca)
	c.CAType = Clean(string(cr.String()), MaxName)
	k.Cert = c
	return nil
}

// Verified says whether a signature over the exchange hash checked out, and, when it did not or
// could not, why.
type Verified struct {
	OK   bool
	Note string
}

// Verify checks the server's signature blob (string algorithm, string signature) over the
// exchange hash h. sigAlg is the host key algorithm negotiated (it decides the hash for RSA).
func (k *PublicKey) Verify(sigAlg string, h, sigBlob []byte) Verified {
	r := NewReader(sigBlob)
	format := Clean(string(r.String()), MaxName)
	sig := r.String()
	if r.Err() != nil {
		return Verified{Note: "the signature blob did not parse"}
	}
	want := strings.TrimSuffix(sigAlg, "-cert-v01@openssh.com")
	if format != want {
		return Verified{Note: fmt.Sprintf("the signature is %s, not the %s negotiated", format, want)}
	}
	if k.Cert != nil {
		return Verified{Note: "certificate host keys are read, not verified"}
	}
	switch key := k.key.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(key, h, sig) {
			return Verified{OK: true}
		}
	case *ecdsa.PublicKey:
		sr := NewReader(sig)
		rr, ss := sr.MPInt(), sr.MPInt()
		if sr.Err() != nil {
			return Verified{Note: "the ECDSA signature did not parse"}
		}
		hash := curves["nistp"+strings.TrimPrefix(key.Curve.Params().Name, "P-")].hash
		hh := hash.New()
		hh.Write(h)
		if ecdsa.Verify(key, hh.Sum(nil), rr, ss) {
			return Verified{OK: true}
		}
	case *rsa.PublicKey:
		var digest []byte
		var ch crypto.Hash
		switch format {
		case "rsa-sha2-256":
			d := sha256.Sum256(h)
			digest, ch = d[:], crypto.SHA256
		case "rsa-sha2-512":
			d := sha512.Sum512(h)
			digest, ch = d[:], crypto.SHA512
		case "ssh-rsa":
			d := sha1.Sum(h) //nolint:gosec // see the import
			digest, ch = d[:], crypto.SHA1
		default:
			return Verified{Note: "unknown RSA signature format " + format}
		}
		if rsa.VerifyPKCS1v15(key, ch, digest, sig) == nil {
			return Verified{OK: true}
		}
	case *mldsa.PublicKey:
		if mldsa.Verify(key, h, sig, nil) == nil {
			return Verified{OK: true}
		}
	default:
		if k.compMLDSA != nil {
			return k.verifyComposite(h, sig)
		}
		return Verified{Note: k.Type + " signatures are recognised, not verified"}
	}
	return Verified{Note: "the signature did not verify"}
}

// verifyComposite checks an ssh-mldsa44-ed25519 signature (draft-miller-sshm-composite-sigs):
// M' = Prefix || Label || len(ctx)=0 || SHA-512(M); ML-DSA-44 signs M' with the Label as its
// context, Ed25519 signs M'; the signature is the two concatenated.
func (k *PublicKey) verifyComposite(m, sig []byte) Verified {
	if len(sig) != mldsa44SignatureSize+ed25519.SignatureSize {
		return Verified{Note: "the composite signature has the wrong length"}
	}
	const label = "COMPSIG-MLDSA44-Ed25519-SHA512"
	d := sha512.Sum512(m)
	mp := append(append(append([]byte("CompositeAlgorithmSignatures2025"), label...), 0), d[:]...)
	if mldsa.Verify(k.compMLDSA, mp, sig[:mldsa44SignatureSize], &mldsa.Options{Context: label}) != nil {
		return Verified{Note: "the ML-DSA-44 half of the composite signature did not verify"}
	}
	if !ed25519.Verify(k.compEd, mp, sig[mldsa44SignatureSize:]) {
		return Verified{Note: "the Ed25519 half of the composite signature did not verify"}
	}
	return Verified{OK: true}
}
