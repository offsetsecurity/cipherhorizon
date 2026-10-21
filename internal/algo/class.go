package algo

import (
	"fmt"
	"regexp"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// The three classes an algorithm belongs to (PRD-011 §2), and the roles within them.
const (
	ClassAsymmetric = "asymmetric"
	ClassSymmetric  = "symmetric"
	ClassHash       = "hash"

	RoleKeyExchange = "key exchange"
	RoleSignature   = "signature"
	RoleCipher      = "cipher"
	RoleMAC         = "MAC"
	RoleHash        = "hash"
)

// Class is an algorithm's class and its role within it. The zero value means the name is not
// one this program knows.
type Class struct {
	Class string `json:"class"`
	Role  string `json:"role"`
}

// Known reports whether the class was found.
func (c Class) Known() bool { return c.Class != "" }

// ClassOfPrimitive maps a CycloneDX primitive to its class (PRD-011 §2).
func ClassOfPrimitive(p cdx.CryptoPrimitive) Class {
	switch p {
	case cdx.CryptoPrimitivePKE, cdx.CryptoPrimitiveKeyAgree, cdx.CryptoPrimitiveKEM, cdx.CryptoPrimitiveCombiner:
		return Class{ClassAsymmetric, RoleKeyExchange}
	case cdx.CryptoPrimitiveSignature:
		return Class{ClassAsymmetric, RoleSignature}
	case cdx.CryptoPrimitiveAE, cdx.CryptoPrimitiveBlockCipher, cdx.CryptoPrimitiveStreamCipher:
		return Class{ClassSymmetric, RoleCipher}
	case cdx.CryptoPrimitiveMAC:
		return Class{ClassSymmetric, RoleMAC}
	case cdx.CryptoPrimitiveHash:
		return Class{ClassHash, RoleHash}
	}
	return Class{}
}

// ClassOf is the class of an algorithm by any name this program gives it: a catalogue ID, a
// derived size or curve variant (RSA-2048, ECDSA-P256, DSA-2048), a TLS group name (x25519,
// secp256r1, ffdhe2048, X25519MLKEM768) or a signature algorithm in any common spelling.
func ClassOf(name string) Class {
	if a, ok := Lookup(name); ok {
		return ClassOfPrimitive(a.Primitive)
	}
	switch {
	case strings.HasPrefix(name, "RSA-"):
		return Class{ClassAsymmetric, RoleKeyExchange}
	case strings.HasPrefix(name, "DSA-"), strings.HasPrefix(name, "ECDSA-P"):
		return Class{ClassAsymmetric, RoleSignature}
	case strings.HasPrefix(name, "HMAC-"):
		return Class{ClassSymmetric, RoleMAC}
	}
	// TLS supported groups: named curves, RFC 7919 groups, X25519/X448, ML-KEM and its hybrids.
	if _, ok := CurveStrength(name); ok || strings.HasPrefix(name, "ffdhe") || strings.EqualFold(name, "x25519") ||
		strings.EqualFold(name, "x448") || strings.Contains(name, "MLKEM") {
		return Class{ClassAsymmetric, RoleKeyExchange}
	}
	if _, _, ok := SignatureParts(name); ok {
		return Class{ClassAsymmetric, RoleSignature}
	}
	return Class{}
}

// sigSpellings matches the ways a signature algorithm is named: Go's (ECDSA-SHA256, SHA256-RSA,
// SHA256-RSAPSS), the OID names (sha256WithRSAEncryption, ecdsa-with-SHA256, dsa-with-SHA1) and
// Java's (SHA256withRSA, SHA256withECDSA).
var (
	sigHashFirst = regexp.MustCompile(`(?i)^(md2|md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-?256|sha3-?384|sha3-?512)[-_]?(?:with)?[-_]?(rsa(?:encryption|pss|-?pss)?|ecdsa|dsa)$`)
	sigKeyFirst  = regexp.MustCompile(`(?i)^(rsa|ecdsa|dsa)[-_](?:with[-_])?(md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-?256|sha3-?384|sha3-?512)$`)
)

// SignatureParts splits a signature algorithm into its hash (in the catalogue's spelling,
// SHA-256) and its key algorithm (RSA, ECDSA, DSA). Ed25519, Ed448, ML-DSA and SLH-DSA are not
// split: their hash is part of their definition.
func SignatureParts(name string) (hash, key string, ok bool) {
	if m := sigHashFirst.FindStringSubmatch(name); m != nil {
		return canonicalHash(m[1]), canonicalKey(m[2]), true
	}
	if m := sigKeyFirst.FindStringSubmatch(name); m != nil {
		return canonicalHash(m[2]), canonicalKey(m[1]), true
	}
	return "", "", false
}

func canonicalHash(h string) string {
	h = strings.ToUpper(strings.ReplaceAll(h, "-", ""))
	switch {
	case h == "MD2" || h == "MD5":
		return h
	case strings.HasPrefix(h, "SHA3") && len(h) == len("SHA3256"): // SHA384 also starts with SHA3
		return "SHA3-" + strings.TrimPrefix(h, "SHA3")
	}
	return "SHA-" + strings.TrimPrefix(h, "SHA")
}

func canonicalKey(k string) string {
	k = strings.ToUpper(k)
	switch {
	case strings.HasPrefix(k, "RSA"):
		return "RSA"
	case k == "ECDSA":
		return "ECDSA"
	}
	return "DSA"
}

// SignatureStrength rates a signature algorithm as the weaker of its hash's collision strength
// (SP 800-57 Part 1 Table 3) and its key (PRD-011 REQ-CLS-3). key is the signer's key strength
// when it is known; without it the hash alone is rated and the basis says the key was not given.
// A name that is not a hash-and-key signature is rated as StrengthOf rates it.
func SignatureStrength(name string, key *Strength) Strength {
	hash, keyAlg, ok := SignatureParts(name)
	if !ok {
		s := StrengthOf(name)
		if key != nil && key.Known() && s.Known() && key.Bits < s.Bits {
			return *key
		}
		return s
	}
	h := StrengthOf(hash)
	if h.Status == StrengthBroken {
		return Strength{Status: StrengthBroken, Basis: fmt.Sprintf("%s signatures: %s", hash, h.Basis)}
	}
	if key == nil || !key.Known() {
		if key != nil && key.Status == StrengthBroken {
			return *key
		}
		if !h.Known() {
			return h
		}
		return rated(h.Bits, fmt.Sprintf("%s (%s collisions); the %s key was not given, so it is not counted", basisTable3, hash, keyAlg))
	}
	if key.Bits < h.Bits {
		return Strength{Bits: key.Bits, Status: key.Status, Basis: fmt.Sprintf("its %s key: %s (the %s hash gives %d)", keyAlg, key.Basis, hash, h.Bits)}
	}
	return rated(h.Bits, fmt.Sprintf("%s (%s collisions; the %s key gives %d)", basisTable3, hash, keyAlg, key.Bits))
}

// HashKDFStrength rates a hash where it is used in HMAC, a KDF or a PRF (the TLS PRF and HKDF),
// not where collisions matter: SP 800-57 Part 1 Rev. 5 Table 3 rates that use separately.
func HashKDFStrength(hash string) Strength {
	switch canonicalHash(hash) {
	case "SHA-1":
		return rated(128, basisTable3+" (HMAC, KDF and RBG use)")
	case "SHA-224", "SHA3-224":
		return rated(192, basisTable3+" (HMAC, KDF and RBG use)")
	case "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512":
		return rated(256, basisTable3+" (HMAC, KDF and RBG use)")
	case "MD5":
		return notRated("MD5 is not an approved hash, so SP 800-57 gives it no strength in any use")
	}
	return notRated("NIST assigns this hash no strength")
}
