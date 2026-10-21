package eval

import (
	"fmt"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// The classical strength of what a TLS endpoint accepts (PRD-010, ENH-001): each cipher suite rated
// by its weakest part, and each accepted group and certificate key with its own strength. The
// numbers come from internal/algo (NIST's methods); the four words are this product's, defined here
// and in docs/methodology.md.

// The suite strength words (PRD-010 §2).
const (
	StrengthStrong     = "strong"
	StrengthAcceptable = "acceptable"
	StrengthWeak       = "weak"
	StrengthInsecure   = "insecure"
)

// StrengthPart is one part of a cipher suite and its strength.
type StrengthPart struct {
	Role     string        `json:"role"` // cipher, key exchange, authentication, MAC
	Name     string        `json:"name"` // AES-128-GCM, ffdhe2048, RSA-2048 certificate key, HMAC-SHA-1
	Strength algo.Strength `json:"strength"`
}

// SuiteStrength is a cipher suite's rating: the word, the bits of its weakest rated part, which
// part that is, and the reason for the word.
type SuiteStrength struct {
	Version string         `json:"version"`
	ID      uint16         `json:"id"`
	Name    string         `json:"name"`
	Word    string         `json:"word"`
	Bits    int            `json:"bits,omitempty"`
	Weakest string         `json:"weakest,omitempty"`
	Reason  string         `json:"reason"`
	Parts   []StrengthPart `json:"parts"`
}

// KeyStrength is the strength of an accepted key-exchange group or a presented certificate key.
type KeyStrength struct {
	Kind     string        `json:"kind"` // group | certificate-key
	Version  string        `json:"version,omitempty"`
	Name     string        `json:"name"`
	Strength algo.Strength `json:"strength"`
}

// suiteCipher names a suite's bulk cipher in the catalogue's words and rates it. Ciphers NIST does
// not rate (Camellia, ARIA, SEED, SM4, IDEA, GOST, AEGIS, Ascon) are given the bound an exhaustive
// key search sets, stated as such.
func suiteCipher(s tlsprobe.SuiteResult) (string, algo.Strength) {
	switch s.Cipher {
	case "NULL":
		return "no encryption", algo.Strength{Status: algo.StrengthBroken, Basis: "the suite encrypts nothing (RFC 9325 section 4.1: MUST NOT)"}
	case "AES":
		name := fmt.Sprintf("AES-%d-%s", s.KeyBits, s.Mode)
		if st := algo.StrengthOf(name); st.Known() {
			return name, st
		}
		return name, algo.Strength{Bits: s.KeyBits, Status: algo.StrengthRated, Basis: "NIST SP 800-57 Part 1 Rev. 5, Table 2"}
	case "CHACHA20":
		return "ChaCha20-Poly1305", algo.StrengthOf("ChaCha20-Poly1305")
	case "3DES", "DES", "RC4", "RC2":
		if s.Export {
			return s.Cipher + " (export)", algo.Strength{Status: algo.StrengthBroken, Basis: fmt.Sprintf("export-grade, %d-bit key (RFC 9325 section 4.1: MUST NOT under 112 bits)", s.KeyBits)}
		}
		return s.Cipher, algo.StrengthOf(s.Cipher)
	}
	name := fmt.Sprintf("%s-%d %s", s.Cipher, s.KeyBits, s.Mode)
	if s.Export {
		return name, algo.Strength{Status: algo.StrengthBroken, Basis: "export-grade (RFC 9325 section 4.1)"}
	}
	if s.KeyBits < 80 {
		return name, algo.Strength{Status: algo.StrengthBroken, Basis: fmt.Sprintf("%d-bit key: exhaustive search is practical", s.KeyBits)}
	}
	return name, algo.Strength{Bits: s.KeyBits, Status: algo.StrengthRated, Basis: fmt.Sprintf("%d-bit key; NIST assigns %s no strength, so this is the bound an exhaustive key search sets", s.KeyBits, s.Cipher)}
}

// macPart is a non-AEAD suite's MAC.
func macPart(s tlsprobe.SuiteResult) (StrengthPart, bool) {
	name := map[string]string{"SHA1": "HMAC-SHA-1", "SHA256": "HMAC-SHA-256", "SHA384": "HMAC-SHA-384", "MD5": "HMAC-MD5"}[s.MAC]
	if s.AEAD || name == "" {
		return StrengthPart{}, false
	}
	return StrengthPart{Role: "MAC", Name: name, Strength: algo.StrengthOf(name)}, true
}

// leafKeys are the end-entity keys the server presented to clients that send a server name
// (a no-SNI-only chain is not what those clients see), weakest first is not assumed.
func leafKeys(rep *tlsprobe.Report) []tlsprobe.KeyInfo {
	var out []tlsprobe.KeyInfo
	seen := map[string]bool{}
	for _, cr := range rep.Certificates {
		if cr.NoSNI || len(cr.Chain) == 0 {
			continue
		}
		leaf := cr.Chain[0]
		if seen[leaf.SHA256] {
			continue
		}
		seen[leaf.SHA256] = true
		out = append(out, leaf.PublicKey)
	}
	return out
}

func keyName(k tlsprobe.KeyInfo) string {
	switch {
	case k.Curve != "":
		return fmt.Sprintf("%s %s certificate key", k.Algorithm, k.Curve)
	case k.Bits > 0 && (k.Algorithm == "RSA" || k.Algorithm == "DSA"):
		return fmt.Sprintf("%s-%d certificate key", k.Algorithm, k.Bits)
	}
	return k.Algorithm + " certificate key"
}

// weakestOf picks the weakest part: a broken one first, then the fewest bits. Not-rated parts do
// not decide (they are stated, but say nothing about the number).
func weakestOf(parts []StrengthPart) (StrengthPart, bool) {
	var best StrengthPart
	found := false
	for _, p := range parts {
		switch {
		case p.Strength.Status == algo.StrengthBroken:
			if !found || best.Strength.Status != algo.StrengthBroken {
				best, found = p, true
			}
		case p.Strength.Known():
			if !found || (best.Strength.Status != algo.StrengthBroken && p.Strength.Bits < best.Strength.Bits) {
				best, found = p, true
			}
		}
	}
	return best, found
}

// suiteStrengths rates every accepted suite (PRD-010 §2).
func suiteStrengths(rep *tlsprobe.Report) []SuiteStrength {
	if rep == nil {
		return nil
	}
	groupsOf := func(version string) []tlsprobe.GroupResult {
		var out []tlsprobe.GroupResult
		for _, g := range rep.Groups {
			if g.Version == version {
				out = append(out, g)
			}
		}
		if len(out) == 0 && version != "TLSv1.3" {
			// TLS 1.0 and 1.1 use the same ECDHE curves as TLS 1.2, which is where they are probed.
			for _, g := range rep.Groups {
				if g.Version == "TLSv1.2" {
					out = append(out, g)
				}
			}
		}
		return out
	}
	weakestGroup := func(version string) (StrengthPart, bool) {
		var parts []StrengthPart
		for _, g := range groupsOf(version) {
			parts = append(parts, StrengthPart{Role: "key exchange", Name: g.Name, Strength: algo.GroupStrength(g.Name)})
		}
		return weakestOf(parts)
	}
	keys := leafKeys(rep)
	weakestKey := func(alg string) (StrengthPart, bool) {
		var parts []StrengthPart
		for _, k := range keys {
			if alg != "" && !strings.EqualFold(k.Algorithm, alg) {
				continue
			}
			parts = append(parts, StrengthPart{Role: "authentication", Name: keyName(k), Strength: algo.KeyStrength(k.Algorithm, k.Bits, k.Curve)})
		}
		return weakestOf(parts)
	}

	out := make([]SuiteStrength, 0, len(rep.Suites))
	for _, s := range rep.Suites {
		cname, cst := suiteCipher(s)
		parts := []StrengthPart{{Role: "cipher", Name: cname, Strength: cst}}
		noFS := false
		switch {
		case s.Version == "TLSv1.3":
			if p, ok := weakestGroup("TLSv1.3"); ok {
				parts = append(parts, p)
			}
		case s.Kx == "ECDHE" || s.Kx == "ECDH":
			if p, ok := weakestGroup(s.Version); ok {
				parts = append(parts, p)
			}
			noFS = s.Kx == "ECDH"
		case s.Kx == "DHE" || s.Kx == "DH":
			if rep.DH != nil && rep.DH.PrimeBits > 0 {
				parts = append(parts, StrengthPart{Role: "key exchange", Name: fmt.Sprintf("%d-bit DH prime", rep.DH.PrimeBits), Strength: algo.KeyStrength("DH", rep.DH.PrimeBits, "")})
			}
			noFS = s.Kx == "DH"
		case s.Kx == "RSA":
			if p, ok := weakestKey("RSA"); ok {
				p.Role = "key exchange"
				parts = append(parts, p)
			}
			noFS = true
		}
		switch {
		case s.Anon:
			parts = append(parts, StrengthPart{Role: "authentication", Name: "none (anonymous)", Strength: algo.Strength{Status: algo.StrengthBroken, Basis: "no authentication: anyone can impersonate the server"}})
		case s.Version == "TLSv1.3":
			if p, ok := weakestKey(""); ok {
				parts = append(parts, p)
			}
		case s.Auth == "RSA" || s.Auth == "ECDSA" || s.Auth == "DSS":
			alg := map[string]string{"RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA"}[s.Auth]
			if p, ok := weakestKey(alg); ok {
				parts = append(parts, p)
			}
		}
		if p, ok := macPart(s); ok {
			parts = append(parts, p)
		}
		out = append(out, rateSuite(s, parts, noFS))
	}
	return out
}

// rateSuite turns a suite's parts into its word, bits and reason.
func rateSuite(s tlsprobe.SuiteResult, parts []StrengthPart, noFS bool) SuiteStrength {
	r := SuiteStrength{Version: s.Version, ID: s.ID, Name: s.Name, Parts: parts}
	w, ok := weakestOf(parts)
	if ok {
		r.Weakest = w.Name
		if w.Strength.Known() {
			r.Bits = w.Strength.Bits
		}
	}
	aead := s.AEAD || s.Version == "TLSv1.3"
	switch {
	case ok && w.Strength.Status == algo.StrengthBroken:
		r.Word, r.Reason = StrengthInsecure, fmt.Sprintf("%s is broken: %s", w.Name, w.Strength.Basis)
	case ok && r.Bits < 80:
		r.Word, r.Reason = StrengthInsecure, fmt.Sprintf("%s gives %d bits, below 80", w.Name, r.Bits)
	case ok && r.Bits < 112:
		r.Word, r.Reason = StrengthWeak, fmt.Sprintf("%s gives %d bits, below 112 (RFC 9325 section 4.1)", w.Name, r.Bits)
	case s.BlockBits == 64:
		r.Word, r.Reason = StrengthWeak, "64-bit block cipher: long connections are exposed to birthday attacks (Sweet32; RFC 9325 section 4.2)"
	case noFS:
		r.Word, r.Reason = StrengthWeak, "no forward secrecy: a stolen server key decrypts recorded traffic (RFC 9325 section 4.1)"
	case !ok:
		r.Word, r.Reason = StrengthAcceptable, "no part of this suite has a NIST strength to compare"
	case r.Bits < 128:
		r.Word, r.Reason = StrengthAcceptable, fmt.Sprintf("weakest part: %s, %d bits", w.Name, r.Bits)
	case !aead:
		r.Word, r.Reason = StrengthAcceptable, fmt.Sprintf("%d bits, but not an AEAD cipher (RFC 9325 section 4.2 prefers AEAD)", r.Bits)
	default:
		r.Word, r.Reason = StrengthStrong, fmt.Sprintf("every part at least %d bits, AEAD, forward secrecy; weakest part: %s", r.Bits, w.Name)
	}
	return r
}

// keyStrengths lists the strength of every accepted group and every presented certificate key.
func keyStrengths(rep *tlsprobe.Report) []KeyStrength {
	if rep == nil {
		return nil
	}
	var out []KeyStrength
	for _, g := range rep.Groups {
		out = append(out, KeyStrength{Kind: "group", Version: g.Version, Name: g.Name, Strength: algo.GroupStrength(g.Name)})
	}
	seen := map[string]bool{}
	for _, cr := range rep.Certificates {
		for _, ci := range cr.Chain {
			if ci.SHA256 == "" || seen[ci.SHA256] {
				continue
			}
			seen[ci.SHA256] = true
			out = append(out, KeyStrength{Kind: "certificate-key", Name: ci.SHA256, Strength: algo.KeyStrength(ci.PublicKey.Algorithm, ci.PublicKey.Bits, ci.PublicKey.Curve)})
		}
	}
	return out
}
