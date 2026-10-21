package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/tlscbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
)

// Every algorithm a TLS endpoint uses, by class (PRD-011, ENH-002): asymmetric (key exchange,
// signatures), symmetric (ciphers, MACs) and hash (the PRF or HKDF, and the hash in a certificate
// signature), each with its classical strength, post-quantum status and what uses it.

// AlgorithmUse is one algorithm in one role on an endpoint.
type AlgorithmUse struct {
	Name     string        `json:"name"`
	Class    string        `json:"class"` // asymmetric | symmetric | hash
	Role     string        `json:"role"`  // key exchange, signature, cipher, MAC, hash (HKDF), hash (PRF), hash (signature)
	Strength algo.Strength `json:"strength"`
	// PQC is the catalogue's post-quantum status, quantum-vulnerable or quantum-safe, or empty
	// when the catalogue gives none (a hash's question is not a quantum one).
	PQC string `json:"pqc,omitempty"`
	// Versions are the protocol versions it is used in; UsedBy names the suites, or the
	// certificates, that use it.
	Versions []string `json:"versions,omitempty"`
	UsedBy   []string `json:"usedBy"`
	// Weakest marks the weakest algorithm of its class (a broken one first, then the fewest bits).
	Weakest bool `json:"weakest,omitempty"`
}

// The roles a hash is used in.
const (
	roleHashHKDF      = "hash (HKDF)"
	roleHashPRF       = "hash (PRF)"
	roleHashSignature = "hash (signature)"
)

// classOfRole is the class a suite part's role belongs to.
func classOfRole(role string) string {
	switch {
	case role == "cipher" || role == "MAC":
		return algo.ClassSymmetric
	case strings.HasPrefix(role, "hash"):
		return algo.ClassHash
	}
	return algo.ClassAsymmetric
}

// hashPart is the hash a suite's key schedule uses (PRD-011 REQ-CLS-2): HKDF's in TLS 1.3, the
// PRF's in TLS 1.2 (SHA-256 unless the suite names SHA-384, RFC 5246 section 5), and the MD5 and
// SHA-1 pair of TLS 1.0 and 1.1 (RFC 2246 section 5). It is rated in that use, not by collisions.
func hashPart(s tlsprobe.SuiteResult) (StrengthPart, bool) {
	named := ""
	if r, ok := registry.SuiteByID(s.ID); ok {
		named = r.Hash
	}
	if s.MAC == "SHA384" {
		named = "SHA384"
	}
	switch s.Version {
	case "TLSv1.3":
		if named == "" {
			return StrengthPart{}, false
		}
		h := hashName(named)
		return StrengthPart{Role: roleHashHKDF, Name: h, Strength: algo.HashKDFStrength(h)}, true
	case "TLSv1.2":
		h := "SHA-256"
		if named == "SHA384" || named == "SHA512" || named == "SM3" || named == "ASCONHASH256" {
			h = hashName(named)
		}
		return StrengthPart{Role: roleHashPRF, Name: h, Strength: algo.HashKDFStrength(h)}, true
	case "TLSv1.1", "TLSv1.0":
		return StrengthPart{Role: roleHashPRF, Name: "MD5 and SHA-1", Strength: algo.Strength{Bits: 128, Status: algo.StrengthRated,
			Basis: "the TLS 1.0 and 1.1 PRF XORs P_MD5 and P_SHA-1, so it holds while either does (RFC 2246 section 5): at least HMAC-SHA-1's 128 in KDF use, NIST SP 800-57 Part 1 Rev. 5, Table 3"}}, true
	}
	return StrengthPart{Role: roleHashPRF, Name: "SSL key derivation", Strength: algo.Strength{Status: algo.StrengthNotRated,
		Basis: "SSL's own MD5 and SHA-1 construction; NIST rates it at nothing (the protocol itself is prohibited, RFC 7568)"}}, true
}

// hashName is the catalogue's spelling of a registry hash: SHA256 is SHA-256.
func hashName(h string) string {
	switch h {
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "ASCONHASH256":
		return "Ascon-Hash256"
	}
	return h
}

// keyLabel names a public key the way the catalogue derives it: RSA-2048, ECDSA P-256, Ed25519.
func keyLabel(k tlsprobe.KeyInfo) string {
	switch {
	case k.Curve != "":
		return k.Algorithm + " " + k.Curve
	case k.Bits > 0 && (k.Algorithm == "RSA" || k.Algorithm == "DSA"):
		return fmt.Sprintf("%s-%d", k.Algorithm, k.Bits)
	}
	return k.Algorithm
}

// pqcOf is the catalogue's post-quantum status of a catalogue ID, or "" when it gives none.
func pqcOf(id string) string {
	oid := ""
	if a, ok := algo.Lookup(id); ok {
		oid = a.OID
	}
	if c, ok := pqc.ClassOf(id, oid); ok {
		return string(c)
	}
	return ""
}

// keyCatalogueID is the catalogue's family for a public key algorithm.
func keyCatalogueID(k tlsprobe.KeyInfo) string {
	switch k.Algorithm {
	case "RSA", "RSASSA-PSS":
		return "RSA"
	case "DSA":
		return "DSA"
	case "ECDSA", "EC":
		return "ECDSA"
	}
	return k.Algorithm // Ed25519, Ed448, ML-DSA-65
}

// algorithmsInUse lists every algorithm the endpoint uses, by class (REQ-CLS-4).
func algorithmsInUse(rep *tlsprobe.Report, suites []SuiteStrength) []AlgorithmUse {
	if rep == nil {
		return nil
	}
	byKey := map[string]*AlgorithmUse{}
	var order []string
	add := func(name, role, pqcStatus string, st algo.Strength, version, usedBy string) {
		k := name + "\x00" + role
		u, ok := byKey[k]
		if !ok {
			u = &AlgorithmUse{Name: name, Class: classOfRole(role), Role: role, Strength: st, PQC: pqcStatus}
			byKey[k] = u
			order = append(order, k)
		}
		if version != "" && !contains(u.Versions, version) {
			u.Versions = append(u.Versions, version)
		}
		if usedBy != "" && !contains(u.UsedBy, usedBy) {
			u.UsedBy = append(u.UsedBy, usedBy)
		}
	}

	// Each suite's cipher, MAC and key-schedule hash, as rated for the suite.
	rated := map[string]SuiteStrength{}
	for _, s := range suites {
		rated[s.Version+"\x00"+s.Name] = s
	}
	for _, s := range rep.Suites {
		ss := rated[s.Version+"\x00"+s.Name]
		for _, p := range ss.Parts {
			switch {
			case p.Role == "cipher":
				id, _ := tlscbom.CipherID(s)
				add(p.Name, p.Role, pqcOf(id), p.Strength, s.Version, s.Name)
			case p.Role == "MAC" || strings.HasPrefix(p.Role, "hash"):
				add(p.Name, p.Role, pqcOf(p.Name), p.Strength, s.Version, s.Name)
			case p.Role == "key exchange" && s.Kx == "RSA":
				add(strings.TrimSuffix(p.Name, " certificate key")+" (key transport)", p.Role, pqcOf("RSA"), p.Strength, s.Version, s.Name)
			case p.Role == "key exchange" && (s.Kx == "DHE" || s.Kx == "DH"):
				add(p.Name, p.Role, pqcOf("DH"), p.Strength, s.Version, s.Name)
			}
		}
	}
	// Every accepted group, not only the weakest a suite is rated by.
	for _, g := range rep.Groups {
		id, ok := tlscbom.GroupID(g)
		if !ok {
			id = g.Name // a hybrid named in the catalogue, even when the report did not flag it
		}
		add(g.Name, "key exchange", pqcOf(id), algo.GroupStrength(g.Name), g.Version, "key exchange group")
	}
	// Certificates: each key that signs the handshake, and each certificate's signature and its hash.
	seen := map[string]bool{}
	for _, cr := range rep.Certificates {
		if cr.NoSNI {
			continue
		}
		for i, ci := range cr.Chain {
			if ci.SHA256 == "" || seen[ci.SHA256] {
				continue
			}
			seen[ci.SHA256] = true
			who := certWho(i, ci)
			if i == 0 {
				add(keyLabel(ci.PublicKey), algo.RoleSignature, pqcOf(keyCatalogueID(ci.PublicKey)),
					algo.KeyStrength(ci.PublicKey.Algorithm, ci.PublicKey.Bits, ci.PublicKey.Curve), "", "the server's certificate key")
			}
			if ci.SignatureAlg.Name == "" {
				continue
			}
			// The signer's key: the next certificate's, or its own when it is self-signed.
			var signer *algo.Strength
			switch {
			case i+1 < len(cr.Chain):
				k := cr.Chain[i+1].PublicKey
				st := algo.KeyStrength(k.Algorithm, k.Bits, k.Curve)
				signer = &st
			case ci.SelfSigned:
				st := algo.KeyStrength(ci.PublicKey.Algorithm, ci.PublicKey.Bits, ci.PublicKey.Curve)
				signer = &st
			}
			keyAlg := ""
			if _, ka, ok := algo.SignatureParts(ci.SignatureAlg.Name); ok {
				keyAlg = ka
			}
			add(ci.SignatureAlg.Name, algo.RoleSignature, pqcOf(firstNonEmptyStr(keyAlg, ci.SignatureAlg.Name)),
				algo.SignatureStrength(ci.SignatureAlg.Name, signer), "", "signature on "+who)
			if h, _, ok := algo.SignatureParts(ci.SignatureAlg.Name); ok {
				add(h, roleHashSignature, "", algo.StrengthOf(h), "", "signature on "+who)
			}
		}
	}

	out := make([]AlgorithmUse, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	classRank := map[string]int{algo.ClassAsymmetric: 0, algo.ClassSymmetric: 1, algo.ClassHash: 2}
	sort.SliceStable(out, func(i, j int) bool {
		if classRank[out[i].Class] != classRank[out[j].Class] {
			return classRank[out[i].Class] < classRank[out[j].Class]
		}
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Name < out[j].Name
	})
	markWeakest(out)
	return out
}

// markWeakest marks the weakest algorithm of each class.
func markWeakest(uses []AlgorithmUse) {
	for _, class := range []string{algo.ClassAsymmetric, algo.ClassSymmetric, algo.ClassHash} {
		var parts []StrengthPart
		var idx []int
		for i, u := range uses {
			if u.Class == class {
				parts = append(parts, StrengthPart{Name: u.Name, Role: u.Role, Strength: u.Strength})
				idx = append(idx, i)
			}
		}
		if w, ok := weakestOf(parts); ok {
			for j, p := range parts {
				if p.Name == w.Name && p.Role == w.Role {
					uses[idx[j]].Weakest = true
					break
				}
			}
		}
	}
}

// certWho names a certificate in a chain for people: its CN and its position.
func certWho(i int, ci tlsprobe.CertInfo) string {
	cn := ci.Subject
	if j := strings.Index(cn, "CN="); j >= 0 {
		cn = cn[j+3:]
		if k := strings.Index(cn, ","); k >= 0 {
			cn = cn[:k]
		}
	}
	switch {
	case i == 0:
		return "the server's certificate (" + cn + ")"
	case ci.SelfSigned:
		return "the root " + cn
	}
	return "the intermediate " + cn
}

func firstNonEmptyStr(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
