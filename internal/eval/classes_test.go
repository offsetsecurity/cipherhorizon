package eval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
)

// REQ-CLS-2: every suite has its key-schedule hash as a part, rated in that use, and the part
// never decides a word on its own (it ties at most).
func TestSuiteHasItsHashPart(t *testing.T) {
	cases := []struct {
		version string
		id      uint16
		role    string
		name    string
		words   string
	}{
		{"TLSv1.3", 0x1302, "hash (HKDF)", "SHA-384", "256 bits"},
		{"TLSv1.3", 0x1301, "hash (HKDF)", "SHA-256", "256 bits"},
		{"TLSv1.2", 0xC02F, "hash (PRF)", "SHA-256", "256 bits"},
		{"TLSv1.2", 0xC030, "hash (PRF)", "SHA-384", "256 bits"},
		{"TLSv1.2", 0x002F, "hash (PRF)", "SHA-256", "256 bits"}, // a CBC suite: the default PRF
		{"TLSv1.0", 0x002F, "hash (PRF)", "MD5 and SHA-1", "128 bits"},
	}
	for _, c := range cases {
		ev := eval.Evaluate(strengthReport(tlsprobe.KeyInfo{Algorithm: "ECDSA", Curve: "secp384r1"}, []string{"secp384r1", "1.2:secp384r1"}, ianaSuite(c.version, c.id)), time.Now())
		var found bool
		for _, p := range ev.SuiteStrength[0].Parts {
			if p.Role == c.role {
				found = true
				if p.Name != c.name || p.Strength.Words() != c.words || p.Class != "hash" {
					t.Errorf("%s %#04x: hash part %s %q class %q, want %s %q", c.version, c.id, p.Name, p.Strength.Words(), p.Class, c.name, c.words)
				}
			}
		}
		if !found {
			t.Errorf("%s %#04x has no %s part", c.version, c.id, c.role)
		}
	}

	// Across the registry, with keys strong enough that only the suite's own parts decide.
	hashNames := map[string]bool{"SHA-256": true, "SHA-384": true, "SHA-512": true, "MD5 and SHA-1": true, "SM3": true, "Ascon-Hash256": true}
	for _, s := range registry.Suites() {
		if strings.HasSuffix(s.Name, "_SCSV") { // signalling values, never an accepted suite
			continue
		}
		// Each suite at the versions that can carry it: AEAD and SHA-2 MAC suites need TLS 1.2.
		versions := []string{"TLSv1.2"}
		switch {
		case s.Kx == "" || s.Kx == "ANY":
			versions = []string{"TLSv1.3"}
		case !s.AEAD && (s.MAC == "SHA1" || s.MAC == "MD5"):
			versions = []string{"TLSv1.0", "TLSv1.2"}
		}
		for _, v := range versions {
			ev := eval.Evaluate(strengthReport(tlsprobe.KeyInfo{Algorithm: "ECDSA", Curve: "secp521r1"}, []string{"secp521r1", "1.2:secp521r1"}, ianaSuite(v, s.ID)), time.Now())
			r := ev.SuiteStrength[0]
			var classes []string
			for _, p := range r.Parts {
				if p.Class == "" {
					t.Errorf("%s %s: part %s has no class", v, s.Name, p.Role)
				}
				classes = append(classes, p.Class)
			}
			if !strings.Contains(strings.Join(classes, ","), "hash") {
				t.Errorf("%s %s has no hash part", v, s.Name)
			}
			if hashNames[r.Weakest] {
				t.Errorf("%s %s: the hash part (%s) decided the word %s", v, s.Name, r.Weakest, r.Word)
			}
		}
	}
}

// REQ-CLS-4: the evaluation lists every algorithm the endpoint uses, by class, with strength,
// post-quantum status and uses; the weakest of each class is marked.
func TestEvaluationListsAlgorithmsByClass(t *testing.T) {
	rep := strengthReport(tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}, []string{"X25519MLKEM768", "x25519", "1.2:secp256r1"},
		ianaSuite("TLSv1.3", 0x1301), ianaSuite("TLSv1.3", 0x1302), ianaSuite("TLSv1.2", 0xC02F), ianaSuite("TLSv1.2", 0x000A))
	rep.Certificates[0].Chain[0].SignatureAlg = tlsprobe.AlgInfo{Name: "SHA256-RSA"}
	rep.Certificates[0].Chain[0].SelfSigned = true
	ev := eval.Evaluate(rep, time.Now())

	type row struct{ class, words, pqc string }
	got := map[string]row{}
	weakest := map[string]string{}
	for _, a := range ev.Algorithms {
		got[a.Role+":"+a.Name] = row{a.Class, a.Strength.Words(), a.PQC}
		if len(a.UsedBy) == 0 {
			t.Errorf("%s %s lists no use", a.Role, a.Name)
		}
		if a.Weakest {
			if weakest[a.Class] != "" {
				t.Errorf("two weakest %s algorithms: %s and %s", a.Class, weakest[a.Class], a.Name)
			}
			weakest[a.Class] = a.Name
		}
	}
	for k, want := range map[string]row{
		"key exchange:X25519MLKEM768":           {"asymmetric", "192 bits", "quantum-safe"},
		"key exchange:x25519":                   {"asymmetric", "128 bits", "quantum-vulnerable"},
		"key exchange:secp256r1":                {"asymmetric", "128 bits", "quantum-vulnerable"},
		"signature:RSA-2048":                    {"asymmetric", "112 bits", "quantum-vulnerable"},
		"signature:SHA256-RSA":                  {"asymmetric", "112 bits", "quantum-vulnerable"}, // its key is weaker than SHA-256
		"key exchange:RSA-2048 (key transport)": {"asymmetric", "112 bits", "quantum-vulnerable"},
		"cipher:AES-128-GCM":                    {"symmetric", "128 bits", "quantum-safe"},
		"cipher:AES-256-GCM":                    {"symmetric", "256 bits", "quantum-safe"},
		"cipher:3DES":                           {"symmetric", "112 bits, disallowed", ""},
		"MAC:HMAC-SHA-1":                        {"symmetric", "128 bits", ""},
		"hash (HKDF):SHA-256":                   {"hash", "256 bits", ""},
		"hash (HKDF):SHA-384":                   {"hash", "256 bits", ""},
		"hash (PRF):SHA-256":                    {"hash", "256 bits", ""},
		"hash (signature):SHA-256":              {"hash", "128 bits", ""},
	} {
		g, ok := got[k]
		if !ok {
			t.Errorf("%s is not listed (got %v)", k, got)
			continue
		}
		if g.class != want.class || g.words != want.words || (want.pqc != "" && g.pqc != want.pqc) {
			t.Errorf("%s = %+v, want %+v", k, g, want)
		}
	}
	if weakest["symmetric"] != "3DES" || weakest["hash"] != "SHA-256" || !strings.Contains(weakest["asymmetric"], "RSA") {
		t.Errorf("weakest per class = %v, want 3DES, SHA-256 and an RSA-2048 row", weakest)
	}
}
