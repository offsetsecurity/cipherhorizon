package algo

import "testing"

// REQ-CLS-1: every catalogue entry has a class from PRD-011 §2, and so does every name this
// program derives.
func TestEveryAlgorithmHasAClass(t *testing.T) {
	for _, a := range All() {
		if c := ClassOf(a.ID); !c.Known() {
			t.Errorf("%s (primitive %q) has no class", a.ID, a.Primitive)
		}
	}
	for name, want := range map[string]Class{
		"RSA-2048":                {ClassAsymmetric, RoleKeyExchange},
		"ECDSA-P256":              {ClassAsymmetric, RoleSignature},
		"DSA-2048":                {ClassAsymmetric, RoleSignature},
		"x25519":                  {ClassAsymmetric, RoleKeyExchange},
		"secp384r1":               {ClassAsymmetric, RoleKeyExchange},
		"ffdhe2048":               {ClassAsymmetric, RoleKeyExchange},
		"X25519MLKEM768":          {ClassAsymmetric, RoleKeyExchange},
		"SecP256r1MLKEM768":       {ClassAsymmetric, RoleKeyExchange},
		"ECDSA-SHA256":            {ClassAsymmetric, RoleSignature},
		"SHA256withRSA":           {ClassAsymmetric, RoleSignature},
		"sha384WithRSAEncryption": {ClassAsymmetric, RoleSignature},
		"AES-256-GCM":             {ClassSymmetric, RoleCipher},
		"3DES":                    {ClassSymmetric, RoleCipher},
		"RC4":                     {ClassSymmetric, RoleCipher},
		"HMAC-SHA-256":            {ClassSymmetric, RoleMAC},
		"SHA-384":                 {ClassHash, RoleHash},
	} {
		if got := ClassOf(name); got != want {
			t.Errorf("ClassOf(%q) = %+v, want %+v", name, got, want)
		}
	}
	if c := ClassOf("not-an-algorithm"); c.Known() {
		t.Errorf("an unknown name was classified as %+v", c)
	}
}

// REQ-CLS-3: a signature algorithm is its hash and its key, in every spelling, rated as the weaker.
func TestSignatureAlgorithmIsHashAndKey(t *testing.T) {
	for name, want := range map[string][2]string{
		"ECDSA-SHA256":            {"SHA-256", "ECDSA"},
		"SHA256-RSA":              {"SHA-256", "RSA"},
		"SHA384-RSAPSS":           {"SHA-384", "RSA"},
		"sha256WithRSAEncryption": {"SHA-256", "RSA"},
		"ecdsa-with-SHA384":       {"SHA-384", "ECDSA"},
		"dsa-with-SHA1":           {"SHA-1", "DSA"},
		"SHA256withRSA":           {"SHA-256", "RSA"},
		"SHA512withECDSA":         {"SHA-512", "ECDSA"},
		"MD5-RSA":                 {"MD5", "RSA"},
	} {
		h, k, ok := SignatureParts(name)
		if !ok || h != want[0] || k != want[1] {
			t.Errorf("SignatureParts(%q) = %q, %q, %v; want %q, %q", name, h, k, ok, want[0], want[1])
		}
	}
	for _, name := range []string{"Ed25519", "ML-DSA-65", "RSASSA-PSS", "AES-128-GCM"} {
		if _, _, ok := SignatureParts(name); ok {
			t.Errorf("%s was split into a hash and a key", name)
		}
	}

	rsa2048, p384 := KeyStrength("RSA", 2048, ""), KeyStrength("ECDSA", 0, "secp384r1")
	cases := []struct {
		name string
		key  *Strength
		want string
	}{
		{"SHA256-RSA", &rsa2048, "112 bits"}, // the key is weaker than SHA-256's 128
		{"ECDSA-SHA256", &p384, "128 bits"},  // the hash is weaker than P-384's 192
		{"SHA256withRSA", nil, "128 bits"},   // no key: the hash, and the basis says so
		{"SHA1-RSA", &rsa2048, "broken"},     // SHA-1 collisions
		{"MD5-RSA", nil, "broken"},           // MD5 collisions
	}
	for _, c := range cases {
		if got := SignatureStrength(c.name, c.key).Words(); got != c.want {
			t.Errorf("SignatureStrength(%s) = %s, want %s", c.name, got, c.want)
		}
	}
	if got := StrengthOf("SHA256withRSA"); got.Words() != "128 bits" {
		t.Errorf("SHA256withRSA is %q, want 128 bits (it was not rated before PRD-011)", got.Words())
	}
}

// The hash a TLS PRF or HKDF uses is rated in that use, not by its collision strength.
func TestHashKDFStrengthFollowsTable3(t *testing.T) {
	for hash, want := range map[string]string{"SHA-1": "128 bits", "SHA256": "256 bits", "SHA-384": "256 bits", "MD5": "not rated"} {
		if got := HashKDFStrength(hash).Words(); got != want {
			t.Errorf("HashKDFStrength(%s) = %s, want %s", hash, got, want)
		}
	}
}
