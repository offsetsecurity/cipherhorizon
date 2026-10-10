package evidence

import (
	"strings"
	"testing"
)

func certObservation(attrs, sourceAttrs map[string]string) Observation {
	o := Observation{
		Stream: StreamHost, Origin: OriginObserved,
		Subject: Subject{Kind: KindCertificate, Key: CertificateKey(strings.Repeat("ab", 32)), Name: "CN=x", Attrs: attrs},
		Claim:   Claim{Rung: RungProvisioned}, Outcome: OutcomeObserved,
		Method: MethodCertFile, Source: Source{Kind: "file", Location: "etc/ssl/certs/x.crt", Attrs: sourceAttrs}, Privilege: "user",
	}
	Finish(&o)
	return o
}

// REQ-CERT-3, -4: what a certificate observation may carry is an allow-list. There is no
// attribute for key material, so a sensor cannot put any on a certificate even by mistake.
func TestCertificateObservationsCarryOnlyAllowedMetadata(t *testing.T) {
	good := map[string]string{"sha256": strings.Repeat("ab", 32), "subject": "CN=x", "issuer": "CN=ca", "keyAlg": "RSA", "keyBits": "2048", "isCA": "false", "selfSigned": "false"}
	if err := Validate(certObservation(good, map[string]string{"privateKey": "unknown"})); err != nil {
		t.Fatalf("a well-formed certificate observation was refused: %v", err)
	}
	for name, c := range map[string]struct{ attrs, source map[string]string }{
		"a key attribute":           {map[string]string{"privateKeyPem": "x"}, nil},
		"a password attribute":      {map[string]string{"password": "x"}, nil},
		"a path on the subject":     {map[string]string{"path": "/etc/ssl/private/x.key"}, nil},
		"privateKey on the subject": {map[string]string{"privateKey": "yes"}, nil},
		"keyBits not digits":        {map[string]string{"keyBits": "2048 bits"}, nil},
		"keyBits absurdly long":     {map[string]string{"keyBits": "1234567"}, nil},
		"isCA not a boolean":        {map[string]string{"isCA": "maybe"}, nil},
		"sha256 not hex":            {map[string]string{"sha256": strings.Repeat("zz", 32)}, nil},
		"sha256 the wrong length":   {map[string]string{"sha256": "abcd"}, nil},
		"an unknown source attr":    {good, map[string]string{"keyFile": "/etc/ssl/private/x.key"}},
		"privateKey not yes/no/unk": {good, map[string]string{"privateKey": "true"}},
		"a key body in a value":     {map[string]string{"subject": "a\x00b"}, nil},
	} {
		if err := Validate(certObservation(c.attrs, c.source)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCertificateKeyIsCanonical(t *testing.T) {
	if got := CertificateKey("  ABCDEF  "); got != "cert:abcdef" {
		t.Errorf("CertificateKey = %q", got)
	}
}

func TestCertFileMethodIsDeclaredAdjacentToSecrets(t *testing.T) {
	m, ok := LookupMethod(MethodCertFile)
	if !ok || m.SecretProximity != "adjacent" || m.Sensor != "cert-files" {
		t.Errorf("method = %+v, %v: opening files that can sit beside private keys must be declared adjacent (ADR-0005)", m, ok)
	}
}
