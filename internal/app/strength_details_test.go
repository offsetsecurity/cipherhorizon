package app

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// PRD-010 REQ-STR-5: tls scan --details prints each suite's and each group's classical strength,
// as the evaluation gives it.
func TestDetailsShowSuiteStrength(t *testing.T) {
	rep := &tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: "details.example", Port: 443},
		Protocols: []tlsprobe.ProtocolResult{{Version: "TLSv1.2", Supported: true}},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.2", ID: 0xC02F, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Kx: "ECDHE", Auth: "RSA", Cipher: "AES", KeyBits: 128, Mode: "GCM", MAC: "AEAD", AEAD: true, Ephemeral: true},
			{Version: "TLSv1.2", ID: 0x0009, Name: "TLS_RSA_WITH_DES_CBC_SHA", Kx: "RSA", Auth: "RSA", Cipher: "DES", KeyBits: 56, Mode: "CBC", BlockBits: 64, MAC: "SHA1"},
		},
		Groups:       []tlsprobe.GroupResult{{Version: "TLSv1.2", Name: "secp256r1"}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{{SHA256: strings.Repeat("cd", 32), PublicKey: tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}}}}},
	}
	ev := eval.Evaluate(rep, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	var b bytes.Buffer
	if err := rep.WriteTextWith(&b, strengthAnnotations(ev)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"acceptable 112 (RSA-2048 certificate key)", "insecure (DES)", "secp256r1  iana:  128 bits"} {
		if !strings.Contains(out, want) {
			t.Errorf("--details lacks %q:\n%s", want, out)
		}
	}
}

// PRD-011 REQ-CLS-8: --details lists every algorithm by class, and each suite's parts.
func TestDetailsShowAlgorithmsByClass(t *testing.T) {
	rep := &tlsprobe.Report{
		SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: "details.example", Port: 443},
		Protocols: []tlsprobe.ProtocolResult{{Version: "TLSv1.2", Supported: true}},
		Suites: []tlsprobe.SuiteResult{
			{Version: "TLSv1.2", ID: 0xC02F, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Kx: "ECDHE", Auth: "RSA", Cipher: "AES", KeyBits: 128, Mode: "GCM", MAC: "AEAD", AEAD: true, Ephemeral: true},
		},
		Groups:       []tlsprobe.GroupResult{{Version: "TLSv1.2", Name: "secp256r1"}},
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{{SHA256: strings.Repeat("cd", 32), PublicKey: tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}}}}},
	}
	ev := eval.Evaluate(rep, time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC))
	var b bytes.Buffer
	writeAlgorithms(&b, ev)
	out := b.String()
	for _, want := range []string{"Algorithms in use, by class", "  Asymmetric", "  Symmetric", "  Hash", "secp256r1", "AES-128-GCM", "SHA-256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: cipher AES-128-GCM 128 bits", "authentication RSA-2048 certificate key 112 bits (weakest)", "hash (PRF) SHA-256 256 bits"} {
		if !strings.Contains(out, want) {
			t.Errorf("--details lacks %q:\n%s", want, out)
		}
	}
}
