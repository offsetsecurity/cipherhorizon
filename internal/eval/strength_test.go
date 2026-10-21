package eval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
)

// PRD-010 REQ-STR-2 and REQ-STR-3: a suite is as strong as its weakest part, and the evaluation
// says which part and why.

func ianaSuite(version string, id uint16) tlsprobe.SuiteResult {
	s, ok := registry.SuiteByID(id)
	if !ok {
		panic("unknown suite")
	}
	return tlsprobe.SuiteResult{Version: version, ID: s.ID, Name: s.Name, IANARecommended: string(s.Recommended), Kx: s.Kx, Auth: s.Auth,
		Cipher: s.Cipher, KeyBits: s.KeyBits, Mode: s.Mode, BlockBits: s.BlockBits, MAC: s.MAC, AEAD: s.AEAD, Export: s.Export, Anon: s.Anon, Ephemeral: s.Ephemeral}
}

func strengthReport(key tlsprobe.KeyInfo, groups []string, suites ...tlsprobe.SuiteResult) *tlsprobe.Report {
	rep := &tlsprobe.Report{SchemaVersion: tlsprobe.SchemaVersion, Target: tlsprobe.Target{Host: "strength.example", Port: 443}, Suites: suites,
		Certificates: []tlsprobe.CertResult{{Source: "tls-default", Chain: []tlsprobe.CertInfo{{SHA256: strings.Repeat("ab", 32), PublicKey: key}}}}}
	for _, g := range groups {
		v := "TLSv1.3"
		if strings.HasPrefix(g, "1.2:") {
			v, g = "TLSv1.2", strings.TrimPrefix(g, "1.2:")
		}
		rep.Groups = append(rep.Groups, tlsprobe.GroupResult{Version: v, Name: g})
	}
	return rep
}

func rated(t *testing.T, rep *tlsprobe.Report) map[string]eval.SuiteStrength {
	t.Helper()
	out := map[string]eval.SuiteStrength{}
	for _, s := range eval.Evaluate(rep, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)).SuiteStrength {
		out[s.Name] = s
	}
	return out
}

func TestSuiteStrengthIsTheWeakestPart(t *testing.T) {
	p256 := tlsprobe.KeyInfo{Algorithm: "ECDSA", Bits: 256, Curve: "P-256"}
	rsa2048 := tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}
	rsa3072 := tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 3072}

	// TLS 1.3, X25519, ECDSA P-256: every part 128 or more, AEAD, forward secret.
	r := rated(t, strengthReport(p256, []string{"x25519", "X25519MLKEM768"}, ianaSuite("TLSv1.3", 0x1301), ianaSuite("TLSv1.3", 0x1302)))
	if s := r["TLS_AES_128_GCM_SHA256"]; s.Word != eval.StrengthStrong || s.Bits != 128 {
		t.Errorf("AES-128 / X25519 / P-256: %+v", s)
	}
	// The same with an RSA-2048 certificate: 112 bits, Acceptable (OD-1).
	r = rated(t, strengthReport(rsa2048, []string{"x25519"}, ianaSuite("TLSv1.3", 0x1302)))
	if s := r["TLS_AES_256_GCM_SHA384"]; s.Word != eval.StrengthAcceptable || s.Bits != 112 || s.Weakest != "RSA-2048 certificate key" {
		t.Errorf("RSA-2048 certificate: %+v", s)
	}
	// TLS 1.2 CBC with secp384r1 and RSA-3072: 128 bits, but not AEAD.
	r = rated(t, strengthReport(rsa3072, []string{"1.2:secp384r1"}, ianaSuite("TLSv1.2", 0xC028))) // ECDHE_RSA_AES_256_CBC_SHA384
	if s := r["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"]; s.Word != eval.StrengthAcceptable || s.Bits != 128 {
		t.Errorf("CBC suite: %+v", s)
	}
	// A 1024-bit DH prime: 80 bits, Weak.
	rep := strengthReport(rsa3072, nil, ianaSuite("TLSv1.2", 0x009E)) // DHE_RSA_AES_128_GCM_SHA256
	rep.DH = &tlsprobe.DHResult{PrimeBits: 1024}
	if s := rated(t, rep)["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]; s.Word != eval.StrengthWeak || s.Bits != 80 {
		t.Errorf("DHE-1024: %+v", s)
	}
	// 3DES: 112 bits but a 64-bit block; RSA key transport. Weak.
	if s := rated(t, strengthReport(rsa2048, nil, ianaSuite("TLSv1.2", 0x000A)))["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]; s.Word != eval.StrengthWeak {
		t.Errorf("3DES: %+v", s)
	}
	// Static RSA with AES-GCM: no forward secrecy, Weak.
	if s := rated(t, strengthReport(rsa3072, nil, ianaSuite("TLSv1.2", 0x009C)))["TLS_RSA_WITH_AES_128_GCM_SHA256"]; s.Word != eval.StrengthWeak || !strings.Contains(s.Reason, "forward secrecy") {
		t.Errorf("static RSA: %+v", s)
	}
	// RC4, NULL, export, anonymous: Insecure.
	for id, name := range map[uint16]string{0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0001: "TLS_RSA_WITH_NULL_MD5",
		0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA"} {
		if s := rated(t, strengthReport(rsa2048, nil, ianaSuite("TLSv1.2", id)))[name]; s.Word != eval.StrengthInsecure {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

// Issue #18: single DES (56-bit key) is Insecure, not Weak.
func TestSingleDESIsInsecure(t *testing.T) {
	s := rated(t, strengthReport(tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}, nil, ianaSuite("TLSv1.2", 0x0009)))["TLS_RSA_WITH_DES_CBC_SHA"]
	if s.Word != eval.StrengthInsecure || s.Weakest != "DES" {
		t.Errorf("single DES: %+v", s)
	}
}

// Every suite in the IANA registry gets a word and a reason; the weakest part is always named when
// a part was rated.
func TestEverySuiteInTheRegistryIsRated(t *testing.T) {
	var all []tlsprobe.SuiteResult
	for _, s := range registry.Suites() {
		v := "TLSv1.2"
		if s.Class == registry.ClassTLS13 {
			v = "TLSv1.3"
		}
		all = append(all, ianaSuite(v, s.ID))
	}
	rep := strengthReport(tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}, []string{"x25519", "1.2:secp256r1"}, all...)
	rep.DH = &tlsprobe.DHResult{PrimeBits: 2048}
	words := map[string]int{}
	for _, s := range rated(t, rep) {
		if s.Word == "" || s.Reason == "" {
			t.Errorf("%s: %+v", s.Name, s)
		}
		words[s.Word]++
	}
	if words[eval.StrengthInsecure] == 0 || words[eval.StrengthWeak] == 0 || words[eval.StrengthAcceptable] == 0 {
		t.Errorf("the registry should span the words: %v", words)
	}
}

// The evaluation lists each group's and each certificate key's strength.
func TestEvaluationCarriesStrength(t *testing.T) {
	ev := eval.Evaluate(strengthReport(tlsprobe.KeyInfo{Algorithm: "RSA", Bits: 2048}, []string{"x25519", "ffdhe2048", "secp384r1"}, ianaSuite("TLSv1.3", 0x1301)), time.Now())
	got := map[string]int{}
	for _, k := range ev.KeyStrength {
		got[k.Kind+":"+k.Name] = k.Strength.Bits
	}
	for k, want := range map[string]int{"group:x25519": 128, "group:ffdhe2048": 112, "group:secp384r1": 192, "certificate-key:" + strings.Repeat("ab", 32): 112} {
		if got[k] != want {
			t.Errorf("%s = %d, want %d (all: %v)", k, got[k], want, got)
		}
	}
	if len(ev.SuiteStrength) != 1 || ev.Version != "eval/9" {
		t.Errorf("suiteStrength %d, version %s", len(ev.SuiteStrength), ev.Version)
	}
}

// PRD-010 REQ-STR-7: every advertised SSH algorithm (bar compression) carries its classical
// strength; an RSA host key's comes from the key the server presented.
func TestSSHAlgorithmsCarryStrength(t *testing.T) {
	rep := modernSSH()
	rep.Algorithms.Kex = append(rep.Algorithms.Kex, "diffie-hellman-group14-sha256")
	rep.Algorithms.HostKey = append(rep.Algorithms.HostKey, "rsa-sha2-256", "ssh-rsa")
	rep.Algorithms.CipherC2S = append(rep.Algorithms.CipherC2S, "3des-cbc")
	rep.Algorithms.MACC2S = append(rep.Algorithms.MACC2S, "hmac-md5")
	rep.HostKeys = append(rep.HostKeys, sshprobe.HostKey{Type: "ssh-rsa", Algorithm: "RSA", Bits: 1024, Fingerprint: "SHA256:r"})
	got := map[string]string{}
	for _, a := range sshEval(rep).SSHAlgorithms {
		if a.Strength != nil {
			got[a.Name] = a.Strength.Words()
		} else if a.Kind != "compression" {
			t.Errorf("%s (%s) has no strength", a.Name, a.Kind)
		}
	}
	for name, want := range map[string]string{
		"curve25519-sha256": "128 bits", "ecdh-sha2-nistp256": "128 bits", "mlkem768x25519-sha256": "192 bits",
		"diffie-hellman-group14-sha256": "112 bits", "ssh-ed25519": "128 bits", "ecdsa-sha2-nistp256": "128 bits",
		"rsa-sha2-256": "80 bits", "ssh-rsa": "broken", "chacha20-poly1305@openssh.com": "256 bits", "aes128-ctr": "128 bits",
		"3des-cbc": "112 bits, disallowed", "hmac-sha2-256-etm@openssh.com": "256 bits", "hmac-md5": "not rated",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}
