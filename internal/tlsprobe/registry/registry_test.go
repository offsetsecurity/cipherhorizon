package registry_test

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/example/cbom-scan/internal/tlsprobe/registry"
)

// Go's crypto/tls is an independent oracle: it names suites and groups from the
// same IANA registry, so every suite it implements must match ours exactly.
func TestSuitesMatchGoStdlib(t *testing.T) {
	var std []*tls.CipherSuite
	std = append(std, tls.CipherSuites()...)
	std = append(std, tls.InsecureCipherSuites()...)
	if len(std) < 20 {
		t.Fatalf("stdlib reports only %d suites", len(std))
	}
	for _, s := range std {
		got, ok := registry.SuiteByID(s.ID)
		if !ok {
			t.Errorf("0x%04X %s (known to Go) missing from registry", s.ID, s.Name)
			continue
		}
		if got.Name != s.Name {
			t.Errorf("0x%04X: registry %q, Go %q", s.ID, got.Name, s.Name)
		}
	}
}

func TestGroupsMatchGoStdlib(t *testing.T) {
	for id, name := range map[tls.CurveID]string{
		tls.CurveP256:      "secp256r1",
		tls.CurveP384:      "secp384r1",
		tls.CurveP521:      "secp521r1",
		tls.X25519:         "x25519",
		tls.X25519MLKEM768: "X25519MLKEM768",
		// The next three are typed constants only in Go 1.26+/1.27+; the module
		// targets Go 1.25, so use their code points, as defined in common.go there.
		tls.CurveID(4587): "SecP256r1MLKEM768",
		tls.CurveID(4589): "SecP384r1MLKEM1024",
		tls.CurveID(514):  "MLKEM1024",
	} {
		g, ok := registry.GroupByID(uint16(id))
		if !ok || g.Name != name {
			t.Errorf("group %d: registry %+v ok=%v, want name %q", id, g, ok, name)
		}
	}
}

func TestKnownSuiteDecompositions(t *testing.T) {
	type want struct {
		class                 registry.SuiteClass
		kx, auth, cipher, mac string
		mode                  string
		keyBits, blockBits    int
		aead, export, anon    bool
		ephemeral             bool
		hash                  string
	}
	for id, w := range map[uint16]want{
		0x1301: {class: registry.ClassTLS13, cipher: "AES", mode: "GCM", keyBits: 128, blockBits: 128, mac: "AEAD", aead: true, hash: "SHA256"},
		0x1302: {class: registry.ClassTLS13, cipher: "AES", mode: "GCM", keyBits: 256, blockBits: 128, mac: "AEAD", aead: true, hash: "SHA384"},
		0x1303: {class: registry.ClassTLS13, cipher: "CHACHA20", mode: "POLY1305", keyBits: 256, mac: "AEAD", aead: true, hash: "SHA256"},
		0xC02F: {kx: "ECDHE", auth: "RSA", cipher: "AES", mode: "GCM", keyBits: 128, blockBits: 128, mac: "AEAD", aead: true, ephemeral: true, hash: "SHA256"},
		0xC030: {kx: "ECDHE", auth: "RSA", cipher: "AES", mode: "GCM", keyBits: 256, blockBits: 128, mac: "AEAD", aead: true, ephemeral: true, hash: "SHA384"},
		0xC02B: {kx: "ECDHE", auth: "ECDSA", cipher: "AES", mode: "GCM", keyBits: 128, blockBits: 128, mac: "AEAD", aead: true, ephemeral: true, hash: "SHA256"},
		0xCCA8: {kx: "ECDHE", auth: "RSA", cipher: "CHACHA20", mode: "POLY1305", keyBits: 256, mac: "AEAD", aead: true, ephemeral: true, hash: "SHA256"},
		0x009C: {kx: "RSA", auth: "RSA", cipher: "AES", mode: "GCM", keyBits: 128, blockBits: 128, mac: "AEAD", aead: true, hash: "SHA256"},
		0x002F: {kx: "RSA", auth: "RSA", cipher: "AES", mode: "CBC", keyBits: 128, blockBits: 128, mac: "SHA1"},
		0x0039: {kx: "DHE", auth: "RSA", cipher: "AES", mode: "CBC", keyBits: 256, blockBits: 128, mac: "SHA1", ephemeral: true},
		0x000A: {kx: "RSA", auth: "RSA", cipher: "3DES", mode: "CBC", keyBits: 168, blockBits: 64, mac: "SHA1"},
		0x0005: {kx: "RSA", auth: "RSA", cipher: "RC4", mode: "STREAM", keyBits: 128, mac: "SHA1"},
		0x0003: {kx: "RSA", auth: "RSA", cipher: "RC4", mode: "STREAM", keyBits: 40, mac: "MD5", export: true},
		0x0000: {kx: "NULL", auth: "NULL", cipher: "NULL", mode: "NONE", mac: "NONE"},
		0x0001: {kx: "RSA", auth: "RSA", cipher: "NULL", mode: "NONE", mac: "MD5"},
		0x0018: {kx: "DHE", auth: "anon", cipher: "RC4", mode: "STREAM", keyBits: 128, mac: "MD5", anon: true, ephemeral: true},
		0x0034: {kx: "DHE", auth: "anon", cipher: "AES", mode: "CBC", keyBits: 128, blockBits: 128, mac: "SHA1", anon: true, ephemeral: true},
	} {
		s, ok := registry.SuiteByID(id)
		if !ok {
			t.Errorf("0x%04X missing", id)
			continue
		}
		if s.Class != w.class || s.Kx != w.kx || s.Auth != w.auth || s.Cipher != w.cipher || s.Mode != w.mode ||
			s.KeyBits != w.keyBits || s.BlockBits != w.blockBits || s.MAC != w.mac || s.Hash != w.hash ||
			s.AEAD != w.aead || s.Export != w.export || s.Anon != w.anon || s.Ephemeral != w.ephemeral {
			t.Errorf("0x%04X %s decomposed as %+v", id, s.Name, s)
		}
	}
}

func TestSignallingValues(t *testing.T) {
	for id, name := range map[uint16]string{0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0x5600: "TLS_FALLBACK_SCSV"} {
		s, ok := registry.SuiteByID(id)
		if !ok || s.Name != name || s.Class != registry.ClassSignalling {
			t.Errorf("0x%04X = %+v ok=%v", id, s, ok)
		}
	}
}

// Structural invariants that must hold for every entry, including ones the
// spot-checks above don't cover.
func TestSuiteInvariants(t *testing.T) {
	names := map[string]uint16{}
	var legacy, tls13, signalling int
	for _, s := range registry.Suites() {
		if other, dup := names[s.Name]; dup {
			t.Errorf("name %s used by 0x%04X and 0x%04X", s.Name, other, s.ID)
		}
		names[s.Name] = s.ID
		if s.Recommended != registry.RecommendedYes && s.Recommended != registry.RecommendedNo && s.Recommended != registry.RecommendedDiscouraged {
			t.Errorf("%s: Recommended = %q", s.Name, s.Recommended)
		}

		switch s.Class {
		case registry.ClassSignalling:
			signalling++
			if s.Cipher != "" || s.Kx != "" {
				t.Errorf("%s: signalling value has a decomposition", s.Name)
			}
			continue
		case registry.ClassTLS13:
			tls13++
			if s.Kx != "" || s.Auth != "" {
				t.Errorf("%s: TLS 1.3-style suite has kx/auth", s.Name)
			}
		case registry.ClassLegacy:
			legacy++
			if s.Kx == "" || s.Auth == "" {
				t.Errorf("%s: legacy suite lacks kx/auth", s.Name)
			}
		}
		if s.Cipher == "" || s.Mode == "" || s.MAC == "" {
			t.Errorf("%s: incomplete decomposition %+v", s.Name, s)
		}
		if s.AEAD != (s.MAC == "AEAD") {
			t.Errorf("%s: AEAD=%v but MAC=%q", s.Name, s.AEAD, s.MAC)
		}
		if s.Cipher != "NULL" && s.KeyBits == 0 {
			t.Errorf("%s: no key size for %s", s.Name, s.Cipher)
		}
		if s.Anon && s.Auth != "anon" {
			t.Errorf("%s: anon suite with auth %q", s.Name, s.Auth)
		}
		if strings.Contains(s.Name, "_EXPORT") && !s.Export {
			t.Errorf("%s: name says EXPORT but Export=false", s.Name)
		}
		if strings.Contains(s.Name, "_anon_") && !s.Anon {
			t.Errorf("%s: name says anon but Anon=false", s.Name)
		}
		if (strings.Contains(s.Name, "_DHE_") || strings.Contains(s.Name, "_ECDHE_")) && !s.Ephemeral {
			t.Errorf("%s: name says ephemeral but Ephemeral=false", s.Name)
		}
	}
	if legacy < 250 || tls13 < 5 || signalling != 2 {
		t.Errorf("counts legacy=%d tls13=%d signalling=%d", legacy, tls13, signalling)
	}
}

func TestPostQuantumGroups(t *testing.T) {
	type want struct {
		pq, hybrid, obsolete bool
		rec                  registry.Recommended
	}
	for id, w := range map[uint16]want{
		4588:  {true, true, false, registry.RecommendedYes}, // X25519MLKEM768
		4587:  {true, true, false, registry.RecommendedNo},  // SecP256r1MLKEM768
		4589:  {true, true, false, registry.RecommendedNo},  // SecP384r1MLKEM1024
		512:   {true, false, false, registry.RecommendedNo}, // MLKEM512 (pure)
		513:   {true, false, false, registry.RecommendedNo}, // MLKEM768
		514:   {true, false, false, registry.RecommendedNo}, // MLKEM1024
		25497: {true, true, true, registry.RecommendedDiscouraged},
		25498: {true, true, true, registry.RecommendedDiscouraged},
		29:    {false, false, false, registry.RecommendedYes}, // x25519
		23:    {false, false, false, registry.RecommendedYes}, // secp256r1
	} {
		g, ok := registry.GroupByID(id)
		if !ok {
			t.Errorf("group %d missing", id)
			continue
		}
		if g.PQ != w.pq || g.Hybrid != w.hybrid || g.Obsolete != w.obsolete || g.Recommended != w.rec {
			t.Errorf("group %d %s = %+v", id, g.Name, g)
		}
		if g.Obsolete && strings.Contains(g.Name, "OBSOLETE") {
			t.Errorf("group %d: OBSOLETE marker left in name %q", id, g.Name)
		}
	}
	// Nothing outside the ML-KEM/Kyber families may be flagged PQ.
	for _, g := range registry.Groups() {
		l := strings.ToLower(g.Name)
		if g.PQ != (strings.Contains(l, "mlkem") || strings.Contains(l, "kyber")) {
			t.Errorf("group %d %s: PQ=%v inconsistent with its name", g.ID, g.Name, g.PQ)
		}
		if g.Hybrid && !g.PQ {
			t.Errorf("group %d %s: hybrid but not PQ", g.ID, g.Name)
		}
	}
}

func TestNamesAndProvenance(t *testing.T) {
	if got := registry.SuiteName(0xC02F); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("SuiteName = %q", got)
	}
	if got := registry.SuiteName(0xDEAD); got != "UNKNOWN_0xDEAD" {
		t.Errorf("unregistered suite = %q", got)
	}
	if got := registry.GroupName(0xBEEF); got != "UNKNOWN_0xBEEF" {
		t.Errorf("unregistered group = %q", got)
	}
	if registry.SuitesRetrieved == "" || registry.GroupsRetrieved == "" {
		t.Error("registry provenance (retrieval date) missing")
	}
	for i := 1; i < len(registry.Suites()); i++ {
		if registry.Suites()[i-1].ID >= registry.Suites()[i].ID {
			t.Fatal("Suites() not sorted by ID")
		}
	}
}
