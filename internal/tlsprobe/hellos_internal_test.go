package tlsprobe

import (
	"crypto/tls"
	"encoding/binary"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
)

// offeredSchemes reads signature_algorithms back out of a ClientHello.
func offeredSchemes(h *wire.ClientHello) map[uint16]bool {
	for _, e := range h.Extensions {
		if e.Type != wire.ExtSignatureAlgorithms {
			continue
		}
		out := map[uint16]bool{}
		n := int(binary.BigEndian.Uint16(e.Data))
		for i := 2; i < 2+n; i += 2 {
			out[binary.BigEndian.Uint16(e.Data[i:])] = true
		}
		return out
	}
	return nil
}

// REQ-PQS-1: every hello offering TLS 1.3 offers ML-DSA; hellos for TLS 1.2 and earlier do not.
func TestTLS13HellosOfferMLDSA(t *testing.T) {
	initCandidates()
	p := newProber(Options{}, Target{Host: "localhost", Port: 443, SNI: "localhost"}, "127.0.0.1:443")
	p.opts.defaults()
	mldsa := []uint16{uint16(tls.MLDSA44), uint16(tls.MLDSA65), uint16(tls.MLDSA87)}

	h13, err := p.tls13Hello(tls13IDs, allGroupIDs)
	if err != nil {
		t.Fatal(err)
	}
	got := offeredSchemes(h13)
	for _, s := range mldsa {
		if !got[s] {
			t.Errorf("TLS 1.3 hello does not offer 0x%04x", s)
		}
	}
	if _, err := h13.Marshal(); err != nil {
		t.Fatal(err)
	}
	h12, err := p.legacyHello(wire.VersionTLS12, legacyIDs, ecGroupIDs)
	if err != nil {
		t.Fatal(err)
	}
	got = offeredSchemes(h12)
	for _, s := range mldsa {
		if got[s] {
			t.Errorf("TLS 1.2 hello offers 0x%04x, which is defined for TLS 1.3 only", s)
		}
	}
	// The stage's candidates are crypto/tls's values, not a copy that could drift.
	pins := map[string]tls.SignatureScheme{"mldsa44": tls.MLDSA44, "mldsa65": tls.MLDSA65, "mldsa87": tls.MLDSA87,
		"ecdsa_secp256r1_sha256": tls.ECDSAWithP256AndSHA256, "ecdsa_secp384r1_sha384": tls.ECDSAWithP384AndSHA384,
		"ecdsa_secp521r1_sha512": tls.ECDSAWithP521AndSHA512, "ed25519": tls.Ed25519,
		"rsa_pss_rsae_sha256": tls.PSSWithSHA256, "rsa_pss_rsae_sha384": tls.PSSWithSHA384, "rsa_pss_rsae_sha512": tls.PSSWithSHA512}
	for _, c := range sigCandidates {
		if want, ok := pins[c.Name]; ok && uint16(want) != c.ID {
			t.Errorf("%s is 0x%04x here, 0x%04x in crypto/tls", c.Name, c.ID, uint16(want))
		}
	}
}
