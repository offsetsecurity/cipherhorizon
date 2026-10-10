package tlsprobe

import (
	"crypto/tls"
	"strings"
	"sync"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
)

// signatureSchemes are offered so a server can pick a certificate of any common
// type. RFC 8446 section 4.2.3; the values are pinned against crypto/tls in tests.
var signatureSchemes = []uint16{
	0x0403, 0x0503, 0x0603, // ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
	0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
	0x0807, 0x0808, // ed25519, ed448
	0x0809, 0x080A, 0x080B, // rsa_pss_pss_sha{256,384,512}
	0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
	0x0201, 0x0203, // rsa_pkcs1_sha1, ecdsa_sha1 (legacy: only to let old servers pick a cert)
}

const (
	scsvRenegotiation uint16 = 0x00FF
	scsvFallback      uint16 = 0x5600
)

var (
	candOnce     sync.Once
	legacyIDs    []uint16 // every legacy-class suite in the registry
	tls13IDs     []uint16 // every TLS 1.3-style suite
	commonSuites []uint16 // suites crypto/tls knows: a small list for servers that dislike big hellos
	ecGroupIDs   []uint16 // every non-PQ, non-FFDHE group
	allGroupIDs  []uint16 // every real group in the registry
	commonGroups = []uint16{29, 23, 24, 25}
	commonTLS13  = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}
)

func initCandidates() {
	candOnce.Do(func() {
		for _, s := range registry.Suites() {
			switch s.Class {
			case registry.ClassLegacy:
				legacyIDs = append(legacyIDs, s.ID)
			case registry.ClassTLS13:
				tls13IDs = append(tls13IDs, s.ID)
			}
		}
		for _, s := range tls.CipherSuites() {
			commonSuites = append(commonSuites, s.ID)
		}
		for _, s := range tls.InsecureCipherSuites() {
			commonSuites = append(commonSuites, s.ID)
		}
		for _, g := range registry.Groups() {
			allGroupIDs = append(allGroupIDs, g.ID)
			if !g.PQ && !isFFDHE(g.Name) {
				ecGroupIDs = append(ecGroupIDs, g.ID)
			}
		}
	})
}

func isFFDHE(name string) bool { return strings.HasPrefix(name, "ffdhe") }

// legacyHello builds a hello for SSLv3 through TLS 1.2. The server's ServerHello
// version tells whether v is supported: a server answers with the highest
// version it supports that does not exceed the one offered.
func (p *prober) legacyHello(v wire.Version, suites, groups []uint16) (*wire.ClientHello, error) {
	list := append(append([]uint16(nil), suites...), scsvRenegotiation)
	h, err := wire.NewClientHello(p.random(), v, list)
	if err != nil {
		return nil, err
	}
	if v == wire.VersionSSL30 {
		h.NoExtensions = true // SSLv3 defines no extensions; the SCSV above signals renegotiation support
		return h, nil
	}
	if p.target.SNI != "" {
		h.Extensions = append(h.Extensions, wire.SNI(p.target.SNI))
	}
	h.Extensions = append(h.Extensions,
		wire.SupportedGroups(groups), wire.ECPointFormats(),
		wire.RenegotiationInfo(), wire.ExtendedMasterSecret(), wire.SessionTicket(),
		wire.Extension{Type: wire.ExtEncryptThenMAC}, wire.StatusRequest())
	if v >= wire.VersionTLS12 {
		h.Extensions = append(h.Extensions, wire.SignatureAlgorithms(signatureSchemes))
	}
	return h, nil
}

// tls13Hello builds a TLS 1.3-only hello with an EMPTY key_share. A server that
// supports one of the offered groups must answer with a HelloRetryRequest naming
// its choice, so both the group and the cipher suite are learned without the
// client generating any key material.
func (p *prober) tls13Hello(suites, groups []uint16) (*wire.ClientHello, error) {
	h, err := wire.NewClientHello(p.random(), wire.VersionTLS12, suites)
	if err != nil {
		return nil, err
	}
	sid := make([]byte, 32) // middlebox-compatibility session id, as real clients send
	if _, err := p.random().Read(sid); err != nil {
		return nil, err
	}
	h.SessionID = sid
	if p.target.SNI != "" {
		h.Extensions = append(h.Extensions, wire.SNI(p.target.SNI))
	}
	h.Extensions = append(h.Extensions,
		wire.SupportedVersions(wire.VersionTLS13), wire.SupportedGroups(groups),
		wire.SignatureAlgorithms(signatureSchemes), wire.KeyShareEmpty(), wire.PSKKeyExchangeModes())
	return h, nil
}

// without returns list minus the elements of drop, preserving order.
func without(list []uint16, drop ...uint16) []uint16 {
	skip := make(map[uint16]bool, len(drop))
	for _, d := range drop {
		skip[d] = true
	}
	out := make([]uint16, 0, len(list))
	for _, v := range list {
		if !skip[v] {
			out = append(out, v)
		}
	}
	return out
}

func contains(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
