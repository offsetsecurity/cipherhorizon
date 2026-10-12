package tlsprobe

import (
	"context"
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
)

// The signature stage (PRD-008 REQ-PQS-3, REQ-PQS-4; ENG-HANDOFF-005 D-2, D-3).
//
// In TLS 1.3 the certificate and the CertificateVerify are encrypted, so which keys a server
// holds cannot be read off the wire. But a server must choose a certificate it can sign for with
// one of the client's signature_algorithms before it sends its ServerHello (RFC 8446 section
// 4.4.2.2). Offering one scheme per hello therefore shows, scheme by scheme, whether the server
// has a key for it: a ServerHello means yes, an alert means no.
//
// Two things keep that honest. Each hello carries real key shares, so the server answers with a
// ServerHello rather than a HelloRetryRequest; some servers (Go's) send a HelloRetryRequest before
// they look at certificates at all. And a control hello offers only a private-use code point that
// no server can sign with: a server that answers it is not choosing by scheme, and the stage says
// so instead of listing every scheme as accepted.

// SignatureControlScheme is the control: RFC 8446 section 11 reserves 0xFE00 to 0xFFFF for private use.
const SignatureControlScheme uint16 = 0xFE01

// SigSchemeInfo describes one TLS 1.3 signature scheme the stage tests.
type SigSchemeInfo struct {
	ID        uint16
	Name      string // the TLS SignatureScheme name: "mldsa65", "ecdsa_secp256r1_sha256"
	Algorithm string // the key it needs, in the catalogue's words: "ML-DSA-65", "ECDSA", "RSA", "Ed25519"
	Detail    string // curve or padding, for people: "P-256", "PSS (RSA key)"
	PQ        bool
}

// sigCandidates are the schemes a TLS 1.3 server can sign a handshake with (RFC 8446 section
// 4.2.3; ML-DSA from draft-ietf-tls-mldsa). PKCS #1 v1.5 and SHA-1 schemes are not usable in a TLS
// 1.3 CertificateVerify, so they are not tested. The code points are pinned against crypto/tls.
var sigCandidates = []SigSchemeInfo{
	{0x0904, "mldsa44", "ML-DSA-44", "", true},
	{0x0905, "mldsa65", "ML-DSA-65", "", true},
	{0x0906, "mldsa87", "ML-DSA-87", "", true},
	{0x0403, "ecdsa_secp256r1_sha256", "ECDSA", "P-256", false},
	{0x0503, "ecdsa_secp384r1_sha384", "ECDSA", "P-384", false},
	{0x0603, "ecdsa_secp521r1_sha512", "ECDSA", "P-521", false},
	{0x0807, "ed25519", "Ed25519", "", false},
	{0x0808, "ed448", "Ed448", "", false},
	{0x0804, "rsa_pss_rsae_sha256", "RSA", "PSS, RSA key", false},
	{0x0805, "rsa_pss_rsae_sha384", "RSA", "PSS, RSA key", false},
	{0x0806, "rsa_pss_rsae_sha512", "RSA", "PSS, RSA key", false},
	{0x0809, "rsa_pss_pss_sha256", "RSASSA-PSS", "PSS, PSS key", false},
	{0x080A, "rsa_pss_pss_sha384", "RSASSA-PSS", "PSS, PSS key", false},
	{0x080B, "rsa_pss_pss_sha512", "RSASSA-PSS", "PSS, PSS key", false},
}

// SigCandidates returns the schemes the signature stage tests, in the order it tests them.
func SigCandidates() []SigSchemeInfo { return append([]SigSchemeInfo(nil), sigCandidates...) }

// SigScheme is one tested scheme with its result.
type SigScheme struct {
	ID        uint16 `json:"id"`
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Detail    string `json:"detail,omitempty"`
	PQ        bool   `json:"pq,omitempty"`
	// Result is accepted (a ServerHello answered a hello offering only this scheme), refused (an
	// alert or a closed connection) or inconclusive (a timeout, a HelloRetryRequest, a network error).
	Result string `json:"result"`
	Why    string `json:"why,omitempty"`
}

// The results of one scheme, and of the control.
const (
	SigAccepted     = "accepted"
	SigRefused      = "refused"
	SigInconclusive = "inconclusive"
)

// SignatureResult is what the signature stage found (TLS 1.3 only).
type SignatureResult struct {
	Version string `json:"version"`
	// Control is the answer to the private-use scheme: refused is the only result that lets the
	// per-scheme answers mean anything.
	Control    string      `json:"control"`
	ControlWhy string      `json:"controlWhy,omitempty"`
	KeyShare   string      `json:"keyShare,omitempty"` // the group the shares were made for
	Schemes    []SigScheme `json:"schemes"`
}

// Conclusive reports whether the per-scheme results can be relied on.
func (r *SignatureResult) Conclusive() bool { return r != nil && r.Control == SigRefused }

// Accepted returns the schemes the server answered, when the stage was conclusive.
func (r *SignatureResult) Accepted() []SigScheme {
	if !r.Conclusive() {
		return nil
	}
	var out []SigScheme
	for _, s := range r.Schemes {
		if s.Result == SigAccepted {
			out = append(out, s)
		}
	}
	return out
}

// shareMaker makes a client key share for one group. Only groups whose share the standard
// library can make are listed; the stage never needs to finish a handshake, so the private
// halves are discarded.
var shareMaker = map[uint16]func() ([]byte, error){
	29: func() ([]byte, error) { return ecdhShare(ecdh.X25519()) },
	23: func() ([]byte, error) { return ecdhShare(ecdh.P256()) },
	24: func() ([]byte, error) { return ecdhShare(ecdh.P384()) },
	25: func() ([]byte, error) { return ecdhShare(ecdh.P521()) },
	// RFC 10024: X25519MLKEM768 is the ML-KEM-768 encapsulation key then the X25519 share; the
	// two NIST-curve hybrids put the ECDH share first.
	0x11EC: func() ([]byte, error) { return hybridShare(768, ecdh.X25519(), false) },
	0x11EB: func() ([]byte, error) { return hybridShare(768, ecdh.P256(), true) },
	0x11ED: func() ([]byte, error) { return hybridShare(1024, ecdh.P384(), true) },
}

func ecdhShare(c ecdh.Curve) ([]byte, error) {
	k, err := c.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func hybridShare(kem int, c ecdh.Curve, ecFirst bool) ([]byte, error) {
	ec, err := ecdhShare(c)
	if err != nil {
		return nil, err
	}
	var ek []byte
	switch kem {
	case 768:
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			return nil, err
		}
		ek = dk.EncapsulationKey().Bytes()
	default:
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			return nil, err
		}
		ek = dk.EncapsulationKey().Bytes()
	}
	if ecFirst {
		return append(ec, ek...), nil
	}
	return append(ek, ec...), nil
}

// sigHello is a TLS 1.3 hello offering every TLS 1.3 suite, the given groups with real shares
// for shareGroups, and exactly the given signature schemes.
func (p *prober) sigHello(suites, groups, shareGroups []uint16, schemes []uint16) (*wire.ClientHello, error) {
	h, err := wire.NewClientHello(p.random(), wire.VersionTLS12, suites)
	if err != nil {
		return nil, err
	}
	sid := make([]byte, 32)
	if _, err := p.random().Read(sid); err != nil {
		return nil, err
	}
	h.SessionID = sid
	var shares []wire.KeyShareEntry
	for _, g := range shareGroups {
		mk := shareMaker[g]
		if mk == nil {
			return nil, fmt.Errorf("no key share maker for group 0x%04x", g)
		}
		key, err := mk()
		if err != nil {
			return nil, err
		}
		shares = append(shares, wire.KeyShareEntry{Group: g, Key: key})
	}
	if p.target.SNI != "" {
		h.Extensions = append(h.Extensions, wire.SNI(p.target.SNI))
	}
	h.Extensions = append(h.Extensions,
		wire.SupportedVersions(wire.VersionTLS13), wire.SupportedGroups(groups),
		wire.SignatureAlgorithms(schemes), wire.KeyShare(shares...), wire.PSKKeyExchangeModes())
	return h, nil
}

// sigOutcome classifies one answer.
func sigOutcome(o outcome) (string, string) {
	switch o.kind {
	case kindServerHello:
		sh := o.serverHello()
		switch {
		case sh.HelloRetryRequest:
			return SigInconclusive, "the server asked for a key share in another group"
		case sh.SelectedVersion != wire.VersionTLS13:
			return SigInconclusive, "the server answered with " + sh.SelectedVersion.String()
		}
		return SigAccepted, ""
	case kindAlert, kindClosed:
		return SigRefused, o.detail()
	}
	return SigInconclusive, o.detail()
}

// signatures runs the stage. groups are the TLS 1.3 groups the server accepted, most preferred
// first; the shares are made for the first group the stage can make a share for, else for
// X25519 and P-256 together.
func (p *prober) signatures(ctx context.Context, small bool, groups []uint16) *SignatureResult {
	res := &SignatureResult{Version: "TLSv1.3", Schemes: []SigScheme{}}
	suites, offer := tls13IDs, allGroupIDs
	if small {
		suites, offer = commonTLS13, commonGroups
	}
	share := []uint16{29, 23}
	for _, g := range groups {
		if shareMaker[g] != nil {
			share = []uint16{g}
			break
		}
	}
	// The shared groups go first in supported_groups, so the server has no reason to ask for another.
	offer = append(append([]uint16(nil), share...), without(offer, share...)...)
	if res.KeyShare = registry.GroupName(share[0]); len(share) > 1 {
		res.KeyShare += ", " + registry.GroupName(share[1])
	}

	ask := func(scheme uint16) (string, string) {
		h, err := p.sigHello(suites, offer, share, []uint16{scheme})
		if err != nil {
			return SigInconclusive, err.Error()
		}
		return sigOutcome(p.exchange(ctx, h))
	}

	res.Control, res.ControlWhy = ask(SignatureControlScheme)
	if res.Control == SigAccepted {
		res.ControlWhy = "the server answered a hello whose only signature scheme is a private-use code point no certificate can match, so it does not choose its certificate by the schemes offered"
	}
	for _, c := range sigCandidates {
		if ctx.Err() != nil {
			break
		}
		s := SigScheme{ID: c.ID, Name: c.Name, Algorithm: c.Algorithm, Detail: c.Detail, PQ: c.PQ}
		s.Result, s.Why = ask(c.ID)
		res.Schemes = append(res.Schemes, s)
	}
	return res
}

// tls13small reports whether the TLS 1.3 probe needed the short, conventional offer.
func tls13small(protos []protoProbe) bool {
	for _, pr := range protos {
		if pr.version == wire.VersionTLS13 {
			return pr.small
		}
	}
	return false
}
