package wire

import (
	"errors"
	"fmt"
	"io"
)

// Extension is one hello extension, in the order it is sent.
type Extension struct {
	Type uint16
	Data []byte
	err  error // set by a constructor whose data did not fit; reported by Marshal
}

// ClientHello describes a ClientHello to send. It is a plain value: the probe
// decides every field, nothing is defaulted behind its back.
type ClientHello struct {
	// RecordVersion is the version in the record header of the hello.
	RecordVersion Version
	// LegacyVersion is client_version. For a TLS 1.3 offer it stays TLS 1.2 and the
	// real versions go in the supported_versions extension.
	LegacyVersion Version
	Random        [32]byte
	SessionID     []byte
	Suites        []uint16
	Compression   []byte // nil means the null method only
	// Extensions are sent in order. If nil and NoExtensions is false, the hello
	// still carries an (empty) extensions block; set NoExtensions for SSLv3-style
	// hellos that omit the block entirely.
	Extensions   []Extension
	NoExtensions bool
}

// NewClientHello returns a hello with a fresh random drawn from rnd.
func NewClientHello(rnd io.Reader, legacy Version, suites []uint16, exts ...Extension) (*ClientHello, error) {
	h := &ClientHello{RecordVersion: VersionTLS10, LegacyVersion: legacy, Suites: suites, Extensions: exts}
	if legacy == VersionSSL30 {
		h.RecordVersion = VersionSSL30
	}
	if _, err := io.ReadFull(rnd, h.Random[:]); err != nil {
		return nil, fmt.Errorf("wire: reading random: %w", err)
	}
	return h, nil
}

// Marshal encodes the hello as a single handshake record.
func (h *ClientHello) Marshal() ([]byte, error) {
	if len(h.Suites) == 0 || len(h.Suites) > 1<<14 {
		return nil, fmt.Errorf("wire: %d cipher suites", len(h.Suites))
	}
	if len(h.SessionID) > 32 {
		return nil, errors.New("wire: session id longer than 32 bytes")
	}
	comp := h.Compression
	if comp == nil {
		comp = []byte{0}
	}

	var body builder
	body.u16(uint16(h.LegacyVersion))
	body.bytes(h.Random[:])
	body.vec8(h.SessionID)
	body.lenU16(2 * len(h.Suites))
	for _, s := range h.Suites {
		body.u16(s)
	}
	body.vec8(comp)
	if !h.NoExtensions {
		var exts builder
		for _, e := range h.Extensions {
			if e.err != nil {
				return nil, fmt.Errorf("wire: extension %d: %w", e.Type, e.err)
			}
			if len(e.Data) > 0xFFFF {
				return nil, fmt.Errorf("wire: extension %d too large", e.Type)
			}
			exts.u16(e.Type)
			exts.vec16(e.Data)
		}
		if len(exts.b) > 0xFFFF {
			return nil, errors.New("wire: extensions block too large")
		}
		body.vec16(exts.b)
	}

	var msg builder
	msg.u8(HandshakeClientHello)
	msg.vec24(body.b)
	if len(msg.b) > 16384 {
		return nil, fmt.Errorf("wire: ClientHello is %d bytes; would need fragmenting", len(msg.b))
	}

	var rec builder
	rec.u8(RecordHandshake)
	rec.u16(uint16(h.RecordVersion))
	rec.vec16(msg.b)
	for _, b := range []*builder{&body, &msg, &rec} {
		if b.err != nil {
			return nil, b.err
		}
	}
	return rec.b, nil
}

// ---- extension constructors ----------------------------------------------------------

// SNI is the server_name extension for a DNS host name.
func SNI(host string) Extension {
	var name builder
	name.u8(0) // host_name
	name.vec16([]byte(host))
	var list builder
	list.vec16(name.b)
	return Extension{Type: ExtServerName, Data: list.b, err: firstErr(&name, &list)}
}

// SupportedGroups is the supported_groups extension.
func SupportedGroups(groups []uint16) Extension {
	var b builder
	b.lenU16(2 * len(groups))
	for _, g := range groups {
		b.u16(g)
	}
	return Extension{Type: ExtSupportedGroups, Data: b.b, err: b.err}
}

// ECPointFormats offers only the uncompressed format.
func ECPointFormats() Extension { return Extension{Type: ExtECPointFormats, Data: []byte{1, 0}} }

// SignatureAlgorithms is the signature_algorithms extension.
func SignatureAlgorithms(schemes []uint16) Extension {
	var b builder
	b.lenU16(2 * len(schemes))
	for _, s := range schemes {
		b.u16(s)
	}
	return Extension{Type: ExtSignatureAlgorithms, Data: b.b, err: b.err}
}

// SupportedVersions is the ClientHello form of supported_versions.
func SupportedVersions(versions ...Version) Extension {
	var b builder
	b.lenU8(2 * len(versions))
	for _, v := range versions {
		b.u16(uint16(v))
	}
	return Extension{Type: ExtSupportedVersions, Data: b.b, err: b.err}
}

// KeyShareEmpty is a key_share carrying no shares. A TLS 1.3 server that supports
// one of the offered groups must answer with a HelloRetryRequest naming it, which
// reveals its choice without the client generating any key material.
func KeyShareEmpty() Extension { return Extension{Type: ExtKeyShare, Data: []byte{0, 0}} }

// KeyShareEntry is one client key share: a group and the client's public value for it.
type KeyShareEntry struct {
	Group uint16
	Key   []byte
}

// KeyShare is a key_share carrying real shares (RFC 8446 section 4.2.8). A server
// that supports one of the shared groups answers with a ServerHello rather than a
// HelloRetryRequest, so it must first choose a certificate it can sign with.
func KeyShare(entries ...KeyShareEntry) Extension {
	var list builder
	for _, e := range entries {
		list.u16(e.Group)
		list.vec16(e.Key)
	}
	var b builder
	b.vec16(list.b)
	return Extension{Type: ExtKeyShare, Data: b.b, err: firstErr(&list, &b)}
}

// PSKKeyExchangeModes offers psk_dhe_ke, as a TLS 1.3 client normally does.
func PSKKeyExchangeModes() Extension {
	return Extension{Type: ExtPSKKeyExchangeModes, Data: []byte{1, 1}}
}

// RenegotiationInfo is the initial (empty) renegotiation_info extension.
func RenegotiationInfo() Extension { return Extension{Type: ExtRenegotiationInfo, Data: []byte{0}} }

// ExtendedMasterSecret asks for extended_master_secret.
func ExtendedMasterSecret() Extension { return Extension{Type: ExtExtendedMasterSecret, Data: nil} }

// SessionTicket offers session tickets with an empty ticket.
func SessionTicket() Extension { return Extension{Type: ExtSessionTicket, Data: nil} }

// StatusRequest asks for an OCSP staple (status_request, type ocsp, empty lists).
func StatusRequest() Extension { return Extension{Type: ExtStatusRequest, Data: []byte{1, 0, 0, 0, 0}} }

// Heartbeat offers the heartbeat extension (RFC 6520) in mode peer_allowed_to_send. The scan only
// reads whether the server echoes it: it never sends a heartbeat message.
func Heartbeat() Extension { return Extension{Type: ExtHeartbeat, Data: []byte{1}} }

// ALPN offers application protocols.
func ALPN(protocols ...string) Extension {
	var list builder
	for _, p := range protocols {
		list.vec8([]byte(p))
	}
	var b builder
	b.vec16(list.b)
	return Extension{Type: ExtALPN, Data: b.b, err: firstErr(&list, &b)}
}

// firstErr returns the first error recorded by any of the builders.
func firstErr(bs ...*builder) error {
	for _, b := range bs {
		if b.err != nil {
			return b.err
		}
	}
	return nil
}
