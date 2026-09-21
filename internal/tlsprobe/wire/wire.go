// Package wire implements just enough of the TLS/SSL wire protocol to probe a
// server: it builds ClientHello messages the standard library will not send
// (SSLv3, arbitrary suite and group lists, empty key shares) and parses what a
// server answers, up to the point where the rest is encrypted.
//
// It never completes a handshake and holds no key material. It is written
// defensively, because everything it parses comes from an untrusted peer: every
// read is bounds-checked, every length is capped, and the parsers are fuzzed.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is a protocol version as it appears on the wire.
type Version uint16

// The versions.
const (
	VersionSSL20 Version = 0x0002 // SSLv2; carried in its own record format
	VersionSSL30 Version = 0x0300
	VersionTLS10 Version = 0x0301
	VersionTLS11 Version = 0x0302
	VersionTLS12 Version = 0x0303
	VersionTLS13 Version = 0x0304
)

func (v Version) String() string {
	switch v {
	case VersionSSL20:
		return "SSLv2"
	case VersionSSL30:
		return "SSLv3"
	case VersionTLS10:
		return "TLSv1.0"
	case VersionTLS11:
		return "TLSv1.1"
	case VersionTLS12:
		return "TLSv1.2"
	case VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04X", uint16(v))
}

// Record and handshake message types.
const (
	RecordChangeCipherSpec uint8 = 20
	RecordAlert            uint8 = 21
	RecordHandshake        uint8 = 22
	RecordApplicationData  uint8 = 23

	HandshakeClientHello       uint8 = 1
	HandshakeServerHello       uint8 = 2
	HandshakeCertificate       uint8 = 11
	HandshakeServerKeyExchange uint8 = 12
	HandshakeCertRequest       uint8 = 13
	HandshakeServerHelloDone   uint8 = 14
	HandshakeCertStatus        uint8 = 22
)

// Extension types (IANA TLS ExtensionType registry).
const (
	ExtServerName           uint16 = 0
	ExtStatusRequest        uint16 = 5
	ExtSupportedGroups      uint16 = 10
	ExtECPointFormats       uint16 = 11
	ExtSignatureAlgorithms  uint16 = 13
	ExtALPN                 uint16 = 16
	ExtEncryptThenMAC       uint16 = 22
	ExtExtendedMasterSecret uint16 = 23
	ExtSessionTicket        uint16 = 35
	ExtSupportedVersions    uint16 = 43
	ExtPSKKeyExchangeModes  uint16 = 45
	ExtKeyShare             uint16 = 51
	ExtRenegotiationInfo    uint16 = 0xFF01
)

// Limits on what is accepted from a peer.
const (
	maxRecordPayload  = 16384 + 2048 // RFC 8446 s5.2 plus slack for old expansion
	maxHandshakeMsg   = 1 << 20      // certificate chains are the only large messages
	maxFlightBytes    = 4 << 20      // total bytes read while waiting for a server flight
	maxFlightMessages = 64
)

// ErrShort is returned when a message is shorter than its own length fields say.
var ErrShort = errors.New("wire: truncated message")

// Alert is a TLS alert.
type Alert struct {
	Level       uint8 // 1 warning, 2 fatal
	Description uint8
}

func (a Alert) String() string { return AlertName(a.Description) }

var alertNames = map[uint8]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed_RESERVED",
	22: "record_overflow", 30: "decompression_failure_RESERVED", 40: "handshake_failure",
	41: "no_certificate_RESERVED", 42: "bad_certificate", 43: "unsupported_certificate",
	44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
	47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error",
	51: "decrypt_error", 60: "export_restriction_RESERVED", 70: "protocol_version",
	71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
	90: "user_canceled", 100: "no_renegotiation_RESERVED", 109: "missing_extension",
	110: "unsupported_extension", 111: "certificate_unobtainable_RESERVED", 112: "unrecognized_name",
	113: "bad_certificate_status_response", 114: "bad_certificate_hash_value_RESERVED",
	115: "unknown_psk_identity", 116: "certificate_required", 120: "no_application_protocol",
	121: "ech_required",
}

// AlertName returns the IANA name of an alert description.
func AlertName(d uint8) string {
	if n, ok := alertNames[d]; ok {
		return n
	}
	return fmt.Sprintf("alert(%d)", d)
}

// ---- bounds-checked reader --------------------------------------------------------

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = ErrShort
		return nil
	}
	out := r.b[:n:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return uint16(b[0])<<8 | uint16(b[1])
	}
	return 0
}

func (r *reader) u24() int {
	if b := r.take(3); b != nil {
		return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	}
	return 0
}

func (r *reader) u24u32() uint32 {
	if b := r.take(3); b != nil {
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	}
	return 0
}

func (r *reader) vec8() []byte  { return r.take(int(r.u8())) }
func (r *reader) vec16() []byte { return r.take(int(r.u16())) }
func (r *reader) vec24() []byte { return r.take(r.u24()) }
func (r *reader) empty() bool   { return len(r.b) == 0 }

// ---- builder ---------------------------------------------------------------------

// builder accumulates wire bytes. A field too large for its length prefix sets err
// instead of being silently truncated; callers check err once at the end.
type builder struct {
	b   []byte
	err error
}

// errTooLong reports a field that does not fit its length prefix.
var errTooLong = errors.New("wire: field too long for its length prefix")

// The three narrowing conversions below are the only ones in this package. Each is
// range-checked first, so oversize input becomes an error rather than a wrong length.

func (b *builder) fits(n, max int) bool {
	if n < 0 || n > max {
		if b.err == nil {
			b.err = errTooLong
		}
		return false
	}
	return true
}

func (b *builder) u8(v uint8)   { b.b = append(b.b, v) }
func (b *builder) u16(v uint16) { b.b = binary.BigEndian.AppendUint16(b.b, v) }

// u24 appends the low 24 bits of v, which must be in range.
func (b *builder) u24(v int) {
	if !b.fits(v, 0xFFFFFF) {
		return
	}
	tmp := binary.BigEndian.AppendUint32(nil, uint32(v)) //nolint:gosec // range-checked by fits
	b.b = append(b.b, tmp[1:]...)
}

// lenU8 and lenU16 append a length as a one- or two-byte prefix.
func (b *builder) lenU8(n int) {
	if b.fits(n, 0xFF) {
		b.b = append(b.b, uint8(n)) //nolint:gosec // range-checked by fits
	}
}

func (b *builder) lenU16(n int) {
	if b.fits(n, 0xFFFF) {
		b.b = binary.BigEndian.AppendUint16(b.b, uint16(n)) //nolint:gosec // range-checked by fits
	}
}

func (b *builder) bytes(p []byte) { b.b = append(b.b, p...) }
func (b *builder) vec8(p []byte)  { b.lenU8(len(p)); b.bytes(p) }
func (b *builder) vec16(p []byte) { b.lenU16(len(p)); b.bytes(p) }
func (b *builder) vec24(p []byte) { b.u24(len(p)); b.bytes(p) }
