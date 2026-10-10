package pki

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// SCT is one Signed Certificate Timestamp (RFC 6962 §3.2). Its signature is
// decoded but not verified: T1 checks presence and names the log, nothing more.
type SCT struct {
	Version    uint8
	LogID      [32]byte
	Timestamp  time.Time
	Extensions []byte
	HashAlg    uint8
	SigAlg     uint8
	Signature  []byte
}

// Bounds on SCT data, generous for anything a real certificate carries.
const (
	MaxSCTs      = 64
	maxSCTBytes  = 4 << 10
	maxListBytes = 64 << 10
)

var (
	oidEmbeddedSCTs = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidOCSPSCTs     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}
)

// ParseSCT decodes one SerializedSCT body (the form crypto/tls hands over from
// the TLS extension, without the uint16 length prefix).
func ParseSCT(b []byte) (SCT, error) {
	var s SCT
	if len(b) > maxSCTBytes {
		return s, errors.New("sct: too long")
	}
	// version(1) logID(32) timestamp(8) exts(2+n) hash(1) sig(1) sig(2+n)
	if len(b) < 1+32+8+2 {
		return s, errors.New("sct: truncated header")
	}
	s.Version = b[0]
	if s.Version != 0 {
		return s, fmt.Errorf("sct: unsupported version %d", s.Version)
	}
	copy(s.LogID[:], b[1:33])
	ms := binary.BigEndian.Uint64(b[33:41])
	if ms > 1<<62 {
		return s, errors.New("sct: timestamp out of range")
	}
	s.Timestamp = time.UnixMilli(int64(ms)).UTC()
	rest := b[41:]
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if n > len(rest) {
		return s, errors.New("sct: extensions overrun")
	}
	s.Extensions, rest = rest[:n], rest[n:]
	if len(rest) < 4 {
		return s, errors.New("sct: truncated signature")
	}
	s.HashAlg, s.SigAlg = rest[0], rest[1]
	n = int(binary.BigEndian.Uint16(rest[2:]))
	rest = rest[4:]
	if n != len(rest) {
		return s, errors.New("sct: signature length does not match")
	}
	s.Signature = rest
	return s, nil
}

// ParseSCTList decodes a SignedCertificateTimestampList (RFC 6962 §3.3): a
// uint16 total length and then uint16-length-prefixed SCTs. Every length is
// checked against what remains; at most MaxSCTs are accepted.
func ParseSCTList(b []byte) ([]SCT, error) {
	if len(b) > maxListBytes {
		return nil, errors.New("sct list: too long")
	}
	if len(b) < 2 {
		return nil, errors.New("sct list: truncated")
	}
	total := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if total != len(b) {
		return nil, errors.New("sct list: length does not match")
	}
	var out []SCT
	for len(b) > 0 {
		if len(out) == MaxSCTs {
			return nil, fmt.Errorf("sct list: more than %d entries", MaxSCTs)
		}
		if len(b) < 2 {
			return nil, errors.New("sct list: truncated entry")
		}
		n := int(binary.BigEndian.Uint16(b))
		b = b[2:]
		if n == 0 || n > len(b) {
			return nil, errors.New("sct list: entry length overrun")
		}
		s, err := ParseSCT(b[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
		b = b[n:]
	}
	return out, nil
}

// parseWrappedList decodes the X.509/OCSP extension form: an OCTET STRING
// holding the TLS-encoded list.
func parseWrappedList(ext []byte) ([]SCT, error) {
	var inner []byte
	rest, err := asn1.Unmarshal(ext, &inner)
	if err != nil {
		return nil, fmt.Errorf("sct list: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("sct list: trailing data")
	}
	return ParseSCTList(inner)
}

// EmbeddedSCTs decodes the SCT list extension of a certificate. It returns nil,
// nil when there is none.
func EmbeddedSCTs(c *x509.Certificate) ([]SCT, error) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidEmbeddedSCTs) {
			return parseWrappedList(e.Value)
		}
	}
	return nil, nil
}
