package certfiles

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
)

// pemScan is what one pass over a file's text found.
type pemScan struct {
	certs     [][]byte // DER of each CERTIFICATE block, at most maxCertsPerFile
	keyBlocks int      // blocks whose label names a private key: counted, never decoded
	other     int      // any other block: counted, never decoded
	malformed int      // a block that never ended, or a certificate body that is not base64
	truncated bool     // more certificates than maxCertsPerFile
}

const (
	maxCertsPerFile = 4000
	maxCertDER      = 64 << 10
)

var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
	pemDash  = []byte("-----")
)

// scanPEM finds the certificates in text. It is deliberately not encoding/pem: pem.Decode
// base64-decodes every block it meets, private keys included. This scanner reads a
// block's label first and decodes the body only of a CERTIFICATE. A private key's bytes
// are never decoded, copied or kept; the block is skipped and counted (ADR-0005,
// SECARCH-001 SR-06). The one thing that can be said about a key block is that it exists.
func scanPEM(data []byte) pemScan {
	var res pemScan
	for len(data) > 0 {
		i := bytes.Index(data, pemBegin)
		if i < 0 {
			return res
		}
		data = data[i+len(pemBegin):]
		eol := bytes.IndexByte(data, '\n')
		if eol < 0 {
			res.malformed++
			return res
		}
		label, ok := bytes.CutSuffix(bytes.TrimRight(data[:eol], "\r \t"), pemDash)
		if !ok || len(label) == 0 || len(label) > 64 {
			res.malformed++
			data = data[eol+1:]
			continue
		}
		body := data[eol+1:]
		end := bytes.Index(body, append(append([]byte{}, pemEnd...), label...))
		if end < 0 {
			res.malformed++
			return res
		}
		rest := body[end:]
		body = body[:end]
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			data = rest[nl+1:]
		} else {
			data = nil
		}

		switch string(label) {
		case "CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE":
			if len(res.certs) >= maxCertsPerFile {
				res.truncated = true
				continue
			}
			if der, ok := decodeBody(body); ok {
				res.certs = append(res.certs, der)
			} else {
				res.malformed++
			}
		default:
			if bytes.Contains(label, []byte("PRIVATE KEY")) {
				res.keyBlocks++
			} else {
				res.other++
			}
		}
	}
	return res
}

// decodeBody decodes a certificate block's base64 body, skipping RFC 1421 style header
// lines ("Key: value") and whitespace. It returns the first ASN.1 element, so an
// OpenSSL "TRUSTED CERTIFICATE" (a certificate followed by trust settings) yields the
// certificate alone.
func decodeBody(body []byte) ([]byte, bool) {
	var b64 []byte
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.IndexByte(line, ':') >= 0 {
			continue
		}
		b64 = append(b64, line...)
		if len(b64) > base64.StdEncoding.EncodedLen(maxCertDER*2) {
			return nil, false
		}
	}
	der := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(der, b64)
	if err != nil || n == 0 || n > maxCertDER*2 {
		return nil, false
	}
	return firstElement(der[:n])
}

// firstElement returns the first DER element of b, which must be a SEQUENCE and at most
// maxCertDER long.
func firstElement(b []byte) ([]byte, bool) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil || raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound || len(raw.FullBytes) > maxCertDER {
		return nil, false
	}
	return raw.FullBytes, true
}

// PEMCertificates is the certificate-only PEM reader for callers outside this sensor
// (the private trust-anchor upload, the server-wide CA bundle): the same rules, so a
// private key in an upload is counted and refused, never decoded.
type PEMCertificates struct {
	Certs     [][]byte
	KeyBlocks int
	Other     int
	Malformed int
	Truncated bool
}

// ReadPEMCertificates scans text for certificate blocks.
func ReadPEMCertificates(data []byte) PEMCertificates {
	r := scanPEM(data)
	return PEMCertificates{Certs: r.certs, KeyBlocks: r.keyBlocks, Other: r.other, Malformed: r.malformed, Truncated: r.truncated}
}
