package wire

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// helloRetryRequestRandom is the fixed ServerHello.random that marks a
// HelloRetryRequest: SHA-256("HelloRetryRequest"), RFC 8446 section 4.1.3.
var helloRetryRequestRandom = sha256.Sum256([]byte("HelloRetryRequest"))

// ServerHello is a parsed ServerHello or, when HelloRetryRequest is set, a
// HelloRetryRequest (which shares the wire format).
type ServerHello struct {
	Version     Version // the legacy_version field
	Random      [32]byte
	SessionID   []byte
	Suite       uint16
	Compression uint8
	Extensions  []Extension

	HelloRetryRequest bool
	// SelectedVersion is the negotiated version: supported_versions if the server
	// sent it (TLS 1.3), otherwise Version.
	SelectedVersion Version
	// KeyShareGroup is the group the server chose (TLS 1.3 only, HasKeyShare).
	KeyShareGroup uint16
	HasKeyShare   bool
}

// Ext returns the data of the first extension of type t.
func (s *ServerHello) Ext(t uint16) ([]byte, bool) {
	for _, e := range s.Extensions {
		if e.Type == t {
			return e.Data, true
		}
	}
	return nil, false
}

// HasExt reports whether the server sent extension t.
func (s *ServerHello) HasExt(t uint16) bool { _, ok := s.Ext(t); return ok }

// Flight is what a server sent in reply to a ClientHello, as far as it is readable.
type Flight struct {
	ServerHello *ServerHello
	// Certificates is the certificate chain, DER, leaf first. Only present for
	// TLS 1.2 and earlier: in TLS 1.3 the Certificate message is encrypted.
	Certificates [][]byte
	// ServerKeyExchange is the raw body of the message, when the server sent one.
	ServerKeyExchange []byte
	// CertificateStatus reports that the server sent a stapled OCSP response.
	CertificateStatus bool
	// CertificateRequest reports that the server asked for a client certificate.
	CertificateRequest bool
	Done               bool // ServerHelloDone seen (TLS 1.2 and earlier)
	Alert              *Alert
}

// NotTLSError means the peer's first bytes were not a TLS record, for example a
// plain HTTP server answering on a TLS port.
type NotTLSError struct{ Prefix []byte }

func (e *NotTLSError) Error() string {
	return fmt.Sprintf("wire: peer did not answer with a TLS record (first bytes %q)", e.Prefix)
}

// ErrNoResponse is returned when the peer closed the connection without sending
// anything.
var ErrNoResponse = errors.New("wire: connection closed without a response")

// ReadFlight reads the server's reply to a ClientHello. It returns as soon as the
// remainder is unreadable or absent: after a TLS 1.3 ServerHello or
// HelloRetryRequest (everything after is encrypted), after ServerHelloDone, or
// after an alert. An alert is a normal answer and is returned in Flight.Alert
// with a nil error; only I/O failures and malformed data are errors, and then
// whatever was parsed before the failure is still returned.
func ReadFlight(r io.Reader) (*Flight, error) {
	f := &Flight{}
	var (
		hs     []byte // handshake bytes not yet consumed as whole messages
		total  int
		nMsgs  int
		record = true // still expecting the first record
	)

	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:1]); err != nil {
			if record && errors.Is(err, io.EOF) {
				return f, ErrNoResponse
			}
			return f, err
		}
		if record {
			switch hdr[0] {
			case RecordAlert, RecordHandshake, RecordChangeCipherSpec:
			default:
				prefix := append([]byte{hdr[0]}, peek(r, 15)...)
				return f, &NotTLSError{Prefix: prefix}
			}
			record = false
		}
		if _, err := io.ReadFull(r, hdr[1:]); err != nil {
			return f, noEOF(err)
		}
		typ := hdr[0]
		if hdr[1] != 3 {
			return f, fmt.Errorf("wire: record with version 0x%02X%02X", hdr[1], hdr[2])
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > maxRecordPayload {
			return f, fmt.Errorf("wire: record length %d", n)
		}
		if total += 5 + n; total > maxFlightBytes {
			return f, errors.New("wire: server flight too large")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return f, noEOF(err)
		}

		switch typ {
		case RecordAlert:
			if len(payload) < 2 {
				return f, ErrShort
			}
			f.Alert = &Alert{Level: payload[0], Description: payload[1]}
			return f, nil
		case RecordChangeCipherSpec:
			continue
		case RecordHandshake:
			hs = append(hs, payload...)
		default:
			return f, fmt.Errorf("wire: unexpected record type %d", typ)
		}

		for len(hs) >= 4 {
			mt := hs[0]
			mlen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
			if mlen > maxHandshakeMsg {
				return f, fmt.Errorf("wire: handshake message of %d bytes", mlen)
			}
			if len(hs) < 4+mlen {
				break // continues in the next record
			}
			body := hs[4 : 4+mlen]
			hs = hs[4+mlen:]
			if nMsgs++; nMsgs > maxFlightMessages {
				return f, errors.New("wire: too many handshake messages")
			}

			done, err := f.handle(mt, body)
			if err != nil {
				return f, err
			}
			if done {
				return f, nil
			}
		}
	}
}

// handle folds one handshake message into the flight and reports whether the
// readable part of the flight is over.
func (f *Flight) handle(mt uint8, body []byte) (done bool, err error) {
	switch mt {
	case HandshakeServerHello:
		sh, err := parseServerHello(body)
		if err != nil {
			return true, fmt.Errorf("wire: ServerHello: %w", err)
		}
		f.ServerHello = sh
		// A TLS 1.3 ServerHello or a HelloRetryRequest is followed only by encrypted data.
		return sh.SelectedVersion == VersionTLS13 || sh.HelloRetryRequest, nil
	case HandshakeCertificate:
		certs, err := parseCertificateChain(body)
		if err != nil {
			return true, fmt.Errorf("wire: Certificate: %w", err)
		}
		f.Certificates = certs
	case HandshakeServerKeyExchange:
		f.ServerKeyExchange = append([]byte(nil), body...)
	case HandshakeCertStatus:
		f.CertificateStatus = true
	case HandshakeCertRequest:
		f.CertificateRequest = true
	case HandshakeServerHelloDone:
		f.Done = true
		return true, nil
	}
	return false, nil
}

func parseServerHello(b []byte) (*ServerHello, error) {
	r := &reader{b: b}
	sh := &ServerHello{}
	sh.Version = Version(r.u16())
	copy(sh.Random[:], r.take(32))
	sh.SessionID = r.vec8()
	sh.Suite = r.u16()
	sh.Compression = r.u8()
	if r.err != nil {
		return nil, r.err
	}
	sh.SelectedVersion = sh.Version
	sh.HelloRetryRequest = sh.Random == helloRetryRequestRandom

	if !r.empty() {
		extBlock := r.vec16()
		if r.err != nil {
			return nil, r.err
		}
		er := &reader{b: extBlock}
		for !er.empty() {
			t := er.u16()
			d := er.vec16()
			if er.err != nil {
				return nil, er.err
			}
			sh.Extensions = append(sh.Extensions, Extension{Type: t, Data: d})
		}
	}

	if d, ok := sh.Ext(ExtSupportedVersions); ok {
		if len(d) != 2 {
			return nil, errors.New("malformed supported_versions")
		}
		sh.SelectedVersion = Version(uint16(d[0])<<8 | uint16(d[1]))
	}
	if d, ok := sh.Ext(ExtKeyShare); ok {
		kr := &reader{b: d}
		sh.KeyShareGroup = kr.u16()
		if !sh.HelloRetryRequest {
			kr.vec16() // the server's key share; its length is validated, its value is not needed
		}
		if kr.err != nil || !kr.empty() {
			return nil, errors.New("malformed key_share")
		}
		sh.HasKeyShare = true
	}
	return sh, nil
}

// parseCertificateChain parses the TLS 1.2-and-earlier Certificate message body.
func parseCertificateChain(b []byte) ([][]byte, error) {
	r := &reader{b: b}
	list := &reader{b: r.vec24()}
	if r.err != nil || !r.empty() {
		return nil, ErrShort
	}
	var certs [][]byte
	for !list.empty() {
		c := list.vec24()
		if list.err != nil {
			return nil, list.err
		}
		certs = append(certs, append([]byte(nil), c...))
	}
	return certs, nil
}

// peek reads up to n more bytes for diagnostics; failures just shorten the result.
func peek(r io.Reader, n int) []byte {
	buf := make([]byte, n)
	got, _ := io.ReadFull(r, buf)
	return buf[:got]
}

// noEOF turns a clean EOF in the middle of a record into ErrUnexpectedEOF.
func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
