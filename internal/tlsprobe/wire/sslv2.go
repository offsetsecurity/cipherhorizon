package wire

import (
	"errors"
	"fmt"
	"io"
)

// SSLv2 cipher kinds. These are NOT in the IANA registry (SSLv2 predates it);
// the source is the SSL 2.0 protocol specification, C. Hickman, "The SSL
// Protocol", Netscape, 1995 (draft-hickman-netscape-ssl-00), appendix C.
var sslv2Names = map[uint32]string{
	0x010080: "SSL_CK_RC4_128_WITH_MD5",
	0x020080: "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
	0x030080: "SSL_CK_RC2_128_CBC_WITH_MD5",
	0x040080: "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
	0x050080: "SSL_CK_IDEA_128_CBC_WITH_MD5",
	0x060040: "SSL_CK_DES_64_CBC_WITH_MD5",
	0x0700C0: "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
}

// SSLv2CipherKinds returns the seven cipher kinds the SSLv2 specification
// defines, in specification order.
func SSLv2CipherKinds() []uint32 {
	return []uint32{0x010080, 0x020080, 0x030080, 0x040080, 0x050080, 0x060040, 0x0700C0}
}

// SSLv2CipherName names an SSLv2 cipher kind.
func SSLv2CipherName(kind uint32) string {
	if n, ok := sslv2Names[kind]; ok {
		return n
	}
	return fmt.Sprintf("SSL_CK_UNKNOWN_0x%06X", kind)
}

// MarshalSSLv2ClientHello builds an SSLv2 CLIENT-HELLO offering the given cipher
// kinds. SSLv2 uses its own record framing, not the TLS record layer.
func MarshalSSLv2ClientHello(rnd io.Reader, kinds []uint32) ([]byte, error) {
	if len(kinds) == 0 || len(kinds) > 1000 {
		return nil, fmt.Errorf("wire: %d SSLv2 cipher kinds", len(kinds))
	}
	var challenge [16]byte
	if _, err := io.ReadFull(rnd, challenge[:]); err != nil {
		return nil, err
	}
	var msg builder
	msg.u8(1) // CLIENT-HELLO
	msg.u16(uint16(VersionSSL20))
	msg.lenU16(3 * len(kinds))
	msg.u16(0) // session id length
	msg.lenU16(len(challenge))
	for _, k := range kinds {
		msg.u24(int(k))
	}
	msg.bytes(challenge[:])

	if msg.err != nil || len(msg.b) > 0x7FFF {
		return nil, errors.New("wire: SSLv2 hello too long")
	}
	// Two-byte record header; the high bit says "no padding".
	var hdr builder
	hdr.lenU16(len(msg.b))
	hdr.b[0] |= 0x80
	return append(hdr.b, msg.b...), nil
}

// SSLv2ServerHello is a parsed SSLv2 SERVER-HELLO.
type SSLv2ServerHello struct {
	Version     uint16
	CipherKinds []uint32
	CertLength  int
}

// SSLv2Error is an SSLv2 ERROR message.
type SSLv2Error struct{ Code uint16 }

func (e *SSLv2Error) Error() string { return fmt.Sprintf("SSLv2 error 0x%04X", e.Code) }

// ErrNotSSLv2 means the peer answered a SSLv2 hello with something that is not
// SSLv2, typically a TLS alert or a closed connection: the normal reply of a
// server with SSLv2 disabled.
var ErrNotSSLv2 = errors.New("wire: peer did not answer in SSLv2")

// ReadSSLv2ServerHello reads the reply to an SSLv2 CLIENT-HELLO. It returns
// ErrNotSSLv2 (wrapping the observed alert, if any) for a non-SSLv2 reply and an
// *SSLv2Error for an SSLv2 ERROR message.
func ReadSSLv2ServerHello(r io.Reader) (*SSLv2ServerHello, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: connection closed without a response", ErrNotSSLv2)
		}
		return nil, err
	}
	if first[0]&0x80 == 0 {
		// Not an SSLv2 record header: look for a TLS alert, which is what a TLS
		// server that refuses SSLv2 sends.
		var rest [4]byte
		_, _ = io.ReadFull(r, rest[:])
		if first[0] == RecordAlert {
			return nil, fmt.Errorf("%w: TLS alert record", ErrNotSSLv2)
		}
		return nil, fmt.Errorf("%w: first byte 0x%02X", ErrNotSSLv2, first[0])
	}

	var second [1]byte
	if _, err := io.ReadFull(r, second[:]); err != nil {
		return nil, noEOF(err)
	}
	n := int(first[0]&0x7F)<<8 | int(second[0])
	if n < 3 || n > 0x7FFF {
		return nil, errSSLv2
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, noEOF(err)
	}

	br := &reader{b: body}
	switch mt := br.u8(); mt {
	case 0: // ERROR
		code := br.u16()
		if br.err != nil {
			return nil, errSSLv2
		}
		return nil, &SSLv2Error{Code: code}
	case 4: // SERVER-HELLO
		br.u8() // session-id-hit
		br.u8() // certificate-type
		sh := &SSLv2ServerHello{Version: br.u16()}
		certLen := int(br.u16())
		specLen := int(br.u16())
		connLen := int(br.u16())
		br.take(certLen)
		specs := &reader{b: br.take(specLen)}
		br.take(connLen)
		if br.err != nil || specLen%3 != 0 {
			return nil, errSSLv2
		}
		sh.CertLength = certLen
		for !specs.empty() {
			sh.CipherKinds = append(sh.CipherKinds, specs.u24u32())
		}
		return sh, nil
	default:
		return nil, errSSLv2
	}
}
