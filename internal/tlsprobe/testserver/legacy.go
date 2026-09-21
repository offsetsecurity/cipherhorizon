package testserver

import "encoding/binary"

// Scripted replies for servers the standard library cannot be: SSLv3, export-grade
// and NULL suites. The reply answers a ClientHello the way the described server
// would; it cannot complete a handshake.

// offeredHello extracts client_version and the cipher-suite list from a TLS
// ClientHello record.
func offeredHello(b []byte) (version uint16, suites []uint16, ok bool) {
	if len(b) < 5+4+2+32+1 || b[0] != 22 || b[5] != 1 {
		return 0, nil, false
	}
	body := b[9:]
	version = uint16(body[0])<<8 | uint16(body[1])
	p := 34
	p += 1 + int(body[p]) // session id
	if p+2 > len(body) {
		return 0, nil, false
	}
	n := int(body[p])<<8 | int(body[p+1])
	p += 2
	if p+n > len(body) {
		return 0, nil, false
	}
	for i := 0; i < n; i += 2 {
		suites = append(suites, uint16(body[p+i])<<8|uint16(body[p+i+1]))
	}
	return version, suites, true
}

// ServerHello is a ServerHello plus ServerHelloDone record choosing suite.
func ServerHello(version, suite uint16) []byte {
	sh := binary.BigEndian.AppendUint16(nil, version)
	sh = append(sh, make([]byte, 32)...) // random
	sh = append(sh, 0)                   // empty session id
	sh = binary.BigEndian.AppendUint16(sh, suite)
	sh = append(sh, 0) // compression: null
	msg := []byte{2, 0}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(sh))) //nolint:gosec // a ServerHello of a few dozen bytes
	msg = append(msg, sh...)
	msg = append(msg, 14, 0, 0, 0) // ServerHelloDone
	rec := binary.BigEndian.AppendUint16([]byte{22}, version)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(msg))) //nolint:gosec // as above
	return append(rec, msg...)
}

// Alert is a fatal TLS alert record.
func Alert(desc byte) []byte { return []byte{21, 3, 3, 0, 2, 2, desc} }

// Legacy speaks exactly one protocol version. order is the server's
// preference; clientPref makes it pick the first acceptable suite in the CLIENT's
// order instead.
func Legacy(version uint16, order []uint16, clientPref bool) func([]byte) []byte {
	return func(in []byte) []byte {
		if len(in) > 0 && in[0]&0x80 != 0 {
			return nil // an SSLv2 hello: this server does not speak it
		}
		cv, offered, ok := offeredHello(in)
		if !ok {
			return nil
		}
		if cv < version {
			return Alert(70) // protocol_version
		}
		accept := func(id uint16) bool {
			for _, o := range order {
				if o == id {
					return true
				}
			}
			return false
		}
		if clientPref {
			for _, id := range offered {
				if accept(id) {
					return ServerHello(version, id)
				}
			}
		} else {
			for _, id := range order {
				for _, o := range offered {
					if o == id {
						return ServerHello(version, id)
					}
				}
			}
		}
		return Alert(40) // handshake_failure
	}
}
