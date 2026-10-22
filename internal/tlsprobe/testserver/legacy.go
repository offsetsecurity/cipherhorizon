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

// offeredExtensions lists the extension types a TLS ClientHello record carries.
func offeredExtensions(b []byte) map[uint16]bool {
	out := map[uint16]bool{}
	if len(b) < 5+4+2+32+1 || b[0] != 22 || b[5] != 1 {
		return out
	}
	body := b[9:]
	p := 34
	p += 1 + int(body[p]) // session id
	if p+2 > len(body) {
		return out
	}
	p += 2 + (int(body[p])<<8 | int(body[p+1])) // cipher suites
	if p+1 > len(body) {
		return out
	}
	p += 1 + int(body[p]) // compression methods
	if p+2 > len(body) {
		return out
	}
	end := p + 2 + (int(body[p])<<8 | int(body[p+1]))
	for p += 2; p+4 <= end && p+4 <= len(body); {
		t := uint16(body[p])<<8 | uint16(body[p+1])
		n := int(body[p+2])<<8 | int(body[p+3])
		out[t] = true
		p += 4 + n
	}
	return out
}

// ServerHelloWithExtensions is ServerHello with empty-bodied extensions of the given types (an
// echo, the way a server confirms extended_master_secret or heartbeat; heartbeat gets its mode).
func ServerHelloWithExtensions(version, suite uint16, types []uint16) []byte {
	sh := binary.BigEndian.AppendUint16(nil, version)
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0)
	sh = binary.BigEndian.AppendUint16(sh, suite)
	sh = append(sh, 0)
	var ext []byte
	for _, t := range types {
		ext = binary.BigEndian.AppendUint16(ext, t)
		if t == 15 {
			ext = append(ext, 0, 1, 1) // heartbeat: peer_allowed_to_send
			continue
		}
		ext = append(ext, 0, 0)
	}
	sh = binary.BigEndian.AppendUint16(sh, uint16(len(ext))) //nolint:gosec // a few bytes
	sh = append(sh, ext...)
	msg := []byte{2, 0}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(sh))) //nolint:gosec // a ServerHello of a few dozen bytes
	msg = append(msg, sh...)
	msg = append(msg, 14, 0, 0, 0)
	rec := binary.BigEndian.AppendUint16([]byte{22}, version)
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(msg))) //nolint:gosec // as above
	return append(rec, msg...)
}

// LegacyEcho is Legacy that also echoes, in its ServerHello, each extension in echo the client
// offered.
func LegacyEcho(version uint16, order []uint16, echo []uint16) func([]byte) []byte {
	base := Legacy(version, order, false)
	return func(in []byte) []byte {
		out := base(in)
		if len(out) < 6 || out[0] != 22 {
			return out
		}
		offered := offeredExtensions(in)
		var types []uint16
		for _, t := range echo {
			if offered[t] {
				types = append(types, t)
			}
		}
		if len(types) == 0 {
			return out
		}
		suite := uint16(out[5+4+2+32+1])<<8 | uint16(out[5+4+2+32+2])
		return ServerHelloWithExtensions(version, suite, types)
	}
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

// AnswerAnyTLS13 answers every ClientHello with a TLS 1.3 ServerHello (TLS_AES_128_GCM_SHA256,
// an X25519 share), whatever it offered: a server that does not choose its certificate by the
// client's signature_algorithms. It cannot complete a handshake.
func AnswerAnyTLS13() func([]byte) []byte {
	return func(in []byte) []byte {
		if len(in) < 5+4+2+32+1 || in[0] != 22 || in[5] != 1 {
			return nil
		}
		body := in[9:]
		sidLen := int(body[34])
		if 35+sidLen > len(body) {
			return nil
		}
		sid := body[35 : 35+sidLen]
		sh := []byte{3, 3}
		random := make([]byte, 32) // never the HelloRetryRequest value
		random[0] = 1
		sh = append(sh, random...)
		sh = append(sh, byte(sidLen)) //nolint:gosec // a session id is at most 32 bytes (one length byte)
		sh = append(sh, sid...)
		sh = append(sh, 0x13, 0x01, 0)                  // TLS_AES_128_GCM_SHA256, null compression
		ext := []byte{0, 0x2b, 0, 2, 3, 4}              // supported_versions: TLS 1.3
		ext = append(ext, 0, 0x33, 0, 36, 0, 29, 0, 32) // key_share: x25519, 32 bytes
		share := make([]byte, 32)
		share[0] = 9
		ext = append(ext, share...)
		sh = binary.BigEndian.AppendUint16(sh, uint16(len(ext))) //nolint:gosec // a few dozen bytes
		sh = append(sh, ext...)
		msg := []byte{2, 0}
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(sh))) //nolint:gosec // as above
		msg = append(msg, sh...)
		rec := binary.BigEndian.AppendUint16([]byte{22}, 0x0303)
		rec = binary.BigEndian.AppendUint16(rec, uint16(len(msg))) //nolint:gosec // as above
		return append(rec, msg...)
	}
}

// LegacyWithCertificate is Legacy (server order), but its flight carries the certificate chain
// (DER, leaf first) between the ServerHello and the ServerHelloDone: a server whose only suites
// crypto/tls will not offer (3DES, RC4, NULL), so its certificate is seen only in raw flights.
func LegacyWithCertificate(version uint16, order []uint16, chain [][]byte) func([]byte) []byte {
	plain := Legacy(version, order, false)
	return func(in []byte) []byte {
		out := plain(in)
		if len(out) < 9 || out[0] != 22 {
			return out
		}
		// Rebuild the handshake messages: the ServerHello, the Certificate, the ServerHelloDone.
		msgs := out[5 : len(out)-4]
		var list []byte
		for _, der := range chain {
			list = append(list, byte(len(der)>>16), byte(len(der)>>8), byte(len(der))) //nolint:gosec // 24-bit TLS lengths of a test chain
			list = append(list, der...)
		}
		body := append([]byte{byte(len(list) >> 16), byte(len(list) >> 8), byte(len(list))}, list...)     //nolint:gosec // as above
		cert := append([]byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...) //nolint:gosec // as above
		all := append(append(append([]byte(nil), msgs...), cert...), 14, 0, 0, 0)
		rec := binary.BigEndian.AppendUint16([]byte{22}, version)
		rec = binary.BigEndian.AppendUint16(rec, uint16(len(all))) //nolint:gosec // a test chain of a few KiB
		return append(rec, all...)
	}
}
