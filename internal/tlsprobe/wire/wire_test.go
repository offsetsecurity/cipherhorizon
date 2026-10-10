package wire_test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
)

const (
	groupX25519         = 29
	groupP256           = 23
	groupX25519MLKEM768 = 4588
)

var sigAlgs = []uint16{0x0403, 0x0503, 0x0804, 0x0805, 0x0807, 0x0401, 0x0501}

// exchange sends the hello to addr and reads the server's flight.
func exchange(t testing.TB, addr string, h *wire.ClientHello) (*wire.Flight, error) {
	t.Helper()
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return exchangeRaw(t, addr, raw)
}

func exchangeRaw(t testing.TB, addr string, raw []byte) (*wire.Flight, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close() //nolint:errcheck // test
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	return wire.ReadFlight(c)
}

func hello12(t testing.TB, suites []uint16, groups []uint16) *wire.ClientHello {
	t.Helper()
	h, err := wire.NewClientHello(rand.Reader, wire.VersionTLS12, suites,
		wire.SNI("localhost"), wire.SupportedGroups(groups), wire.ECPointFormats(),
		wire.SignatureAlgorithms(sigAlgs), wire.RenegotiationInfo(), wire.ExtendedMasterSecret())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func hello13(t testing.TB, groups []uint16) *wire.ClientHello {
	t.Helper()
	h, err := wire.NewClientHello(rand.Reader, wire.VersionTLS12,
		[]uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		wire.SNI("localhost"), wire.SupportedVersions(wire.VersionTLS13), wire.SupportedGroups(groups),
		wire.SignatureAlgorithms(sigAlgs), wire.KeyShareEmpty(), wire.PSKKeyExchangeModes())
	if err != nil {
		t.Fatal(err)
	}
	h.SessionID = bytes.Repeat([]byte{0xAB}, 32) // TLS 1.3 middlebox-compatibility mode
	return h
}

// ---- ClientHello encoding ------------------------------------------------------------

func TestClientHelloEncoding(t *testing.T) {
	h, err := wire.NewClientHello(rand.Reader, wire.VersionTLS12, []uint16{0xC02F, 0x1301},
		wire.SNI("example.org"), wire.SupportedGroups([]uint16{groupX25519, groupX25519MLKEM768}))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if raw[0] != wire.RecordHandshake || raw[1] != 3 || raw[2] != 1 {
		t.Errorf("record header % X", raw[:5])
	}
	if got := int(raw[3])<<8 | int(raw[4]); got != len(raw)-5 {
		t.Errorf("record length %d, payload %d", got, len(raw)-5)
	}
	msg := raw[5:]
	if msg[0] != wire.HandshakeClientHello {
		t.Errorf("handshake type %d", msg[0])
	}
	if got := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]); got != len(msg)-4 {
		t.Errorf("handshake length %d, body %d", got, len(msg)-4)
	}
	body := msg[4:]
	if body[0] != 3 || body[1] != 3 {
		t.Errorf("client_version % X", body[:2])
	}
	// version(2) random(32) sessionid-len(1)=0 suites-len(2)=4 suites(4) comp-len(1)=1 comp(1)
	if !bytes.Equal(body[34:35], []byte{0}) || !bytes.Equal(body[35:41], []byte{0, 4, 0xC0, 0x2F, 0x13, 0x01}) ||
		!bytes.Equal(body[41:43], []byte{1, 0}) {
		t.Errorf("body layout % X", body[34:43])
	}
	if !bytes.Contains(body, []byte("example.org")) || !bytes.Contains(body, []byte{0x11, 0xEC}) {
		t.Error("SNI or group missing from encoded hello")
	}
}

func TestClientHelloValidation(t *testing.T) {
	ok, _ := wire.NewClientHello(rand.Reader, wire.VersionTLS12, []uint16{1})
	for name, mutate := range map[string]func(*wire.ClientHello){
		"no suites":         func(h *wire.ClientHello) { h.Suites = nil },
		"long session id":   func(h *wire.ClientHello) { h.SessionID = make([]byte, 33) },
		"huge extension":    func(h *wire.ClientHello) { h.Extensions = []wire.Extension{{Type: 1, Data: make([]byte, 70000)}} },
		"oversized message": func(h *wire.ClientHello) { h.Suites = make([]uint16, 9000) },
	} {
		h := *ok
		mutate(&h)
		if _, err := h.Marshal(); err == nil {
			t.Errorf("%s: Marshal accepted it", name)
		}
	}
	// SSLv3 hellos use the SSLv3 record version and may omit the extensions block.
	h, _ := wire.NewClientHello(rand.Reader, wire.VersionSSL30, []uint16{0x000A})
	h.NoExtensions = true
	raw, err := h.Marshal()
	if err != nil || raw[1] != 3 || raw[2] != 0 || len(raw) != 5+4+2+32+1+2+2+2 {
		t.Errorf("SSLv3 hello: len=%d err=%v % X", len(raw), err, raw[:6])
	}
}

// A length that does not fit its prefix must be an error, never a silently
// truncated (and therefore wrong) length on the wire.
func TestOversizedFieldsAreErrorsNotTruncation(t *testing.T) {
	huge := make([]uint16, 40000) // 80000 bytes: does not fit a 16-bit length
	for name, ext := range map[string]wire.Extension{
		"supported_groups":     wire.SupportedGroups(huge),
		"signature_algorithms": wire.SignatureAlgorithms(huge),
		"supported_versions":   wire.SupportedVersions(make([]wire.Version, 200)...), // 400 bytes: no 8-bit length
		"sni":                  wire.SNI(strings.Repeat("a", 70000)),
		"alpn":                 wire.ALPN(strings.Repeat("h", 300)),
	} {
		h, err := wire.NewClientHello(rand.Reader, wire.VersionTLS12, []uint16{1}, ext)
		if err != nil {
			t.Fatal(err)
		}
		if raw, err := h.Marshal(); err == nil {
			t.Errorf("%s: Marshal accepted an oversized field (%d bytes)", name, len(raw))
		}
	}
	// Just under the limits must still work.
	h, _ := wire.NewClientHello(rand.Reader, wire.VersionTLS12, []uint16{1},
		wire.SupportedGroups(make([]uint16, 3000)), wire.SupportedVersions(wire.VersionTLS13, wire.VersionTLS12))
	if _, err := h.Marshal(); err != nil {
		t.Errorf("in-range hello rejected: %v", err)
	}
}

// ---- against real servers (crypto/tls is the oracle) -----------------------------------

func TestReadFlightTLS12(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Cert: testserver.CertRSA})
	f, err := exchange(t, srv.Addr, hello12(t,
		[]uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384},
		[]uint16{groupX25519, groupP256}))
	if err != nil {
		t.Fatal(err)
	}
	sh := f.ServerHello
	if sh == nil || sh.Version != wire.VersionTLS12 || sh.SelectedVersion != wire.VersionTLS12 || sh.HelloRetryRequest {
		t.Fatalf("ServerHello = %+v", sh)
	}
	if sh.Suite != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 && sh.Suite != tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 {
		t.Errorf("server chose unoffered suite 0x%04X", sh.Suite)
	}
	if !f.Done || f.Alert != nil {
		t.Errorf("done=%v alert=%v", f.Done, f.Alert)
	}
	if !sh.HasExt(wire.ExtRenegotiationInfo) || !sh.HasExt(wire.ExtExtendedMasterSecret) {
		t.Error("server did not echo renegotiation_info / extended_master_secret")
	}

	if len(f.Certificates) != 1 {
		t.Fatalf("got %d certificates", len(f.Certificates))
	}
	leaf, err := x509.ParseCertificate(f.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}
	_, rsaCert := testserver.Certificates(t)
	if !leaf.Equal(rsaCert.Leaf) {
		t.Error("parsed certificate is not the one the server presents")
	}

	ke, err := wire.ParseServerKeyExchange("ECDHE", false, f.ServerKeyExchange)
	if err != nil {
		t.Fatal(err)
	}
	if ke.CurveID != groupX25519 && ke.CurveID != groupP256 {
		t.Errorf("ECDHE curve %d was not offered", ke.CurveID)
	}
}

func TestReadFlightOldProtocolVersions(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
		Suites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, Cert: testserver.CertRSA,
	})
	suites := []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}

	// Offering TLS 1.0 to a TLS 1.0 server: negotiated.
	h := hello12(t, suites, []uint16{groupP256})
	h.LegacyVersion = wire.VersionTLS10
	f, err := exchange(t, srv.Addr, h)
	if err != nil || f.ServerHello == nil || f.ServerHello.Version != wire.VersionTLS10 {
		t.Fatalf("TLS1.0 offer: err=%v flight=%+v", err, f)
	}

	// Offering TLS 1.2 to a TLS 1.0-only server: the server answers with its own
	// (lower) version, which is how "TLS 1.2 unsupported" is detected.
	f, err = exchange(t, srv.Addr, hello12(t, suites, []uint16{groupP256}))
	if err != nil || f.ServerHello == nil || f.ServerHello.Version != wire.VersionTLS10 {
		t.Fatalf("TLS1.2 offer: err=%v flight=%+v", err, f)
	}

	// A hello no server suite matches is refused with an alert, not an error.
	f, err = exchange(t, srv.Addr, hello12(t, []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}, []uint16{groupP256}))
	if err != nil || f.Alert == nil || f.Alert.Description != 40 || f.ServerHello != nil {
		t.Fatalf("no shared suite: err=%v flight=%+v alert=%v", err, f, f.Alert)
	}
}

func TestReadFlightTLS13HelloRetryRevealsGroup(t *testing.T) {
	// Go 1.24+ servers offer the X25519MLKEM768 hybrid by default.
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS13, Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	})

	for _, tc := range []struct {
		name    string
		offered []uint16
		want    uint16
	}{
		{"hybrid only", []uint16{groupX25519MLKEM768}, groupX25519MLKEM768},
		{"classical only", []uint16{groupX25519}, groupX25519},
		{"both: server preference wins", []uint16{groupX25519, groupX25519MLKEM768}, groupX25519MLKEM768},
	} {
		f, err := exchange(t, srv.Addr, hello13(t, tc.offered))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		sh := f.ServerHello
		if sh == nil || !sh.HelloRetryRequest || sh.SelectedVersion != wire.VersionTLS13 || !sh.HasKeyShare {
			t.Fatalf("%s: expected a HelloRetryRequest, got %+v", tc.name, sh)
		}
		if sh.KeyShareGroup != tc.want {
			t.Errorf("%s: HRR names group %d, want %d", tc.name, sh.KeyShareGroup, tc.want)
		}
		switch sh.Suite {
		case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256:
		default:
			t.Errorf("%s: HRR suite 0x%04X", tc.name, sh.Suite)
		}
	}

	// A group the server does not have is refused with an alert.
	f, err := exchange(t, srv.Addr, hello13(t, []uint16{groupP256}))
	if err != nil || f.Alert == nil || f.ServerHello != nil {
		t.Fatalf("unsupported group: err=%v flight=%+v", err, f)
	}
}

func TestTLS13ServerRefusesAPre13Offer(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{MinVersion: tls.VersionTLS13})
	f, err := exchange(t, srv.Addr, hello12(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []uint16{groupX25519}))
	if err != nil || f.Alert == nil || f.Alert.Description != 70 { // protocol_version
		t.Fatalf("err=%v alert=%+v", err, f.Alert)
	}
}

// ---- hostile and unusual servers ---------------------------------------------------------

func TestPeersThatAreNotTLS(t *testing.T) {
	h := hello12(t, []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}, []uint16{groupX25519})

	http := testserver.StartScript(t, func([]byte) []byte { return []byte("HTTP/1.1 400 Bad Request\r\n\r\n") })
	_, err := exchange(t, http.Addr, h)
	var notTLS *wire.NotTLSError
	if !errors.As(err, &notTLS) || !bytes.HasPrefix(notTLS.Prefix, []byte("HTTP/1.1")) {
		t.Errorf("HTTP server: err=%v", err)
	}

	silent := testserver.StartScript(t, func([]byte) []byte { return nil })
	if _, err := exchange(t, silent.Addr, h); !errors.Is(err, wire.ErrNoResponse) {
		t.Errorf("closing server: err=%v, want ErrNoResponse", err)
	}
}

func TestMalformedFlights(t *testing.T) {
	rec := func(typ byte, payload []byte) []byte {
		return append([]byte{typ, 3, 3, byte(len(payload) >> 8), byte(len(payload))}, payload...)
	}
	hsMsg := func(typ byte, body []byte) []byte {
		return append([]byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	cases := map[string][]byte{
		"empty":                    nil,
		"header only":              {22, 3, 3},
		"zero-length record":       {22, 3, 3, 0, 0},
		"record longer than data":  {22, 3, 3, 0x40, 0, 1, 2, 3},
		"oversized record":         {22, 3, 3, 0xFF, 0xFF},
		"bad record version":       {22, 9, 9, 0, 1, 0},
		"truncated ServerHello":    rec(22, hsMsg(2, []byte{3, 3, 1, 2})),
		"one-byte alert":           rec(21, []byte{2}),
		"application data":         rec(23, []byte{1, 2, 3}),
		"huge handshake length":    rec(22, []byte{2, 0xFF, 0xFF, 0xFF, 0}),
		"truncated certificate":    rec(22, hsMsg(11, []byte{0, 0, 9, 0, 0, 5, 1})),
		"junk after ServerHello":   rec(22, append(hsMsg(2, make([]byte, 20)), 9, 9, 9)),
		"key_share without length": nil, // filled below
	}
	// A ServerHello whose key_share extension is shorter than its own length.
	sh := append([]byte{3, 3}, make([]byte, 32)...)             // version + random
	sh = append(sh, 0, 0x13, 0x01, 0, 0, 6, 0, 51, 0, 2, 0, 29) // sid=0, suite, comp, exts(len 6): key_share len 2 = group only, but not HRR
	cases["key_share without length"] = rec(22, hsMsg(2, sh))

	for name, data := range cases {
		f, err := wire.ReadFlight(bytes.NewReader(data))
		if f == nil {
			t.Errorf("%s: nil flight", name)
		}
		if err == nil && f.ServerHello == nil && f.Alert == nil {
			t.Errorf("%s: no error and no result", name)
		}
	}
}

func TestSSLv3ServerHelloIsParsed(t *testing.T) {
	// A scripted SSLv3 server: the standard library cannot be one.
	var sh []byte
	sh = append(sh, 3, 0)                // server_version SSLv3
	sh = append(sh, make([]byte, 32)...) // random
	sh = append(sh, 0)                   // session id
	sh = append(sh, 0x00, 0x0A, 0)       // TLS_RSA_WITH_3DES_EDE_CBC_SHA, no compression
	msg := append([]byte{2, 0, 0, byte(len(sh))}, sh...)
	rec := append([]byte{22, 3, 0, 0, byte(len(msg))}, msg...)
	done := []byte{22, 3, 0, 0, 4, 14, 0, 0, 0}

	f, err := wire.ReadFlight(bytes.NewReader(append(rec, done...)))
	if err != nil || f.ServerHello == nil || f.ServerHello.Version != wire.VersionSSL30 || f.ServerHello.Suite != 0x000A || !f.Done {
		t.Fatalf("err=%v flight=%+v", err, f)
	}
	if f.ServerHello.HasExt(wire.ExtRenegotiationInfo) {
		t.Error("SSLv3 hello has no extensions")
	}
}

func TestMessagesSplitAcrossRecords(t *testing.T) {
	var sh []byte
	sh = append(sh, 3, 3)
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0, 0xC0, 0x2F, 0)
	msg := append([]byte{2, 0, 0, byte(len(sh))}, sh...)
	msg = append(msg, 14, 0, 0, 0) // ServerHelloDone right behind it

	var stream []byte
	for _, chunk := range [][]byte{msg[:3], msg[3:20], msg[20:]} { // fragmented mid-header and mid-body
		stream = append(stream, 22, 3, 3, 0, byte(len(chunk)))
		stream = append(stream, chunk...)
	}
	f, err := wire.ReadFlight(bytes.NewReader(stream))
	if err != nil || f.ServerHello == nil || f.ServerHello.Suite != 0xC02F || !f.Done {
		t.Fatalf("err=%v flight=%+v", err, f)
	}
}

func TestReadFlightStopsAtLimits(t *testing.T) {
	// An endless stream of tiny records must not be read forever.
	endless := readerFunc(func(p []byte) (int, error) {
		rec := []byte{22, 3, 3, 0, 4, 9, 0, 0, 0} // an unknown (ignored) handshake type, forever
		return copy(p, rec), nil
	})
	done := make(chan error, 1)
	go func() { _, err := wire.ReadFlight(endless); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("endless stream accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFlight did not stop on an endless stream")
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// ---- ServerKeyExchange ---------------------------------------------------------------------

func TestParseServerKeyExchangeDHE(t *testing.T) {
	p := append([]byte{0xFF}, make([]byte, 255)...) // a 2048-bit prime-shaped value
	g := []byte{2}
	y := append([]byte{0x80}, make([]byte, 255)...)
	body := []byte{}
	for _, v := range [][]byte{p, g, y} {
		body = append(body, byte(len(v)>>8), byte(len(v)))
		body = append(body, v...)
	}
	body = append(body, 0x04, 0x01, 0, 0) // start of the signature: must be ignored

	ke, err := wire.ParseServerKeyExchange("DHE", false, body)
	if err != nil || ke.PrimeBits != 2048 || ke.GeneratorBits != 2 || ke.PublicBits != 2048 || len(ke.Prime) != 256 {
		t.Fatalf("ke=%+v err=%v", ke, err)
	}

	// A leading zero byte must not inflate the size (a 1024-bit prime sent as 129 bytes).
	body = []byte{0, 129, 0}
	body = append(body, bytes.Repeat([]byte{0xC0}, 128)...)
	body = append(body, 0, 1, 2, 0, 1, 5)
	ke, err = wire.ParseServerKeyExchange("DHE", false, body)
	if err != nil || ke.PrimeBits != 1024 {
		t.Fatalf("ke=%+v err=%v", ke, err)
	}
}

func TestParseServerKeyExchangeECDHEAndPSK(t *testing.T) {
	// named_curve x25519, 32-byte point.
	body := append([]byte{3, 0, 29, 32}, make([]byte, 32)...)
	ke, err := wire.ParseServerKeyExchange("ECDHE", false, body)
	if err != nil || ke.CurveID != 29 || ke.ExplicitCurve {
		t.Fatalf("ke=%+v err=%v", ke, err)
	}
	// PSK variants start with an identity hint.
	withHint := append([]byte{0, 3, 'a', 'b', 'c'}, body...)
	if ke, err = wire.ParseServerKeyExchange("ECDHE", true, withHint); err != nil || ke.CurveID != 29 {
		t.Fatalf("PSK ke=%+v err=%v", ke, err)
	}
	// Explicit curves are flagged, not decoded.
	if ke, err = wire.ParseServerKeyExchange("ECDHE", false, []byte{1, 0}); err != nil || !ke.ExplicitCurve {
		t.Fatalf("explicit: ke=%+v err=%v", ke, err)
	}
	for name, bad := range map[string][]byte{"empty": nil, "unknown curve type": {9}, "truncated": {3, 0}} {
		if _, err := wire.ParseServerKeyExchange("ECDHE", false, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := wire.ParseServerKeyExchange("DHE", false, []byte{0, 5, 1}); err == nil {
		t.Error("truncated DHE accepted")
	}
	if _, err := wire.ParseServerKeyExchange("RSA", false, body); err == nil {
		t.Error("non-ephemeral kind accepted")
	}
}

// ---- SSLv2 -------------------------------------------------------------------------------------

func TestSSLv2ClientHello(t *testing.T) {
	raw, err := wire.MarshalSSLv2ClientHello(rand.Reader, wire.SSLv2CipherKinds())
	if err != nil {
		t.Fatal(err)
	}
	if raw[0]&0x80 == 0 {
		t.Error("SSLv2 record header must have the high bit set")
	}
	if n := int(raw[0]&0x7F)<<8 | int(raw[1]); n != len(raw)-2 {
		t.Errorf("record length %d, payload %d", n, len(raw)-2)
	}
	// msg-type 1, version 0x0002, specs 7*3, session 0, challenge 16
	if !bytes.HasPrefix(raw[2:], []byte{1, 0, 2, 0, 21, 0, 0, 0, 16, 0x01, 0x00, 0x80}) || len(raw) != 2+9+21+16 {
		t.Errorf("layout % X", raw)
	}
	if _, err := wire.MarshalSSLv2ClientHello(rand.Reader, nil); err == nil {
		t.Error("empty cipher list accepted")
	}
}

func TestSSLv2ServerReplies(t *testing.T) {
	// SERVER-HELLO: hit 0, cert type 1, version 2, cert len 2, specs len 6, conn id len 0
	body := []byte{4, 0, 1, 0, 2, 0, 2, 0, 6, 0, 0, 0xAA, 0xBB, 0x01, 0x00, 0x80, 0x06, 0x00, 0x40}
	reply := append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
	sh, err := wire.ReadSSLv2ServerHello(bytes.NewReader(reply))
	if err != nil || sh.Version != 2 || len(sh.CipherKinds) != 2 || sh.CipherKinds[0] != 0x010080 || sh.CipherKinds[1] != 0x060040 {
		t.Fatalf("sh=%+v err=%v", sh, err)
	}
	if wire.SSLv2CipherName(0x060040) != "SSL_CK_DES_64_CBC_WITH_MD5" || !strings.HasPrefix(wire.SSLv2CipherName(1), "SSL_CK_UNKNOWN") {
		t.Error("cipher names")
	}

	// ERROR message: NO_CIPHER_ERROR.
	var e2 *wire.SSLv2Error
	_, err = wire.ReadSSLv2ServerHello(bytes.NewReader([]byte{0x80, 3, 0, 0, 1}))
	if !errors.As(err, &e2) || e2.Code != 1 {
		t.Errorf("err=%v", err)
	}

	// What a TLS server that refuses SSLv2 sends back: a TLS alert, or nothing.
	for name, data := range map[string][]byte{
		"tls alert": {21, 3, 1, 0, 2, 2, 40}, "closed": nil, "http": []byte("HTTP/1.1 400"),
	} {
		if _, err := wire.ReadSSLv2ServerHello(bytes.NewReader(data)); !errors.Is(err, wire.ErrNotSSLv2) {
			t.Errorf("%s: err=%v, want ErrNotSSLv2", name, err)
		}
	}
	for name, data := range map[string][]byte{
		"truncated header": {0x80}, "short length": {0x80, 1, 4}, "spec length not multiple of 3": {0x80, 12, 4, 0, 1, 0, 2, 0, 0, 0, 4, 0, 0, 1, 2, 3, 4},
		"unknown message": {0x80, 3, 9, 0, 0},
	} {
		if _, err := wire.ReadSSLv2ServerHello(bytes.NewReader(data)); err == nil || errors.Is(err, wire.ErrNotSSLv2) {
			t.Errorf("%s: err=%v, want a malformed-SSLv2 error", name, err)
		}
	}
}

// ---- names ---------------------------------------------------------------------------------------

// crypto/tls describes alerts in prose ("revoked certificate"), not by IANA
// identifier, so names cannot be compared. What can be compared is which alert
// numbers exist: every alert Go knows must be in our table.
func TestAlertNumbersCoverGoStdlib(t *testing.T) {
	known := 0
	for d := 0; d < 256; d++ {
		if strings.HasPrefix(strings.TrimPrefix(tls.AlertError(d).Error(), "tls: "), "alert(") {
			continue // Go does not know this alert
		}
		known++
		if strings.HasPrefix(wire.AlertName(uint8(d)), "alert(") {
			t.Errorf("alert %d is known to Go (%v) but missing from our table", d, tls.AlertError(d))
		}
	}
	if known < 25 {
		t.Errorf("only %d alerts known to Go", known)
	}
	if wire.AlertName(199) != "alert(199)" || (wire.Alert{Description: 40}).String() != "handshake_failure" ||
		wire.AlertName(121) != "ech_required" || wire.AlertName(112) != "unrecognized_name" {
		t.Error("AlertName")
	}
}

func TestVersionString(t *testing.T) {
	for v, want := range map[wire.Version]string{
		wire.VersionSSL20: "SSLv2", wire.VersionSSL30: "SSLv3", wire.VersionTLS10: "TLSv1.0",
		wire.VersionTLS11: "TLSv1.1", wire.VersionTLS12: "TLSv1.2", wire.VersionTLS13: "TLSv1.3", 0x7F7F: "0x7F7F",
	} {
		if v.String() != want {
			t.Errorf("%d: %q, want %q", uint16(v), v.String(), want)
		}
	}
}

// ---- fuzzing (seed corpora run as ordinary tests; `go test -fuzz` explores) --------------------------

func FuzzReadFlight(f *testing.F) {
	f.Add([]byte{22, 3, 3, 0, 4, 14, 0, 0, 0})
	f.Add([]byte{21, 3, 3, 0, 2, 2, 40})
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	f.Add([]byte{22, 3, 3, 0, 8, 2, 0, 0, 4, 3, 3, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		fl, _ := wire.ReadFlight(io.LimitReader(bytes.NewReader(data), 1<<20))
		if fl == nil {
			t.Fatal("nil flight")
		}
	})
}

func FuzzParseServerKeyExchange(f *testing.F) {
	f.Add("ECDHE", false, []byte{3, 0, 29, 32})
	f.Add("DHE", false, []byte{0, 1, 0xFF, 0, 1, 2, 0, 1, 5})
	f.Add("ECDHE", true, []byte{0, 0, 3, 0, 23, 0})
	f.Fuzz(func(t *testing.T, kind string, psk bool, body []byte) {
		_, _ = wire.ParseServerKeyExchange(kind, psk, body)
	})
}

func FuzzReadSSLv2ServerHello(f *testing.F) {
	f.Add([]byte{0x80, 3, 0, 0, 1})
	f.Add([]byte{21, 3, 1, 0, 2, 2, 40})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = wire.ReadSSLv2ServerHello(bytes.NewReader(data))
	})
}
