package tlsprobe

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"strings"
	"sync"
	"time"
)

// Resumption is what the scan learned about session resumption: for TLS 1.3 and for TLS 1.2,
// whether the server issues session tickets, how long it says they live, whether a second
// connection resumes with one, and (TLS 1.3) whether its tickets allow early data (0-RTT).
//
// The scan completes one ordinary handshake, reads the tickets the server sends, and connects a
// second time with a ticket. It never sends early data: whether the server permits it is read
// from the ticket's max_early_data_size (RFC 8446 section 4.6.1), which is the server's own
// statement, and nothing replayable is put on the wire.
type Resumption struct {
	TLS13 *ResumeResult `json:"tls13,omitempty"`
	TLS12 *ResumeResult `json:"tls12,omitempty"`
}

// ResumeResult is the outcome for one protocol version.
type ResumeResult struct {
	// Tickets is how many NewSessionTicket messages the first connection received.
	Tickets int `json:"tickets"`
	// LifetimeSeconds is the lifetime the first ticket states (ticket_lifetime in TLS 1.3, the
	// lifetime hint in TLS 1.2, where 0 means "unspecified"). nil when no ticket was read.
	LifetimeSeconds *uint32 `json:"lifetimeSeconds,omitempty"`
	// MaxEarlyData is the largest max_early_data_size among the TLS 1.3 tickets: 0 means the server
	// does not accept early data. nil when the tickets could not be read (or for TLS 1.2).
	MaxEarlyData *uint32 `json:"maxEarlyData,omitempty"`
	// Resumed is whether the second connection resumed the session. nil when it was not attempted
	// (no ticket) or failed before an answer.
	Resumed *bool `json:"resumed,omitempty"`
	// Note says, in words, why a field above is missing.
	Note string `json:"note,omitempty"`
}

var probesResumption = "per version (TLS 1.3, TLS 1.2): one full handshake that keeps the session ticket, then a second connection offering it, to see whether the server resumes; the tickets' stated lifetime and early-data allowance are read, and no early data is sent. When HTTP checks are on and no TLS 1.3 ticket has arrived, one HEAD / is sent to prompt it"

// ticketWait bounds how long the first TLS 1.3 connection waits for tickets, which arrive after
// the handshake: long enough for a slow server, short enough not to stall a scan of one that
// sends none.
const ticketWait = 1500 * time.Millisecond

// recorder keeps what the server sent, so the tickets can be read out of it afterwards.
type recorder struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

const recordLimit = 512 << 10

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if r.buf.Len() < recordLimit {
			r.buf.Write(p[:n])
		}
		r.mu.Unlock()
	}
	return n, err
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

// oneSession is a session cache that holds the latest session, whatever the key.
type oneSession struct {
	mu   sync.Mutex
	s    *tls.ClientSessionState
	puts int
}

// Get returns the held session (tls.ClientSessionCache).
func (c *oneSession) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s, c.s != nil
}

// Put keeps the session the library just received (tls.ClientSessionCache).
func (c *oneSession) Put(_ string, s *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s != nil {
		c.s = s
		c.puts++
	}
}

func (c *oneSession) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.puts
}

// resumption runs the probe for each version the server supports.
func (p *prober) resumption(ctx context.Context, tls13, tls12 bool) *Resumption {
	r := &Resumption{}
	if tls13 {
		r.TLS13 = p.resume(ctx, tls.VersionTLS13)
	}
	if tls12 && ctx.Err() == nil {
		r.TLS12 = p.resume(ctx, tls.VersionTLS12)
	}
	if r.TLS13 == nil && r.TLS12 == nil {
		return nil
	}
	return r
}

func (p *prober) resume(ctx context.Context, version uint16) *ResumeResult {
	res := &ResumeResult{}
	cache := &oneSession{}
	var keylog bytes.Buffer
	// Some servers issue TLS 1.3 tickets only once a request has arrived. Where the scan may send
	// an HTTP request (the same permission the HSTS check uses), it offers HTTP/1.1 alone so that
	// one plain request can prompt them.
	nudge := p.opts.HTTPChecks && p.target.StartTLS == ""
	alpn := []string{"h2", "http/1.1"}
	if nudge {
		alpn = []string{"http/1.1"}
	}
	cfg := func() *tls.Config {
		return &tls.Config{InsecureSkipVerify: true, ServerName: p.target.SNI, //nolint:gosec // the certificate stage judges the chain; this one only resumes
			MinVersion: version, MaxVersion: version, NextProtos: alpn, ClientSessionCache: cache}
	}

	// First connection: a full handshake, kept open just long enough to receive the tickets.
	conn, release, err := p.connect(ctx)
	if err != nil {
		res.Note = "the connection failed: " + err.Error()
		return res
	}
	rec := &recorder{Conn: conn}
	first := cfg()
	first.KeyLogWriter = &keylog
	tc := tls.Client(rec, first)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = tc.Close()
		release()
		res.Note = "the handshake failed: " + err.Error()
		return res
	}
	suite := tc.ConnectionState().CipherSuite
	if version == tls.VersionTLS13 {
		waitForTickets(tc, cache, ticketWait)
		if cache.count() == 0 && nudge {
			_ = tc.SetWriteDeadline(time.Now().Add(p.opts.Timeout))
			if _, err := tc.Write([]byte("HEAD / HTTP/1.1\r\nHost: " + p.target.serverName() + "\r\nConnection: close\r\n\r\n")); err == nil {
				waitForTickets(tc, cache, ticketWait)
			}
		}
	}
	_ = tc.Close()
	release()

	var tickets []ticket
	if version == tls.VersionTLS13 {
		tickets, err = tickets13(rec.bytes(), keylog.String(), suite)
	} else {
		tickets = tickets12(rec.bytes())
	}
	res.Tickets = len(tickets)
	if res.Tickets == 0 && cache.count() > 0 {
		// The TLS library received tickets that could not be read back out of the record stream.
		res.Tickets = cache.count()
		res.Note = "the tickets' contents could not be read"
		if err != nil {
			res.Note += ": " + err.Error()
		}
	}
	if len(tickets) > 0 {
		life := tickets[0].lifetime
		res.LifetimeSeconds = &life
		if version == tls.VersionTLS13 {
			var most uint32
			for _, t := range tickets {
				most = max(most, t.maxEarlyData)
			}
			res.MaxEarlyData = &most
		}
	}
	if cache.count() == 0 {
		if res.Note == "" {
			res.Note = "the server sent no session ticket while the scan waited"
		}
		return res
	}
	if ctx.Err() != nil {
		return res
	}

	// Second connection: the same hello, now offering the ticket.
	conn, release, err = p.connect(ctx)
	if err != nil {
		res.Note = "the second connection failed: " + err.Error()
		return res
	}
	defer release()
	tc = tls.Client(conn, cfg())
	defer tc.Close() //nolint:errcheck // probe connection
	if err := tc.HandshakeContext(ctx); err != nil {
		res.Note = "the second handshake failed: " + err.Error()
		return res
	}
	resumed := tc.ConnectionState().DidResume
	res.Resumed = &resumed
	return res
}

// waitForTickets reads from a connection whose handshake is complete until tickets have arrived
// (and the line has gone quiet) or the limit has passed. Application data the server volunteers
// (a mail banner) is read and dropped.
func waitForTickets(tc *tls.Conn, cache *oneSession, limit time.Duration) {
	start := time.Now()
	buf := make([]byte, 4096)
	for time.Since(start) < limit {
		_ = tc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		_, err := tc.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return // closed or broken: nothing more will come
		}
		if cache.count() > 0 {
			return // tickets arrived and a quiet interval followed
		}
	}
}

// ticket is what one NewSessionTicket message states.
type ticket struct {
	lifetime     uint32
	maxEarlyData uint32
}

// records walks a TLS record stream, calling fn with each record's type, header and body.
func records(stream []byte, fn func(typ byte, header, body []byte) bool) {
	for len(stream) >= 5 {
		n := int(binary.BigEndian.Uint16(stream[3:5]))
		if len(stream) < 5+n {
			return
		}
		if !fn(stream[0], stream[:5], stream[5:5+n]) {
			return
		}
		stream = stream[5+n:]
	}
}

// messages walks a handshake byte stream, calling fn with each complete message.
func messages(hs []byte, fn func(typ byte, body []byte)) {
	for len(hs) >= 4 {
		n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
		if len(hs) < 4+n {
			return
		}
		fn(hs[0], hs[4:4+n])
		hs = hs[4+n:]
	}
}

const (
	recChangeCipherSpec = 20
	recHandshake        = 22
	recApplicationData  = 23
	hsNewSessionTicket  = 4
	extEarlyData        = 42
)

// tickets12 reads the NewSessionTicket of a TLS 1.2 handshake (RFC 5077): it is sent in the clear,
// before the server's ChangeCipherSpec.
func tickets12(stream []byte) []ticket {
	var hs []byte
	records(stream, func(typ byte, _, body []byte) bool {
		if typ == recChangeCipherSpec {
			return false
		}
		if typ == recHandshake {
			hs = append(hs, body...)
		}
		return true
	})
	var out []ticket
	messages(hs, func(typ byte, body []byte) {
		if typ == hsNewSessionTicket && len(body) >= 6 {
			out = append(out, ticket{lifetime: binary.BigEndian.Uint32(body[:4])})
		}
	})
	return out
}

// tickets13 reads the NewSessionTicket messages of a TLS 1.3 connection. They are encrypted under
// the server's application traffic secret, which the TLS library hands over through its key log;
// the records before them (the handshake's) fail to open under that key and are skipped.
func tickets13(stream []byte, keylog string, suite uint16) ([]ticket, error) {
	secret, err := keylogSecret(keylog, "SERVER_TRAFFIC_SECRET_0")
	if err != nil {
		return nil, err
	}
	aead, iv, err := trafficAEAD(suite, secret)
	if err != nil {
		return nil, err
	}
	var hs []byte
	var seq uint64
	nonce := make([]byte, len(iv))
	records(stream, func(typ byte, header, body []byte) bool {
		if typ != recApplicationData {
			return true
		}
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i)) //nolint:gosec // one byte of the sequence number, by design
		}
		plain, err := aead.Open(nil, nonce, body, header)
		if err != nil {
			return seq == 0 // a handshake record, before the application keys; after them, stop
		}
		seq++
		// TLSInnerPlaintext: content, the real type, then zero padding.
		i := len(plain) - 1
		for i >= 0 && plain[i] == 0 {
			i--
		}
		if i >= 0 && plain[i] == recHandshake {
			hs = append(hs, plain[:i]...)
		}
		return true
	})
	var out []ticket
	messages(hs, func(typ byte, body []byte) {
		if typ != hsNewSessionTicket {
			return
		}
		if t, ok := parseTicket13(body); ok {
			out = append(out, t)
		}
	})
	return out, nil
}

// parseTicket13 reads a TLS 1.3 NewSessionTicket (RFC 8446 section 4.6.1): lifetime, age_add,
// nonce, ticket, extensions; the early_data extension carries max_early_data_size.
func parseTicket13(b []byte) (ticket, bool) {
	if len(b) < 9 {
		return ticket{}, false
	}
	t := ticket{lifetime: binary.BigEndian.Uint32(b[:4])}
	b = b[8:]
	n := int(b[0])
	if len(b) < 1+n+2 {
		return ticket{}, false
	}
	b = b[1+n:]
	n = int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n+2 {
		return ticket{}, false
	}
	b = b[2+n:]
	n = int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return ticket{}, false
	}
	exts := b[2 : 2+n]
	for len(exts) >= 4 {
		typ, l := binary.BigEndian.Uint16(exts), int(binary.BigEndian.Uint16(exts[2:]))
		if len(exts) < 4+l {
			break
		}
		if typ == extEarlyData && l == 4 {
			t.maxEarlyData = binary.BigEndian.Uint32(exts[4:8])
		}
		exts = exts[4+l:]
	}
	return t, true
}

func keylogSecret(keylog, label string) ([]byte, error) {
	for _, line := range strings.Split(keylog, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == label {
			return hex.DecodeString(f[2])
		}
	}
	return nil, errors.New("the TLS library logged no " + label)
}

// opener is the half of an AEAD the ticket reader needs.
type opener interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// trafficAEAD derives the record protection of a TLS 1.3 traffic secret (RFC 8446 section 7.3).
func trafficAEAD(suite uint16, secret []byte) (opener, []byte, error) {
	var h func() hash.Hash
	keyLen := 16
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256:
		h = sha256.New
	case tls.TLS_AES_256_GCM_SHA384:
		h, keyLen = sha512.New384, 32
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		h, keyLen = sha256.New, 32
	default:
		return nil, nil, errors.New("an unexpected TLS 1.3 cipher suite")
	}
	key, err := expandLabel(h, secret, "key", keyLen)
	if err != nil {
		return nil, nil, err
	}
	iv, err := expandLabel(h, secret, "iv", 12)
	if err != nil {
		return nil, nil, err
	}
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		c := &chachaOpener{}
		copy(c.key[:], key)
		return c, iv, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(block)
	return a, iv, err
}

// expandLabel is HKDF-Expand-Label with an empty context (RFC 8446 section 7.1).
func expandLabel(h func() hash.Hash, secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 4+len(full))
	info = binary.BigEndian.AppendUint16(info, uint16(n)) //nolint:gosec // n is 12, 16 or 32
	info = append(info, byte(len(full)))                  //nolint:gosec // a label of a few bytes
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(h, secret, string(info), n)
}

// lines renders the result as label and value pairs for the text report.
func (r *Resumption) lines() [][2]string {
	if r == nil {
		return nil
	}
	var out [][2]string
	for _, v := range []struct {
		name string
		res  *ResumeResult
	}{{"TLS 1.3", r.TLS13}, {"TLS 1.2", r.TLS12}} {
		if v.res == nil {
			continue
		}
		var s string
		switch {
		case v.res.Tickets == 0:
			s = "no session ticket issued"
		case v.res.Resumed == nil:
			s = "ticket issued; resumption not determined"
		case *v.res.Resumed:
			s = "resumes with a ticket"
		default:
			s = "ticket issued, but a second connection did not resume"
		}
		if l := v.res.LifetimeSeconds; l != nil && *l > 0 {
			s += fmt.Sprintf("; tickets state %s", (time.Duration(*l) * time.Second).String())
		}
		if v.res.Note != "" && v.res.Tickets > 0 {
			s += " (" + v.res.Note + ")"
		}
		out = append(out, [2]string{"session resumption, " + v.name, s})
	}
	if e := r.TLS13; e != nil {
		s := "not determined"
		switch {
		case e.MaxEarlyData != nil && *e.MaxEarlyData > 0:
			s = fmt.Sprintf("ACCEPTED, up to %d bytes (read from the ticket; none was sent)", *e.MaxEarlyData)
		case e.MaxEarlyData != nil || e.Tickets == 0:
			s = "not accepted"
		}
		out = append(out, [2]string{"early data (0-RTT, RFC 8446 4.2.10)", s})
	}
	return out
}
