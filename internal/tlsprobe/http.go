package tlsprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
)

// httpReadBudget caps how much of an HTTP response checkHSTS reads, so a
// misbehaving server cannot use this check to exhaust memory.
const httpReadBudget = 8 << 10 // 8 KiB

// checkHSTS sends one minimal HTTP/1.1 request over an already-established TLS
// connection and reports whether the response carries a Strict-Transport-Security
// header. It sends nothing else: no body, no other header is acted on, and a
// Location header is never followed (a redirect could point off-target).
//
// The result is nil when the connection does not appear to be speaking HTTP at
// all (the reply is not a valid HTTP status line): false means "a response
// arrived and lacked the header," not "this wasn't a web server."
func checkHSTS(conn *tls.Conn, host string) (*bool, error) {
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	for buf.Len() < httpReadBudget {
		n, err := conn.Read(chunk)
		if n > 0 {
			if room := httpReadBudget - buf.Len(); n > room {
				n = room
			}
			buf.Write(chunk[:n])
		}
		if err != nil {
			break // EOF or timeout: parse whatever arrived
		}
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("HTTP/1.")) {
		return nil, nil //nolint:nilnil // "not speaking HTTP" is unknown, not an error
	}

	found := false
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	sc.Scan() // status line, already checked above
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers
		}
		name, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Strict-Transport-Security") {
			found = true
		}
	}
	return &found, nil
}

// hstsCheck opens one additional TLS connection — only ever called when
// Options.HTTPChecks is set — and asks checkHSTS whether the server sends
// Strict-Transport-Security. Any failure short of a genuine HTTP response
// leaves the result nil and records why, per the "nil means unknown, not no"
// rule documented on checkHSTS.
func (p *prober) hstsCheck(ctx context.Context) *bool {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: p.target.SNI, //nolint:gosec // reading a header, not trusting the identity
		MinVersion: tls.VersionTLS10, NextProtos: []string{"http/1.1"}}
	conn, release, err := p.connect(ctx)
	if err != nil {
		p.note("HSTS check: connecting: %v", err)
		return nil
	}
	defer release()
	tc := tls.Client(conn, cfg)
	defer tc.Close() //nolint:errcheck // probe connection
	if err := tc.HandshakeContext(ctx); err != nil {
		p.note("HSTS check: handshake: %v", err)
		return nil
	}

	host := p.target.SNI
	if host == "" {
		host = p.target.Host
	}
	found, err := checkHSTS(tc, host)
	if err != nil {
		p.note("HSTS check: %v", err)
		return nil
	}
	if found == nil {
		p.note("HSTS check: the connection did not answer with an HTTP response")
	}
	return found
}
