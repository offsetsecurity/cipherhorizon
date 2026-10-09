package tlsprobe

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// STARTTLS (PRD-007 REQ-SX): services that begin in plain text and switch to TLS on request.
// Every probe connection runs the protocol's short plain-text exchange before its ClientHello,
// so every stage of the scan works unchanged. The exchange sends only what the protocol needs
// to ask for TLS: no user name, no password, no message.

// The protocols a scan can negotiate STARTTLS for.
const (
	StartTLSNone     = ""
	StartTLSSMTP     = "smtp"
	StartTLSIMAP     = "imap"
	StartTLSPOP3     = "pop3"
	StartTLSFTP      = "ftp"
	StartTLSXMPP     = "xmpp"
	StartTLSLDAP     = "ldap"
	StartTLSPostgres = "postgres"
)

// StartTLSProtocols lists the protocols in the order the interface offers them.
var StartTLSProtocols = []string{StartTLSSMTP, StartTLSIMAP, StartTLSPOP3, StartTLSFTP, StartTLSXMPP, StartTLSLDAP, StartTLSPostgres}

// startTLSNames are the protocols' names as people write them.
var startTLSNames = map[string]string{
	StartTLSSMTP: "SMTP", StartTLSIMAP: "IMAP", StartTLSPOP3: "POP3", StartTLSFTP: "FTP",
	StartTLSXMPP: "XMPP", StartTLSLDAP: "LDAP", StartTLSPostgres: "PostgreSQL",
}

// StartTLSName is a protocol's display name ("SMTP"); empty for direct TLS.
func StartTLSName(proto string) string { return startTLSNames[proto] }

// wellKnownStartTLS maps the ports where STARTTLS is the norm (REQ-SX-2). 465, 993, 995, 636
// and 5223 are direct TLS and are not listed.
var wellKnownStartTLS = map[int]string{
	25: StartTLSSMTP, 587: StartTLSSMTP, 143: StartTLSIMAP, 110: StartTLSPOP3, 21: StartTLSFTP,
	5222: StartTLSXMPP, 389: StartTLSLDAP, 5432: StartTLSPostgres,
}

// ResolveStartTLS turns a choice ("auto", "none", "" or a protocol) and a port into the
// protocol to use: "auto" picks by well-known port, "none" and "" mean direct TLS.
func ResolveStartTLS(choice string, port int) (string, error) {
	switch c := strings.ToLower(strings.TrimSpace(choice)); c {
	case "auto":
		return wellKnownStartTLS[port], nil
	case "", "none", "tls", "direct":
		return StartTLSNone, nil
	default:
		if c == "postgresql" {
			c = StartTLSPostgres
		}
		if _, ok := startTLSNames[c]; ok {
			return c, nil
		}
		return "", fmt.Errorf("unknown STARTTLS protocol %q; use auto, none, %s", choice, strings.Join(StartTLSProtocols, ", "))
	}
}

// schemes are the URL forms a target may take, with their default ports.
var schemes = map[string]struct {
	proto string
	port  int
}{
	"https": {StartTLSNone, 443}, "tls": {StartTLSNone, 443},
	"smtp": {StartTLSSMTP, 25}, "submission": {StartTLSSMTP, 587}, "imap": {StartTLSIMAP, 143}, "pop3": {StartTLSPOP3, 110},
	"ftp": {StartTLSFTP, 21}, "xmpp": {StartTLSXMPP, 5222}, "ldap": {StartTLSLDAP, 389},
	"postgres": {StartTLSPostgres, 5432}, "postgresql": {StartTLSPostgres, 5432},
	"smtps": {StartTLSNone, 465}, "imaps": {StartTLSNone, 993}, "pop3s": {StartTLSNone, 995}, "ldaps": {StartTLSNone, 636},
}

// SplitScheme reads an optional "scheme://" prefix: it returns the rest, the protocol the scheme
// names, its default port, and whether there was a scheme. A path after the host is dropped.
func SplitScheme(s string) (rest, proto string, port int, ok bool, err error) {
	i := strings.Index(s, "://")
	if i < 0 {
		return s, "", 0, false, nil
	}
	sc, found := schemes[strings.ToLower(s[:i])]
	if !found {
		return "", "", 0, false, fmt.Errorf("unknown scheme %q", s[:i])
	}
	rest = s[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return rest, sc.proto, sc.port, true, nil
}

// StartTLSError says why a service did not switch to TLS: it refused, or it is not the protocol.
type StartTLSError struct {
	Proto string
	Reply string // what the server said, trimmed
	Why   string
}

func (e *StartTLSError) Error() string {
	msg := fmt.Sprintf("STARTTLS (%s): %s", StartTLSName(e.Proto), e.Why)
	if e.Reply != "" {
		msg += fmt.Sprintf("; the server answered %q", e.Reply)
	}
	return msg
}

// maxPlain bounds what a plain-text exchange reads, so a server that never stops talking ends the
// probe instead of filling memory.
const maxPlain = 64 << 10

// startTLS runs the protocol's plain-text exchange on conn. On success the next byte the server
// reads is the ClientHello. It reads byte by byte where the protocol is line based, so not one byte
// of the server's TLS answer is consumed by the plain-text reader.
func startTLS(conn net.Conn, proto, host string) error {
	switch proto {
	case StartTLSSMTP:
		return smtpStartTLS(conn)
	case StartTLSIMAP:
		return imapStartTLS(conn)
	case StartTLSPOP3:
		return pop3StartTLS(conn)
	case StartTLSFTP:
		return ftpStartTLS(conn)
	case StartTLSXMPP:
		return xmppStartTLS(conn, host)
	case StartTLSLDAP:
		return ldapStartTLS(conn)
	case StartTLSPostgres:
		return postgresStartTLS(conn)
	}
	return fmt.Errorf("unknown STARTTLS protocol %q", proto)
}

// readLine reads one CRLF- or LF-terminated line, without the terminator.
func readLine(r io.Reader, budget *int) (string, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return string(b), err
		}
		*budget--
		if *budget < 0 {
			return string(b), errors.New("the plain-text reply is too long")
		}
		if one[0] == '\n' {
			return strings.TrimRight(string(b), "\r"), nil
		}
		b = append(b, one[0])
	}
}

// readReply reads a numbered reply (SMTP, FTP): lines "250-..." until "250 ...". It returns the
// code and every line.
func readReply(r io.Reader, budget *int) (string, []string, error) {
	var lines []string
	for {
		l, err := readLine(r, budget)
		if err != nil {
			return "", lines, err
		}
		lines = append(lines, l)
		if len(l) < 3 {
			return "", lines, nil
		}
		if len(l) == 3 || l[3] == ' ' {
			return l[:3], lines, nil
		}
		if l[3] != '-' {
			return "", lines, nil
		}
	}
}

func clipReply(lines []string) string {
	s := strings.Join(lines, " | ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func smtpStartTLS(c net.Conn) error {
	budget := maxPlain
	code, lines, err := readReply(c, &budget)
	if err != nil || code != "220" {
		return startTLSFailure(StartTLSSMTP, lines, err, "no SMTP greeting (220)")
	}
	if _, err := io.WriteString(c, "EHLO cipherhorizon.invalid\r\n"); err != nil {
		return err
	}
	code, lines, err = readReply(c, &budget)
	if err != nil || code != "250" {
		return startTLSFailure(StartTLSSMTP, lines, err, "EHLO was refused")
	}
	offered := false
	for _, l := range lines {
		if len(l) > 4 && strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			offered = true
		}
	}
	if !offered {
		return &StartTLSError{Proto: StartTLSSMTP, Why: "the server does not offer STARTTLS", Reply: clipReply(lines)}
	}
	if _, err := io.WriteString(c, "STARTTLS\r\n"); err != nil {
		return err
	}
	code, lines, err = readReply(c, &budget)
	if err != nil || code != "220" {
		return startTLSFailure(StartTLSSMTP, lines, err, "STARTTLS was refused")
	}
	return nil
}

func imapStartTLS(c net.Conn) error {
	budget := maxPlain
	l, err := readLine(c, &budget)
	if err != nil || !strings.HasPrefix(strings.ToUpper(l), "* OK") {
		return startTLSFailure(StartTLSIMAP, []string{l}, err, "no IMAP greeting (* OK)")
	}
	if _, err := io.WriteString(c, "ch1 STARTTLS\r\n"); err != nil {
		return err
	}
	for {
		l, err := readLine(c, &budget)
		if err != nil {
			return startTLSFailure(StartTLSIMAP, []string{l}, err, "no answer to STARTTLS")
		}
		up := strings.ToUpper(l)
		switch {
		case strings.HasPrefix(up, "CH1 OK"):
			return nil
		case strings.HasPrefix(up, "CH1 "):
			return &StartTLSError{Proto: StartTLSIMAP, Why: "STARTTLS was refused", Reply: clipReply([]string{l})}
		}
		// untagged lines ("* CAPABILITY ...") come first; keep reading
	}
}

func pop3StartTLS(c net.Conn) error {
	budget := maxPlain
	l, err := readLine(c, &budget)
	if err != nil || !strings.HasPrefix(l, "+OK") {
		return startTLSFailure(StartTLSPOP3, []string{l}, err, "no POP3 greeting (+OK)")
	}
	if _, err := io.WriteString(c, "STLS\r\n"); err != nil {
		return err
	}
	l, err = readLine(c, &budget)
	if err != nil || !strings.HasPrefix(l, "+OK") {
		return startTLSFailure(StartTLSPOP3, []string{l}, err, "STLS was refused")
	}
	return nil
}

func ftpStartTLS(c net.Conn) error {
	budget := maxPlain
	code, lines, err := readReply(c, &budget)
	if err != nil || code != "220" {
		return startTLSFailure(StartTLSFTP, lines, err, "no FTP greeting (220)")
	}
	if _, err := io.WriteString(c, "AUTH TLS\r\n"); err != nil {
		return err
	}
	code, lines, err = readReply(c, &budget)
	if err != nil || code != "234" {
		return startTLSFailure(StartTLSFTP, lines, err, "AUTH TLS was refused")
	}
	return nil
}

// readUntil reads until one of the needles has been seen and returns what was read.
func readUntil(r io.Reader, budget *int, needles ...string) (string, int, error) {
	var b []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return string(b), -1, err
		}
		b = append(b, one[0])
		if *budget--; *budget < 0 {
			return string(b), -1, errors.New("the plain-text reply is too long")
		}
		for i, n := range needles {
			if bytes.HasSuffix(b, []byte(n)) {
				return string(b), i, nil
			}
		}
	}
}

func xmppStartTLS(c net.Conn, host string) error {
	budget := maxPlain
	header := "<?xml version='1.0'?><stream:stream to='" + xmlAttr(host) +
		"' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	if _, err := io.WriteString(c, header); err != nil {
		return err
	}
	got, _, err := readUntil(c, &budget, "</stream:features>", "</features>")
	if err != nil {
		return startTLSFailure(StartTLSXMPP, []string{got}, err, "no XMPP stream features")
	}
	if !strings.Contains(got, "urn:ietf:params:xml:ns:xmpp-tls") {
		return &StartTLSError{Proto: StartTLSXMPP, Why: "the server does not offer STARTTLS", Reply: clipReply([]string{got})}
	}
	if _, err := io.WriteString(c, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"); err != nil {
		return err
	}
	got, which, err := readUntil(c, &budget, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
		"<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>", "</proceed>", "<failure")
	if err != nil || which == 3 {
		return startTLSFailure(StartTLSXMPP, []string{got}, err, "STARTTLS was refused")
	}
	return nil
}

func xmlAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "'", "&apos;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(s)
}

// ldapStartTLSRequest is an LDAPv3 ExtendedRequest for StartTLS (RFC 4511 section 4.14), message 1.
var ldapStartTLSRequest = append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, []byte("1.3.6.1.4.1.1466.20037")...)

func ldapStartTLS(c net.Conn) error {
	if _, err := c.Write(ldapStartTLSRequest); err != nil {
		return err
	}
	msg, err := readBER(c)
	if err != nil {
		return startTLSFailure(StartTLSLDAP, nil, err, "no LDAP answer")
	}
	code, ok := ldapExtendedResult(msg)
	switch {
	case !ok:
		return &StartTLSError{Proto: StartTLSLDAP, Why: "the answer is not an LDAP extended response"}
	case code != 0:
		return &StartTLSError{Proto: StartTLSLDAP, Why: fmt.Sprintf("StartTLS was refused (LDAP result code %d)", code)}
	}
	return nil
}

// readBER reads exactly one BER element (tag, length, content), at most maxPlain bytes.
func readBER(r io.Reader) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(head[1])
	out := head
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 {
			return nil, errors.New("unsupported BER length")
		}
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		out = append(out, lb...)
		n = 0
		for _, x := range lb {
			n = n<<8 | int(x)
		}
	}
	if n > maxPlain {
		return nil, errors.New("the LDAP answer is too long")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(out, body...), nil
}

// berNext splits the first element off b: its tag, its content and the rest.
func berNext(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, n, off := b[0], int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 3 || len(b) < 2+k {
			return 0, nil, nil, false
		}
		n = 0
		for _, x := range b[2 : 2+k] {
			n = n<<8 | int(x)
		}
		off += k
	}
	if len(b) < off+n {
		return 0, nil, nil, false
	}
	return tag, b[off : off+n], b[off+n:], true
}

// ldapExtendedResult reads the resultCode of an ExtendedResponse ([APPLICATION 24]).
func ldapExtendedResult(msg []byte) (int, bool) {
	tag, seq, _, ok := berNext(msg)
	if !ok || tag != 0x30 {
		return 0, false
	}
	tag, _, rest, ok := berNext(seq) // messageID
	if !ok || tag != 0x02 {
		return 0, false
	}
	tag, op, _, ok := berNext(rest)
	if !ok || tag != 0x78 {
		return 0, false
	}
	tag, code, _, ok := berNext(op)
	if !ok || tag != 0x0a || len(code) == 0 {
		return 0, false
	}
	v := 0
	for _, x := range code {
		v = v<<8 | int(x)
	}
	return v, true
}

func postgresStartTLS(c net.Conn) error {
	// SSLRequest: length 8, code 80877103.
	if _, err := c.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return err
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(c, one); err != nil {
		return startTLSFailure(StartTLSPostgres, nil, err, "no answer to the SSL request")
	}
	switch one[0] {
	case 'S':
		return nil
	case 'N':
		return &StartTLSError{Proto: StartTLSPostgres, Why: "the server does not offer TLS (it answered N)"}
	}
	return &StartTLSError{Proto: StartTLSPostgres, Why: fmt.Sprintf("the answer is not PostgreSQL's (first byte 0x%02x)", one[0])}
}

// startTLSFailure wraps what went wrong in the plain-text exchange: a network error stays a
// network error (the probe may retry), anything else becomes a StartTLSError.
func startTLSFailure(proto string, lines []string, err error, why string) error {
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			// A service that speaks TLS from the first byte waits for the client in silence, just
			// as this exchange waits for a greeting: say so rather than report a bare timeout.
			return &StartTLSError{Proto: proto, Why: why + " in time; if this port speaks TLS from the first byte, scan it without STARTTLS",
				Reply: clipReply(lines)}
		}
		if errors.As(err, &ne) {
			return err
		}
	}
	reply := clipReply(lines)
	if err != nil && reply == "" {
		why += " (the connection closed)"
	}
	return &StartTLSError{Proto: proto, Why: why, Reply: reply}
}

// ParseTargetStartTLS parses a target that may carry a scheme ("smtp://mail.example.com",
// "imap://host:1143") and decides its STARTTLS protocol: the scheme's when there is one, else
// choice ("auto", "none" or a protocol) applied to the port. A scheme without a port takes the
// scheme's usual port.
func ParseTargetStartTLS(s, choice string) (Target, error) {
	rest, proto, defPort, hasScheme, err := SplitScheme(strings.TrimSpace(s))
	if err != nil {
		return Target{}, err
	}
	t, err := ParseTarget(rest)
	if err != nil {
		return Target{}, err
	}
	if hasScheme {
		if _, _, perr := net.SplitHostPort(rest); perr != nil {
			t.Port = defPort
		}
		t.StartTLS = proto
		return t, nil
	}
	t.StartTLS, err = ResolveStartTLS(choice, t.Port)
	return t, err
}
