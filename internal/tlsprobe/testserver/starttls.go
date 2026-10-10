package testserver

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

// serveStartTLS accepts plain connections, plays the server's side of the STARTTLS exchange for
// proto, then hands the connection to crypto/tls exactly as Listen's TLS listener would. With
// refuse set, the server says no at the point the protocol allows it.
func serveStartTLS(l net.Listener, tc *tls.Config, proto string, refuse bool, httpResponse func([]byte) []byte) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close() //nolint:errcheck // test server
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if !plainSide(c, proto, refuse) {
				return
			}
			tlsc := tls.Server(c, tc)
			if err := tlsc.Handshake(); err != nil || httpResponse == nil {
				return
			}
			buf := make([]byte, 1<<16)
			n, _ := tlsc.Read(buf)
			if out := httpResponse(buf[:n]); out != nil {
				_, _ = tlsc.Write(out)
			}
		}()
	}
}

// lineReader reads one line at a time without reading ahead: the client's ClientHello follows the
// last plain-text line directly, and must stay unread for crypto/tls.
func lineReader(c net.Conn) func() (string, error) {
	return func() (string, error) {
		var b []byte
		one := make([]byte, 1)
		for len(b) < 4096 {
			if _, err := io.ReadFull(c, one); err != nil {
				return "", err
			}
			if one[0] == '\n' {
				return strings.TrimRight(string(b), "\r"), nil
			}
			b = append(b, one[0])
		}
		return string(b), nil
	}
}

func plainSide(c net.Conn, proto string, refuse bool) bool {
	w := bufio.NewWriter(c)
	say := func(s string) bool {
		_, err := w.WriteString(s)
		return err == nil && w.Flush() == nil
	}
	read := lineReader(c)
	switch proto {
	case "smtp":
		if !say("220-mail.test ESMTP ready\r\n220 mail.test\r\n") {
			return false
		}
		if l, err := read(); err != nil || !strings.HasPrefix(strings.ToUpper(l), "EHLO") {
			return false
		}
		if refuse {
			say("250-mail.test\r\n250 SIZE 1000000\r\n") // no STARTTLS offered
			return false
		}
		if !say("250-mail.test greets you\r\n250-SIZE 1000000\r\n250 STARTTLS\r\n") {
			return false
		}
		if l, err := read(); err != nil || !strings.EqualFold(l, "STARTTLS") {
			return false
		}
		return say("220 2.0.0 Ready to start TLS\r\n")
	case "imap":
		if !say("* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n") {
			return false
		}
		l, err := read()
		if err != nil {
			return false
		}
		tag := strings.Fields(l)[0]
		if refuse {
			say(tag + " BAD STARTTLS not available\r\n")
			return false
		}
		return say("* CAPABILITY IMAP4rev1\r\n" + tag + " OK Begin TLS negotiation now\r\n")
	case "pop3":
		if !say("+OK POP3 ready\r\n") {
			return false
		}
		if l, err := read(); err != nil || !strings.EqualFold(l, "STLS") {
			return false
		}
		if refuse {
			say("-ERR not available\r\n")
			return false
		}
		return say("+OK Begin TLS negotiation\r\n")
	case "ftp":
		if !say("220-Welcome\r\n220 FTP ready\r\n") {
			return false
		}
		if l, err := read(); err != nil || !strings.EqualFold(l, "AUTH TLS") {
			return false
		}
		if refuse {
			say("502 Command not implemented\r\n")
			return false
		}
		return say("234 AUTH TLS successful\r\n")
	case "xmpp":
		if err := readTo(c, "version='1.0'>"); err != nil {
			return false
		}
		head := "<?xml version='1.0'?><stream:stream from='chat.test' id='t1' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
		if refuse {
			say(head + "<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/></stream:features>")
			return false
		}
		if !say(head + "<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>") {
			return false
		}
		if err := readTo(c, "/>"); err != nil {
			return false
		}
		return say("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
	case "ldap":
		req := make([]byte, 31)
		if _, err := io.ReadFull(c, req); err != nil || !strings.Contains(string(req), "1.3.6.1.4.1.1466.20037") {
			return false
		}
		code := byte(0)
		if refuse {
			code = 2 // protocolError
		}
		// LDAPMessage { messageID 1, extendedResp { resultCode, matchedDN "", diagnosticMessage "" } }
		_, err := c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, code, 0x04, 0x00, 0x04, 0x00})
		return err == nil && !refuse
	case "postgres":
		req := make([]byte, 8)
		if _, err := io.ReadFull(c, req); err != nil || string(req[4:]) != "\x04\xd2\x16\x2f" {
			return false
		}
		if refuse {
			_, _ = c.Write([]byte{'N'})
			return false
		}
		_, err := c.Write([]byte{'S'})
		return err == nil
	}
	return false
}

func readTo(c net.Conn, needle string) error {
	var b []byte
	one := make([]byte, 1)
	for len(b) < 1<<16 {
		if _, err := io.ReadFull(c, one); err != nil {
			return err
		}
		b = append(b, one[0])
		if strings.HasSuffix(string(b), needle) {
			return nil
		}
	}
	return io.ErrShortBuffer
}
