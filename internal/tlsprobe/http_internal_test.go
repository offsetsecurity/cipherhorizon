package tlsprobe

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// The HSTS check writes its host into the request line by line, so a host carrying a line break,
// another control character or a space is refused and nothing at all is sent.
func TestCheckHSTSRefusesHostWithControlCharacters(t *testing.T) {
	for _, host := range []string{"a\r\nX-Extra: 1", "a\nb", "a b", "a\tb", "a\x00b", "a\x7fb"} {
		client, peer := net.Pipe()
		sent := make(chan int, 1)
		go func() {
			buf := make([]byte, 1)
			n, _ := peer.Read(buf)
			sent <- n
		}()
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_, err := checkHSTS(tls.Client(client, &tls.Config{InsecureSkipVerify: true}), host)
		_ = client.Close()
		if n := <-sent; n != 0 {
			t.Errorf("host %q: the check sent data to the server", host)
		}
		_ = peer.Close()
		if err == nil {
			t.Errorf("host %q: no error", host)
		}
	}
}
