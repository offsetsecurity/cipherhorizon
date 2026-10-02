// Command demo-targets runs a handful of deliberately different TLS servers on
// 127.0.0.1 so the product can be tried, demonstrated and QA'd without scanning
// anyone else's systems. It is a development tool and is not part of the release
// binary.
//
//	demo-targets [-base-port 9440]
//
// Start "cipherhorizon serve --allow-loopback" and add the addresses it prints.
// Scans of loopback addresses are refused unless --allow-loopback is set.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

// The suites a deliberately terrible SSLv3 server prefers, in its order.
var terribleOrder = []uint16{
	0x000A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
	0x0005, // TLS_RSA_WITH_RC4_128_SHA
	0x0003, // TLS_RSA_EXPORT_WITH_RC4_40_MD5
	0x0001, // TLS_RSA_WITH_NULL_MD5
	0x0018, // TLS_DH_anon_WITH_RC4_128_MD5
}

var (
	hybridCurves    = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256}
	classicalCurves = []tls.CurveID{tls.X25519, tls.CurveP256}
)

// toggle is a TLS 1.3 server whose post-quantum key exchange can be switched on and
// off while it runs, standing in for an operator who enables hybrid key exchange
// between two scans.
type toggle struct {
	addr string
	mu   sync.Mutex
	srv  *testserver.Server
	pq   bool
}

func (t *toggle) set(pq bool) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.srv != nil {
		t.srv.Close()
		t.srv = nil
	}
	curves := classicalCurves
	if pq {
		curves = hybridCurves
	}
	var err error
	for i := 0; i < 20; i++ { // the port can take a moment to be released
		t.srv, err = testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS13, Curves: curves, Addr: t.addr})
		if err == nil {
			t.pq = pq
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func (t *toggle) state() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pq
}

// slowProxy forwards to target after a delay per connection, so a scan of it lasts
// long enough to watch progress and to cancel.
func slowProxy(addr, target string, delay time.Duration) (io.Closer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // demo proxy
				time.Sleep(delay)
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close() //nolint:errcheck // demo proxy
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
				go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return l, nil
}

func main() {
	base := flag.Int("base-port", 9440, "first port; the targets use base..base+10")
	flag.Parse()
	addr := func(off int) string { return fmt.Sprintf("127.0.0.1:%d", *base+off) }
	fail := func(err error) {
		fmt.Fprintln(os.Stderr, "demo-targets:", err)
		os.Exit(1)
	}

	if _, err := testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, Curves: hybridCurves, Addr: addr(0)}); err != nil {
		fail(err)
	}
	if _, err := testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS13, Curves: classicalCurves, Addr: addr(1)}); err != nil {
		fail(err)
	}
	if _, err := testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, Addr: addr(2)}); err != nil {
		fail(err)
	}
	if _, err := testserver.ListenScript(addr(3), testserver.Legacy(0x0300, terribleOrder, false)); err != nil {
		fail(err)
	}
	// addr(4) is left unused on purpose: a port with nothing listening.
	tg := &toggle{addr: addr(5)}
	if err := tg.set(false); err != nil {
		fail(err)
	}
	slowBackend, err := testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, Curves: hybridCurves})
	if err != nil {
		fail(err)
	}
	if _, err := slowProxy(addr(6), slowBackend.Addr, 2*time.Second); err != nil {
		fail(err)
	}

	pki, err := newDemoPKI()
	if err != nil {
		fail(err)
	}
	if err := startPKITargets(pki, addr(8), addr(9)); err != nil {
		fail(err)
	}
	if err := startHostileTarget(pki, addr(10)); err != nil {
		fail(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /corp-root.pem", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(pki.rootPEM)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "toggle target %s: post-quantum key exchange is %s\n", tg.addr, map[bool]string{true: "ON", false: "OFF"}[tg.state()])
	})
	mux.HandleFunc("POST /pq/{state}", func(w http.ResponseWriter, r *http.Request) {
		var on bool
		switch r.PathValue("state") {
		case "on":
			on = true
		case "off":
		default:
			http.Error(w, "use /pq/on or /pq/off", http.StatusBadRequest)
			return
		}
		if err := tg.set(on); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, "post-quantum key exchange is now %s\n", map[bool]string{true: "on", false: "off"}[on])
	})
	ctl := &http.Server{Addr: addr(7), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := ctl.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fail(err)
		}
	}()

	fmt.Printf(`demo-targets are running (loopback only). Add these in the UI:

  %s   modern-hybrid      TLS 1.2/1.3, hybrid post-quantum key exchange   -> expect L3
  %s   classical-tls13    TLS 1.3 only, no post-quantum                   -> expect L1
  %s   legacy-tls12       TLS 1.2 only                                    -> expect L0
  %s   terrible-legacy    SSLv3 with RC4, 3DES, export, NULL, anonymous   -> expect TLS hygiene Broken
  %s   dead-port          nothing listening                               -> expect a failed scan
  %s   pq-toggle          starts classical; switch it between scans:
                              curl -X POST http://%s/pq/on    (then /pq/off)
  %s   slow-hybrid        hybrid, ~2 s per connection (a scan takes about 20 s:
                          use it to watch progress and to cancel)
  %s   private-ca         a private CA chain and a short HSTS header -> untrusted until its
                          root is added to the system's CA bundle:
                              curl http://%s/corp-root.pem
  %s   broken-chain       the same CA, intermediate not sent, no HSTS -> missing intermediate
  %s   hostile-pki        markup in the certificate and the HSTS header (must render as text)

Start the product with:  cipherhorizon serve --allow-loopback
Ctrl+C stops everything.
`, addr(0), addr(1), addr(2), addr(3), addr(4), addr(5), addr(7), addr(6), addr(8), addr(7), addr(9), addr(10))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
