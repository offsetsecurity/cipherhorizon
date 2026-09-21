// Package testserver provides hermetic servers for testing the TLS prober
// without touching the network: real crypto/tls servers whose versions, suites
// and groups are configurable, and a scripted raw-TCP server for replies the
// standard library cannot produce (SSLv2/SSLv3, garbage, stalls).
//
// Test and demo support only: nothing in the shipped cbom-scan binary imports it
// (cmd/demo-targets, a development tool, does).
package testserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// CertKind selects which certificates a server presents.
type CertKind int

// The certificate kinds.
const (
	CertECDSA CertKind = iota // one ECDSA P-256 certificate
	CertRSA                   // one RSA-2048 certificate
	CertBoth                  // both; the suite chosen decides which is used
)

// Config configures a TLS server. Zero values mean crypto/tls defaults.
type Config struct {
	MinVersion, MaxVersion uint16
	Suites                 []uint16 // TLS 1.2 and earlier; TLS 1.3 suites are fixed by Go
	Curves                 []tls.CurveID
	Cert                   CertKind
	ALPN                   []string
	// Addr is the listen address; empty means 127.0.0.1:0. Restarting a server on
	// the same address with a different Config simulates an endpoint being changed.
	Addr string
}

// Server is a running test server.
type Server struct {
	Host string
	Port int
	Addr string // host:port

	close func()
}

// Close stops the server early (it is also stopped when the test ends).
func (s *Server) Close() {
	if s.close != nil {
		s.close()
	}
}

var (
	certOnce sync.Once
	ecCert   tls.Certificate
	rsaCert  tls.Certificate
	certErr  error
)

func makeCerts() {
	mk := func(pub, priv any) (tls.Certificate, error) {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"cbom-scan test"}},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			return tls.Certificate{}, err
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
	}

	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		certErr = err
		return
	}
	if ecCert, certErr = mk(&ek.PublicKey, ek); certErr != nil {
		return
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		certErr = err
		return
	}
	rsaCert, certErr = mk(&rk.PublicKey, rk)
}

// LoadCertificates returns the ECDSA and RSA certificates (self-signed).
func LoadCertificates() (ec, rsaC tls.Certificate, err error) {
	certOnce.Do(makeCerts)
	return ecCert, rsaCert, certErr
}

// Certificates returns the test ECDSA and RSA certificates (self-signed).
func Certificates(t testing.TB) (ec, rsaC tls.Certificate) {
	t.Helper()
	ec, rsaC, err := LoadCertificates()
	if err != nil {
		t.Fatalf("testserver: generating certificates: %v", err)
	}
	return ec, rsaC
}

// Start runs a TLS server on 127.0.0.1 until the test ends. Each connection is
// handshaken and closed.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	srv, err := Listen(cfg)
	if err != nil {
		t.Fatalf("testserver: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// Listen is Start for programs that are not tests (the demo targets). The caller
// closes the server.
func Listen(cfg Config) (*Server, error) {
	ec, rsaC, err := LoadCertificates()
	if err != nil {
		return nil, err
	}

	tc := &tls.Config{
		MinVersion:       cfg.MinVersion,
		MaxVersion:       cfg.MaxVersion,
		CipherSuites:     cfg.Suites,
		CurvePreferences: cfg.Curves,
		NextProtos:       cfg.ALPN,
	}
	switch cfg.Cert {
	case CertRSA:
		tc.Certificates = []tls.Certificate{rsaC}
	case CertBoth:
		tc.Certificates = []tls.Certificate{ec, rsaC}
	default:
		tc.Certificates = []tls.Certificate{ec}
	}

	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	l, err := tls.Listen("tcp", addr, tc)
	if err != nil {
		return nil, err
	}
	go serve(l)
	srv, err := addrOf(l)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	srv.close = func() { _ = l.Close() }
	return srv, nil
}

func serve(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close() //nolint:errcheck // test server
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
		}()
	}
}

// StartScript runs a raw TCP server that reads one chunk from the client and
// answers with reply(chunk), then closes. A nil reply closes without answering;
// stall keeps the connection open and silent until the client gives up.
func StartScript(t testing.TB, reply func(clientBytes []byte) []byte) *Server {
	t.Helper()
	srv, err := ListenScript("127.0.0.1:0", reply)
	if err != nil {
		t.Fatalf("testserver: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// ListenScript is StartScript for programs that are not tests. The caller closes
// the server.
func ListenScript(addr string, reply func(clientBytes []byte) []byte) (*Server, error) {
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
				defer c.Close() //nolint:errcheck // test server
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 1<<16)
				n, _ := c.Read(buf)
				if out := reply(buf[:n]); out != nil {
					_, _ = c.Write(out)
				}
			}()
		}
	}()
	srv, err := addrOf(l)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	srv.close = func() { _ = l.Close() }
	return srv, nil
}

func addrOf(l net.Listener) (*Server, error) {
	host, portStr, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	return &Server{Host: host, Port: port, Addr: l.Addr().String()}, nil
}
