package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/server"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// selfSignedPair is a short-lived ECDSA P-256 certificate for 127.0.0.1, like the one an operator
// might mount; its trust findings are expected (nobody trusts it), nothing else is.
func selfSignedPair(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// expectedOnSelfSigned are the findings a self-signed test certificate must produce: trust,
// revocation and transparency are about who issued the certificate, not about the server. Two
// informational notes are inherent too: no certificate authority issues post-quantum
// certificates yet, and HSTS deliberately omits includeSubDomains (the server usually lives on a
// subdomain of its owner's domain, whose siblings it must not force onto HTTPS).
var expectedOnSelfSigned = map[string]bool{
	"CERT.UNTRUSTED": true, "CERT.PARTIAL-TRUST": true, "OCSP.NO-STAPLE": true, "CT.NO-SCTS": true,
	"PQC.CLASSICAL-AUTH": true, "HTTP.HSTS-NO-SUBDOMAINS": true,
}

// PRD-007 REQ-SS-1..3: the product's own HTTPS listener, scanned and judged by the product.
func TestTheServerPassesItsOwnScan(t *testing.T) {
	e := newEnv(t)
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.TLS = server.TLSConfig([]tls.Certificate{selfSignedPair(t)})
	ts.Config.ErrorLog = log.New(io.Discard, "", 0) // the scan's refused handshakes are expected
	ts.StartTLS()
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	p, _ := strconv.Atoi(port)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := tlsprobe.Scan(ctx, tlsprobe.Target{Host: "127.0.0.1", Port: p},
		tlsprobe.Options{Timeout: 5 * time.Second, Concurrency: 8, HTTPChecks: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	ev := eval.Evaluate(rep, time.Now())
	var unexpected, seen []string
	for _, f := range ev.Findings {
		seen = append(seen, f.ID)
		if !expectedOnSelfSigned[f.ID] {
			unexpected = append(unexpected, f.ID+" ("+string(f.Severity)+"): "+f.Detail)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("the server's own HTTPS has findings beyond its test certificate:\n  %s", strings.Join(unexpected, "\n  "))
	}
	t.Logf("findings: %v; readiness L%d; %d suites", seen, ev.Readiness.Level, len(rep.Suites))
	if len(rep.Suites) == 0 {
		t.Fatal("the scan found no suites: it did not reach the server")
	}
	if ev.Readiness.Level < 3 {
		t.Errorf("readiness L%d, want L3 or better (hybrid post-quantum key exchange negotiated)", ev.Readiness.Level)
	}
	for _, s := range rep.Suites {
		if s.Version == "TLSv1.2" && !s.AEAD {
			t.Errorf("TLS 1.2 accepts a non-AEAD suite: %s", s.Name)
		}
	}
}

// REQ-SS-2: HSTS on HTTPS responses, never on plain loopback HTTP (it would be ignored there,
// and saying it would be untrue).
func TestHSTSOnlyOverTLS(t *testing.T) {
	e := newEnv(t)
	if s, _, h := e.req("GET", "/api/v1/health", nil, nil); s != 200 || h.Get("Strict-Transport-Security") != "" {
		t.Fatalf("plain HTTP: %d, HSTS %q; want none", s, h.Get("Strict-Transport-Security"))
	}
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.TLS = server.TLSConfig([]tls.Certificate{selfSignedPair(t)})
	ts.StartTLS()
	defer ts.Close()
	client := ts.Client()
	resp, err := client.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("HTTPS: HSTS %q, want max-age=31536000", got)
	}
	// A forged proxy header from an untrusted peer must not switch HSTS on.
	req, _ := http.NewRequest("GET", e.ts.URL+"/api/v1/health", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("an untrusted X-Forwarded-Proto turned HSTS on")
	}
}
