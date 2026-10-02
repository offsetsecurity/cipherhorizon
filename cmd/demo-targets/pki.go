package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

// A small private PKI for the certificate and trust sections: a root (never
// served), an intermediate, and leaves for 127.0.0.1. The root is offered by the
// control server so it can be added as a system's private CA bundle.
type demoPKI struct {
	rootPEM []byte
	inter   *x509.Certificate
	interK  crypto.Signer
}

func newDemoPKI() (*demoPKI, error) {
	mk := func(tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) (*x509.Certificate, error) {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			return nil, err
		}
		return x509.ParseCertificate(der)
	}
	now := time.Now()
	rk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo Corp Root CA", Organization: []string{"Demo Corp"}},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root, err := mk(rootT, rootT, &rk.PublicKey, rk)
	if err != nil {
		return nil, err
	}
	ik, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Demo Corp Issuing CA 1", Organization: []string{"Demo Corp"}},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	inter, err := mk(interT, root, &ik.PublicKey, rk)
	if err != nil {
		return nil, err
	}
	return &demoPKI{rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), inter: inter, interK: ik}, nil
}

// leaf issues a 90-day leaf for 127.0.0.1 and returns it with the chain to serve.
func (p *demoPKI) leaf(serial int64, withIntermediate bool) (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "intranet.demo-corp.test"},
		NotBefore: now.AddDate(0, 0, -10), NotAfter: now.AddDate(0, 0, 80), DNSNames: []string{"intranet.demo-corp.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IssuingCertificateURL: []string{"http://pki.demo-corp.test/issuing-ca-1.der"},
		OCSPServer: []string{"http://ocsp.demo-corp.test/"}}
	der, err := x509.CreateCertificate(rand.Reader, t, p.inter, &k.PublicKey, p.interK)
	if err != nil {
		return tls.Certificate{}, err
	}
	c := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	if withIntermediate {
		c.Certificate = append(c.Certificate, p.inter.Raw)
	}
	return c, nil
}

// startPKITargets runs the private-CA target (full chain, a short HSTS header)
// and the broken-chain target (intermediate missing, no HSTS).
func startPKITargets(p *demoPKI, corpAddr, brokenAddr string) error {
	corp, err := p.leaf(10, true)
	if err != nil {
		return err
	}
	if _, err := testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, Curves: hybridCurves, Chain: []tls.Certificate{corp}, Addr: corpAddr,
		HTTPResponse: func([]byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=600\r\nContent-Length: 0\r\n\r\n")
		}}); err != nil {
		return err
	}
	broken, err := p.leaf(11, false)
	if err != nil {
		return err
	}
	_, err = testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, Curves: classicalCurves, Chain: []tls.Certificate{broken}, Addr: brokenAddr,
		HTTPResponse: func([]byte) []byte { return []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }})
	return err
}

// startHostileTarget serves a certificate and an HSTS header full of markup, so the
// browser journey can check every new report section renders target text as text.
func startHostileTarget(p *demoPKI, addr string) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	t := &x509.Certificate{SerialNumber: big.NewInt(12),
		Subject:   pkix.Name{CommonName: `<img src=x onerror="window.__xss=5">`, Organization: []string{`<script>window.__xss=6</script>`}},
		NotBefore: now.AddDate(0, 0, -1), NotAfter: now.AddDate(0, 0, 30),
		DNSNames:    []string{`<svg onload=window.__xss=7>.test`},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, OCSPServer: []string{`javascript:window.__xss=8`},
		IssuingCertificateURL: []string{`"><img src=x onerror=window.__xss=9>`}}
	der, err := x509.CreateCertificate(rand.Reader, t, p.inter, &k.PublicKey, p.interK)
	if err != nil {
		return err
	}
	_, err = testserver.Listen(testserver.Config{MinVersion: tls.VersionTLS12, Chain: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}, Addr: addr,
		HTTPResponse: func([]byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=5; <script>window.__xss=10</script>\r\nContent-Length: 0\r\n\r\n")
		}})
	return err
}
