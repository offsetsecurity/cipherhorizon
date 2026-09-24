package tlsprobe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"

	"github.com/example/cipherhorizon/internal/algo"
	"github.com/example/cipherhorizon/internal/tlsprobe/registry"
	"github.com/example/cipherhorizon/internal/tlsprobe/wire"
)

// Suite lists for the restricted TLS 1.2-and-earlier handshakes that coax a
// server into presenting its ECDSA and its RSA certificate respectively.
var (
	ecdsaSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}
	rsaSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}
)

// certificates completes real handshakes with crypto/tls to read the certificate
// chain (encrypted in TLS 1.3, so the raw probes cannot see it) and to record
// what a current client negotiates. Verification is done separately, after the
// handshake, so an untrusted or expired certificate is reported rather than
// refused.
//
// The returned *bool is whether the server asked for a client certificate
// (mTLS) during the first (tls-default) attempt: crypto/tls only calls
// GetClientCertificate when the server sends a CertificateRequest, so setting
// it turns "did the server ask" into something observable independent of
// whether the handshake goes on to succeed or fail for lack of one. An empty
// certificate is returned from the callback so the handshake proceeds as far
// as the server allows; no real client certificate is ever presented.
//
// true is returned the moment the server asks, even if the handshake then
// fails (an mTLS-required server correctly rejecting an empty certificate is
// itself the observation). false is returned only when the handshake
// succeeded outright — a complete handshake with no request is proof none was
// sent. Anything else (the handshake failed for some other reason before or
// without a request) is nil: unknown, not "no."
func (p *prober) certificates(ctx context.Context, legacy map[wire.Version]*legacyEnum) ([]CertResult, *Negotiated, *bool) {
	type attempt struct {
		source string
		cfg    *tls.Config
	}
	base := func() *tls.Config {
		return &tls.Config{InsecureSkipVerify: true, ServerName: p.target.SNI, //nolint:gosec // verified explicitly below
			MinVersion: tls.VersionTLS10, NextProtos: []string{"h2", "http/1.1"}}
	}

	var clientCertRequested bool
	first := base()
	first.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		clientCertRequested = true
		return &tls.Certificate{}, nil
	}
	attempts := []attempt{{"tls-default", first}}
	if len(legacy) > 0 {
		ec, rs := base(), base()
		ec.MaxVersion, ec.CipherSuites = tls.VersionTLS12, ecdsaSuites
		rs.MaxVersion, rs.CipherSuites = tls.VersionTLS12, rsaSuites
		attempts = append(attempts, attempt{"tls1.2-ecdsa", ec}, attempt{"tls1.2-rsa", rs})
	}

	var (
		results    []CertResult
		negotiated *Negotiated
		firstErr   error
		firstDone  bool
		byLeaf     = map[string]int{}
	)
	for i, a := range attempts {
		if ctx.Err() != nil {
			break
		}
		state, err := p.handshake(ctx, a.cfg)
		if i == 0 {
			negotiated = negotiatedFrom(state, err)
			firstErr, firstDone = err, true
		}
		if state == nil || len(state.PeerCertificates) == 0 {
			continue
		}
		fp := sha256.Sum256(state.PeerCertificates[0].Raw)
		key := hex.EncodeToString(fp[:])
		if idx, seen := byLeaf[key]; seen {
			results[idx].Source += ", " + a.source
			continue
		}
		byLeaf[key] = len(results)
		results = append(results, p.describeChain(a.source, state.PeerCertificates))
	}

	var requested *bool
	switch {
	case clientCertRequested:
		requested = &clientCertRequested
	case firstDone && firstErr == nil:
		notRequested := false
		requested = &notRequested
	}
	return results, negotiated, requested
}

// handshake completes one TLS handshake and returns the connection state.
func (p *prober) handshake(ctx context.Context, cfg *tls.Config) (*tls.ConnectionState, error) {
	conn, release, err := p.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	tc := tls.Client(conn, cfg)
	defer tc.Close() //nolint:errcheck // probe connection
	if err := tc.HandshakeContext(ctx); err != nil {
		// A failed handshake can still have delivered the certificates.
		st := tc.ConnectionState()
		return &st, err
	}
	st := tc.ConnectionState()
	return &st, nil
}

func negotiatedFrom(st *tls.ConnectionState, err error) *Negotiated {
	n := &Negotiated{}
	if err != nil {
		n.Error = err.Error()
	}
	if st == nil || st.Version == 0 {
		return n
	}
	n.Version = wire.Version(st.Version).String()
	n.SuiteID = st.CipherSuite
	n.Suite = registry.SuiteName(st.CipherSuite)
	n.ALPN = st.NegotiatedProtocol
	n.OCSPStaple = len(st.OCSPResponse) > 0
	if st.CurveID != 0 {
		n.GroupID = uint16(st.CurveID)
		n.Group = registry.GroupName(uint16(st.CurveID))
		if g, ok := registry.GroupByID(uint16(st.CurveID)); ok {
			n.PQ = g.PQ
		}
	}
	return n
}

// describeChain describes a presented chain and checks its trust and name.
func (p *prober) describeChain(source string, chain []*x509.Certificate) CertResult {
	res := CertResult{Source: source}
	for _, c := range chain {
		res.Chain = append(res.Chain, describeCert(c))
	}
	leaf := chain[0]

	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: inter, CurrentTime: p.opts.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	res.Trusted = err == nil
	if err != nil {
		res.TrustError = err.Error()
	}
	if err := leaf.VerifyHostname(p.target.Host); err != nil {
		res.NameError = err.Error()
	} else {
		res.NameMatches = true
	}
	return res
}

// ---- certificate description --------------------------------------------------------------

var (
	oidTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	oidSCTList    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// knownKeyOIDs names the public-key algorithms whose identity is fixed by RFCs.
// Anything else is looked up in the algorithm catalogue (which carries the
// NIST post-quantum OIDs) and otherwise reported as "unknown", never guessed.
var knownKeyOIDs = map[string]string{
	"1.2.840.113549.1.1.1":  "RSA",
	"1.2.840.10045.2.1":     "ECDSA", // id-ecPublicKey: also used by ECDH keys, but as a certificate key it signs
	"1.3.101.110":           "X25519",
	"1.3.101.111":           "X448",
	"1.3.101.112":           "Ed25519",
	"1.3.101.113":           "Ed448",
	"1.2.840.10040.4.1":     "DSA",
	"1.2.840.113549.1.1.10": "RSASSA-PSS",
}

func describeCert(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.Raw)
	ci := CertInfo{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		SerialHex: c.SerialNumber.Text(16), DNSNames: c.DNSNames,
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, IsCA: c.IsCA,
		SelfSigned:  bytes.Equal(c.RawSubject, c.RawIssuer),
		SHA256:      hex.EncodeToString(sum[:]),
		OCSPServers: c.OCSPServer, IssuerURLs: c.IssuingCertificateURL, CRLPoints: c.CRLDistributionPoints,
	}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	for _, e := range c.Extensions {
		switch {
		case e.Id.Equal(oidSCTList):
			ci.EmbeddedSCTs = true
		case e.Id.Equal(oidTLSFeature):
			// TLS Feature: SEQUENCE OF INTEGER; 5 is status_request, i.e. OCSP must-staple.
			ci.OCSPMustStaple = bytes.Contains(e.Value, []byte{0x02, 0x01, 0x05})
		}
	}
	ci.PublicKey = describeKey(c)
	ci.SignatureAlg = describeSignature(c)
	return ci
}

func describeKey(c *x509.Certificate) KeyInfo {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	oid := ""
	if _, err := asn1.Unmarshal(c.RawSubjectPublicKeyInfo, &spki); err == nil {
		oid = spki.Algorithm.Algorithm.String()
	}
	k := KeyInfo{OID: oid, Algorithm: keyName(oid)}

	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		k.Algorithm, k.Bits = "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		k.Algorithm, k.Curve, k.Bits = "ECDSA", pub.Curve.Params().Name, pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		k.Algorithm, k.Bits = "Ed25519", 256
	}
	return k
}

func keyName(oid string) string {
	if n, ok := knownKeyOIDs[oid]; ok {
		return n
	}
	for _, a := range algo.All() {
		if a.OID != "" && a.OID == oid {
			return a.ID
		}
	}
	return "unknown"
}

// describeSignature reports the certificate's signature algorithm with its OID,
// read from the outer structure so it works for algorithms Go does not implement.
func describeSignature(c *x509.Certificate) AlgInfo {
	var outer struct {
		TBS asn1.RawValue
		Alg pkix.AlgorithmIdentifier
		Sig asn1.BitString
	}
	oid := ""
	if _, err := asn1.Unmarshal(c.Raw, &outer); err == nil {
		oid = outer.Alg.Algorithm.String()
	}
	name := c.SignatureAlgorithm.String()
	if c.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		name = keyName(oid) // e.g. an ML-DSA signature OID
		if name == "unknown" {
			name = "unknown (" + oid + ")"
		}
	}
	return AlgInfo{Name: strings.TrimSpace(name), OID: oid}
}
