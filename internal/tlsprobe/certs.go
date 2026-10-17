package tlsprobe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"

	"github.com/offsetsecurity/cipherhorizon/internal/certinfo"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/registry"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/wire"
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
func (p *prober) certificates(ctx context.Context, legacy map[wire.Version]*legacyEnum) ([]CertResult, *Negotiated, *bool, string) {
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
	// Without server_name: what a client that sends no SNI (old clients, scanners,
	// direct-to-address connections) is served (REQ-TCHN-1).
	if p.target.SNI != "" {
		nosni := base()
		nosni.ServerName = ""
		attempts = append(attempts, attempt{"no-sni", nosni})
	}

	var (
		results    []CertResult
		negotiated *Negotiated
		firstErr   error
		firstDone  bool
		byLeaf     = map[string]int{}
		defaultFP  string
		noSNI      string
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
			if a.source == "no-sni" {
				noSNI = "failed"
			}
			continue
		}
		fp := sha256.Sum256(state.PeerCertificates[0].Raw)
		key := hex.EncodeToString(fp[:])
		if i == 0 {
			defaultFP = key
		}
		if a.source == "no-sni" {
			if key == defaultFP {
				noSNI = "same"
				continue
			}
			noSNI = "different"
			r := p.describeChain(a.source, state)
			r.NoSNI = true
			results = append(results, r)
			continue
		}
		if idx, seen := byLeaf[key]; seen {
			results[idx].Source += ", " + a.source
			p.mergeRevocation(&results[idx], state)
			continue
		}
		byLeaf[key] = len(results)
		results = append(results, p.describeChain(a.source, state))
	}

	var requested *bool
	switch {
	case clientCertRequested:
		requested = &clientCertRequested
	case firstDone && firstErr == nil:
		notRequested := false
		requested = &notRequested
	}
	return results, negotiated, requested, noSNI
}

// Bounds on the raw revocation data kept from a handshake.
const (
	maxStapleBytes = 64 << 10
	maxTLSSCTs     = 32
	maxTLSSCTBytes = 4 << 10
)

// revocationData returns the stapled OCSP response and the TLS-extension SCTs,
// base64, within the bounds; anything over a bound is dropped and noted.
func (p *prober) revocationData(st *tls.ConnectionState) (string, []string) {
	var staple string
	if n := len(st.OCSPResponse); n > maxStapleBytes {
		p.note("stapled OCSP response of %d bytes ignored (limit %d)", n, maxStapleBytes)
	} else if n > 0 {
		staple = base64.StdEncoding.EncodeToString(st.OCSPResponse)
	}
	var scts []string
	for i, s := range st.SignedCertificateTimestamps {
		if i == maxTLSSCTs {
			p.note("more than %d SCTs in the TLS extension; the rest were ignored", maxTLSSCTs)
			break
		}
		if len(s) > maxTLSSCTBytes {
			continue
		}
		scts = append(scts, base64.StdEncoding.EncodeToString(s))
	}
	return staple, scts
}

// mergeRevocation fills in a staple or SCTs a later handshake for the same leaf
// returned when the first did not.
func (p *prober) mergeRevocation(r *CertResult, st *tls.ConnectionState) {
	staple, scts := p.revocationData(st)
	if r.OCSPStaple == "" {
		r.OCSPStaple = staple
	}
	if len(r.TLSSCTs) == 0 {
		r.TLSSCTs = scts
	}
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

// describeChain describes a presented chain, keeps its raw bytes for
// evaluation, and checks its name. Trust against the bundled root stores is
// decided in evaluation, from the raw certificates; the OS store is consulted
// here only when Options.OSTrust is set.
func (p *prober) describeChain(source string, st *tls.ConnectionState) CertResult {
	chain := st.PeerCertificates
	res := CertResult{Source: source}
	for _, c := range chain {
		res.Chain = append(res.Chain, describeCert(c))
	}
	leaf := chain[0]
	res.OCSPStaple, res.TLSSCTs = p.revocationData(st)

	if p.opts.OSTrust {
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
	}
	if err := leaf.VerifyHostname(p.target.Host); err != nil {
		res.NameError = err.Error()
	} else {
		res.NameMatches = true
	}
	return res
}

// ---- certificate description --------------------------------------------------------------

// describeCert describes one certificate. The facts themselves come from certinfo, the
// one place they are worked out, so a certificate a server presents and the same
// certificate a host holds have identical attributes.
func describeCert(c *x509.Certificate) CertInfo { return DescribeCertificate(c) }

// DescribeCertificate is the CertInfo the scanner records for a certificate,
// raw DER included. Exported for evaluation fixtures and importers.
func DescribeCertificate(c *x509.Certificate) CertInfo {
	f := certinfo.Describe(c)
	ci := CertInfo{
		Subject: f.Subject, Issuer: f.Issuer, SerialHex: f.SerialHex, DNSNames: f.DNSNames, IPAddresses: f.IPAddresses,
		NotBefore: f.NotBefore, NotAfter: f.NotAfter, IsCA: f.IsCA, SelfSigned: f.SelfSigned, SHA256: f.SHA256,
		PublicKey:    KeyInfo{Algorithm: f.KeyAlgorithm, OID: f.KeyOID, Bits: f.KeyBits, Curve: f.Curve},
		SignatureAlg: AlgInfo{Name: f.SigName, OID: f.SigOID},
		OCSPServers:  f.OCSPServers, IssuerURLs: f.IssuerURLs, CRLPoints: f.CRLPoints,
		OCSPMustStaple: f.OCSPMustStaple, EmbeddedSCTs: f.EmbeddedSCTs,

		DER: base64.StdEncoding.EncodeToString(c.Raw), SPKISHA256: f.SPKISHA256, KeyUsage: f.KeyUsage,
		ExtKeyUsage: f.ExtKeyUsage, Policies: f.Policies, PolicyClass: f.PolicyClass, CNOnly: f.CNOnly,
		Wildcards: f.Wildcards, LifetimeDays: f.LifetimeDays, RSAExponent: f.RSAExponent,
		SignatureParams: f.SigParams, AuthorityKeyID: f.AuthorityKey, SubjectKeyID: f.SubjectKey,
	}
	for _, e := range f.Extensions {
		ci.Extensions = append(ci.Extensions, CertExtension{OID: e.OID, Critical: e.Critical, Name: e.Name})
	}
	if bc := f.BasicConstraints; bc != nil {
		ci.BasicConstraints = &BasicConstraints{CA: bc.CA, MaxPathLen: bc.MaxPathLen}
	}
	if nc := f.NameConstraints; nc != nil {
		ci.NameConstraints = &NameConstraints{Critical: nc.Critical, Permitted: nc.Permitted, Excluded: nc.Excluded}
	}
	return ci
}
