package server

import "crypto/tls"

// TLSConfig is the configuration of the server's own HTTPS listener (PRD-007 REQ-SS-1). It is
// what this product's own rules call good: TLS 1.2 and 1.3 only; in TLS 1.2 only ECDHE suites
// with authenticated encryption (no CBC, no RSA key transport, no 64-bit ciphers); in TLS 1.3
// Go's suites, and Go's default groups, which offer the hybrid X25519MLKEM768 first. A test scans
// a listener built from this with the product's own scanner and expects no finding.
func TLSConfig(certs []tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: certs,
		CipherSuites: []uint16{ // TLS 1.2 only; TLS 1.3 suites are not configurable
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

// hstsValue is sent on every response that reached the server over HTTPS (REQ-SS-2): one year,
// the minimum the product's own HSTS check accepts without a note.
const hstsValue = "max-age=31536000"
