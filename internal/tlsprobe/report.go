// Package tlsprobe actively probes a TLS server and reports what it supports:
// protocol versions, every cipher suite, key-exchange groups (including
// post-quantum hybrids), and certificates.
//
// It speaks the protocol itself (package wire) so it can offer things the
// standard library never would, and it works from IANA's registries (package
// registry) so nothing is limited to what a linked TLS library happens to
// implement. Findings here are OBSERVED facts about the server; judging them
// (weak, deprecated, quantum-vulnerable) is the evaluation layer's job.
package tlsprobe

import (
	"time"
)

// SchemaVersion identifies the JSON shape of Report. It changes only with a
// documented, backward-incompatible change.
const SchemaVersion = "tls-report/1"

// Target is one endpoint to probe.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// SNI is the server name sent in the handshake; empty when Host is an IP address.
	SNI string `json:"sni,omitempty"`
}

// Report is everything learned about one endpoint.
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Target        Target    `json:"target"`
	Addresses     []string  `json:"addresses,omitempty"` // every address the name resolved to
	Address       string    `json:"address"`             // the one probed
	Started       time.Time `json:"started"`
	DurationMS    int64     `json:"durationMs"`
	Connections   int       `json:"connections"`

	// Protocols has one entry for every version tested, supported or not.
	Protocols []ProtocolResult `json:"protocols"`
	// Suites lists every cipher suite the server accepted, per protocol version.
	Suites []SuiteResult `json:"suites"`
	// Preference says, per version, whether the server or the client decides.
	Preference []PreferenceResult `json:"preference,omitempty"`
	// Groups lists supported key-exchange groups: TLS 1.3 groups, and the
	// ephemeral-ECDH curves TLS 1.2 and earlier servers use.
	Groups []GroupResult `json:"groups,omitempty"`
	// DH describes the finite-field Diffie-Hellman parameters of DHE suites.
	DH *DHResult `json:"dh,omitempty"`

	Features     Features     `json:"features"`
	Certificates []CertResult `json:"certificates,omitempty"`
	// Negotiated is what a current client (Go's crypto/tls, which offers the
	// X25519MLKEM768 hybrid) actually negotiates with this server.
	Negotiated *Negotiated `json:"negotiated,omitempty"`

	// Notes are non-fatal observations about the probing itself.
	Notes []string `json:"notes,omitempty"`
	// Incomplete is true when some probes were inconclusive (timeouts, budget);
	// absence of a finding is then not evidence of absence.
	Incomplete bool `json:"incomplete"`
}

// Evidence says how a result was obtained.
type Evidence string

// The evidence kinds. Observed means a server reply demonstrated it.
const (
	EvidenceServerHello  Evidence = "server-hello" // the server answered with a ServerHello / HelloRetryRequest
	EvidenceAlert        Evidence = "alert"        // the server refused with a TLS alert
	EvidenceClosed       Evidence = "closed"       // the server closed the connection without answering
	EvidenceInconclusive Evidence = "inconclusive" // timeout or network error: proves nothing
)

// ProtocolResult is the outcome of probing one protocol version.
type ProtocolResult struct {
	Version   string   `json:"version"` // "SSLv2", "SSLv3", "TLSv1.0" ... "TLSv1.3"
	Code      uint16   `json:"code"`
	Supported bool     `json:"supported"`
	Evidence  Evidence `json:"evidence"`
	Detail    string   `json:"detail,omitempty"` // alert name or error
}

// SuiteResult is one accepted cipher suite together with its registry properties.
type SuiteResult struct {
	Version string `json:"version"`
	ID      uint16 `json:"id"`
	Name    string `json:"name"`
	// Rank is the suite's position in the server's preference order (1 = most
	// preferred) when the server enforces its own order, and 0 when there is no
	// server ranking (the server follows the client's order, or is mixed).
	Rank int `json:"rank"`

	// IANA registry properties; see registry.Suite.
	IANARecommended string `json:"ianaRecommended"`
	Kx              string `json:"kx,omitempty"`
	Auth            string `json:"auth,omitempty"`
	Cipher          string `json:"cipher"`
	KeyBits         int    `json:"keyBits,omitempty"`
	Mode            string `json:"mode"`
	BlockBits       int    `json:"blockBits,omitempty"`
	MAC             string `json:"mac"`
	AEAD            bool   `json:"aead"`
	Export          bool   `json:"export,omitempty"`
	Anon            bool   `json:"anon,omitempty"`
	Ephemeral       bool   `json:"ephemeral,omitempty"`
}

// PreferenceResult records who decides between the suites (or groups) offered.
type PreferenceResult struct {
	Version string `json:"version"`
	// Subject is "suites" or "groups".
	Subject string `json:"subject"`
	// Order is "server" (the server picks by its own list), "client" (it picks the
	// first acceptable in the client's list), "mixed" (it does one for some pairs and
	// the other for others) or "unknown" (fewer than two items, or no answer).
	Order string `json:"order"`
}

// GroupResult is one key-exchange group the server accepts.
type GroupResult struct {
	// Version is "TLSv1.3" for groups learned via HelloRetryRequest, or
	// "TLSv1.2" for the ECDHE curves of TLS 1.2 and earlier.
	Version string `json:"version"`
	ID      uint16 `json:"id"`
	Name    string `json:"name"`
	// Rank: 1 = most preferred, 0 = no server ranking (client-order server).
	Rank int `json:"rank"`

	IANARecommended string `json:"ianaRecommended"`
	PQ              bool   `json:"pq,omitempty"`
	Hybrid          bool   `json:"hybrid,omitempty"`
	Obsolete        bool   `json:"obsolete,omitempty"` // IANA marks this draft-era name OBSOLETE
}

// DHResult describes the server's DHE parameters, as sent in ServerKeyExchange.
type DHResult struct {
	PrimeBits     int    `json:"primeBits"`
	GeneratorBits int    `json:"generatorBits"`
	PrimeSHA256   string `json:"primeSha256"` // fingerprint of the prime, for matching known groups
	Suite         string `json:"suite"`       // the suite the sample came from
}

// Features are server behaviours read from hello messages.
type Features struct {
	// SecureRenegotiation: the server echoed renegotiation_info (RFC 5746).
	SecureRenegotiation *bool `json:"secureRenegotiation,omitempty"`
	// ExtendedMasterSecret: the server echoed extended_master_secret (RFC 7627).
	ExtendedMasterSecret *bool `json:"extendedMasterSecret,omitempty"`
	// SessionTickets: the server offered session tickets.
	SessionTickets *bool `json:"sessionTickets,omitempty"`
	// EncryptThenMAC: the server echoed encrypt_then_mac (RFC 7366).
	EncryptThenMAC *bool `json:"encryptThenMac,omitempty"`
	// OCSPStapling: the server supports status_request.
	OCSPStapling *bool `json:"ocspStapling,omitempty"`
	// Compression: the server accepted TLS-level compression (CRIME).
	Compression *bool `json:"compression,omitempty"`
	// FallbackSCSV: the server enforces TLS_FALLBACK_SCSV (RFC 7507); nil when it
	// could not be tested (fewer than two supported versions).
	FallbackSCSV *bool `json:"fallbackScsv,omitempty"`
}

// CertResult is one certificate the server presented.
type CertResult struct {
	// Source says how it was obtained, e.g. "tls-default", "tls1.2-ecdsa", "tls1.2-rsa".
	Source string `json:"source"`
	// Chain is the presented chain, leaf first.
	Chain []CertInfo `json:"chain"`
	// Trusted: the chain builds to a root in the trust store.
	Trusted    bool   `json:"trusted"`
	TrustError string `json:"trustError,omitempty"`
	// NameMatches: the leaf is valid for the target host name.
	NameMatches bool   `json:"nameMatches"`
	NameError   string `json:"nameError,omitempty"`
}

// CertInfo describes one certificate.
type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialHex    string    `json:"serial"`
	DNSNames     []string  `json:"dnsNames,omitempty"`
	IPAddresses  []string  `json:"ipAddresses,omitempty"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
	IsCA         bool      `json:"isCa"`
	SelfSigned   bool      `json:"selfSigned"`
	SHA256       string    `json:"sha256"`
	PublicKey    KeyInfo   `json:"publicKey"`
	SignatureAlg AlgInfo   `json:"signatureAlgorithm"`

	OCSPServers    []string `json:"ocspServers,omitempty"`
	IssuerURLs     []string `json:"issuerUrls,omitempty"`
	CRLPoints      []string `json:"crlPoints,omitempty"`
	OCSPMustStaple bool     `json:"ocspMustStaple,omitempty"`
	EmbeddedSCTs   bool     `json:"embeddedScts,omitempty"`
	ParseError     string   `json:"parseError,omitempty"`
}

// KeyInfo describes a public key.
type KeyInfo struct {
	Algorithm string `json:"algorithm"` // RSA, ECDSA, Ed25519, ... or "unknown"
	OID       string `json:"oid"`       // the SubjectPublicKeyInfo algorithm OID
	Bits      int    `json:"bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

// AlgInfo names an algorithm and carries its OID.
type AlgInfo struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
}

// Negotiated is the outcome of a full handshake by a current client.
type Negotiated struct {
	Version    string `json:"version"`
	Suite      string `json:"suite"`
	SuiteID    uint16 `json:"suiteId"`
	Group      string `json:"group,omitempty"`
	GroupID    uint16 `json:"groupId,omitempty"`
	PQ         bool   `json:"pq"`
	ALPN       string `json:"alpn,omitempty"`
	OCSPStaple bool   `json:"ocspStaple"`
	Error      string `json:"error,omitempty"`
}
