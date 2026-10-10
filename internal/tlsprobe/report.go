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
// documented change. tls-report/2 adds the stage records, the raw served
// certificates, the stapled OCSP response and TLS SCTs, the no-SNI chain and
// the parsed HSTS header; every /1 field keeps its meaning.
const SchemaVersion = "tls-report/2"

// SchemaVersion1 is the previous shape, still read from stored scans.
const SchemaVersion1 = "tls-report/1"

// Target is one endpoint to probe.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// SNI is the server name sent in the handshake; empty when Host is an IP address.
	SNI string `json:"sni,omitempty"`
	// StartTLS names the plain-text protocol every connection negotiates before TLS (smtp, imap,
	// pop3, ftp, xmpp, ldap, postgres); empty for a service that speaks TLS from the first byte.
	StartTLS string `json:"starttls,omitempty"`
}

// serverName is the name a STARTTLS exchange addresses (XMPP's stream "to").
func (t Target) serverName() string {
	if t.SNI != "" {
		return t.SNI
	}
	return t.Host
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
	// HSTS is whether the server sends Strict-Transport-Security, read from one
	// plain HTTP GET / made only when Options.HTTPChecks is set. nil when the
	// check was not attempted (the default) or the connection did not answer
	// with an HTTP response; true/false only when a response was observed.
	HSTS *bool `json:"hsts,omitempty"`
	// HSTSHeader is what the Strict-Transport-Security header said, parsed. nil
	// when no HTTP response was read.
	HSTSHeader *HSTSResult `json:"hstsHeader,omitempty"`
	// NoSNI is what a handshake without server_name returned: "same" (the same
	// leaf as with SNI), "different" (a separate certificate result with NoSNI
	// set), "failed", or empty when not attempted (the target is an address).
	NoSNI string `json:"noSni,omitempty"`

	// Stages record, for each part of the scan (the sections of the endpoint
	// page), whether it ran, why not, and what it cost.
	Stages []Stage `json:"stages,omitempty"`

	// Notes are non-fatal observations about the probing itself.
	Notes []string `json:"notes,omitempty"`
	// Incomplete is true when some probes were inconclusive (timeouts, budget);
	// absence of a finding is then not evidence of absence.
	Incomplete bool `json:"incomplete"`
}

// Stage names: fixed, they are the endpoint page's sections.
const (
	StageProtocols   = "protocols"
	StageSuites      = "suites"
	StageKeyExchange = "key-exchange"
	StageFeatures    = "features"
	StageCerts       = "certificates"
	StageRevocation  = "revocation"
	StageHTTP        = "http"
)

// Stage outcomes and reason codes.
const (
	OutcomeDone         = "done"
	OutcomeSkipped      = "skipped"
	OutcomeInconclusive = "inconclusive"

	ReasonOptionOff     = "option-off"
	ReasonNotApplicable = "not-applicable"
	ReasonNotReached    = "not-reached"
	ReasonBudget        = "budget"
	ReasonLegacy        = "legacy-report"
)

// Stage is one part of the scan.
type Stage struct {
	Name        string   `json:"name"`
	Outcome     string   `json:"outcome"`
	Reason      string   `json:"reason,omitempty"`
	ReasonCode  string   `json:"reasonCode,omitempty"`
	Connections int      `json:"connections"`
	Probes      []string `json:"probes,omitempty"` // what was sent, in words
	// Inconclusive lists the parts of a done stage that proved nothing
	// (timeouts, budget), so an absent finding there is not evidence of absence.
	Inconclusive []string `json:"inconclusive,omitempty"`
}

// HSTSResult is the parsed Strict-Transport-Security header (RFC 6797 §6.1).
type HSTSResult struct {
	// Values are the raw header values, cleaned and bounded (at most 4, each at
	// most 512 bytes). Empty: the response had no such header.
	Values            []string `json:"values,omitempty"`
	MaxAge            *int64   `json:"maxAge,omitempty"`
	IncludeSubDomains bool     `json:"includeSubDomains,omitempty"`
	Preload           bool     `json:"preload,omitempty"`
	// Problems are reasons the header is invalid; a user agent ignores an
	// invalid header entirely.
	Problems []string `json:"problems,omitempty"`
}

// Valid reports whether a header was present and a user agent would honour it.
func (h *HSTSResult) Valid() bool {
	return h != nil && len(h.Values) > 0 && h.MaxAge != nil && len(h.Problems) == 0
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
	// ClientCertRequested: the server sent a CertificateRequest (RFC 8446 section
	// 4.3.2) during the handshake, i.e. it wants (or requires) a client
	// certificate (mTLS). true is set the moment the server asks, even if the
	// handshake then fails for lack of one. false is set only when a full
	// handshake succeeded without ever asking. Anything else (the handshake
	// failed before or without a request) leaves this nil: unknown, not "no."
	ClientCertRequested *bool `json:"clientCertRequested,omitempty"`
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

	// NoSNI marks the chain returned to a handshake without server_name, when it
	// differs from the SNI chain.
	NoSNI bool `json:"noSni,omitempty"`
	// OCSPStaple is the raw stapled OCSP response (base64), at most 64 KiB.
	OCSPStaple string `json:"ocspStaple,omitempty"`
	// TLSSCTs are the raw SCTs from the TLS extension (base64), at most 32.
	TLSSCTs []string `json:"tlsScts,omitempty"`
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

	// tls-report/2 additions.
	DER              string            `json:"der,omitempty"` // base64 of the certificate as served
	SPKISHA256       string            `json:"spkiSha256,omitempty"`
	KeyUsage         []string          `json:"keyUsage,omitempty"`
	ExtKeyUsage      []string          `json:"extKeyUsage,omitempty"`
	BasicConstraints *BasicConstraints `json:"basicConstraints,omitempty"`
	NameConstraints  *NameConstraints  `json:"nameConstraints,omitempty"`
	Policies         []string          `json:"policies,omitempty"`
	PolicyClass      string            `json:"policyClass,omitempty"` // DV | OV | IV | EV | unknown
	CNOnly           bool              `json:"cnOnly,omitempty"`
	Wildcards        []string          `json:"wildcards,omitempty"`
	LifetimeDays     int               `json:"lifetimeDays,omitempty"`
	RSAExponent      int               `json:"rsaExponent,omitempty"`
}

// BasicConstraints is the basicConstraints extension.
type BasicConstraints struct {
	CA         bool `json:"ca"`
	MaxPathLen int  `json:"maxPathLen"` // -1 when absent
}

// NameConstraints is the nameConstraints extension.
type NameConstraints struct {
	Critical  bool     `json:"critical"`
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
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
