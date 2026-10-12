// Package sshprobe actively probes an SSH server and reports, with evidence, what it offers: its
// identification, every algorithm it advertises, what a current client negotiates with it, and
// each of its host keys. It never authenticates and never opens a channel: every connection ends
// at the server's key-exchange reply, before any key is derived (ADR-0019).
//
// It speaks the protocol itself (package wire), from the standard library only, so it can see
// what a client library would refuse (DSA keys, SHA-1 key exchange, CBC) and record exactly where
// each fact came from. Findings here are observations; judging them is internal/eval's job.
package sshprobe

import (
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/wire"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// SchemaVersion identifies the JSON shape of Report.
const SchemaVersion = "ssh-report/1"

// Target is one SSH endpoint.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Stage is the same record the TLS report keeps for each part of a scan.
type Stage = tlsprobe.Stage

// Stage names, in page order.
const (
	StageIdentification = "identification"
	StageAlgorithms     = "algorithms"
	StageNegotiation    = "negotiation"
	StageHostKeys       = "host-keys"
)

// StageNames lists the stages in order.
var StageNames = []string{StageIdentification, StageAlgorithms, StageNegotiation, StageHostKeys}

// Report is everything learned about one SSH endpoint.
type Report struct {
	SchemaVersion string    `json:"schemaVersion"`
	Target        Target    `json:"target"`
	Addresses     []string  `json:"addresses,omitempty"`
	Address       string    `json:"address"`
	Started       time.Time `json:"started"`
	DurationMS    int64     `json:"durationMs"`
	Connections   int       `json:"connections"`

	Identification *Identification `json:"identification,omitempty"`
	// Algorithms is the server's own KEXINIT: what it advertises.
	Algorithms *Algorithms `json:"algorithms,omitempty"`
	// Negotiated is what a current client (OpenSSH 10.6's default lists) gets.
	Negotiated *Negotiated `json:"negotiated,omitempty"`
	HostKeys   []HostKey   `json:"hostKeys"`
	// HostKeyAttempts records, per advertised host key algorithm, what fetching it gave.
	HostKeyAttempts []HostKeyAttempt `json:"hostKeyAttempts"`

	Stages     []Stage  `json:"stages"`
	Notes      []string `json:"notes,omitempty"`
	Incomplete bool     `json:"incomplete"`
}

// Identification is the server's identification line.
type Identification struct {
	Raw          string   `json:"raw"`
	ProtoVersion string   `json:"protoVersion"`
	Software     string   `json:"software"`
	Comment      string   `json:"comment,omitempty"`
	SSH1         bool     `json:"ssh1"`     // the server accepts SSH-1 ("1.x", or "1.99" meaning both)
	SSH1Only     bool     `json:"ssh1Only"` // and nothing else
	Preamble     []string `json:"preamble,omitempty"`
}

// Algorithms are the name-lists of the server's KEXINIT (RFC 4253 section 7.1). Kex holds key
// exchanges only; the signals carried in the same list are broken out.
type Algorithms struct {
	Kex            []string `json:"kex"`
	HostKey        []string `json:"hostKey"`
	CipherC2S      []string `json:"cipherC2S"`
	CipherS2C      []string `json:"cipherS2C"`
	MACC2S         []string `json:"macC2S"`
	MACS2C         []string `json:"macS2C"`
	CompressionC2S []string `json:"compressionC2S"`
	CompressionS2C []string `json:"compressionS2C"`
	// StrictKex: kex-strict-s-v00@openssh.com, OpenSSH's countermeasure to Terrapin (CVE-2023-48795).
	StrictKex bool `json:"strictKex"`
	// ExtInfo: ext-info-s (RFC 8308).
	ExtInfo bool `json:"extInfo"`
	// Signals are the other non-algorithm entries of the kex list, verbatim (cleaned).
	Signals []string `json:"signals,omitempty"`
}

// Negotiated is the outcome of negotiating as a current client.
type Negotiated struct {
	Client      string `json:"client"` // "OpenSSH 10.6 defaults"
	Kex         string `json:"kex,omitempty"`
	HostKey     string `json:"hostKey,omitempty"`
	Cipher      string `json:"cipher,omitempty"`
	MAC         string `json:"mac,omitempty"` // empty with an AEAD cipher
	Compression string `json:"compression,omitempty"`
	// Completed: the key exchange ran to the server's reply. Verified: the server's signature
	// over the exchange hash checked out with the host key it sent.
	Completed bool `json:"completed"`
	Verified  bool `json:"verified"`
	// Evidence is observed (the exchange was carried out) or computed (the choice follows from the
	// two lists by RFC 4253 section 7.1, but this scanner does not implement that method).
	Evidence string `json:"evidence"`
	Error    string `json:"error,omitempty"`
}

// Evidence values for Negotiated.
const (
	EvidenceObserved = "observed"
	EvidenceComputed = "computed"
)

// HostKey is one host key the server presented.
type HostKey struct {
	Type        string            `json:"type"`      // the blob's type: "ssh-ed25519", "ssh-mldsa44-ed25519", "ssh-rsa"
	Algorithm   string            `json:"algorithm"` // "Ed25519", "ECDSA", "RSA", "ML-DSA-44+Ed25519"
	Bits        int               `json:"bits,omitempty"`
	Curve       string            `json:"curve,omitempty"`
	PQ          bool              `json:"pq,omitempty"`
	Fingerprint string            `json:"fingerprint"`
	Blob        string            `json:"blob"` // base64, at most wire.MaxHostKeyBlob
	ServedBy    []string          `json:"servedBy"`
	Verified    bool              `json:"verified"`
	VerifyNote  string            `json:"verifyNote,omitempty"`
	Certificate *wire.Certificate `json:"certificate,omitempty"`
}

// HostKeyAttempt is what asking for one host key algorithm gave.
type HostKeyAttempt struct {
	Algorithm string `json:"algorithm"`
	Kex       string `json:"kex,omitempty"`
	Outcome   string `json:"outcome"` // key | refused | no-common-kex | inconclusive
	Detail    string `json:"detail,omitempty"`
}

// Host key attempt outcomes.
const (
	AttemptKey          = "key"
	AttemptRefused      = "refused"
	AttemptNoCommonKex  = "no-common-kex"
	AttemptInconclusive = "inconclusive"
)

// PQKex returns the advertised post-quantum key exchanges.
func (a *Algorithms) PQKex() []string {
	if a == nil {
		return nil
	}
	var out []string
	for _, k := range a.Kex {
		if isPQKex(k) {
			out = append(out, k)
		}
	}
	return out
}
