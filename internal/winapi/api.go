// Package winapi is the platform layer for Windows cryptography: the ONLY code in
// the collector that calls the CNG, key storage and legacy CSP APIs. Like
// internal/hostinfo it is where operating-system code lives, so nothing else has to
// import x/sys/windows or unsafe (enforced by internal/archtest).
//
// It knows nothing about evidence, CBOMs or knowledge: it answers "what does Windows
// say", with bounded, validated values. The sensor in internal/sense/wincng turns the
// answers into evidence.
//
// It is split so the logic above it is testable anywhere:
//
//   - api.go         the interface, the limits and the error type;
//   - api_windows.go the real implementation (hand-written, bounded);
//   - api_other.go   a stub for every other operating system.
//
// Security rules (ADR-0004, ADR-0005, ADR-0013): no subprocess and no network; no
// private key, certificate or secret is opened or enumerated; a provider is opened
// (which loads its code) only when the caller asks for that one provider, and the
// sensor asks only for an allow-listed in-box provider; every string that comes back
// is bounded and checked before it is used.
package winapi

import (
	"errors"
	"fmt"
)

// Operation classes for BCryptEnumAlgorithms and NCryptEnumAlgorithms (the
// BCRYPT_*_OPERATION values in bcrypt.h).
const (
	OpCipher            uint32 = 0x00000001
	OpHash              uint32 = 0x00000002
	OpAsymmetricEncrypt uint32 = 0x00000004
	OpSecretAgreement   uint32 = 0x00000008
	OpSignature         uint32 = 0x00000010
	OpRNG               uint32 = 0x00000020
	OpKeyDerivation     uint32 = 0x00000040
	OpAll               uint32 = 0x0000007f
)

// Limits. Every one bounds what a misconfigured or hostile registration can make a
// run read or carry.
const (
	MaxEntries = 2048 // algorithms, providers or CSPs accepted from one call
	MaxName    = 256  // UTF-16 code units in one name
)

// Algorithm is one identifier CNG has registered.
type Algorithm struct {
	Name string
	// Ops is the set of operation classes it supports.
	Ops uint32
}

// StorageProvider is a registered key storage provider.
type StorageProvider struct {
	Name    string
	Comment string
}

// CSP is a registered legacy cryptographic service provider.
type CSP struct {
	Name string
	Type uint32 // PROV_* provider type
}

// API is what the sensor needs from Windows. Every method returns only bounded,
// valid strings; a value that is not is omitted and counted in Skipped.
type API interface {
	// Native reports whether this is the real Windows implementation. A fake or the
	// non-Windows stub returns false, so the sensor is not detected on a host it
	// cannot describe.
	Native() bool
	// Algorithms lists the registered algorithm identifiers that support ops.
	Algorithms(ops uint32) (list []Algorithm, skipped int, err error)
	// AlgorithmProviders lists the CNG providers registered for one algorithm.
	AlgorithmProviders(algID string) (names []string, skipped int, err error)
	// RegisteredProviders lists every registered CNG provider.
	RegisteredProviders() (names []string, skipped int, err error)
	// StorageProviders lists the registered key storage providers. It loads none.
	StorageProviders() (list []StorageProvider, skipped int, err error)
	// StorageProviderAlgorithms opens ONE key storage provider and lists the
	// algorithms it offers. The sensor calls it only for allow-listed providers.
	StorageProviderAlgorithms(provider string, ops uint32) (list []Algorithm, skipped int, err error)
	// CSPs lists the registered legacy providers. It loads none.
	CSPs() (list []CSP, skipped int, err error)
	// Probe reports whether the default CNG provider will open algID and, when
	// paramSet (digits only) is not empty, accept it as the algorithm's parameter
	// set. Probing a parameter set generates an ephemeral in-memory key pair and
	// destroys it immediately; it is never exported, stored or used.
	Probe(algID, paramSet string) (bool, error)
}

// StatusError is a failed Windows call and its NTSTATUS or Win32 code.
type StatusError struct {
	Call string
	Code uint32
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s failed: 0x%08X", e.Call, e.Code) }

// ErrUnsupported means the API exists only on Windows.
var ErrUnsupported = errors.New("wincng: Windows cryptography is not available on this operating system")
