package wincng

import "github.com/example/cipherhorizon/internal/winapi"

// The platform layer's types, under this package's names, so the sensor reads as one
// unit while every call into Windows stays in internal/winapi.
type (
	// API is what the sensor needs from Windows.
	API = winapi.API
	// Algorithm is one registered algorithm identifier.
	Algorithm = winapi.Algorithm
	// StorageProvider is a registered key storage provider.
	StorageProvider = winapi.StorageProvider
	// CSP is a registered legacy cryptographic service provider.
	CSP = winapi.CSP
	// StatusError is a failed Windows call.
	StatusError = winapi.StatusError
)

// Operation classes and limits.
const (
	OpCipher            = winapi.OpCipher
	OpHash              = winapi.OpHash
	OpAsymmetricEncrypt = winapi.OpAsymmetricEncrypt
	OpSecretAgreement   = winapi.OpSecretAgreement
	OpSignature         = winapi.OpSignature
	OpRNG               = winapi.OpRNG
	OpKeyDerivation     = winapi.OpKeyDerivation
	OpAll               = winapi.OpAll
	MaxName             = winapi.MaxName
)

// ErrUnsupported means the API exists only on Windows.
var ErrUnsupported = winapi.ErrUnsupported

// NewAPI returns the real Windows implementation, or a stub off Windows.
func NewAPI() API { return winapi.New() }
