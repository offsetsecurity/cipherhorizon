package winapi

import "errors"

// StoreLocation is where a system certificate store lives.
type StoreLocation string

// The store locations the layer will read.
const (
	LocalMachine StoreLocation = "LocalMachine"
	CurrentUser  StoreLocation = "CurrentUser"
)

// CertStoreNames is the fixed list of system store names the layer will open (ADR-0016).
// The Disallowed store is left out on purpose: a certificate on a deny list must not be
// mistaken for a trust anchor.
var CertStoreNames = []string{"MY", "Root", "CA", "TrustedPeople", "TrustedPublisher", "AuthRoot"}

// Limits on what one store can make a run carry (ADR-0016).
const (
	MaxCertsPerStore = 20_000
	MaxCertDER       = 64 << 10
)

// Private-key answers. "no" means no key is associated with the certificate in that
// store; it is not a claim about any other place.
const (
	KeyYes     = "yes"
	KeyNo      = "no"
	KeyUnknown = "unknown"
)

// StoreCert is one certificate from a store: its own encoded bytes and whether a private
// key is associated with it. Nothing else is read from the store.
type StoreCert struct {
	DER        []byte
	PrivateKey string
}

// CertStoreAPI is what the certificate sensor needs from Windows.
type CertStoreAPI interface {
	// Native reports whether this is the real Windows implementation.
	Native() bool
	// CertStore lists the certificates in one allow-listed store. A store that does not
	// exist yields no certificates and no error. skipped counts certificates left out
	// because they were too large or the store held more than MaxCertsPerStore.
	CertStore(loc StoreLocation, name string) (certs []StoreCert, skipped int, err error)
}

// ValidStore reports whether (loc, name) is on the allow-list. The real implementation
// checks it before calling Windows, whoever the caller is.
func ValidStore(loc StoreLocation, name string) bool {
	if loc != LocalMachine && loc != CurrentUser {
		return false
	}
	for _, n := range CertStoreNames {
		if n == name {
			return true
		}
	}
	return false
}

// ErrStoreNotAllowed is returned for a store outside the allow-list.
var ErrStoreNotAllowed = errors.New("winapi: that certificate store is not on the allow-list")
