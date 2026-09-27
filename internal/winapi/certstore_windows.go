//go:build windows

package winapi

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Certificate store enumeration (ADR-0016). Like the rest of this package it is
// hand-written and bounded, and it follows the ADR's constraints exactly:
//
//   - stores are opened read-only and existing-only, from a fixed allow-list, checked here
//     whatever the caller passes;
//   - only the certificate's own encoded bytes are copied out;
//   - no function that opens, acquires, exports or uses a private key is called anywhere in
//     this package (TestNoKeyMaterialFunctionIsCalled scans the source);
//   - private-key presence is one property query with no output buffer, which can only say
//     whether a key association exists, never what it contains;
//   - every certificate context is freed on every path.

var (
	crypt32                            = windows.NewLazySystemDLL("crypt32.dll")
	pCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
)

const (
	certKeyProvInfoPropID = 2          // CERT_KEY_PROV_INFO_PROP_ID
	errFileNotFound       = 2          // ERROR_FILE_NOT_FOUND: the store does not exist
	cryptENotFound        = 0x80092004 // CRYPT_E_NOT_FOUND: no more certificates, or no such property
)

// NewCertStore returns the real Windows implementation.
func NewCertStore() CertStoreAPI { return winCertStores{} }

type winCertStores struct{}

// Native implements CertStoreAPI.
func (winCertStores) Native() bool { return true }

// CertStore implements CertStoreAPI.
func (winCertStores) CertStore(loc StoreLocation, name string) ([]StoreCert, int, error) {
	if !ValidStore(loc, name) {
		return nil, 0, ErrStoreNotAllowed
	}
	if err := find(pCertGetCertificateContextProperty); err != nil {
		return nil, 0, err
	}
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, 0, err
	}
	flags := uint32(windows.CERT_STORE_OPEN_EXISTING_FLAG | windows.CERT_STORE_READONLY_FLAG)
	if loc == LocalMachine {
		flags |= windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	} else {
		flags |= windows.CERT_SYSTEM_STORE_CURRENT_USER
	}
	store, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(namePtr))) //nolint:gosec // audited: the name is a NUL-terminated UTF-16 string we own, from a fixed allow-list
	if err != nil {
		var errno windows.Errno
		if errors.As(err, &errno) && errno == errFileNotFound {
			return nil, 0, nil // a store that does not exist has no certificates
		}
		return nil, 0, &StatusError{"CertOpenStore", errnoCode(err)}
	}
	defer windows.CertCloseStore(store, 0) //nolint:errcheck // read-only handle

	var out []StoreCert
	skipped := 0
	var prev *windows.CertContext
	for n := 0; ; n++ {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if ctx == nil {
			// The previous context is freed by the enumeration call itself when it returns nil.
			if err != nil {
				var errno windows.Errno
				if !errors.As(err, &errno) || uint32(errno) != cryptENotFound {
					return out, skipped, &StatusError{"CertEnumCertificatesInStore", errnoCode(err)}
				}
			}
			return out, skipped, nil
		}
		prev = ctx
		if n >= MaxCertsPerStore {
			skipped++
			_ = windows.CertFreeCertificateContext(prev) // stop early: free what we hold
			return out, skipped, nil
		}
		if ctx.Length == 0 || ctx.Length > MaxCertDER || ctx.EncodedCert == nil {
			skipped++
			continue
		}
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length)) //nolint:gosec // audited: the length is capped above and the OS owns the buffer for the life of the context
		out = append(out, StoreCert{DER: der, PrivateKey: keyAssociation(ctx)})
	}
}

// keyAssociation asks whether the certificate has a key association: one property query
// with NO output buffer. That form can only report that the property exists; it cannot
// return its contents, and it does not open the key or its provider.
func keyAssociation(ctx *windows.CertContext) string {
	var cb uint32
	ok, _, callErr := pCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&cb))) //nolint:gosec // audited: a context we hold, a fixed property id, no output buffer
	if ok != 0 {
		return KeyYes
	}
	var errno windows.Errno
	if errors.As(callErr, &errno) && uint32(errno) == cryptENotFound {
		return KeyNo
	}
	return KeyUnknown
}

func errnoCode(err error) uint32 {
	var errno windows.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}
