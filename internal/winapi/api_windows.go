//go:build windows

package winapi

import (
	"errors"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file is the ONLY code in the collector that calls Windows cryptography. It is
// hand-written, so it is small and each function follows the same rules:
//
//   - the libraries come from System32 only (NewLazySystemDLL), never from the
//     current directory or PATH;
//   - a list the OS allocates is always freed, and its element count is capped
//     BEFORE it is used to size a slice (MaxEntries), whatever the OS said;
//   - a string is read with an explicit length cap (MaxName) and must be valid,
//     printable and terminated inside it, or it is skipped and counted, never
//     passed on;
//   - nothing here opens a key, a certificate or a secret, and a provider is
//     opened (which loads its code) only by StorageProviderAlgorithms and Probe,
//     for the providers the sensor's allow-list names.

var (
	bcrypt = windows.NewLazySystemDLL("bcrypt.dll")
	ncrypt = windows.NewLazySystemDLL("ncrypt.dll")
	advapi = windows.NewLazySystemDLL("advapi32.dll")

	pBCryptEnumAlgorithms          = bcrypt.NewProc("BCryptEnumAlgorithms")
	pBCryptEnumProviders           = bcrypt.NewProc("BCryptEnumProviders")
	pBCryptEnumRegisteredProviders = bcrypt.NewProc("BCryptEnumRegisteredProviders")
	pBCryptFreeBuffer              = bcrypt.NewProc("BCryptFreeBuffer")
	pBCryptOpenAlgorithmProvider   = bcrypt.NewProc("BCryptOpenAlgorithmProvider")
	pBCryptCloseAlgorithmProvider  = bcrypt.NewProc("BCryptCloseAlgorithmProvider")
	pBCryptSetProperty             = bcrypt.NewProc("BCryptSetProperty")
	pBCryptGenerateKeyPair         = bcrypt.NewProc("BCryptGenerateKeyPair")
	pBCryptFinalizeKeyPair         = bcrypt.NewProc("BCryptFinalizeKeyPair")
	pBCryptDestroyKey              = bcrypt.NewProc("BCryptDestroyKey")

	pNCryptEnumStorageProviders = ncrypt.NewProc("NCryptEnumStorageProviders")
	pNCryptOpenStorageProvider  = ncrypt.NewProc("NCryptOpenStorageProvider")
	pNCryptEnumAlgorithms       = ncrypt.NewProc("NCryptEnumAlgorithms")
	pNCryptFreeBuffer           = ncrypt.NewProc("NCryptFreeBuffer")
	pNCryptFreeObject           = ncrypt.NewProc("NCryptFreeObject")

	pCryptEnumProvidersW = advapi.NewProc("CryptEnumProvidersW")
)

// NTSTATUS values that mean "this system does not offer that", which a probe reports
// as an answer (no) rather than as a failure.
const (
	statusNotFound     = 0xC0000225
	statusNotSupported = 0xC00000BB
	statusInvalidParam = 0xC000000D
	errNoMoreItems     = 259 // ERROR_NO_MORE_ITEMS
	ntSuccess          = 0
	paramSetNameProp   = "ParameterSetName" // BCRYPT_PARAMETER_SET_NAME
	classFirst         = 1
	classLast          = 7
)

// New returns the real Windows implementation.
func New() API { return winAPI{} }

type winAPI struct{}

// Native implements API.
func (winAPI) Native() bool { return true }

// find loads the export, so a Windows that lacks it (an older build) reports
// "unsupported" instead of crashing.
func find(p *windows.LazyProc) error {
	if err := p.Find(); err != nil {
		return ErrUnsupported
	}
	return nil
}

// readString reads a NUL-terminated UTF-16 string of at most MaxName code units.
// ok is false for a nil pointer, a string that does not end inside the cap, invalid
// UTF-16, or a control character.
func readString(p *uint16) (string, bool) {
	if p == nil {
		return "", false
	}
	units := make([]uint16, 0, 32)
	for i := 0; i < MaxName; i++ {
		c := *(*uint16)(unsafe.Add(unsafe.Pointer(p), i*2)) //nolint:gosec // bounded by MaxName; the OS terminates its strings
		if c == 0 {
			s := string(utf16.Decode(units))
			return s, printable(s)
		}
		units = append(units, c)
	}
	return "", false // not terminated within the cap
}

// printable accepts non-empty text with no control character and no replacement
// character (which UTF-16 decoding produces for a lone surrogate).
func printable(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == 0xFFFD {
			return false
		}
	}
	return true
}

// capCount bounds an element count reported by the OS before it sizes anything.
func capCount(n uint32) int {
	if n > MaxEntries {
		return MaxEntries
	}
	return int(n)
}

func freeBCrypt(p unsafe.Pointer) {
	if p != nil {
		_, _, _ = pBCryptFreeBuffer.Call(uintptr(p))
	}
}

func freeNCrypt(p unsafe.Pointer) {
	if p != nil {
		_, _, _ = pNCryptFreeBuffer.Call(uintptr(p))
	}
}

// algorithmIdentifier is BCRYPT_ALGORITHM_IDENTIFIER.
type algorithmIdentifier struct {
	name  *uint16
	class uint32
	flags uint32
}

// ncryptAlgorithmName is NCryptAlgorithmName.
type ncryptAlgorithmName struct {
	name  *uint16
	class uint32
	ops   uint32
	flags uint32
}

// classBit turns an interface class (1 to 7) into the matching operation bit.
func classBit(class uint32) uint32 {
	if class < classFirst || class > classLast {
		return 0
	}
	return 1 << (class - 1)
}

// Algorithms implements API.
func (winAPI) Algorithms(ops uint32) ([]Algorithm, int, error) {
	if err := find(pBCryptEnumAlgorithms); err != nil {
		return nil, 0, err
	}
	var count uint32
	var list unsafe.Pointer
	st, _, _ := pBCryptEnumAlgorithms.Call(uintptr(ops), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"BCryptEnumAlgorithms", uint32(st)} //nolint:gosec // NTSTATUS is 32 bits
	}
	defer freeBCrypt(list)
	if list == nil || count == 0 {
		return nil, 0, nil
	}
	entries := unsafe.Slice((*algorithmIdentifier)(list), capCount(count)) //nolint:gosec // the count is capped before it sizes the slice
	var out []Algorithm
	skipped := 0
	for _, e := range entries {
		name, ok := readString(e.name)
		if !ok {
			skipped++
			continue
		}
		out = append(out, Algorithm{Name: name, Ops: classBit(e.class)})
	}
	return out, skipped, nil
}

// AlgorithmProviders implements API.
func (winAPI) AlgorithmProviders(algID string) ([]string, int, error) {
	if err := find(pBCryptEnumProviders); err != nil {
		return nil, 0, err
	}
	id, err := windows.UTF16PtrFromString(algID)
	if err != nil {
		return nil, 0, err
	}
	var count uint32
	var list unsafe.Pointer
	st, _, _ := pBCryptEnumProviders.Call(uintptr(unsafe.Pointer(id)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"BCryptEnumProviders", uint32(st)} //nolint:gosec // NTSTATUS is 32 bits
	}
	defer freeBCrypt(list)
	if list == nil || count == 0 {
		return nil, 0, nil
	}
	// BCRYPT_PROVIDER_NAME is a struct holding one string pointer.
	entries := unsafe.Slice((**uint16)(list), capCount(count)) //nolint:gosec // audited: OS out-parameter, count capped before use
	var out []string
	skipped := 0
	for _, p := range entries {
		name, ok := readString(p)
		if !ok {
			skipped++
			continue
		}
		out = append(out, name)
	}
	return out, skipped, nil
}

// cryptProviders is CRYPT_PROVIDERS.
type cryptProviders struct {
	count uint32
	names **uint16
}

// RegisteredProviders implements API.
func (winAPI) RegisteredProviders() ([]string, int, error) {
	if err := find(pBCryptEnumRegisteredProviders); err != nil {
		return nil, 0, err
	}
	var cb uint32
	var list unsafe.Pointer
	st, _, _ := pBCryptEnumRegisteredProviders.Call(uintptr(unsafe.Pointer(&cb)), uintptr(unsafe.Pointer(&list))) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"BCryptEnumRegisteredProviders", uint32(st)} //nolint:gosec // NTSTATUS is 32 bits
	}
	defer freeBCrypt(list)
	if list == nil {
		return nil, 0, nil
	}
	head := (*cryptProviders)(list)
	if head.count == 0 || head.names == nil {
		return nil, 0, nil
	}
	entries := unsafe.Slice(head.names, capCount(head.count)) //nolint:gosec // audited: OS out-parameter, count capped before use
	var out []string
	skipped := 0
	for _, p := range entries {
		name, ok := readString(p)
		if !ok {
			skipped++
			continue
		}
		out = append(out, name)
	}
	return out, skipped, nil
}

// ncryptProviderName is NCryptProviderName.
type ncryptProviderName struct {
	name    *uint16
	comment *uint16
}

// StorageProviders implements API.
func (winAPI) StorageProviders() ([]StorageProvider, int, error) {
	if err := find(pNCryptEnumStorageProviders); err != nil {
		return nil, 0, err
	}
	var count uint32
	var list unsafe.Pointer
	st, _, _ := pNCryptEnumStorageProviders.Call(uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"NCryptEnumStorageProviders", uint32(st)} //nolint:gosec // status is 32 bits
	}
	defer freeNCrypt(list)
	if list == nil || count == 0 {
		return nil, 0, nil
	}
	entries := unsafe.Slice((*ncryptProviderName)(list), capCount(count)) //nolint:gosec // audited: OS out-parameter, count capped before use
	var out []StorageProvider
	skipped := 0
	for _, e := range entries {
		name, ok := readString(e.name)
		if !ok {
			skipped++
			continue
		}
		comment, _ := readString(e.comment) // a missing or unusable comment is just omitted
		out = append(out, StorageProvider{Name: name, Comment: comment})
	}
	return out, skipped, nil
}

// StorageProviderAlgorithms implements API.
func (winAPI) StorageProviderAlgorithms(provider string, ops uint32) ([]Algorithm, int, error) {
	if err := find(pNCryptOpenStorageProvider); err != nil {
		return nil, 0, err
	}
	name, err := windows.UTF16PtrFromString(provider)
	if err != nil {
		return nil, 0, err
	}
	var h uintptr
	st, _, _ := pNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"NCryptOpenStorageProvider", uint32(st)} //nolint:gosec // status is 32 bits
	}
	defer func() { _, _, _ = pNCryptFreeObject.Call(h) }()

	var count uint32
	var list unsafe.Pointer
	st, _, _ = pNCryptEnumAlgorithms.Call(h, uintptr(ops), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&list)), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if st != ntSuccess {
		return nil, 0, &StatusError{"NCryptEnumAlgorithms", uint32(st)} //nolint:gosec // status is 32 bits
	}
	defer freeNCrypt(list)
	if list == nil || count == 0 {
		return nil, 0, nil
	}
	entries := unsafe.Slice((*ncryptAlgorithmName)(list), capCount(count)) //nolint:gosec // audited: OS out-parameter, count capped before use
	var out []Algorithm
	skipped := 0
	for _, e := range entries {
		n, ok := readString(e.name)
		if !ok {
			skipped++
			continue
		}
		out = append(out, Algorithm{Name: n, Ops: e.ops & OpAll})
	}
	return out, skipped, nil
}

// CSPs implements API.
func (winAPI) CSPs() ([]CSP, int, error) {
	if err := find(pCryptEnumProvidersW); err != nil {
		return nil, 0, err
	}
	var out []CSP
	skipped := 0
	for i := uint32(0); i < MaxEntries; i++ {
		var typ, cb uint32
		// First call: how many bytes the name needs.
		r, _, e := pCryptEnumProvidersW.Call(uintptr(i), 0, 0, uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&cb))) //nolint:gosec // audited: OS out-parameter, count capped before use
		if r == 0 {
			var errno windows.Errno
			if errors.As(e, &errno) && errno == errNoMoreItems {
				break
			}
			// ERROR_MORE_DATA is the expected answer to a size query; anything else ends the list.
			var en windows.Errno
			if !errors.As(e, &en) || en != windows.ERROR_MORE_DATA {
				if skipped == 0 && len(out) == 0 {
					return nil, 0, &StatusError{"CryptEnumProvidersW", uint32(en)}
				}
				break
			}
		}
		if cb == 0 || cb > MaxName*2+2 {
			skipped++
			continue
		}
		buf := make([]uint16, cb/2+1)
		r, _, _ = pCryptEnumProvidersW.Call(uintptr(i), 0, 0, uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&cb))) //nolint:gosec // audited: OS out-parameter, count capped before use
		if r == 0 {
			skipped++
			continue
		}
		n, ok := readString(&buf[0])
		if !ok {
			skipped++
			continue
		}
		out = append(out, CSP{Name: n, Type: typ})
	}
	return out, skipped, nil
}

// Probe reports whether the default CNG provider offers algID and, when paramSet is
// given, accepts it as the algorithm's parameter set.
//
// A parameter set can only be set on a key handle, so probing one generates an
// EPHEMERAL key pair in this process's memory and destroys it at once. The key is
// never exported, never persisted (BCryptGenerateKeyPair makes no stored key), never
// read and never used; it exists only to ask "will you accept this parameter set".
// That is the one place the collector performs a cryptographic operation, it is
// limited to the post-quantum families by the sensor, and paramSet must be digits so
// no other property value can be sent.
func (winAPI) Probe(algID, paramSet string) (bool, error) {
	if err := find(pBCryptOpenAlgorithmProvider); err != nil {
		return false, err
	}
	if !digitsOnly(paramSet) {
		return false, errors.New("wincng: a parameter set is digits only")
	}
	id, err := windows.UTF16PtrFromString(algID)
	if err != nil {
		return false, err
	}
	var h uintptr
	st, _, _ := pBCryptOpenAlgorithmProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(id)), 0, 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if answer, err := answerFor(st, "BCryptOpenAlgorithmProvider"); err != nil || !answer {
		return false, err
	}
	defer func() { _, _, _ = pBCryptCloseAlgorithmProvider.Call(h, 0) }()
	if paramSet == "" {
		return true, nil
	}

	var key uintptr
	st, _, _ = pBCryptGenerateKeyPair.Call(h, uintptr(unsafe.Pointer(&key)), 0, 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if answer, err := answerFor(st, "BCryptGenerateKeyPair"); err != nil || !answer {
		return false, err
	}
	defer func() { _, _, _ = pBCryptDestroyKey.Call(key) }() // the ephemeral key never outlives this call

	prop, err := windows.UTF16PtrFromString(paramSetNameProp)
	if err != nil {
		return false, err
	}
	val, err := windows.UTF16FromString(paramSet)
	if err != nil {
		return false, err
	}
	st, _, _ = pBCryptSetProperty.Call(key, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&val[0])), uintptr(len(val)*2), 0) //nolint:gosec // audited: OS out-parameter, count capped before use
	if answer, err := answerFor(st, "BCryptSetProperty"); err != nil || !answer {
		return false, err
	}
	st, _, _ = pBCryptFinalizeKeyPair.Call(key, 0)
	return answerFor(st, "BCryptFinalizeKeyPair")
}

// answerFor turns a status into an answer: success is yes; "not found", "not
// supported" and "invalid parameter" are a definite no; anything else is an error.
func answerFor(st uintptr, call string) (bool, error) {
	switch st {
	case ntSuccess:
		return true, nil
	case statusNotFound, statusNotSupported, statusInvalidParam:
		return false, nil
	}
	return false, &StatusError{call, uint32(st)} //nolint:gosec // NTSTATUS is 32 bits
}

func digitsOnly(s string) bool {
	if len(s) > 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
