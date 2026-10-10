//go:build windows

package winapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// units builds a NUL-terminated UTF-16 buffer padded well past MaxName, so a reader that
// runs on cannot touch memory this test does not own.
func units(s string, pad int) []uint16 {
	b := utf16.Encode([]rune(s))
	b = append(b, 0)
	return append(b, make([]uint16, pad)...)
}

func filled(n int) []uint16 {
	b := make([]uint16, n)
	for i := range b {
		b[i] = 'A'
	}
	return b
}

func TestReadStringIsBoundedAndValidating(t *testing.T) {
	// MaxName-1 characters then NUL: the longest string accepted.
	atCap := append(filled(MaxName-1), 0)
	atCap = append(atCap, make([]uint16, MaxName)...)
	// MaxName characters then NUL: one too many.
	tooLong := append(filled(MaxName), 0)
	tooLong = append(tooLong, make([]uint16, MaxName)...)
	// Never terminated inside the cap (the memory after it is padding this test owns).
	unterminated := append(filled(MaxName*2), make([]uint16, 8)...)

	for name, tc := range map[string]struct {
		buf  []uint16
		want string
		ok   bool
	}{
		"plain":             {units("Microsoft Primitive Provider", MaxName), "Microsoft Primitive Provider", true},
		"non-ASCII":         {units("Anbieter für Schlüssel", MaxName), "Anbieter für Schlüssel", true},
		"empty":             {units("", MaxName), "", false},
		"control character": {units("evil\x1b[31m", MaxName), "", false},
		"newline":           {units("two\nlines", MaxName), "", false},
		"DEL":               {units("a\x7fb", MaxName), "", false},
		"lone surrogate":    {append([]uint16{'a', 0xD800, 'b', 0}, make([]uint16, MaxName)...), "", false},
		"never terminated":  {unterminated, "", false},
		"longest accepted":  {atCap, "", true},
		"one over the cap":  {tooLong, "", false},
	} {
		got, ok := readString(&tc.buf[0])
		if ok != tc.ok || (tc.want != "" && got != tc.want) {
			t.Errorf("%s: readString = %q, %v; want %q, %v", name, truncate(got), ok, tc.want, tc.ok)
		}
	}
	if _, ok := readString(nil); ok {
		t.Error("a nil string must not be read")
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func TestCountsAreCappedBeforeTheyStandForALength(t *testing.T) {
	for in, want := range map[uint32]int{0: 0, 1: 1, MaxEntries: MaxEntries, MaxEntries + 1: MaxEntries, 0xFFFFFFFF: MaxEntries} {
		if got := capCount(in); got != want {
			t.Errorf("capCount(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestClassBitAndParameterSetGuards(t *testing.T) {
	for class, want := range map[uint32]uint32{0: 0, 1: OpCipher, 2: OpHash, 3: OpAsymmetricEncrypt, 4: OpSecretAgreement, 5: OpSignature, 6: OpRNG, 7: OpKeyDerivation, 8: 0, 99: 0} {
		if got := classBit(class); got != want {
			t.Errorf("classBit(%d) = %#x, want %#x", class, got, want)
		}
	}
	for s, want := range map[string]bool{"": true, "768": true, "1024": true, "12345678": true, "123456789": false, "7 68": false, "76a": false, "-1": false, "ML-KEM": false} {
		if got := digitsOnly(s); got != want {
			t.Errorf("digitsOnly(%q) = %v, want %v", s, got, want)
		}
	}
	// A parameter set that is not digits is refused before anything is sent to Windows.
	if _, err := New().Probe("ML-KEM", "768; drop"); err == nil {
		t.Error("a non-digit parameter set was accepted")
	}
}

func TestStatusesBecomeAnswersOrErrors(t *testing.T) {
	for st, yes := range map[uintptr]bool{ntSuccess: true, statusNotFound: false, statusNotSupported: false, statusInvalidParam: false} {
		if got, err := answerFor(st, "x"); err != nil || got != yes {
			t.Errorf("status %#x: %v, %v; want %v, nil", st, got, err, yes)
		}
	}
	if _, err := answerFor(0xC0000022, "x"); err == nil { // ACCESS_DENIED is a failure, not an answer
		t.Error("an unexpected status must be an error, not a silent no")
	}
}

// Against the real machine: not exact values (they differ between Windows builds) but
// the properties every supported Windows must satisfy.
func TestTheRealMachineAnswersSanely(t *testing.T) {
	api := New()
	if !api.Native() {
		t.Fatal("the Windows implementation must report itself native")
	}
	for op, name := range map[uint32]string{OpCipher: "cipher", OpHash: "hash", OpAsymmetricEncrypt: "asymmetric encryption", OpSignature: "signature"} {
		list, _, err := api.Algorithms(op)
		if err != nil || len(list) == 0 {
			t.Errorf("%s algorithms: %d, %v", name, len(list), err)
		}
		for _, a := range list {
			if !printable(a.Name) || len(a.Name) > MaxName || a.Ops == 0 {
				t.Errorf("%s: unusable entry %+v", name, a)
			}
		}
	}
	regs, _, err := api.RegisteredProviders()
	if err != nil || !has(regs, "Microsoft Primitive Provider") {
		t.Errorf("registered providers %q, %v", regs, err)
	}
	provs, _, err := api.AlgorithmProviders("AES")
	if err != nil || !has(provs, "Microsoft Primitive Provider") {
		t.Errorf("providers of AES %q, %v", provs, err)
	}
	ksps, _, err := api.StorageProviders()
	var names []string
	for _, k := range ksps {
		names = append(names, k.Name)
	}
	if err != nil || !has(names, "Microsoft Software Key Storage Provider") {
		t.Errorf("storage providers %q, %v", names, err)
	}
	if csps, _, err := api.CSPs(); err != nil || len(csps) == 0 {
		t.Errorf("CSPs %d, %v", len(csps), err)
	}
	if ok, err := api.Probe("AES", ""); !ok || err != nil {
		t.Errorf("AES must open: %v, %v", ok, err)
	}
	for _, neg := range []struct{ alg, set string }{{"NOT-AN-ALGORITHM", ""}, {"ML-KEM", "999"}, {"ML-DSA", "1"}} {
		if ok, err := api.Probe(neg.alg, neg.set); ok || err != nil {
			t.Errorf("Probe(%q, %q) = %v, %v; a refusal is an answer (false, nil)", neg.alg, neg.set, ok, err)
		}
	}
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ---- certificate stores (ADR-0016) --------------------------------------------------------

// The layer must never call a function that opens, acquires, exports or uses a private key
// (ADR-0005 decision 4, ADR-0016). This scans the package's own source for those names, so a
// later edit that reaches for one fails the build instead of passing review by accident.
func TestNoKeyMaterialFunctionIsCalled(t *testing.T) {
	forbidden := []string{
		"CryptAcquireCertificatePrivateKey", "CryptAcquireContext", "NCryptOpenKey", "NCryptExportKey", "NCryptImportKey",
		"NCryptSignHash", "NCryptDecrypt", "NCryptEncrypt", "CryptExportKey", "CryptGetUserKey", "CryptImportKey",
		"CryptSignHash", "CryptDecrypt", "PFXExportCertStore", "PFXExportCertStoreEx", "CryptExportPKCS8", "BCryptExportKey",
		"CertGetPublicKeyLength", "CertOpenSystemStore", "CertFindCertificateInStore", "CertAddCertificateContextToStore",
		"CertDeleteCertificateFromStore", "CertSetCertificateContextProperty",
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files found: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Comments may name the functions to say they are not called; code may not.
		code := stripComments(string(src))
		for _, name := range forbidden {
			if strings.Contains(code, name) {
				t.Errorf("%s calls or names %s: the platform layer may not use key-material or store-modifying functions (ADR-0016)", f, name)
			}
		}
	}
}

func stripComments(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// Only one property id is ever queried, and only without an output buffer: the query can say
// that a key association exists, and cannot return what it contains.
func TestKeyAssociationQueryIsTheOnlyPropertyReadAndHasNoBuffer(t *testing.T) {
	src, err := os.ReadFile("certstore_windows.go")
	if err != nil {
		t.Fatal(err)
	}
	code := stripComments(string(src))
	if n := strings.Count(code, "pCertGetCertificateContextProperty.Call("); n != 1 {
		t.Fatalf("%d property queries, want exactly 1", n)
	}
	if !strings.Contains(code, "certKeyProvInfoPropID, 0, uintptr(unsafe.Pointer(&cb))") {
		t.Error("the property query must pass the fixed property id and a nil output buffer")
	}
	if certKeyProvInfoPropID != 2 {
		t.Errorf("property id = %d, want CERT_KEY_PROV_INFO_PROP_ID (2)", certKeyProvInfoPropID)
	}
	if !strings.Contains(code, "windows.CERT_STORE_OPEN_EXISTING_FLAG | windows.CERT_STORE_READONLY_FLAG") {
		t.Error("stores must be opened read-only and existing-only")
	}
}

func TestStoresOutsideTheAllowListAreRefusedBeforeWindowsIsCalled(t *testing.T) {
	api := NewCertStore()
	for _, c := range []struct {
		loc  StoreLocation
		name string
	}{{LocalMachine, "Disallowed"}, {LocalMachine, ""}, {"Users", "Root"}, {CurrentUser, `..\Root`}, {LocalMachine, "root"}, {LocalMachine, "MY\x00"}} {
		if _, _, err := api.CertStore(c.loc, c.name); !errors.Is(err, ErrStoreNotAllowed) {
			t.Errorf("CertStore(%q, %q) = %v, want ErrStoreNotAllowed", c.loc, c.name, err)
		}
	}
}

// Against the real machine: not exact contents but the properties every Windows must satisfy.
func TestTheRealCertificateStoresAnswerSanely(t *testing.T) {
	api := NewCertStore()
	if !api.Native() {
		t.Fatal("the Windows implementation must report itself native")
	}
	total := 0
	for _, loc := range []StoreLocation{LocalMachine, CurrentUser} {
		for _, name := range CertStoreNames {
			certs, skipped, err := api.CertStore(loc, name)
			if err != nil {
				t.Errorf("%s/%s: %v", loc, name, err)
				continue
			}
			if len(certs) > MaxCertsPerStore || skipped < 0 {
				t.Errorf("%s/%s: %d certificates, %d skipped", loc, name, len(certs), skipped)
			}
			for _, c := range certs {
				total++
				if len(c.DER) == 0 || len(c.DER) > MaxCertDER || c.DER[0] != 0x30 {
					t.Errorf("%s/%s: bad DER of %d bytes", loc, name, len(c.DER))
				}
				if c.PrivateKey != KeyYes && c.PrivateKey != KeyNo && c.PrivateKey != KeyUnknown {
					t.Errorf("%s/%s: private-key answer %q", loc, name, c.PrivateKey)
				}
			}
		}
	}
	// A Windows machine trusts some roots; an empty answer everywhere means the call is broken.
	roots, _, _ := api.CertStore(LocalMachine, "Root")
	if len(roots) == 0 {
		t.Error("the LocalMachine Root store is empty")
	}
	// A machine can hold the key of a root it made itself (CI runners and mkcert do); every root
	// claiming a key means the property query is broken.
	keyed := 0
	for _, r := range roots {
		if r.PrivateKey == KeyYes {
			keyed++
		}
	}
	if len(roots) > 0 && keyed == len(roots) {
		t.Error("every trusted root reports a private key on this machine; check the property query")
	}
	t.Logf("%d certificates across the readable stores", total)
}
