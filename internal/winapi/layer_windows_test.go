//go:build windows

package winapi

import (
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
