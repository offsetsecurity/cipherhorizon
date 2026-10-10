// Package registry holds the TLS cipher-suite and supported-group registries the
// prober works from. The tables are generated from IANA's official CSVs by
// ./gen; nothing in them is typed by hand.
//
// Regenerate (the CSVs are not committed; fetch them from
// https://www.iana.org/assignments/tls-parameters/ first):
//
//	go run ./internal/tlsprobe/registry/gen \
//	    -suites tls-parameters-4.csv -groups tls-parameters-8.csv \
//	    -retrieved 2026-09-21 -out internal/tlsprobe/registry
//
// The IANA-derived fields (ID, Name, Recommended, DTLSOK, Reference) are
// verbatim. The decomposition of a suite name into Kx/Auth/Cipher/Mode/MAC is
// derived by a strict grammar in the generator, which refuses to generate
// anything it does not understand; key and block sizes come from a small curated
// table in the generator (they are properties of the ciphers, not of IANA).
package registry

import "sort"

// Recommended is IANA's "Recommended" column.
type Recommended byte

// The IANA values. D is "discouraged": IANA marks the entry as one that should
// not be used.
const (
	RecommendedNo          Recommended = 'N'
	RecommendedYes         Recommended = 'Y'
	RecommendedDiscouraged Recommended = 'D'
)

// SuiteClass distinguishes real cipher suites from signalling values.
type SuiteClass uint8

// The suite classes.
const (
	ClassLegacy     SuiteClass = iota // TLS 1.2 and earlier: kex and auth are in the name
	ClassTLS13                        // TLS 1.3 style: only AEAD/PRF-hash in the name
	ClassSignalling                   // SCSV pseudo-suites; never negotiated
)

// Suite is one IANA cipher-suite registry entry with its decomposition.
type Suite struct {
	ID          uint16
	Name        string
	Recommended Recommended
	DTLSOK      bool
	Reference   string

	Class SuiteClass

	// Key exchange and authentication as named ("" for TLS 1.3 suites, whose key
	// exchange is negotiated separately via supported_groups). Kx is one of RSA, DH,
	// DHE, ECDH, ECDHE, PSK, DHE_PSK, ECDHE_PSK, RSA_PSK, SRP, KRB5, ECCPWD, GOST, NULL;
	// Auth is RSA, DSS, ECDSA, PSK, SRP, KRB5, anon, ECCPWD, GOST or NULL.
	Kx   string
	Auth string

	Cipher    string // AES, CHACHA20, 3DES, RC4, NULL, ...
	KeyBits   int    // nominal key size from the cipher's name (3DES is 168)
	Mode      string // GCM, CBC, CCM, CCM8, POLY1305, STREAM, CTR, MGM, NONE, ...
	BlockBits int    // 0 for stream ciphers and for AEADs that do not expose a block
	MAC       string // SHA1, SHA256, SHA384, MD5, OMAC, IMIT, NONE, or AEAD
	Hash      string // hash named alongside an AEAD (the PRF/handshake hash), else ""

	// Properties read directly off the name. Ephemeral means the name says the key
	// exchange uses ephemeral keys (DHE/ECDHE and their PSK forms); false means
	// "the name does not say so", not "known static".
	AEAD      bool
	Export    bool
	Anon      bool
	Ephemeral bool
}

// Group is one IANA supported-groups registry entry.
type Group struct {
	ID          uint16
	Name        string
	Recommended Recommended
	DTLSOK      bool
	Reference   string
	Comment     string

	// Derived from the name.
	PQ       bool // the group involves ML-KEM or (pre-standard) Kyber
	Hybrid   bool // PQ and combined with a classical key exchange
	Obsolete bool // IANA marks the name OBSOLETE
}

var (
	suiteByID = map[uint16]*Suite{}
	groupByID = map[uint16]*Group{}
)

func init() {
	for i := range suites {
		suiteByID[suites[i].ID] = &suites[i]
	}
	for i := range groups {
		groupByID[groups[i].ID] = &groups[i]
	}
	sort.Slice(suites, func(i, j int) bool { return suites[i].ID < suites[j].ID })
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
}

// Suites returns every named entry in the cipher-suite registry, sorted by ID.
// The slice must not be modified.
func Suites() []Suite { return suites }

// Groups returns every named entry in the supported-groups registry, sorted by ID.
// The slice must not be modified.
func Groups() []Group { return groups }

// SuiteByID returns the registry entry for a cipher-suite code point.
func SuiteByID(id uint16) (Suite, bool) {
	s, ok := suiteByID[id]
	if !ok {
		return Suite{}, false
	}
	return *s, true
}

// GroupByID returns the registry entry for a supported-group code point.
func GroupByID(id uint16) (Group, bool) {
	g, ok := groupByID[id]
	if !ok {
		return Group{}, false
	}
	return *g, true
}

// SuiteName returns the IANA name, or a hex placeholder for an unregistered value.
func SuiteName(id uint16) string {
	if s, ok := suiteByID[id]; ok {
		return s.Name
	}
	return "UNKNOWN_0x" + hex4(id)
}

// GroupName returns the IANA name, or a hex placeholder for an unregistered value.
func GroupName(id uint16) string {
	if g, ok := groupByID[id]; ok {
		return g.Name
	}
	return "UNKNOWN_0x" + hex4(id)
}

func hex4(v uint16) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[v>>12&0xf], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]})
}
