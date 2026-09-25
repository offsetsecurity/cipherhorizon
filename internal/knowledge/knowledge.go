// Package knowledge holds what is known about cryptographic software independent
// of any host: which package or file names belong to which family, and which
// algorithms a family's releases provide, each with its citation.
//
// It is the only place capability is decided. Sensors never assert capability;
// they report what is present, and the derive stage applies these tables to it.
// That is what lets a package on Debian and a loose DLL on Windows get the same
// mapping (ADR-0001), and what keeps a capability a *cited* statement rather than
// something a collector author remembered to label.
//
// Recognition is a heuristic (a name pattern). Capability is knowledge (a
// citation applied to a version). Neither is an observation of use.
package knowledge

import "regexp"

// KBVersion identifies this table's revision; it travels with every derived
// capability so a report says which knowledge produced it. Bump it when a
// mapping changes.
const KBVersion = "2"

// Component kinds a family's artefacts have.
const (
	KindLibrary     = "library"
	KindApplication = "application"
)

// Capability is a set of algorithms a family provides from a given version onward.
type Capability struct {
	// Min is the lowest release providing these algorithms. The zero value means
	// every version. When an installed version cannot be parsed, gated
	// capabilities are omitted rather than assumed.
	Min   Version
	Algos []string // algo catalogue IDs
}

// Family is one family of crypto-relevant software.
//
// Recognition and capability are separate tiers on purpose:
//   - Every family is INVENTORIED: "this crypto artefact, at this version, is
//     present" (a fact a sensor reads).
//   - Only families with Caps yield capability, and each claim is backed by the
//     citations in Basis. A family with no citable mapping is inventoried and
//     nothing is guessed about it.
//
// Capabilities describe what the software can do, not what the host does with it.
type Family struct {
	ID   string
	Kind string
	// Package matches Debian package names in this family; PackageApp matches the
	// ones that are executables (component type application) rather than Kind.
	Package    *regexp.Regexp
	PackageApp *regexp.Regexp
	// Files match lower-cased file base names of loose artefacts (Windows DLLs and
	// executables). A match is a name heuristic only: it never supports a
	// capability by itself (ADR-0002). FileApp matches the ones that are executables.
	Files   []*regexp.Regexp
	FileApp *regexp.Regexp

	// FileConsumers match the loose files of this family that USE the family's
	// implementation rather than provide algorithms themselves (for OpenSSL on
	// Windows: libssl and the openssl command, which sit on top of libcrypto). Such
	// a file is inventoried and never credited with the family's capabilities: it
	// is linked to the file that provides them by what its import table proves.
	// Empty for a family whose files each implement what the family provides, and
	// for Debian packages, where one package holds the whole library.
	FileConsumers []*regexp.Regexp
	// ConsumerBasis cites the statement that the consumers depend on the provider.
	ConsumerBasis string

	Caps  []Capability
	Basis []string // citations for every claim in Caps; required when Caps is non-empty
}

func re(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

// Families is the table. Order matters for matching: the first match wins.
var Families = []Family{
	{
		ID: "openssl",
		// openssl (CLI), libssl3, libssl3t64, libssl1.1, ... but not libssl-dev/-doc.
		Package:    re(`^(openssl|libssl[0-9][0-9a-z.]*)$`),
		Kind:       KindLibrary,
		PackageApp: re(`^openssl$`),
		Files: []*regexp.Regexp{
			re(`^lib(crypto|ssl)-(1_1|3)(-x64|-x86|-arm64)?\.dll$`),
			re(`^(libeay32|ssleay32)\.dll$`),
			re(`^(msys|cyg)-(crypto|ssl)-[0-9][0-9._-]*\.dll$`),
			re(`^openssl\.exe$`),
		},
		FileApp: re(`\.exe$`),
		FileConsumers: []*regexp.Regexp{
			re(`^libssl-(1_1|3)(-x64|-x86|-arm64)?\.dll$`),
			re(`^ssleay32\.dll$`),
			re(`^(msys|cyg)-ssl-[0-9][0-9._-]*\.dll$`),
			re(`^openssl\.exe$`),
		},
		ConsumerBasis: "OpenSSL guide, an introduction to the OpenSSL libraries: libcrypto provides general purpose cryptography and libssl depends on and uses libcrypto (https://docs.openssl.org/3.5/man7/ossl-guide-libraries-introduction/). The openssl command is treated as a consumer of both because it is the command-line program built on them; that page does not say so, and its import table is what links it to a specific file",
		Caps: []Capability{
			{Algos: []string{"RSA", "DSA", "DH", "ECDSA", "ECDH", "AES", "SHA-256", "SHA-384", "SHA-512"}},
			{Min: Version{3, 5, 0}, Algos: []string{
				"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
				"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
				"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
				"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
				"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
			}},
		},
		Basis: []string{
			"OpenSSL manual: EVP_PKEY-RSA, EVP_PKEY-DSA, EVP_PKEY-DH, EVP_PKEY-EC, EVP_CIPHER-AES, EVP_MD-SHA2 (https://docs.openssl.org/3.0/man7/)",
			"OpenSSL 3.5.0 (2025-04-08) CHANGES.md: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), 'added in OpenSSL 3.5' (https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)",
		},
	},
	{
		ID: "gnupg",
		// gnupg/gnupg2 (metapackage in modern Debian), gpg (the binary), gpgv, gpgsm.
		Package: re(`^(gnupg2?|gpg|gpgv|gpgsm)$`),
		Kind:    KindApplication,
		Files:   []*regexp.Regexp{re(`^(gpg|gpgv|gpgsm)\.exe$`)},
		Caps: []Capability{
			{Algos: []string{"RSA", "DSA"}},
			{Min: Version{2, 1, 0}, Algos: []string{"ECDSA", "ECDH", "Ed25519"}},
		},
		Basis: []string{
			"GnuPG manual, gpg options: rsa2048/ed25519 key specs and --enable-dsa2 (https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html)",
			"GnuPG 2.1 'What's new': ECC support (NIST and Brainpool curves) and Ed25519 signing (https://gnupg.org/faq/whats-new-in-2.1.html)",
			"RFC 6637: Elliptic Curve Cryptography in OpenPGP (ECDSA, ECDH)",
		},
	},

	// Inventory-only families: recognised crypto software with no capability
	// mapping yet. Adding a mapping needs citations; adding a name does not.
	{ID: "libgcrypt", Package: re(`^libgcrypt[0-9]+$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib|msys-|cyg)gcrypt-[0-9]+\.dll$`)}},
	{ID: "gnutls", Package: re(`^libgnutls[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib|msys-|cyg)gnutls-[0-9]+\.dll$`)}},
	{ID: "nettle", Package: re(`^lib(nettle|hogweed)[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib|msys-|cyg)(nettle|hogweed)-[0-9]+\.dll$`)}},
	{ID: "libsodium", Package: re(`^libsodium[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^libsodium(-[0-9]+)?\.dll$`)}},
	{ID: "nss", Package: re(`^libnss3$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^nss3\.dll$`)}},
	{ID: "mbedtls", Package: re(`^libmbed(tls|crypto|x509)[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib)?mbed(tls|crypto|x509)(-[0-9]+)?\.dll$`)}},
	{ID: "wolfssl", Package: re(`^libwolfssl[0-9]*(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib)?wolfssl(-[0-9]+)?\.dll$`)}},
	{ID: "botan", Package: re(`^libbotan-[0-9]+-[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^(lib)?botan(-[0-9]+(-[0-9]+)?)?\.dll$`)}},
	{ID: "libssh", Package: re(`^(libssh2?|libssh-gcrypt)-[0-9]+(t64)?$`), Kind: KindLibrary, Files: []*regexp.Regexp{re(`^libssh2?(-[0-9]+)?\.dll$`)}},
	{ID: "openssh", Package: re(`^openssh-(client|server)$`), Kind: KindApplication},
	{ID: "kerberos", Package: re(`^(libk5crypto3|libkrb5-3)$`), Kind: KindLibrary},
	{ID: "libxcrypt", Package: re(`^libcrypt[0-9]+$`), Kind: KindLibrary},
	{ID: "cryptsetup", Package: re(`^libcryptsetup[0-9]+$`), Kind: KindLibrary},
	{ID: "python-cryptography", Package: re(`^python3-(cryptography|openssl)$`), Kind: KindLibrary},
}

// RecognizePackage returns the family a Debian package name belongs to, or nil for
// a package that is not crypto software.
func RecognizePackage(name string) *Family {
	for i := range Families {
		if Families[i].Package != nil && Families[i].Package.MatchString(name) {
			return &Families[i]
		}
	}
	return nil
}

// RecognizeFile returns the family a lower-cased file base name belongs to, or
// nil. This is a name heuristic.
func RecognizeFile(lowerBase string) *Family {
	for i := range Families {
		for _, r := range Families[i].Files {
			if r.MatchString(lowerBase) {
				return &Families[i]
			}
		}
	}
	return nil
}

// ByID returns the family with the given ID.
func ByID(id string) (*Family, bool) {
	for i := range Families {
		if Families[i].ID == id {
			return &Families[i], true
		}
	}
	return nil, false
}

// KindForFile is the component kind of a loose file in this family: executables
// are applications, everything else the family's default kind.
func (f *Family) KindForFile(lowerBase string) string {
	if f.FileApp != nil && f.FileApp.MatchString(lowerBase) {
		return KindApplication
	}
	return f.Kind
}

// KindFor is the component kind of a package in this family.
func (f *Family) KindFor(pkgName string) string {
	if f.PackageApp != nil && f.PackageApp.MatchString(pkgName) {
		return KindApplication
	}
	return f.Kind
}

// Capabilities returns the algorithm IDs a release provides, in table order.
// known is whether the release's version could be read: gated capabilities need
// it, and are omitted (never assumed) when it is not.
func (f *Family) Capabilities(v Version, known bool) []string {
	var ids []string
	for _, c := range f.Caps {
		if c.Min != (Version{}) && (!known || !v.AtLeast(c.Min)) {
			continue
		}
		ids = append(ids, c.Algos...)
	}
	return ids
}

// Mapping is the knowledge reference recorded on a derived capability.
func (f *Family) Mapping() (id string, citations []string) {
	return "capability/" + f.ID + "@" + KBVersion, f.Basis
}

// Roles of a loose file within its family.
const (
	RoleProvider = "provider" // implements the algorithms the family provides
	RoleConsumer = "consumer" // uses a provider of the same family
)

// RoleForFile is the role of a lower-cased file base name in this family, or "" when
// the family does not distinguish roles.
func (f *Family) RoleForFile(lowerBase string) string {
	if len(f.FileConsumers) == 0 {
		return ""
	}
	if f.IsConsumerFile(lowerBase) {
		return RoleConsumer
	}
	return RoleProvider
}

// IsConsumerFile reports whether the file only uses the family's implementation.
func (f *Family) IsConsumerFile(lowerBase string) bool {
	for _, r := range f.FileConsumers {
		if r.MatchString(lowerBase) {
			return true
		}
	}
	return false
}
