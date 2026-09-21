package apt

import (
	"regexp"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// A rule recognises one family of crypto-relevant Debian packages.
//
// Recognition and capability are separate tiers on purpose:
//
//   - Every rule yields an INVENTORY entry: "this crypto package, at this
//     version, is installed". That is a fact read straight from dpkg.
//   - Only rules with capabilities also yield `provides` edges to algorithm
//     assets. Those edges are curated claims ("this package implements RSA"),
//     each backed by the citations in basis. A family with no citable mapping
//     has NO capabilities: it is inventoried, and nothing is guessed about it.
//
// Capabilities describe what the package can do, not what the host does with it.
type rule struct {
	family string // stable identifier, recorded on the component
	name   *regexp.Regexp
	kind   cdx.ComponentType
	// app, if set, matches the package names in this family that are executables
	// (component type "application") rather than kind.
	app *regexp.Regexp

	caps  []capability
	basis []string // citations for every claim in caps; required when caps is non-empty
}

// A capability is a set of algorithms a package provides from a given upstream
// version onward.
type capability struct {
	// min is the lowest upstream version providing these algorithms. The zero
	// value means "every version". When the installed version cannot be parsed,
	// gated capabilities are omitted rather than assumed.
	min   version
	algos []string // algo catalogue IDs
}

func re(pattern string) *regexp.Regexp { return regexp.MustCompile(pattern) }

var rules = []rule{
	{
		family: "openssl",
		// openssl (CLI), libssl3, libssl3t64, libssl1.1, ... but not libssl-dev/-doc.
		name: re(`^(openssl|libssl[0-9][0-9a-z.]*)$`),
		kind: cdx.ComponentTypeLibrary,
		app:  re(`^openssl$`),
		caps: []capability{
			{algos: []string{"RSA", "DSA", "DH", "ECDSA", "ECDH", "AES", "SHA-256", "SHA-384", "SHA-512"}},
			{min: version{3, 5, 0}, algos: []string{
				"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
				"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
				"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
				"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
				"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
			}},
		},
		basis: []string{
			"OpenSSL manual: EVP_PKEY-RSA, EVP_PKEY-DSA, EVP_PKEY-DH, EVP_PKEY-EC, EVP_CIPHER-AES, EVP_MD-SHA2 (https://docs.openssl.org/3.0/man7/)",
			"OpenSSL 3.5.0 (2025-04-08) CHANGES.md: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), 'added in OpenSSL 3.5' (https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)",
		},
	},
	{
		family: "gnupg",
		// gnupg/gnupg2 (metapackage in modern Debian), gpg (the binary), gpgv, gpgsm.
		name: re(`^(gnupg2?|gpg|gpgv|gpgsm)$`),
		kind: cdx.ComponentTypeApplication,
		caps: []capability{
			{algos: []string{"RSA", "DSA"}},
			{min: version{2, 1, 0}, algos: []string{"ECDSA", "ECDH", "Ed25519"}},
		},
		basis: []string{
			"GnuPG manual, gpg options: rsa2048/ed25519 key specs and --enable-dsa2 (https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration-Options.html)",
			"GnuPG 2.1 'What's new': ECC support (NIST and Brainpool curves) and Ed25519 signing (https://gnupg.org/faq/whats-new-in-2.1.html)",
			"RFC 6637: Elliptic Curve Cryptography in OpenPGP (ECDSA, ECDH)",
		},
	},

	// Inventory-only families: recognised crypto packages with no capability
	// mapping yet. Adding a mapping needs citations; adding a name does not.
	{family: "libgcrypt", name: re(`^libgcrypt[0-9]+$`), kind: cdx.ComponentTypeLibrary},
	{family: "gnutls", name: re(`^libgnutls[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "nettle", name: re(`^lib(nettle|hogweed)[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "libsodium", name: re(`^libsodium[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "nss", name: re(`^libnss3$`), kind: cdx.ComponentTypeLibrary},
	{family: "mbedtls", name: re(`^libmbed(tls|crypto|x509)[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "wolfssl", name: re(`^libwolfssl[0-9]*(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "botan", name: re(`^libbotan-[0-9]+-[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "libssh", name: re(`^(libssh2?|libssh-gcrypt)-[0-9]+(t64)?$`), kind: cdx.ComponentTypeLibrary},
	{family: "openssh", name: re(`^openssh-(client|server)$`), kind: cdx.ComponentTypeApplication},
	{family: "kerberos", name: re(`^(libk5crypto3|libkrb5-3)$`), kind: cdx.ComponentTypeLibrary},
	{family: "libxcrypt", name: re(`^libcrypt[0-9]+$`), kind: cdx.ComponentTypeLibrary},
	{family: "cryptsetup", name: re(`^libcryptsetup[0-9]+$`), kind: cdx.ComponentTypeLibrary},
	{family: "python-cryptography", name: re(`^python3-(cryptography|openssl)$`), kind: cdx.ComponentTypeLibrary},
}

// typeFor returns the CycloneDX component type for a package in this family.
func (r *rule) typeFor(name string) cdx.ComponentType {
	if r.app != nil && r.app.MatchString(name) {
		return cdx.ComponentTypeApplication
	}
	return r.kind
}

// match returns the rule for a package name, or nil for a non-crypto package.
func match(name string) *rule {
	for i := range rules {
		if rules[i].name.MatchString(name) {
			return &rules[i]
		}
	}
	return nil
}
