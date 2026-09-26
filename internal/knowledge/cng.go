package knowledge

// Windows CNG: what an algorithm identifier the operating system reports means.
//
// The sensor asks Windows which algorithms are registered and reports them by the
// identifier Windows uses ("SHA256", "ECDSA_P256", "3DES"). This file says which
// catalogue algorithm each identifier is an instance of. It is knowledge, not
// observation: the mapping is a cited statement, applied here and nowhere else.

// CNGBasis cites the identifier list the mapping below follows.
const CNGBasis = "Microsoft, CNG Algorithm Identifiers (Bcrypt.h): the identifier strings and the standard each names (https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers)"

// cngAlgorithms maps a CNG identifier to a catalogue algorithm ID. An identifier that
// is not here (a key-derivation function, a random-number generator, a MAC, an
// extendable-output function, a composite or pre-release algorithm) is still listed
// by name on its provider; it just has no catalogue entry to attach a verdict to.
//
// Where CNG has one identifier per curve (ECDSA_P256, ECDH_P384...), the catalogue
// entry is the family (ECDSA, ECDH): the catalogue carries no curve, and none is
// invented. "3DES_112" is the two-key form of the same cipher and maps to the family.
var cngAlgorithms = map[string]string{
	"AES": "AES", "XTS-AES": "AES",
	"3DES": "3DES", "3DES_112": "3DES", "DES": "DES", "RC2": "RC2", "RC4": "RC4",
	"MD2": "MD2", "MD4": "MD4", "MD5": "MD5", "SHA1": "SHA-1",
	"SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
	"SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
	"RSA": "RSA", "RSA_SIGN": "RSA", "DSA": "DSA", "DH": "DH",
	"ECDSA": "ECDSA", "ECDSA_P256": "ECDSA", "ECDSA_P384": "ECDSA", "ECDSA_P521": "ECDSA",
	"ECDH": "ECDH", "ECDH_P256": "ECDH", "ECDH_P384": "ECDH", "ECDH_P521": "ECDH",
	"CHACHA20_POLY1305": "ChaCha20-Poly1305",
	// The two post-quantum families enter through CNGProbes, which confirms the parameter sets.
}

// CNGAlgorithm returns the catalogue algorithm a CNG identifier is an instance of.
func CNGAlgorithm(identifier string) (id string, ok bool) {
	id, ok = cngAlgorithms[identifier]
	return id, ok
}

// CNGProbe is a post-quantum parameter set the sensor asks Windows to accept.
type CNGProbe struct {
	Algorithm string // the CNG identifier ("ML-KEM")
	ParamSet  string // the parameter set, digits only ("768")
	ID        string // the catalogue algorithm it confirms ("ML-KEM-768")
}

// CNGProbes are the parameter sets FIPS 203 and FIPS 204 define, in the form Windows
// takes (found by asking the operating system: it accepted these and refused "999"
// and "1"). Only these post-quantum families are probed, because probing generates an
// ephemeral in-memory key pair (ADR-0013); nothing else is ever asked that way.
var CNGProbes = []CNGProbe{
	{"ML-KEM", "512", "ML-KEM-512"},
	{"ML-KEM", "768", "ML-KEM-768"},
	{"ML-KEM", "1024", "ML-KEM-1024"},
	{"ML-DSA", "44", "ML-DSA-44"},
	{"ML-DSA", "65", "ML-DSA-65"},
	{"ML-DSA", "87", "ML-DSA-87"},
}

// CNGFamilies are the post-quantum identifiers whose parameter sets are probed, and
// the catalogue family reported when the identifier opens but no parameter set could
// be confirmed.
var CNGFamilies = map[string]string{"ML-KEM": "ML-KEM", "ML-DSA": "ML-DSA"}

// CSPTypeNames names the legacy provider types (PROV_*) by their documented number.
// A type this table lacks is reported by number only.
var CSPTypeNames = map[uint32]string{
	1: "PROV_RSA_FULL", 2: "PROV_RSA_SIG", 3: "PROV_DSS", 4: "PROV_FORTEZZA", 5: "PROV_MS_EXCHANGE",
	6: "PROV_SSL", 12: "PROV_RSA_SCHANNEL", 13: "PROV_DSS_DH", 14: "PROV_EC_ECDSA_SIG",
	15: "PROV_EC_ECNRA_SIG", 16: "PROV_EC_ECDSA_FULL", 17: "PROV_EC_ECNRA_FULL",
	18: "PROV_DH_SCHANNEL", 20: "PROV_SPYRUS_LYNKS", 21: "PROV_RNG", 22: "PROV_INTEL_SEC",
	23: "PROV_REPLACE_OWF", 24: "PROV_RSA_AES",
}

// OpenableStorageProviders are the key storage providers the sensor may OPEN, which
// loads their code, to list the algorithms they offer. It is a short allow-list of
// in-box Microsoft providers; every other provider, whatever its name claims, is
// listed by name only and never loaded (ADR-0013). The Platform (TPM), Smart Card,
// Passport and Pluton providers are deliberately absent: opening one can reach
// hardware, prompt the user or stall.
var OpenableStorageProviders = map[string]bool{
	"Microsoft Software Key Storage Provider": true,
}
