package pqc

// Class is a post-quantum verdict about an algorithm.
type Class string

// The verdicts. There is deliberately no "unknown" verdict here: an algorithm
// with no evidence-backed rule is reported as unclassified, not labelled.
const (
	// Vulnerable: broken in polynomial time by a sufficiently large quantum
	// computer running Shor's algorithm.
	Vulnerable Class = "quantum-vulnerable"
	// Safe: not materially weakened by known quantum attacks, either because it is
	// a NIST post-quantum standard or because the best known quantum attack is only
	// Grover's quadratic speed-up.
	Safe Class = "quantum-safe"
)

// Reference is a citation for a verdict.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// A rule is the evidence for one verdict. Every rule MUST carry a rationale and
// at least one reference (TestEveryRuleIsCited): no citation, no verdict.
//
// A component matches a rule by, in order of authority:
//  1. its OID equalling one of the rule's OIDs (its catalogue algorithms' OIDs
//     plus oids);
//  2. its OID lying under one of the rule's arcs, an OID subtree that the cited
//     standard reserves for this family of algorithms;
//  3. its name equalling, exactly and case-insensitively, one of the rule's
//     catalogue algorithm IDs. Names are matched exactly and never by pattern, so
//     "SHA256withRSA" or "rsa-ish" is not guessed at.
type rule struct {
	class     Class
	rationale string
	basis     []Reference

	algos []string // algo catalogue IDs: contributes each one's OID and its name
	oids  []string // extra exact OIDs
	arcs  []string // OID subtrees
}

var (
	refShor = Reference{
		"Shor, Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer, SIAM J. Comput. 26(5), 1997",
		"https://arxiv.org/abs/quant-ph/9508027",
	}
	refProosZalka = Reference{
		"Proos & Zalka, Shor's discrete logarithm quantum algorithm for elliptic curves, QIC 3(4), 2003",
		"https://arxiv.org/abs/quant-ph/0301141",
	}
	refIR8547 = Reference{
		"NIST IR 8547 (initial public draft, Nov 2024), Transition to Post-Quantum Cryptography Standards: lists RSA, ECDSA, EdDSA, DH and ECDH as quantum-vulnerable, to be deprecated by 2030 and disallowed by 2035",
		"https://csrc.nist.gov/pubs/ir/8547/ipd",
	}
	refNISTCategories = Reference{
		"NIST PQC security categories: 1/3/5 are defined by AES-128/192/256 key search, 2/4 by SHA-256/SHA-384 collision search",
		"https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)",
	}
	refCSOR = Reference{
		"NIST CSOR algorithm registration (OIDs)",
		"https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration",
	}
	refFIPS197  = Reference{"FIPS 197, Advanced Encryption Standard (AES)", "https://doi.org/10.6028/NIST.FIPS.197"}
	refFIPS180  = Reference{"FIPS 180-4, Secure Hash Standard (SHA-2)", "https://doi.org/10.6028/NIST.FIPS.180-4"}
	refFIPS203  = Reference{"FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)", "https://doi.org/10.6028/NIST.FIPS.203"}
	refFIPS204  = Reference{"FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA)", "https://doi.org/10.6028/NIST.FIPS.204"}
	refFIPS205  = Reference{"FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA)", "https://doi.org/10.6028/NIST.FIPS.205"}
	refRFC8017  = Reference{"RFC 8017, PKCS #1 v2.2 (RSA); the 1.2.840.113549.1.1 arc is pkcs-1", "https://www.rfc-editor.org/rfc/rfc8017"}
	refRFC3279  = Reference{"RFC 3279 (id-dsa 1.2.840.10040.4.1, dhpublicnumber 1.2.840.10046.2.1)", "https://www.rfc-editor.org/rfc/rfc3279"}
	refRFC5480  = Reference{"RFC 5480 (id-ecPublicKey under ansi-X9-62 1.2.840.10045; id-ecDH 1.3.132.1.12)", "https://www.rfc-editor.org/rfc/rfc5480"}
	refRFC8410  = Reference{"RFC 8410 (X25519 1.3.101.110, X448 .111, Ed25519 .112, Ed448 .113)", "https://www.rfc-editor.org/rfc/rfc8410"}
	refRFC8439  = Reference{"RFC 8439, ChaCha20 and Poly1305 for IETF Protocols", "https://www.rfc-editor.org/rfc/rfc8439"}
	refRFC10024 = Reference{"RFC 10024: Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3", "https://www.rfc-editor.org/rfc/rfc10024"}
)

const (
	whyFactoring = "Relies on the hardness of integer factorization. Shor's algorithm factors integers in polynomial time on a sufficiently large quantum computer, so larger keys raise the quantum resources needed only polynomially and give no lasting protection."
	whyFiniteDLP = "Relies on the hardness of the discrete logarithm problem in a finite field. Shor's algorithm solves discrete logarithms in polynomial time on a sufficiently large quantum computer."
	whyECDLP     = "Relies on the hardness of the elliptic-curve discrete logarithm problem. Shor's algorithm extends to elliptic-curve groups and solves it in polynomial time on a sufficiently large quantum computer."
	whyPQCStd    = "Standardized by NIST as a post-quantum algorithm, designed to resist attacks by both classical and quantum computers; its standard assigns the parameter set a NIST security category."
)

var rules = []rule{
	{
		class: Vulnerable, rationale: whyFactoring,
		basis: []Reference{refShor, refIR8547, refRFC8017},
		algos: []string{"RSA"}, arcs: []string{"1.2.840.113549.1.1"},
	},
	{
		class: Vulnerable, rationale: whyFiniteDLP,
		basis: []Reference{refShor, refRFC3279},
		algos: []string{"DSA"}, arcs: []string{"1.2.840.10040.4"},
	},
	{
		class: Vulnerable, rationale: whyFiniteDLP,
		basis: []Reference{refShor, refIR8547, refRFC3279},
		algos: []string{"DH"}, arcs: []string{"1.2.840.10046.2"},
	},
	{
		class: Vulnerable, rationale: whyECDLP,
		basis: []Reference{refShor, refProosZalka, refIR8547, refRFC5480},
		algos: []string{"ECDSA", "ECDH"}, arcs: []string{"1.2.840.10045"},
	},
	{
		class: Vulnerable, rationale: whyECDLP + " Applies to the Edwards and Montgomery curves used by EdDSA and X25519/X448 as it does to the NIST curves.",
		basis: []Reference{refShor, refProosZalka, refIR8547, refRFC8410},
		algos: []string{"Ed25519", "X25519"}, oids: []string{"1.3.101.111", "1.3.101.113"}, // X448, Ed448
	},
	{
		class:     Safe,
		rationale: "Symmetric block cipher. The best known quantum attack on key search, Grover's algorithm, gives only a quadratic speed-up, so an n-bit key keeps about n/2 bits of quantum security. NIST defines post-quantum security categories 1, 3 and 5 as the cost of key search against AES-128, AES-192 and AES-256, so AES at any key size the standard defines meets at least category 1. This is a statement about the algorithm, not about the key size or mode in use on a given host.",
		basis:     []Reference{refNISTCategories, refFIPS197, refCSOR},
		algos:     []string{"AES", "AES-128-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM", "AES-128-CCM", "AES-256-CCM"}, arcs: []string{"2.16.840.1.101.3.4.1"},
	},
	{
		class:     Safe,
		rationale: "Hash function. NIST defines post-quantum security categories 2 and 4 as the cost of collision search against 256-bit and 384-bit hash functions (SHA-256, SHA-384), i.e. it treats them as the benchmark of quantum-era strength; SHA-512 is larger still.",
		basis:     []Reference{refNISTCategories, refFIPS180, refCSOR},
		algos:     []string{"SHA-256", "SHA-384", "SHA-512"},
	},
	{
		class:     Safe,
		rationale: "Symmetric authenticated encryption cipher (RFC 8439). Like AES, the best known quantum attack on its 256-bit key is Grover's algorithm, a quadratic speed-up, leaving about 128 bits of quantum security: the same standing as AES-256 under the NIST PQC security categories.",
		basis:     []Reference{refNISTCategories, refRFC8439},
		algos:     []string{"ChaCha20-Poly1305"},
	},
	{
		class: Safe, rationale: whyPQCStd,
		basis: []Reference{refFIPS203, refCSOR},
		algos: []string{"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"},
	},
	{
		class:     Safe,
		rationale: "A hybrid TLS 1.3 key-exchange group combining a classical ECDH group with ML-KEM: RFC 10024 defines it so the shared secret stays secret if EITHER component resists attack, so a quantum computer that breaks only the classical half does not break the combination.",
		basis:     []Reference{refFIPS203, refRFC10024},
		// The three groups RFC 10024 itself defines, exactly as the TLS registry names
		// them. Other hybrid names the registry carries (SecP256r1MLKEM512,
		// MLKEM512X25519, curveSM2MLKEM768) cite only an internet-draft, not an RFC or
		// FIPS standard, and the two "...Kyber768Draft00" names are pre-standard and
		// IANA-obsolete: none of those get a rule, so they are reported unclassified
		// rather than given a verdict this citation bar does not support.
		algos: []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"},
	},
	{
		class: Safe, rationale: whyPQCStd,
		basis: []Reference{refFIPS204, refCSOR},
		algos: []string{"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"},
	},
	{
		class: Safe, rationale: whyPQCStd,
		basis: []Reference{refFIPS205, refCSOR},
		algos: []string{
			"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
			"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
			"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
		},
	},
}
