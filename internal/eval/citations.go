package eval

// The sources the rules cite. Wording that quotes a requirement was checked
// against the document itself (RFC 9325 sections, IANA).

func rfc(num, title string) Citation {
	return Citation{Title: "RFC " + num + ": " + title, URL: "https://www.rfc-editor.org/rfc/rfc" + num}
}

func cve(id, what string) Citation {
	return Citation{Title: id + " (" + what + ")", URL: "https://nvd.nist.gov/vuln/detail/" + id}
}

var (
	citRFC6176  = rfc("6176", "Prohibiting Secure Sockets Layer (SSL) Version 2.0")
	citRFC7568  = rfc("7568", "Deprecating Secure Sockets Layer Version 3.0")
	citRFC8996  = rfc("8996", "Deprecating TLS 1.0 and TLS 1.1")
	citRFC9325  = rfc("9325", "Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram TLS (DTLS)")
	citRFC7465  = rfc("7465", "Prohibiting RC4 Cipher Suites")
	citRFC5746  = rfc("5746", "Transport Layer Security (TLS) Renegotiation Indication Extension")
	citRFC7507  = rfc("7507", "TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks")
	citRFC5280  = rfc("5280", "Internet X.509 Public Key Infrastructure Certificate and CRL Profile")
	citRFC9525  = rfc("9525", "Service Identity in TLS")
	citRFC8446  = rfc("8446", "The Transport Layer Security (TLS) Protocol Version 1.3")
	citRFC10024 = Citation{
		Title: "RFC 10024: Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3",
		URL:   "https://www.rfc-editor.org/rfc/rfc10024",
	}

	citSweet32 = cve("CVE-2016-2183", "Sweet32: birthday attacks on 64-bit block ciphers")
	citFREAK   = cve("CVE-2015-0204", "FREAK: export-grade RSA downgrade")
	citLogjam  = cve("CVE-2015-4000", "Logjam: weak and export-grade Diffie-Hellman")
	citCRIME   = cve("CVE-2012-4929", "CRIME: TLS compression")
	citPOODLE  = cve("CVE-2014-3566", "POODLE: SSLv3 CBC padding oracle")
	citBEAST   = cve("CVE-2011-3389", "BEAST: TLS 1.0 CBC chosen-boundary attack")

	citIANASuites = Citation{
		Title: "IANA TLS Cipher Suites registry (Recommended column; per-suite references)",
		URL:   "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4",
	}
	citIANAGroups = Citation{
		Title: "IANA TLS Supported Groups registry",
		URL:   "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8",
	}
	citCABF = Citation{
		Title: "CA/Browser Forum Baseline Requirements for publicly-trusted TLS server certificates",
		URL:   "https://cabforum.org/working-groups/server/baseline-requirements/documents/",
	}
	citSP80057 = Citation{
		Title: "NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management (comparable strengths, Table 2)",
		URL:   "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final",
	}

	citFIPS203 = Citation{Title: "NIST FIPS 203: ML-KEM", URL: "https://doi.org/10.6028/NIST.FIPS.203"}
	citFIPS204 = Citation{Title: "NIST FIPS 204: ML-DSA", URL: "https://doi.org/10.6028/NIST.FIPS.204"}
	citIR8547  = Citation{
		Title: "NIST IR 8547 (initial public draft): Transition to Post-Quantum Cryptography Standards",
		URL:   "https://csrc.nist.gov/pubs/ir/8547/ipd",
	}
	citHNDL = Citation{
		Title: "CISA/NSA/NIST: Quantum-Readiness: Migration to Post-Quantum Cryptography (harvest now, decrypt later)",
		URL:   "https://www.cisa.gov/resources-tools/resources/quantum-readiness-migration-post-quantum-cryptography",
	}
	citNISTCategories = Citation{
		Title: "NIST PQC security categories (1/3/5 defined by AES-128/192/256 key search)",
		URL:   "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)",
	}
	citOpenSSL35 = Citation{
		Title: "OpenSSL 3.5: ML-KEM added in OpenSSL 3.5 (EVP_PKEY-ML-KEM)",
		URL:   "https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/",
	}
	citGoMLKEM = Citation{
		Title: "Go crypto/tls: X25519MLKEM768 offered by default from Go 1.24",
		URL:   "https://pkg.go.dev/crypto/tls#Config",
	}
)
