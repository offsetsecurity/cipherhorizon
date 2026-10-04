package eval

// passText says, for each check, what was confirmed when it found nothing. A rule's title
// names the problem ("Certificate has expired"); shown with "not found" it reads as a double
// negative, so a check that passed shows this sentence instead (PRD-006 REQ-RV-4). A test
// keeps the map in step with the rules.
var passText = map[string]string{
	"PROTO.SSL2":       "SSLv2 is switched off",
	"PROTO.SSL3":       "SSLv3 is switched off",
	"PROTO.TLS10":      "TLS 1.0 is switched off",
	"PROTO.TLS11":      "TLS 1.1 is switched off",
	"PROTO.NO-TLS12":   "TLS 1.2 or TLS 1.3 is available",
	"PROTO.NO-TLS13":   "TLS 1.3 is available",
	"PQC.HNDL-EXPOSED": "Key exchange is protected against harvest-now-decrypt-later",

	"CIPHER.NULL":             "Every accepted suite encrypts",
	"CIPHER.EXPORT":           "No export-grade suite is accepted",
	"CIPHER.ANON":             "Every accepted suite authenticates the server",
	"CIPHER.RC4":              "No RC4 suite is accepted",
	"CIPHER.DES":              "No single-DES suite is accepted",
	"CIPHER.SWEET32":          "No 64-bit block cipher (3DES, IDEA) is accepted",
	"CIPHER.NO-FS":            "Every accepted suite has forward secrecy",
	"CIPHER.IANA-DISCOURAGED": "No accepted suite is marked Discouraged by IANA",
	"CIPHER.CBC":              "No CBC-mode suite is accepted",

	"KX.DH-SMALL":        "No small Diffie-Hellman prime is used",
	"KX.DH-COMMON-PRIME": "No small, widely shared Diffie-Hellman prime is used",

	"CERT.EXPIRED":              "The certificate has not expired",
	"CERT.NOT-YET-VALID":        "The certificate is already valid",
	"CERT.EXPIRING":             "The certificate does not expire soon",
	"CERT.UNTRUSTED":            "The chain leads to a trusted root",
	"CERT.NAME-MISMATCH":        "The certificate matches the host name",
	"CERT.WEAK-KEY":             "The certificate's public key is large enough",
	"CERT.WEAK-SIGNATURE":       "The certificate is signed with a sound hash",
	"CERT.CHAIN-INCOMPLETE":     "The server sends every intermediate certificate",
	"CERT.CHAIN-ORDER":          "The chain is sent in the right order",
	"CERT.CHAIN-EXTRA":          "The chain carries no certificate clients do not need",
	"CERT.INTERMEDIATE-EXPIRES": "No intermediate expires before the certificate",
	"CERT.LIFETIME":             "The validity period is within the limit for public certificates",
	"CERT.NO-SERVERAUTH":        "The certificate is valid for TLS servers",
	"CERT.CLIENTAUTH-EKU":       "The certificate is for servers only",
	"CERT.PARTIAL-TRUST":        "Every root store checked trusts the certificate",
	"CERT.WEAK-EXPONENT":        "The RSA public exponent is at least 65537",
	"CERT.NO-SNI-DIFFERENT":     "Clients without a server name get the same certificate",

	"OCSP.REVOKED":             "The certificate is not reported revoked",
	"OCSP.MISMATCH":            "A stapled OCSP response, if any, is for this certificate",
	"OCSP.STALE":               "A stapled OCSP response, if any, is current",
	"OCSP.UNKNOWN":             "A stapled OCSP response, if any, gives a status",
	"OCSP.MUST-STAPLE-MISSING": "No Must-Staple requirement is broken",
	"OCSP.NO-STAPLE":           "The server staples an OCSP response",
	"CT.NO-SCTS":               "The certificate carries Certificate Transparency proof",

	"FEAT.RENEGOTIATION":         "Secure renegotiation is advertised",
	"FEAT.COMPRESSION":           "TLS compression is refused",
	"FEAT.NO-FALLBACK-SCSV":      "Protocol downgrade protection (TLS_FALLBACK_SCSV) works",
	"FEAT.CLIENT-CERT-REQUESTED": "No client certificate is requested",

	"HTTP.NO-HSTS":            "HTTP Strict Transport Security is set",
	"HTTP.HSTS-DISABLED":      "HSTS is not switched off",
	"HTTP.HSTS-SHORT":         "HSTS lasts at least a year",
	"HTTP.HSTS-INVALID":       "The HSTS header is valid",
	"HTTP.HSTS-NO-SUBDOMAINS": "HSTS covers subdomains",

	"VULN.POODLE":           "POODLE is not possible: no SSLv3 with CBC suites",
	"VULN.BEAST":            "BEAST is not possible: no TLS 1.0 with CBC suites",
	"VULN.DROWN-SHARED-KEY": "DROWN is not possible: this key is not seen on SSLv2",
}

// PassText is what a check that found nothing confirmed, or "" when none is written.
func PassText(id string) string { return passText[id] }
