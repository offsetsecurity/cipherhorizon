package machinefacts

// Interpretation of the PRD-019 signatures: platform state, runtimes, the installed OpenSSL and
// OpenSSH, TLS and VPN configuration, authentication policy, key providers, TLS bindings,
// listening services and the kernel's cryptography. Each becomes CycloneDX components with
// properties a person can read on the machine page; algorithms named by a setting become
// algorithm components, so the post-quantum verdicts reach them.

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/collector"
)

// ---- shared helpers -------------------------------------------------------------------------

// settingOf splits a configuration line into a name and a value: "key = value", "key: value",
// "key value;" (nginx), "Key value" (Apache, sshd) all read the same way.
func settingOf(line string) (string, string) {
	// A trailing comment ("ssl_protocols TLSv1.2 TLSv1.3; # Dropping SSLv3") is not part of the value.
	if i := strings.Index(line, " #"); i > 0 {
		line = line[:i]
	} else if i := strings.Index(line, "	#"); i > 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ";"))
	if k, v, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(strings.TrimSpace(k), " \t") {
		return strings.TrimSpace(k), strings.TrimSpace(v)
	}
	if k, v, ok := strings.Cut(line, ":"); ok && !strings.ContainsAny(strings.TrimSpace(k), " \t") && !strings.HasPrefix(line, "<") {
		return strings.TrimSpace(k), strings.TrimSpace(v)
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return "", ""
	}
	if len(f) == 1 {
		return f[0], ""
	}
	return f[0], strings.Join(f[1:], " ")
}

// dataComponent is a configuration or state record: a CycloneDX "data" component whose
// properties are what the inventory read, with where it read it.
func dataComponent(ref, name, area, kind, source string, props []cdx.Property) collector.CryptoAsset {
	ps := []cdx.Property{prop("config-area", area), prop("config-kind", kind)}
	if source != "" {
		ps = append(ps, prop("config-source", source))
	}
	ps = append(ps, props...)
	return collector.CryptoAsset{Component: cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeData, Name: name, Properties: &ps}}
}

// protocolConfig is a protocol component (TLS, SSH, IPsec) carrying its area for the page.
func protocolConfig(ref, name, area string, typ cdx.CryptoProtocolType, source string, props []cdx.Property) collector.CryptoAsset {
	ps := []cdx.Property{prop("config-area", area), prop("config-source", source)}
	ps = append(ps, props...)
	return protocolComponent(ref, name, typ, ps, nil)
}

func (b *configBuilder) areaOf(sig string) string {
	if s, ok := b.db.ByID(sig); ok && s.Area != "" {
		return s.Area
	}
	return "software"
}

// bySig groups items by signature, in a stable order.
func bySig(items []Item) ([]string, map[string][]Item) {
	m := map[string][]Item{}
	var order []string
	for _, it := range items {
		if _, ok := m[it.Sig]; !ok {
			order = append(order, it.Sig)
		}
		m[it.Sig] = append(m[it.Sig], it)
	}
	return order, m
}

var versionRE = regexp.MustCompile(`\d+(\.\d+)+[A-Za-z0-9+~.-]*`)

func firstVersion(s string) string { return versionRE.FindString(s) }

// tlsBackend finds the TLS library a build line names ("OpenSSL/3.5.5", "built with OpenSSL 3.0.13",
// "GnuTLS/3.8.9", "LibreSSL 3.9.2", "rustls-ffi").
var tlsBackendRE = regexp.MustCompile(`(?i)\b(OpenSSL|LibreSSL|GnuTLS|rustls|wolfSSL|mbedTLS|BoringSSL|quictls|Schannel|SecureTransport|NSS|libgcrypt)\b[ /:]*v?(\d+(?:\.\d+)+[a-z]?)?`)

func tlsBackend(s string) string {
	m := tlsBackendRE.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	if m[2] == "" {
		return m[1]
	}
	return m[1] + " " + m[2]
}

// ---- algorithm name maps ----------------------------------------------------------------------

// Names used by Kerberos, IPsec, OpenVPN, GnuPG, the kernel and crypt(3), mapped onto the
// catalogue's names. Unknown names are kept as they are, so they are listed, not guessed at.
var algoNames = map[string]string{
	// Kerberos enctypes (RFC 3961, 3962, 8009, 6803) and Windows' names
	"aes256-cts-hmac-sha1-96": "AES", "aes128-cts-hmac-sha1-96": "AES", "aes256-cts-hmac-sha384-192": "AES", "aes128-cts-hmac-sha256-128": "AES",
	"aes256-cts": "AES", "aes128-cts": "AES", "aes256-sha1": "AES", "aes128-sha1": "AES", "aes256-sha2": "AES", "aes128-sha2": "AES",
	"rc4-hmac": "RC4", "arcfour-hmac": "RC4", "arcfour-hmac-md5": "RC4", "rc4-hmac-exp": "RC4", "arcfour-hmac-exp": "RC4", "rc4": "RC4",
	"des-cbc-crc": "DES", "des-cbc-md5": "DES", "des-cbc-md4": "DES", "des": "DES", "des3-cbc-sha1": "3DES", "des3-hmac-sha1": "3DES", "des3": "3DES", "des3-cbc-sha1-kd": "3DES",
	"camellia256-cts-cmac": "Camellia", "camellia128-cts-cmac": "Camellia", "camellia256-cts": "Camellia", "camellia128-cts": "Camellia",
	// IPsec proposals (strongSwan, libreswan)
	"aes128": "AES", "aes192": "AES", "aes256": "AES", "aes128gcm16": "AES-128-GCM", "aes256gcm16": "AES-256-GCM", "aes128gcm8": "AES-128-GCM", "aes256gcm8": "AES-256-GCM",
	"aes128gcm12": "AES-128-GCM", "aes256gcm12": "AES-256-GCM", "aes128gcm128": "AES-128-GCM", "aes256gcm128": "AES-256-GCM", "aes_gcm": "AES-256-GCM", "aes_gcm256": "AES-256-GCM", "aes_gcm128": "AES-128-GCM",
	"aes128ccm16": "AES-128-CCM", "aes256ccm16": "AES-256-CCM", "chacha20poly1305": "ChaCha20-Poly1305", "3des": "3DES", "blowfish": "Blowfish", "camellia128": "Camellia", "camellia256": "Camellia",
	"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha2_256": "SHA-256", "sha2_384": "SHA-384", "sha2_512": "SHA-512", "md5": "MD5",
	"sha1_160": "SHA-1", "sha256_96": "SHA-256", "aesxcbc": "AES", "aescmac": "AES", "prfsha1": "SHA-1", "prfsha256": "SHA-256", "prfsha384": "SHA-384", "prfsha512": "SHA-512", "prfmd5": "MD5",
	"modp768": "DH", "modp1024": "DH", "modp1536": "DH", "modp2048": "DH", "modp3072": "DH", "modp4096": "DH", "modp6144": "DH", "modp8192": "DH", "modp1024s160": "DH", "modp2048s224": "DH", "modp2048s256": "DH",
	"dh2": "DH", "dh5": "DH", "dh14": "DH", "dh15": "DH", "dh16": "DH", "dh17": "DH", "dh18": "DH", "dh19": "ECDH", "dh20": "ECDH", "dh21": "ECDH", "dh31": "X25519",
	"ecp192": "ECDH", "ecp224": "ECDH", "ecp256": "ECDH", "ecp384": "ECDH", "ecp521": "ECDH", "ecp256bp": "ECDH", "ecp384bp": "ECDH", "ecp512bp": "ECDH",
	"x25519": "X25519", "curve25519": "X25519", "x448": "X448", "ke1_mlkem512": "ML-KEM-512", "ke1_mlkem768": "ML-KEM-768", "ke1_mlkem1024": "ML-KEM-1024", "mlkem512": "ML-KEM-512", "mlkem768": "ML-KEM-768", "mlkem1024": "ML-KEM-1024",
	"ke1_frodoa3": "FrodoKEM", "ke1_frodos3": "FrodoKEM", "ke1_frodoa5": "FrodoKEM", "ke1_frodos5": "FrodoKEM",
	"pubkey": "RSA", "psk": "pre-shared key", "rsasig": "RSA", "ecdsasig": "ECDSA", "ecdsa": "ECDSA", "rsa": "RSA", "eddsa": "Ed25519", "ed25519": "Ed25519", "ed448": "Ed448",
	// OpenVPN
	"aes-256-gcm": "AES-256-GCM", "aes-128-gcm": "AES-128-GCM", "aes-192-gcm": "AES", "aes-256-cbc": "AES-256-CBC", "aes-128-cbc": "AES-128-CBC", "aes-192-cbc": "AES-192-CBC",
	"chacha20-poly1305": "ChaCha20-Poly1305", "bf-cbc": "Blowfish", "des-ede3-cbc": "3DES", "des-cbc": "DES", "camellia-256-cbc": "Camellia", "camellia-128-cbc": "Camellia",
	"sha1-openvpn": "SHA-1", "sha256-openvpn": "SHA-256", "sha512-openvpn": "SHA-512", "sha384-openvpn": "SHA-384",
	"secp256r1": "ECDH", "secp384r1": "ECDH", "secp521r1": "ECDH", "prime256v1": "ECDH", "x25519-group": "X25519", "x25519mlkem768": "X25519MLKEM768", "secp256r1mlkem768": "SecP256r1MLKEM768", "secp384r1mlkem1024": "SecP384r1MLKEM1024",
	// GnuPG --version lists
	"elg": "ElGamal", "ecdh": "ECDH", "idea": "IDEA", "cast5": "CAST5", "aes192-gpg": "AES", "aes256-gpg": "AES", "twofish": "Twofish", "camellia128-gpg": "Camellia", "camellia192": "Camellia", "camellia256-gpg": "Camellia",
	"sha224": "SHA-224", "ripemd160": "RIPEMD-160", "sha3-256": "SHA3-256", "sha3-512": "SHA3-512",
	// crypt(3) password hashing
	"yescrypt": "yescrypt", "bcrypt": "bcrypt", "sha512crypt": "SHA-512", "sha256crypt": "SHA-256", "md5crypt": "MD5", "bigcrypt": "DES", "descrypt": "DES",
	// Linux kernel crypto API
	"aes-kernel": "AES", "gcm(aes)": "AES-256-GCM", "xts(aes)": "AES", "cbc(aes)": "AES", "ctr(aes)": "AES", "ccm(aes)": "AES", "ecb(aes)": "AES", "sha1-kernel": "SHA-1",
	"sha256-kernel": "SHA-256", "sha384-kernel": "SHA-384", "sha512-kernel": "SHA-512", "md5-kernel": "MD5", "des3_ede": "3DES", "ecdsa-nist-p256": "ECDSA", "ecdsa-nist-p384": "ECDSA", "ecdsa-nist-p521": "ECDSA",
	"ecdh-nist-p256": "ECDH", "ecdh-nist-p384": "ECDH", "ecdh-nist-p192": "ECDH", "curve25519-kernel": "X25519", "rsa-kernel": "RSA", "rfc7539(chacha20,poly1305)": "ChaCha20-Poly1305", "rfc7539esp(chacha20,poly1305)": "ChaCha20-Poly1305",
	"chacha20": "ChaCha20", "poly1305": "Poly1305", "sm4": "SM4", "sm3": "SM3", "sm2": "SM2", "blake2b-256": "BLAKE2b", "blake2b-512": "BLAKE2b", "blake2s-256": "BLAKE2s", "sha3-256-kernel": "SHA3-256", "sha3-512-kernel": "SHA3-512",
	"ghash": "GHASH", "crc32c": "", "crc32": "", "crct10dif": "", "xxhash64": "", "jitterentropy_rng": "", "stdrng": "", "drbg_nopr_hmac_sha256": "HMAC-DRBG", "drbg_pr_hmac_sha256": "HMAC-DRBG",
	"drbg_nopr_ctr_aes256": "CTR-DRBG", "drbg_pr_ctr_aes256": "CTR-DRBG", "drbg_nopr_sha256": "Hash-DRBG", "drbg_pr_sha256": "Hash-DRBG", "lzo": "", "lz4": "", "zstd": "", "deflate": "", "zlib-deflate": "", "842": "", "lzo-rle": "",
	"cmac(aes)": "AES", "xcbc(aes)": "AES", "essiv(cbc(aes),sha256)": "AES", "hmac(sha256)": "SHA-256", "hmac(sha1)": "SHA-1", "hmac(sha512)": "SHA-512", "hmac(sha384)": "SHA-384", "hmac(md5)": "MD5",
	"authenc(hmac(sha256),cbc(aes))": "AES", "authenc(hmac(sha1),cbc(aes))": "AES", "pkcs1pad(rsa,sha256)": "RSA", "pkcs1pad(rsa,sha1)": "RSA", "pkcs1pad(rsa,sha512)": "RSA", "pkcs1pad(rsa,sha384)": "RSA", "pkcs1(rsa,sha256)": "RSA", "pkcs1(rsa,sha512)": "RSA",
	"p1363(ecdsa-nist-p256)": "ECDSA", "p1363(ecdsa-nist-p384)": "ECDSA", "x962(ecdsa-nist-p256)": "ECDSA", "x962(ecdsa-nist-p384)": "ECDSA", "polyval": "", "xchacha20": "ChaCha20", "xchacha12": "ChaCha20", "adiantum(xchacha12,aes)": "AES",
	"hctr2(aes)": "AES", "michael_mic": "", "arc4": "RC4", "ecb(arc4)": "RC4", "ecb(des3_ede)": "3DES", "cbc(des3_ede)": "3DES", "ecb(des)": "DES", "cbc(des)": "DES", "sha224-kernel": "SHA-224", "ecrdsa": "GOST R 34.10-2012",
	"streebog256": "Streebog", "streebog512": "Streebog", "kuznyechik": "Kuznyechik", "sm4-kernel": "SM4", "aria": "ARIA", "cast6": "CAST6", "twofish-kernel": "Twofish", "serpent": "Serpent", "blowfish-kernel": "Blowfish", "camellia-kernel": "Camellia", "fcrypt": "DES", "tea": "TEA", "khazad": "", "anubis": "", "seed": "SEED", "wp512": "Whirlpool", "tgr192": "Tiger", "rmd160": "RIPEMD-160", "md4": "MD4", "michael": "", "nhpoly1305": "Poly1305", "xts(sm4)": "SM4", "gcm(sm4)": "SM4", "ecdh-nist-p521": "ECDH",
}

// primitiveOf gives a catalogue name's primitive, for the algorithm component.
func primitiveOf(name string) cdx.CryptoPrimitive {
	switch {
	case strings.HasPrefix(name, "ML-KEM"), name == "FrodoKEM":
		return cdx.CryptoPrimitiveKEM
	case strings.Contains(name, "MLKEM"), strings.HasPrefix(name, "mlkem"), strings.HasPrefix(name, "sntrup"):
		return cdx.CryptoPrimitiveCombiner
	case name == "RSA", name == "DSA", name == "ECDSA", name == "Ed25519", name == "Ed448", strings.HasPrefix(name, "ML-DSA"), strings.HasPrefix(name, "SLH-DSA"), name == "XMSS", name == "GOST R 34.10-2012", name == "SM2", name == "ElGamal":
		return cdx.CryptoPrimitiveSignature
	case name == "DH", name == "ECDH", name == "X25519", name == "X448":
		return cdx.CryptoPrimitiveKeyAgree
	case strings.HasSuffix(name, "-GCM"), strings.HasSuffix(name, "-CCM"), name == "ChaCha20-Poly1305":
		return cdx.CryptoPrimitiveAE
	case strings.HasPrefix(name, "SHA"), name == "MD5", name == "MD4", name == "RIPEMD-160", name == "BLAKE2b", name == "BLAKE2s", name == "SM3", name == "Streebog", name == "Whirlpool", name == "Tiger", name == "yescrypt", name == "bcrypt":
		return cdx.CryptoPrimitiveHash
	case name == "GHASH", name == "Poly1305", strings.HasPrefix(name, "UMAC"):
		return cdx.CryptoPrimitiveMAC
	case strings.HasSuffix(name, "DRBG"):
		return cdx.CryptoPrimitiveDRBG
	case name == "RC4", name == "ChaCha20":
		return cdx.CryptoPrimitiveStreamCipher
	}
	return cdx.CryptoPrimitiveBlockCipher
}

// algoNamed adds (once) the algorithm a setting names, under its catalogue name; a token
// mapped to "" is not an algorithm (a checksum, a compressor) and is dropped.
func (b *configBuilder) algoNamed(token, context, source string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(token))
	t = strings.TrimLeft(t, "+-^!")
	if t == "" {
		return "", false
	}
	name, ok := algoNames[t+"-"+context]
	if !ok {
		name, ok = algoNames[t]
	}
	if !ok {
		return "", false
	}
	if name == "" {
		return "", false
	}
	return b.algorithm(name, primitiveOf(name), token, source), true
}

// ---- Windows registry values, in words ---------------------------------------------------------

func onOffWord(v string) string {
	switch strings.TrimSpace(v) {
	case "0":
		return "off"
	case "1":
		return "on"
	}
	return v
}

func parseUint(v string) (uint64, bool) {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
		n, err := strconv.ParseUint(v[2:], 16, 64)
		return n, err == nil
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil
}

// secureProtocolsWords reads the WinHTTP / WinINet protocol bit mask.
func secureProtocolsWords(v string) string {
	n, ok := parseUint(v)
	if !ok {
		return v
	}
	var out []string
	for _, p := range []struct {
		bit  uint64
		name string
	}{{0x8, "SSL 2.0"}, {0x20, "SSL 3.0"}, {0x80, "TLS 1.0"}, {0x200, "TLS 1.1"}, {0x800, "TLS 1.2"}, {0x2000, "TLS 1.3"}} {
		if n&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	if len(out) == 0 {
		return v + " (no version bits set)"
	}
	return strings.Join(out, ", ") + " (" + v + ")"
}

// kerberosEnctypes reads Windows' SupportedEncryptionTypes bit mask into enctype names.
func kerberosEnctypes(v string) []string {
	n, ok := parseUint(v)
	if !ok {
		return nil
	}
	var out []string
	for _, p := range []struct {
		bit  uint64
		name string
	}{{0x1, "des-cbc-crc"}, {0x2, "des-cbc-md5"}, {0x4, "rc4-hmac"}, {0x8, "aes128-cts-hmac-sha1-96"}, {0x10, "aes256-cts-hmac-sha1-96"}, {0x20, "aes256-cts-hmac-sha1-96 (SK)"}} {
		if n&p.bit != 0 {
			out = append(out, p.name)
		}
	}
	if n&0x80000000 != 0 {
		out = append(out, "future encryption types")
	}
	return out
}

var lmCompat = []string{"send LM and NTLM", "send LM and NTLM, use NTLMv2 session security when negotiated", "send NTLM only", "send NTLMv2 only", "send NTLMv2 only, refuse LM", "send NTLMv2 only, refuse LM and NTLM"}

func registryWord(sig, name, value string) string {
	n := strings.ToLower(name)
	switch {
	case n == "schusestrongcrypto", n == "systemdefaulttlsversions", n == "enabled", n == "uefisecurebootenabled", n == "smb1", n == "smb2", n == "requiresecuritysignature",
		n == "enablesecuritysignature", n == "encryptdata", n == "rejectunencryptedaccess", n == "enableinsecureguestlogons", n == "allowinsecureguestauth", n == "requireencryption",
		n == "requiresignorseal", n == "sealsecurechannel", n == "signsecurechannel", n == "requirestrongkey", n == "nolmhash", n == "useadvancedstartup", n == "usetpm", n == "usetpmpin", n == "usetpmkey",
		n == "enablevirtualizationbasedsecurity", n == "runasppl", n == "runaspplboot", n == "locked", n == "fdisableencryption", n == "fdenytsconnections", n == "disablepasswordchange", n == "active":
		return onOffWord(value)
	case n == "defaultsecureprotocols", n == "secureprotocols":
		return secureProtocolsWords(value)
	case n == "supportedencryptiontypes":
		if e := kerberosEnctypes(value); e != nil {
			return strings.Join(e, ", ") + " (" + value + ")"
		}
	case n == "lmcompatibilitylevel":
		if i, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && i >= 0 && i < len(lmCompat) {
			return fmt.Sprintf("%d: %s", i, lmCompat[i])
		}
	case n == "ntlmminclientsec", n == "ntlmminserversec":
		if u, ok := parseUint(value); ok {
			var w []string
			if u&0x20000000 != 0 {
				w = append(w, "NTLMv2 session security")
			}
			if u&0x80000000 != 0 {
				w = append(w, "128-bit encryption")
			}
			if u&0x00080000 != 0 {
				w = append(w, "require NTLMv2 (legacy flag)")
			}
			if len(w) > 0 {
				return strings.Join(w, ", ") + " (" + value + ")"
			}
		}
	case n == "securitylayer":
		return map[string]string{"0": "RDP security layer (no TLS)", "1": "negotiate (TLS when the client can)", "2": "TLS required"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "minencryptionlevel":
		return map[string]string{"1": "low (56-bit, client to server only)", "2": "client compatible", "3": "high (128-bit)", "4": "FIPS compliant"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "userauthentication":
		return map[string]string{"0": "Network Level Authentication not required", "1": "Network Level Authentication required"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "ldapclientintegrity", n == "ldapserverintegrity":
		return map[string]string{"0": "none", "1": "negotiate signing", "2": "require signing"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "ldapenforcechannelbinding":
		return map[string]string{"0": "never", "1": "when supported", "2": "always"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "encryptionmethod", n == "encryptionmethodwithxtsos", n == "encryptionmethodwithxtsfdv", n == "encryptionmethodwithxtsrdv":
		return map[string]string{"1": "AES-128 with diffuser", "2": "AES-256 with diffuser", "3": "AES-128-CBC", "4": "AES-256-CBC", "6": "XTS-AES-128", "7": "XTS-AES-256"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "algorithmid" && strings.Contains(sig, "efs"):
		return map[string]string{"26126": "AES-256", "26115": "3DES", "26113": "DESX", "0x6610": "AES-256", "0x6603": "3DES", "0x6604": "DESX"}[strings.TrimSpace(value)] + " (" + value + ")"
	case n == "aepolicy":
		if u, ok := parseUint(value); ok {
			if u == 0x8000 {
				return "disabled (0x8000)"
			}
			var w []string
			if u&0x1 != 0 {
				w = append(w, "enabled")
			}
			if u&0x2 != 0 {
				w = append(w, "renew expired, update pending, remove revoked")
			}
			if u&0x4 != 0 {
				w = append(w, "update templates")
			}
			if len(w) > 0 {
				return strings.Join(w, "; ") + " (" + value + ")"
			}
		}
	case n == "release" && strings.Contains(sig, "dotnet"):
		return dotnetRelease(value)
	}
	return value
}

// dotnetRelease maps the .NET Framework Release key onto the version it means.
func dotnetRelease(v string) string {
	n, ok := parseUint(v)
	if !ok {
		return v
	}
	for _, r := range []struct {
		min  uint64
		name string
	}{{533320, "4.8.1"}, {528040, "4.8"}, {461808, "4.7.2"}, {461308, "4.7.1"}, {460798, "4.7"}, {394802, "4.6.2"}, {394254, "4.6.1"}, {393295, "4.6"}, {379893, "4.5.2"}, {378675, "4.5.1"}, {378389, "4.5"}} {
		if n >= r.min {
			return ".NET Framework " + r.name + " (release " + v + ")"
		}
	}
	return v
}

// registryLeaf shortens a registry key path to what a reader needs: the last two parts.
func registryLeaf(key string) string {
	parts := strings.Split(key, `\`)
	if len(parts) <= 2 {
		return key
	}
	return strings.Join(parts[len(parts)-2:], `\`)
}

// annotateCertificates writes each personal certificate's key provider onto its certificate
// component, matched by subject common name (the facts carry the SHA-1, the sensors the SHA-256).
func (b *configBuilder) annotateCertificates(assets []collector.CryptoAsset) {
	if len(b.keyProviders) == 0 {
		return
	}
	for i := range assets {
		c := &assets[i].Component
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != cdx.CryptoAssetTypeCertificate {
			continue
		}
		for _, kp := range b.keyProviders {
			if kp[0] == "" || !strings.Contains(c.Name, kp[0]) {
				continue
			}
			hw := "software"
			if hardwareProvider.MatchString(kp[1]) {
				hw = "hardware"
			}
			ps := []cdx.Property{}
			if c.Properties != nil {
				ps = *c.Properties
			}
			ps = append(ps, prop("key-provider", kp[1]), prop("key-storage", hw))
			c.Properties = &ps
			break
		}
	}
}

// ---- the builders ----------------------------------------------------------------------------

// buildV3 interprets the PRD-019 signatures. byInterp maps an interpretation to its items.
func (b *configBuilder) buildV3(byInterp map[string][]Item) {
	b.buildPlatform(byInterp["platform"])
	b.buildRuntimes(byInterp["runtime"])
	b.buildSSHSupported(byInterp["ssh-supported"])
	b.buildSSHPolicy(byInterp["ssh-effective"], "config/protocol/ssh-server-effective", "SSH server (OpenSSH), effective policy", "as sshd -T reports it")
	b.buildSSHPolicy(byInterp["ssh-client-config"], "config/protocol/ssh-client", "SSH client (OpenSSH)", "")
	b.buildHostKeyInfo(byInterp["ssh-host-key-info"])
	b.buildTLSConfigs(byInterp["tls-config"])
	b.buildJavaSecurity(byInterp["java-security"])
	b.buildAuthPolicy(byInterp["auth-policy"])
	b.buildVPN(byInterp["vpn-config"])
	b.buildPKIPolicy(byInterp["pki-policy"])
	b.buildKeyProviders(byInterp["key-providers"])
	b.buildTLSBindings(byInterp["tls-bindings"])
	b.buildListeners(byInterp["listeners"])
	b.buildKernelCrypto(byInterp["kernel-crypto"])
	b.buildGenericConfig(byInterp["config"])
}

// buildPlatform: one "Platform and policy" record of the machine's state, each fact with its
// source. The page shows these as a facts grid.
func (b *configBuilder) buildPlatform(items []Item) {
	if len(items) == 0 {
		return
	}
	var props []cdx.Property
	var sources []string
	set := func(k, v, src string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		props = append(props, prop("platform:"+k, strings.TrimSpace(v)))
		if src != "" {
			sources = append(sources, src)
		}
	}
	var policyLines, features, bitlocker, luks []string
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		switch {
		case it.Kind == "line" && strings.HasSuffix(it.Fields[0], "fips_enabled"):
			if strings.TrimSpace(it.Fields[1]) == "1" {
				set("fips-mode", "on (kernel fips_enabled=1)", it.Fields[0])
			} else {
				set("fips-mode", "off (kernel fips_enabled=0)", it.Fields[0])
			}
		case it.Kind == "registry" && strings.Contains(it.Fields[0], "FipsAlgorithmPolicy"):
			set("fips-mode", onOffWord(it.Fields[2])+" (Windows FIPS algorithm policy)", it.Fields[0])
		case it.Kind == "registry" && strings.Contains(it.Fields[0], "SecureBoot"):
			set("secure-boot", onOffWord(it.Fields[2]), it.Fields[0])
		case it.Kind == "registry" && strings.Contains(it.Fields[0], "InetStp"):
			if strings.EqualFold(it.Fields[1], "VersionString") {
				set("iis", it.Fields[2], it.Fields[0])
			}
		case it.Kind == "registry" && strings.Contains(it.Fields[0], "DeviceGuard"):
			set("vbs-policy:"+strings.ToLower(it.Fields[1]), registryWord(it.Sig, it.Fields[1], it.Fields[2]), registryLeaf(it.Fields[0]))
		case it.Kind == "line" && strings.Contains(it.Fields[0], "/sys/class/tpm"):
			set("tpm", "present, TPM "+strings.TrimSpace(it.Fields[1])+".0 ("+path.Base(path.Dir(strings.ReplaceAll(it.Fields[0], `\`, "/")))+")", it.Fields[0])
		case it.Kind == "line" && strings.HasSuffix(it.Fields[0], "crypttab"):
			f := strings.Fields(it.Fields[1])
			if len(f) >= 2 {
				luks = append(luks, f[0]+" on "+f[1])
			}
		case it.Kind == "query":
			q, text := it.Fields[0], strings.TrimSpace(it.Fields[1])
			switch q {
			case "os.kernel":
				set("kernel", text, "uname -srm")
			case "cpu.crypto-flags":
				set("cpu-crypto", text, "/proc/cpuinfo")
			case "crypto-policies":
				policyLines = append(policyLines, text)
			case "disk.encryption":
				luks = append(luks, text)
			case "secure-boot":
				set("secure-boot", strings.ToLower(strings.TrimPrefix(text, "SecureBoot ")), "mokutil / bootctl")
			case "tpm":
				k, v := settingOf(text)
				set("tpm:"+k, v, "Win32_Tpm")
			case "bitlocker":
				bitlocker = append(bitlocker, text)
			case "deviceguard":
				k, v := settingOf(text)
				set("vbs:"+k, deviceGuardWords(k, v), "Win32_DeviceGuard")
			case "host.role":
				k, v := settingOf(text)
				set(k, v, "Win32_ComputerSystem")
			case "windows.features":
				k, _ := settingOf(text)
				features = append(features, k)
			}
		}
	}
	if len(policyLines) > 0 {
		set("crypto-policy", strings.Join(policyLines, "; "), "update-crypto-policies, fips-mode-setup")
	}
	if len(luks) > 0 {
		set("disk-encryption", strings.Join(dedupe(luks), "; "), "lsblk, /etc/crypttab")
	}
	for i, l := range bitlocker {
		set(fmt.Sprintf("bitlocker:%d", i+1), l, "Get-BitLockerVolume")
	}
	if len(features) > 0 {
		sort.Strings(features)
		set("windows-features", strings.Join(features, ", "), "Get-WindowsOptionalFeature")
	}
	if len(props) == 0 {
		return
	}
	b.add(dataComponent("config/platform", "Platform and policy", "platform", "platform", strings.Join(dedupe(sources), ", "), props))
}

func deviceGuardWords(k, v string) string {
	switch k {
	case "vbs-status":
		return map[string]string{"0": "not enabled", "1": "enabled, not running", "2": "running"}[v] + " (" + v + ")"
	case "services-configured", "services-running":
		names := map[string]string{"1": "Credential Guard", "2": "HVCI (memory integrity)", "3": "System Guard Secure Launch", "4": "SMM firmware measurement", "5": "Kernel-mode hardware-enforced stack protection", "6": "Hypervisor-enforced paging translation"}
		var w []string
		for _, c := range strings.Split(v, ",") {
			if n, ok := names[strings.TrimSpace(c)]; ok {
				w = append(w, n)
			}
		}
		if len(w) == 0 {
			return "none"
		}
		return strings.Join(w, ", ")
	}
	return v
}

// buildRuntimes: a language runtime, server or tool with its version and the TLS library it runs with.
func (b *configBuilder) buildRuntimes(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		list := groups[sig]
		switch list[0].Kind {
		case "query":
			b.runtimeFromQuery(sig, list)
		case "file":
			for _, it := range list {
				b.runtimeFromFile(sig, it)
			}
		case "registry":
			b.runtimeFromRegistry(sig, list)
		}
	}
}

// runtimeNames: what a query's first word or an executable's name is called on the page, and
// the TLS stack that runtime is known to use when its output does not say.
var runtimeNames = map[string][2]string{
	"python": {"Python", "the OpenSSL it was built against"}, "python3": {"Python", ""}, "node": {"Node.js", "bundled OpenSSL"}, "go": {"Go", "Go standard library (crypto/tls)"},
	"ruby": {"Ruby", ""}, "php": {"PHP", ""}, "java": {"Java", "JSSE (the JDK's own TLS)"}, "dotnet": {".NET", ""}, "pwsh": {"PowerShell 7", ".NET"}, "perl": {"Perl", ""},
	"ssh": {"OpenSSH client", ""}, "sshd": {"OpenSSH server", ""}, "ssh-keygen": {"OpenSSH ssh-keygen", ""}, "putty": {"PuTTY", "PuTTY's own"}, "plink": {"PuTTY plink", "PuTTY's own"}, "pageant": {"PuTTY pageant", "PuTTY's own"},
	"psql": {"PostgreSQL client", ""}, "postgres": {"PostgreSQL server", ""}, "mysqld": {"MySQL server", ""}, "mariadbd": {"MariaDB server", ""}, "nginx": {"nginx", ""}, "httpd": {"Apache httpd", ""},
	"haproxy": {"HAProxy", ""}, "openvpn": {"OpenVPN", ""}, "wireguard": {"WireGuard", "WireGuard (Noise, X25519, ChaCha20-Poly1305)"}, "stunnel": {"stunnel", ""}, "curl": {"curl", ""}, "git": {"Git", ""},
	"docker": {"Docker", "Go standard library (crypto/tls)"}, "kubectl": {"kubectl", "Go standard library (crypto/tls)"}, "terraform": {"Terraform", "Go standard library (crypto/tls)"}, "vault": {"HashiCorp Vault", "Go standard library (crypto/tls)"},
	"tomcat": {"Apache Tomcat", "JSSE"}, "redis-server": {"Redis", ""}, "mongod": {"MongoDB", ""}, "gpg": {"GnuPG", ""}, "wget": {"GNU Wget", ""}, "gnutls-cli": {"GnuTLS", "GnuTLS"},
	"cryptsetup": {"cryptsetup", "libcryptsetup"}, "named": {"BIND", ""}, "ipsec": {"strongSwan / libreswan", ""}, "apache": {"Apache httpd", ""},
}

func (b *configBuilder) addRuntime(ref, name, version, backend, source, sig string, extra []cdx.Property) {
	if name == "" {
		return
	}
	props := []cdx.Property{prop("collected-by", sig), prop("config-area", b.areaOf(sig))}
	if backend != "" {
		props = append(props, prop("crypto-backend", backend))
	}
	if source != "" {
		props = append(props, prop("config-source", source))
	}
	props = append(props, extra...)
	c := cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeApplication, Name: name, Version: version, Properties: &props}
	b.add(collector.CryptoAsset{Component: c})
}

func (b *configBuilder) runtimeFromQuery(sig string, list []Item) {
	q := list[0].Fields[0]
	var lines []string
	for _, it := range list {
		if len(it.Fields) >= 2 {
			lines = append(lines, strings.TrimSpace(it.Fields[1]))
		}
	}
	all := strings.Join(lines, "\n")
	first := ""
	if len(lines) > 0 {
		first = lines[0]
	}
	var name, version, backend string
	var extra []cdx.Property
	switch q {
	case "python.ssl":
		name, version, backend = "Python", firstVersion(first), tlsBackend(first)
	case "node.versions":
		name, version, backend = "Node.js", firstVersion(first), tlsBackend("OpenSSL "+strings.TrimSpace(strings.TrimPrefix(first[strings.Index(first, "openssl")+7:], " ")))
		if !strings.Contains(first, "openssl") {
			backend = ""
		}
		if backend != "" {
			backend += " (bundled)"
		}
	case "go.version":
		name, version, backend = "Go", strings.TrimPrefix(firstVersion(strings.ReplaceAll(first, "go1", "1")), "v"), "Go standard library (crypto/tls)"
	case "ruby.openssl":
		name, version, backend = "Ruby", firstVersion(first), tlsBackend(first)
	case "php.openssl":
		name, version, backend = "PHP", firstVersion(first), tlsBackend(first)
	case "dotnet.runtimes":
		for i, l := range lines {
			f := strings.Fields(l)
			if len(f) >= 2 {
				b.addRuntime(fmt.Sprintf("software/runtime/dotnet-%d", i), ".NET runtime "+f[0], f[1], "", strings.Join(f[2:], " "), sig, nil)
			}
		}
		return
	case "java.version":
		name = "Java"
		for _, l := range lines {
			if strings.Contains(l, "version") && version == "" {
				version = strings.Trim(firstVersion(l), `"`)
			}
			if strings.HasPrefix(l, "/") {
				extra = append(extra, prop("path", l))
			}
			if strings.Contains(l, "Runtime Environment") {
				extra = append(extra, prop("runtime", l))
			}
		}
		backend = "JSSE (the JDK's own TLS)"
	case "gnutls.version":
		name, version, backend = "GnuTLS", firstVersion(first), "GnuTLS"
	case "gpg.version":
		name, version = "GnuPG", firstVersion(first)
		var refs []string
		for _, l := range lines {
			head, _, hasHead := strings.Cut(l, ":")
			indented := (!hasHead || strings.Contains(head, " ") || strings.Contains(head, ",")) && len(extra) > 0 &&
				strings.HasPrefix(extra[len(extra)-1].Name, "cipherhorizon:algorithms:") && regexp.MustCompile(`^[A-Z0-9]`).MatchString(l)
			switch {
			case strings.HasPrefix(l, "libgcrypt"):
				backend = "libgcrypt " + firstVersion(l)
			case strings.HasPrefix(l, "Pubkey:"), strings.HasPrefix(l, "Cipher:"), strings.HasPrefix(l, "Hash:"), strings.HasPrefix(l, "AEAD:"), strings.HasPrefix(l, "Compression:"),
				indented:
				k, v := settingOf(l)
				if indented { // a continuation of the previous list
					last := &extra[len(extra)-1]
					k, v = strings.TrimPrefix(last.Name, "cipherhorizon:algorithms:"), l
					last.Value += ", " + l
				} else {
					extra = append(extra, prop("algorithms:"+strings.ToLower(k), v))
				}
				if k == "compression" {
					continue
				}
				for _, tok := range strings.Split(v, ",") {
					ctx := "gpg"
					if strings.EqualFold(k, "Pubkey") {
						ctx = ""
					}
					if r, ok := b.algoNamed(strings.TrimSpace(tok), ctx, "gpg --version"); ok {
						refs = append(refs, r)
					}
				}
			}
		}
		b.addRuntimeProviding("software/runtime/gnupg", name, version, backend, "gpg --version", sig, extra, refs)
		return
	case "curl.version":
		name, version, backend = "curl", firstVersion(first), tlsBackend(first)
		if i := strings.Index(first, "libssh2"); i >= 0 {
			extra = append(extra, prop("ssh-library", strings.Fields(first[i:])[0]))
		}
		if i := strings.Index(first, "krb5"); i >= 0 {
			extra = append(extra, prop("kerberos-library", strings.Fields(first[i:])[0]))
		}
	case "wget.version":
		name, version = "GNU Wget", firstVersion(first)
	case "ssh.version":
		name, version, backend = "OpenSSH", strings.TrimPrefix(strings.Fields(first + " x")[0], "OpenSSH_"), tlsBackend(first)
		if i := strings.Index(first, ","); i > 0 {
			extra = append(extra, prop("build", strings.TrimSpace(first[:i])))
		}
	case "nginx.build":
		name = "nginx"
		for _, l := range lines {
			switch {
			case strings.HasPrefix(l, "nginx version:"):
				version = firstVersion(l)
			case strings.HasPrefix(l, "built with"):
				backend = tlsBackend(l)
				if i := strings.Index(l, "running with"); i >= 0 {
					extra = append(extra, prop("running-with", tlsBackend(l[i:])))
				}
			case strings.HasPrefix(l, "TLS SNI"):
				extra = append(extra, prop("sni", strings.TrimPrefix(l, "TLS SNI support ")))
			}
		}
	case "apache.build":
		name = "Apache httpd"
		for _, l := range lines {
			if strings.HasPrefix(l, "Server version:") {
				version = firstVersion(l)
			}
			if strings.Contains(l, "OPENSSL") || strings.Contains(l, "OpenSSL") {
				backend = "OpenSSL (mod_ssl)"
			}
		}
	case "haproxy.build":
		name = "HAProxy"
		for _, l := range lines {
			switch {
			case strings.HasPrefix(l, "HAProxy version"), strings.HasPrefix(l, "HA-Proxy version"):
				version = firstVersion(l)
			case strings.HasPrefix(l, "Built with OpenSSL"):
				backend = tlsBackend(l)
			case strings.HasPrefix(l, "Running on OpenSSL"):
				extra = append(extra, prop("running-with", tlsBackend(l)))
			}
		}
	case "bind.build":
		name, version = "BIND", firstVersion(first)
		for _, l := range lines {
			if strings.Contains(l, "OpenSSL") {
				backend = tlsBackend(l)
			}
		}
	case "openvpn.version":
		name, version = "OpenVPN", firstVersion(first)
		for _, l := range lines {
			if strings.HasPrefix(l, "library versions") {
				backend = tlsBackend(l)
			}
		}
		if backend == "" {
			backend = tlsBackend(first)
		}
	case "ipsec.version":
		name, version = "strongSwan / libreswan", firstVersion(first)
		if strings.Contains(first, "strongSwan") {
			name = "strongSwan"
		}
		if strings.Contains(first, "Libreswan") || strings.Contains(first, "libreswan") {
			name = "libreswan"
		}
	case "stunnel.version":
		name, version = "stunnel", firstVersion(first)
		for _, l := range lines {
			if strings.HasPrefix(l, "Compiled with") {
				backend = tlsBackend(l)
			}
			if strings.HasPrefix(l, "Running") {
				extra = append(extra, prop("running-with", tlsBackend(l)))
			}
		}
	case "cryptsetup.version":
		name, version = "cryptsetup", firstVersion(first)
		if i := strings.Index(first, "flags:"); i >= 0 {
			extra = append(extra, prop("flags", strings.TrimSpace(first[i+6:])))
		}
	default:
		name, version = titleOf(b.db, sig), firstVersion(first)
		extra = append(extra, prop("output", all))
	}
	b.addRuntime("software/runtime/"+refSafe(q), name, version, backend, q, sig, extra)
}

func (b *configBuilder) addRuntimeProviding(ref, name, version, backend, source, sig string, extra []cdx.Property, refs []string) {
	props := []cdx.Property{prop("collected-by", sig), prop("config-area", b.areaOf(sig)), prop("config-source", source)}
	if backend != "" {
		props = append(props, prop("crypto-backend", backend))
	}
	props = append(props, extra...)
	b.add(collector.CryptoAsset{Component: cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeApplication, Name: name, Version: version, Properties: &props}, Provides: dedupe(refs)})
}

func (b *configBuilder) runtimeFromFile(sig string, it Item) {
	if len(it.Fields) < 1 {
		return
	}
	full := strings.ReplaceAll(it.Fields[0], `\`, "/")
	base := strings.ToLower(strings.TrimSuffix(path.Base(full), ".exe"))
	key := base
	if strings.HasPrefix(base, "tomcat") {
		key = "tomcat"
	}
	rn, ok := runtimeNames[key]
	if !ok {
		rn = [2]string{path.Base(full), ""}
	}
	name, backend := rn[0], rn[1]
	version := ""
	if len(it.Fields) >= 4 {
		version = strings.TrimSpace(it.Fields[3])
	}
	// Windows OpenSSH links LibreSSL; curl.exe on Windows uses Schannel.
	switch key {
	case "ssh", "sshd", "ssh-keygen":
		backend = "LibreSSL (Windows OpenSSH)"
	case "curl":
		if strings.Contains(full, "System32") {
			backend = "Schannel"
		}
	case "python", "node", "ruby", "php":
		if backend == "" {
			backend = "bundled OpenSSL"
		} else if key == "python" {
			backend = "bundled OpenSSL"
		}
	case "dotnet", "pwsh":
		backend = "Schannel / CNG (.NET on Windows)"
	}
	extra := []cdx.Property{prop("path", it.Fields[0])}
	if len(it.Fields) >= 5 && it.Fields[4] != "" {
		extra = append(extra, prop("product", it.Fields[4]))
	}
	b.addRuntime("software/runtime/"+refSafe(full), name, version, backend, it.Fields[0], sig, extra)
}

func (b *configBuilder) runtimeFromRegistry(sig string, list []Item) {
	switch {
	case strings.Contains(sig, "java"):
		homes := map[string]string{}
		for _, it := range list {
			if len(it.Fields) >= 3 && strings.EqualFold(it.Fields[1], "JavaHome") {
				homes[it.Fields[0]] = it.Fields[2]
			}
		}
		keys := make([]string, 0, len(homes))
		for k := range homes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.Split(k, `\`)
			version := parts[len(parts)-1]
			b.addRuntime("software/runtime/java-"+refSafe(homes[k]), "Java ("+parts[len(parts)-2]+")", version, "JSSE (the JDK's own TLS)", k, sig, []cdx.Property{prop("path", homes[k])})
		}
	default:
		for _, it := range list {
			if len(it.Fields) >= 3 && strings.EqualFold(it.Fields[1], "Release") {
				b.addRuntime("software/runtime/dotnet-framework", ".NET Framework", strings.TrimSuffix(strings.TrimPrefix(dotnetRelease(it.Fields[2]), ".NET Framework "), " (release "+it.Fields[2]+")"), "Schannel / CNG", it.Fields[0], sig, []cdx.Property{prop("release", it.Fields[2])})
			}
		}
	}
}

// buildOpenSSL: the installed OpenSSL as one library component with its version, build,
// providers, provider modules, default suites and the algorithms it can use (ML-KEM, ML-DSA).
func (b *configBuilder) buildOpenSSL(items []Item) {
	if len(items) == 0 {
		return
	}
	var version string
	var props []cdx.Property
	var refs []string
	var suites []cdx.CipherSuite
	var providers, modules, kems, sigs []string
	var curProvider string
	var sources []string
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		if it.Kind == "file" {
			modules = append(modules, path.Base(strings.ReplaceAll(it.Fields[0], `\`, "/")))
			sources = append(sources, path.Dir(strings.ReplaceAll(it.Fields[0], `\`, "/")))
			continue
		}
		if it.Kind != "query" {
			continue
		}
		q, l := it.Fields[0], strings.TrimSpace(it.Fields[1])
		sources = append(sources, "openssl "+strings.TrimPrefix(q, "openssl."))
		switch q {
		case "openssl.version":
			switch {
			case strings.HasPrefix(l, "OpenSSL ") && version == "":
				version = firstVersion(l)
				props = append(props, prop("version-line", l))
			case strings.HasPrefix(l, "built on:"), strings.HasPrefix(l, "platform:"), strings.HasPrefix(l, "OPENSSLDIR:"), strings.HasPrefix(l, "ENGINESDIR:"), strings.HasPrefix(l, "MODULESDIR:"), strings.HasPrefix(l, "CPUINFO:"):
				k, v := settingOf(l)
				props = append(props, prop("build:"+strings.ToLower(k), strings.Trim(v, `"`)))
			}
		case "openssl.providers":
			// "Providers:", then a provider's name on its own line, then "name:", "version:",
			// "status:" lines under it (the parser trims the indentation).
			switch {
			case l == "Providers:" || l == "":
			case strings.HasPrefix(l, "name:"), strings.HasPrefix(l, "version:"), strings.HasPrefix(l, "status:"):
				k, v := settingOf(l)
				props = append(props, prop("provider:"+curProvider+":"+k, v))
			default:
				curProvider = l
				providers = append(providers, l)
			}
		case "openssl.kem-algorithms":
			if n := opensslListedName(l); n != "" {
				kems = append(kems, n)
				if r, ok := b.algoNamed(n, "", "openssl list -kem-algorithms"); ok {
					refs = append(refs, r)
				}
			}
		case "openssl.signature-algorithms":
			if n := opensslListedName(l); n != "" {
				sigs = append(sigs, n)
				if r, ok := b.algoNamed(n, "", "openssl list -signature-algorithms"); ok {
					refs = append(refs, r)
				}
			}
		case "openssl.ciphers":
			f := strings.Fields(l)
			if len(f) >= 2 && strings.Contains(f[0], "_") || len(f) >= 2 && strings.Contains(f[0], "-") {
				suites = append(suites, cdx.CipherSuite{Name: f[0]})
			}
		}
	}
	if len(providers) > 0 {
		props = append(props, prop("providers", strings.Join(dedupe(providers), ", ")))
	}
	if len(modules) > 0 {
		props = append(props, prop("provider-modules", strings.Join(dedupe(modules), ", ")))
	}
	if len(kems) > 0 {
		props = append(props, prop("kem-algorithms", strings.Join(dedupe(kems), ", ")))
	}
	if len(sigs) > 0 {
		props = append(props, prop("signature-algorithms", strings.Join(dedupe(sigs), ", ")))
	}
	if len(suites) > 0 {
		props = append(props, prop("default-cipher-suites", strconv.Itoa(len(suites))))
		b.opensslSuites = suites
	}
	props = append([]cdx.Property{prop("config-area", "software"), prop("config-source", strings.Join(dedupe(sources), ", "))}, props...)
	b.add(collector.CryptoAsset{Component: cdx.Component{BOMRef: "software/openssl-installed", Type: cdx.ComponentTypeLibrary, Name: "OpenSSL (installed)", Version: version, Properties: &props}, Provides: dedupe(refs)})
}

// opensslListedName reads "{ 2.16.840.1.101.3.4.4.1, id-alg-ml-kem-512, ML-KEM-512, MLKEM512 } @ default"
// (or "  { 1.3.101.112, ED25519, Ed25519 } @ default") and returns the catalogue-looking name.
func opensslListedName(l string) string {
	l = strings.TrimSpace(l)
	if !strings.HasPrefix(l, "{") {
		// "X25519MLKEM768 @ default": a hybrid or a name without aliases.
		f := strings.Fields(l)
		if len(f) >= 1 && (isCatalogueName(f[0]) || algoNames[strings.ToLower(f[0])] != "") {
			return f[0]
		}
		return ""
	}
	inner := strings.TrimSpace(strings.TrimPrefix(strings.SplitN(l, "}", 2)[0], "{"))
	var best string
	for _, n := range strings.Split(inner, ",") {
		n = strings.TrimSpace(n)
		if n == "" || regexp.MustCompile(`^[0-9.]+$`).MatchString(n) || strings.HasPrefix(n, "id-") {
			continue
		}
		if algoNames[strings.ToLower(n)] != "" || isCatalogueName(n) {
			return n
		}
		if best == "" {
			best = n
		}
	}
	return best
}

// isCatalogueName: names OpenSSL lists that the catalogue knows as they are.
func isCatalogueName(n string) bool {
	switch n {
	case "RSA", "ECDSA", "Ed25519", "Ed448", "DSA", "X25519", "X448", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
		"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
		"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "RSA-PSS", "SM2", "HMAC", "CMAC", "SIPHASH", "POLY1305", "ED25519", "ED448", "EC", "DH", "DHX", "ECDH":
		return true
	}
	return false
}

// buildSSHSupported: what the installed OpenSSH can negotiate (ssh -Q), as a protocol component
// providing the algorithms, marked available rather than configured.
func (b *configBuilder) buildSSHSupported(items []Item) {
	if len(items) == 0 {
		return
	}
	sshMap := b.db.Maps["ssh"]
	var props []cdx.Property
	var refs []string
	version := ""
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		k, v := settingOf(it.Fields[1])
		if k == "version" {
			version = v
			continue
		}
		prim := map[string]cdx.CryptoPrimitive{"kex": cdx.CryptoPrimitiveKeyAgree, "cipher": cdx.CryptoPrimitiveAE, "mac": cdx.CryptoPrimitiveMAC, "key": cdx.CryptoPrimitiveSignature, "sig": cdx.CryptoPrimitiveSignature}[k]
		if prim == "" {
			continue
		}
		props = append(props, prop("ssh:available:"+k, v))
		for _, n := range strings.Fields(v) {
			name := n
			if m, ok := sshMap[n]; ok {
				name = m
			}
			p := prim
			if strings.Contains(n, "mlkem") || strings.Contains(n, "sntrup") {
				p = cdx.CryptoPrimitiveCombiner
			}
			if strings.Contains(n, "mldsa") {
				p = cdx.CryptoPrimitiveSignature
			}
			refs = append(refs, b.algorithm(name, p, n+" (available, ssh -Q)", "ssh -Q"))
		}
	}
	if len(props) == 0 {
		return
	}
	if version != "" {
		props = append([]cdx.Property{prop("version", version)}, props...)
	}
	a := protocolConfig("config/protocol/ssh-available", "OpenSSH (installed): algorithms available", "ssh", cdx.CryptoProtocolTypeSSH, "ssh -Q kex/cipher/mac/key/sig", props)
	a.Provides = dedupe(refs)
	b.add(a)
}

// buildSSHPolicy: sshd -T output or ssh_config lines, as a protocol component (the server's
// as-written policy keeps its own builder in interpret.go).
func (b *configBuilder) buildSSHPolicy(items []Item, ref, name, note string) {
	if len(items) == 0 {
		return
	}
	sshMap := b.db.Maps["ssh"]
	var props []cdx.Property
	var refs []string
	var sources []string
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		sources = append(sources, it.Fields[0])
		if it.Kind == "query" {
			sources = []string{"sshd -T"}
		}
		k, v := settingOf(it.Fields[1])
		lk := strings.ToLower(k)
		props = append(props, prop("ssh:"+lk, v))
		prim, ok := map[string]cdx.CryptoPrimitive{"kexalgorithms": cdx.CryptoPrimitiveKeyAgree, "ciphers": cdx.CryptoPrimitiveAE, "macs": cdx.CryptoPrimitiveMAC,
			"hostkeyalgorithms": cdx.CryptoPrimitiveSignature, "pubkeyacceptedalgorithms": cdx.CryptoPrimitiveSignature, "pubkeyacceptedkeytypes": cdx.CryptoPrimitiveSignature, "casignaturealgorithms": cdx.CryptoPrimitiveSignature}[lk]
		if !ok {
			continue
		}
		for _, n := range strings.Split(strings.TrimLeft(strings.Fields(v + " x")[0], "+-^"), ",") {
			if n == "" {
				continue
			}
			nm := n
			if m, ok := sshMap[n]; ok {
				nm = m
			}
			p := prim
			if strings.Contains(n, "mlkem") || strings.Contains(n, "sntrup") {
				p = cdx.CryptoPrimitiveCombiner
			}
			refs = append(refs, b.algorithm(nm, p, n, sources[len(sources)-1]))
		}
	}
	if note != "" {
		props = append([]cdx.Property{prop("note", note)}, props...)
	}
	a := protocolConfig(ref, name, "ssh", cdx.CryptoProtocolTypeSSH, strings.Join(dedupe(sources), ", "), props)
	a.Provides = dedupe(refs)
	b.add(a)
}

// buildHostKeyInfo: ssh-keygen -l lines ("256 SHA256:… comment (ED25519)") become key-size and
// fingerprint properties on the host key components the .pub lines created, or components of
// their own when none exists.
func (b *configBuilder) buildHostKeyInfo(items []Item) {
	types := map[string]string{"ED25519": "ssh-ed25519", "RSA": "ssh-rsa", "ECDSA": "ecdsa-sha2-nistp256", "DSA": "ssh-dss", "ED25519-SK": "sk-ssh-ed25519@openssh.com", "ECDSA-SK": "sk-ecdsa-sha2-nistp256@openssh.com", "XMSS": "ssh-xmss@openssh.com"}
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		f := strings.Fields(it.Fields[1])
		if len(f) < 3 {
			continue
		}
		bits, fp := f[0], f[1]
		typ := strings.Trim(f[len(f)-1], "()")
		keyType := types[typ]
		if typ == "ECDSA" {
			keyType = "ecdsa-sha2-nistp" + bits
		}
		if keyType == "" {
			keyType = strings.ToLower(typ)
		}
		ref := "config/ssh/host-key/" + refSafe(keyType)
		for i := range b.assets {
			if b.assets[i].Component.BOMRef == ref && b.assets[i].Component.Properties != nil {
				ps := append(*b.assets[i].Component.Properties, prop("key-bits", bits), prop("fingerprint", fp))
				b.assets[i].Component.Properties = &ps
				ref = ""
				break
			}
		}
		if ref == "" {
			continue
		}
		sshMap := b.db.Maps["ssh"]
		alg := typ
		if m, ok := sshMap[keyType]; ok {
			alg = m
		}
		ar := b.algorithm(alg, cdx.CryptoPrimitiveSignature, keyType, "ssh-keygen -l")
		b.add(collector.CryptoAsset{Component: cdx.Component{
			BOMRef: ref, Type: cdx.ComponentTypeCryptographicAsset, Name: "SSH host key (" + keyType + ")",
			CryptoProperties: &cdx.CryptoProperties{AssetType: cdx.CryptoAssetTypeRelatedCryptoMaterial,
				RelatedCryptoMaterialProperties: &cdx.RelatedCryptoMaterialProperties{Type: cdx.RelatedCryptoMaterialTypePublicKey, AlgorithmRef: cdx.BOMReference(ar)}},
			Properties: &[]cdx.Property{prop("config-source", "ssh-keygen -l"), prop("key-bits", bits), prop("fingerprint", fp)},
		}})
	}
}

// certificateDirectives name the certificate a server presents: a binding of material to a service.
var certificateDirectives = regexp.MustCompile(`(?i)^(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate|ssl_client_certificate|SSLCertificateFile|SSLCertificateChainFile|SSLCACertificateFile|crt|ca-file|smtpd_tls_cert_file|smtpd_tls_chain_files|smtpd_tls_CAfile|smtp_tls_CAfile|ssl_cert|ssl_ca|ssl_cert_file|ssl_ca_file|ssl-cert|ssl-ca|cert|CAfile|CApath|TLS_CACERT|TLSCertificateFile|TLSCACertificateFile|olcTLSCertificateFile|olcTLSCACertificateFile|tls certfile|tls cafile|certs|ca|--tls-cert-file|--client-ca-file|--etcd-cafile|--etcd-certfile|--service-account-key-file|--service-account-signing-key-file|--tls-private-key-file)$`)

// versionWords finds TLS/SSL versions a directive's value names.
var versionTokenRE = regexp.MustCompile(`(?i)(SSLv2|SSLv3|TLSv1\.3|TLSv1\.2|TLSv1\.1|TLSv1\.0|TLSv1(?:[^.]|$)|TLS1\.3|TLS1\.2|TLS1\.1|TLS1\.0|TLSv1_3|TLSv1_2|TLSv1_1|TLSv1_0|TLS 1\.3|TLS 1\.2|TLS 1\.1|TLS 1\.0|tlsv13|tlsv12|tlsv11|tlsv10|>=\s*TLSv1\.[0-9])`)

// buildTLSConfigs: each TLS-bearing configuration (a web, mail, database or directory server,
// a stack's defaults, a Windows registry area) as one protocol component with its settings.
func (b *configBuilder) buildTLSConfigs(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		list := groups[sig]
		var props []cdx.Property
		var versions, certs []string
		var sources []string
		for _, it := range list {
			switch it.Kind {
			case "registry":
				if len(it.Fields) < 3 {
					continue
				}
				sources = append(sources, it.Fields[0])
				props = append(props, prop("setting:"+it.Fields[1], registryWord(sig, it.Fields[1], it.Fields[2])))
			case "line", "query":
				if len(it.Fields) < 2 {
					continue
				}
				if it.Kind == "query" {
					sources = append(sources, titleOf(b.db, sig))
				} else {
					sources = append(sources, it.Fields[0])
				}
				k, v := settingOf(it.Fields[1])
				if k == "" {
					continue
				}
				if strings.HasPrefix(k, "<") || strings.HasPrefix(k, "[") || k == "frontend" || k == "backend" || k == "listen" || k == "server_name" || k == "ServerName" || k == "Host" {
					props = append(props, prop("section", strings.TrimSpace(it.Fields[1])))
					continue
				}
				props = append(props, prop("setting:"+k, v))
				for _, m := range versionTokenRE.FindAllString(v, -1) {
					versions = append(versions, strings.TrimSpace(m))
				}
				if certificateDirectives.MatchString(k) && v != "" && !strings.Contains(strings.ToLower(k), "key") {
					certs = append(certs, v)
				}
			}
		}
		if len(props) == 0 {
			continue
		}
		var head []cdx.Property
		if len(versions) > 0 {
			head = append(head, prop("versions-named", strings.Join(dedupe(versions), ", ")))
		}
		if len(certs) > 0 {
			head = append(head, prop("certificates", strings.Join(dedupe(certs), ", ")))
		}
		b.add(protocolConfig("config/tls/"+refSafe(sig), titleOf(b.db, sig), b.areaOf(sig), cdx.CryptoProtocolTypeTLS, strings.Join(dedupe(sources), ", "), append(head, props...)))
	}
}

// buildJavaSecurity: one component per java.security file found, with its policy keys.
func (b *configBuilder) buildJavaSecurity(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		byFile := map[string][]Item{}
		var files []string
		for _, it := range groups[sig] {
			if len(it.Fields) >= 2 {
				if _, ok := byFile[it.Fields[0]]; !ok {
					files = append(files, it.Fields[0])
				}
				byFile[it.Fields[0]] = append(byFile[it.Fields[0]], it)
			}
		}
		for _, f := range files {
			var props []cdx.Property
			var providers []string
			for _, it := range byFile[f] {
				k, v := settingOf(it.Fields[1])
				if strings.HasPrefix(k, "security.provider.") {
					providers = append(providers, strings.TrimPrefix(k, "security.provider.")+"="+v)
					continue
				}
				props = append(props, prop("setting:"+k, v))
			}
			if len(providers) > 0 {
				props = append(props, prop("setting:security.providers", strings.Join(providers, " ")))
			}
			jdk := path.Base(path.Dir(path.Dir(path.Dir(strings.ReplaceAll(f, `\`, "/")))))
			if strings.EqualFold(jdk, "lib") || strings.EqualFold(jdk, "conf") || strings.EqualFold(jdk, "jre") {
				jdk = path.Base(path.Dir(path.Dir(path.Dir(path.Dir(strings.ReplaceAll(f, `\`, "/"))))))
			}
			b.add(protocolConfig("config/tls/java-"+refSafe(f), "Java security policy ("+jdk+")", "tls", cdx.CryptoProtocolTypeTLS, f, props))
		}
	}
}

// buildAuthPolicy: Kerberos, NTLM, SMB, LDAP, Netlogon, Samba and password hashing settings,
// each as a record; enctypes and hashes named become algorithm components.
func (b *configBuilder) buildAuthPolicy(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		list := groups[sig]
		var props []cdx.Property
		var refs []string
		var sources []string
		for _, it := range list {
			switch it.Kind {
			case "registry":
				if len(it.Fields) < 3 {
					continue
				}
				sources = append(sources, registryLeaf(it.Fields[0]))
				props = append(props, prop("setting:"+it.Fields[1], registryWord(sig, it.Fields[1], it.Fields[2])))
				if strings.EqualFold(it.Fields[1], "SupportedEncryptionTypes") {
					for _, e := range kerberosEnctypes(it.Fields[2]) {
						if r, ok := b.algoNamed(strings.Fields(e)[0], "", registryLeaf(it.Fields[0])); ok {
							refs = append(refs, r)
						}
					}
				}
			case "line", "query":
				if len(it.Fields) < 2 {
					continue
				}
				src := it.Fields[0]
				if it.Kind == "query" {
					src = titleOf(b.db, sig)
				}
				sources = append(sources, src)
				line := strings.TrimSpace(it.Fields[1])
				if strings.Contains(line, "pam_unix") {
					props = append(props, prop("setting:pam_unix", line))
					for _, tok := range strings.Fields(line) {
						switch tok {
						case "sha512":
							refs = append(refs, b.algorithm("SHA-512", cdx.CryptoPrimitiveHash, "sha512 (crypt)", src))
						case "sha256":
							refs = append(refs, b.algorithm("SHA-256", cdx.CryptoPrimitiveHash, "sha256 (crypt)", src))
						case "yescrypt":
							refs = append(refs, b.algorithm("yescrypt", cdx.CryptoPrimitiveHash, "yescrypt (crypt)", src))
						case "md5":
							refs = append(refs, b.algorithm("MD5", cdx.CryptoPrimitiveHash, "md5 (crypt)", src))
						}
					}
					continue
				}
				k, v := settingOf(line)
				props = append(props, prop("setting:"+k, v))
				lk := strings.ToLower(k)
				switch {
				case strings.Contains(lk, "enctypes") || lk == "master_key_type" || lk == "kerberos encryption types":
					for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' }) {
						if r, ok := b.algoNamed(tok, "", src); ok {
							refs = append(refs, r)
						}
					}
				case lk == "encrypt_method":
					switch strings.ToUpper(v) {
					case "SHA512":
						refs = append(refs, b.algorithm("SHA-512", cdx.CryptoPrimitiveHash, "ENCRYPT_METHOD SHA512", src))
					case "SHA256":
						refs = append(refs, b.algorithm("SHA-256", cdx.CryptoPrimitiveHash, "ENCRYPT_METHOD SHA256", src))
					case "YESCRYPT":
						refs = append(refs, b.algorithm("yescrypt", cdx.CryptoPrimitiveHash, "ENCRYPT_METHOD YESCRYPT", src))
					case "MD5", "DES":
						refs = append(refs, b.algorithm(strings.ToUpper(v), cdx.CryptoPrimitiveHash, "ENCRYPT_METHOD "+v, src))
					}
				}
			}
		}
		if len(props) == 0 {
			continue
		}
		a := dataComponent("config/auth/"+refSafe(sig), titleOf(b.db, sig), b.areaOf(sig), "auth-policy", strings.Join(dedupe(sources), ", "), props)
		a.Provides = dedupe(refs)
		b.add(a)
	}
}

// buildVPN: OpenVPN, IPsec and WireGuard as protocol components with the algorithms their
// proposals name.
func (b *configBuilder) buildVPN(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		list := groups[sig]
		typ := cdx.CryptoProtocolTypeTLS
		ctx := ""
		switch {
		case strings.Contains(sig, "ipsec"):
			typ, ctx = cdx.CryptoProtocolTypeIPSec, ""
		case strings.Contains(sig, "wireguard"):
			typ = cdx.CryptoProtocolTypeOther
		case strings.Contains(sig, "openvpn"):
			ctx = "openvpn"
		}
		var props []cdx.Property
		var refs []string
		var sources []string
		for _, it := range list {
			if len(it.Fields) < 2 {
				continue
			}
			src := it.Fields[0]
			if it.Kind == "query" {
				src = titleOf(b.db, sig)
			}
			sources = append(sources, src)
			if strings.Contains(sig, "wireguard") {
				props = append(props, prop("interface", strings.TrimSpace(it.Fields[1])))
				continue
			}
			k, v := settingOf(it.Fields[1])
			props = append(props, prop("setting:"+k, v))
			lk := strings.ToLower(k)
			switch lk {
			case "ike", "esp", "ah", "proposals", "esp_proposals", "ah_proposals", "ike_proposals":
				for _, proposal := range strings.Split(v, ",") {
					for _, tok := range strings.Split(strings.TrimSuffix(strings.TrimSpace(proposal), "!"), "-") {
						if r, ok := b.algoNamed(tok, ctx, src); ok {
							refs = append(refs, r)
						}
					}
				}
			case "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "tls-groups", "ecdh-curve":
				for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ' ' || r == ',' }) {
					if r, ok := b.algoNamed(tok, ctx, src); ok {
						refs = append(refs, r)
					} else if r, ok := b.algoNamed(tok+"-group", "", src); ok {
						refs = append(refs, r)
					}
				}
			case "auth":
				if r, ok := b.algoNamed(v, "openvpn", src); ok {
					refs = append(refs, r)
				}
			case "tls-version-min", "tls-version-max":
				props = append(props, prop("versions-named", "TLS "+v))
			}
		}
		if strings.Contains(sig, "wireguard") && len(props) > 0 {
			for _, n := range []string{"X25519", "ChaCha20-Poly1305", "BLAKE2s"} {
				refs = append(refs, b.algorithm(n, primitiveOf(n), "WireGuard (fixed by the protocol)", "wg show interfaces"))
			}
			props = append(props, prop("note", "WireGuard's cryptography is fixed by the protocol: Curve25519 key agreement, ChaCha20-Poly1305, BLAKE2s. Its configuration files hold keys and were not read."))
		}
		if len(props) == 0 {
			continue
		}
		a := protocolConfig("config/vpn/"+refSafe(sig), titleOf(b.db, sig), "vpn", typ, strings.Join(dedupe(sources), ", "), props)
		a.Provides = dedupe(refs)
		b.add(a)
	}
}

// hardwareProvider says whether a Windows key storage provider keeps keys in hardware.
var hardwareProvider = regexp.MustCompile(`(?i)platform crypto provider|smart card|nshield|ncipher|safenet|luna|gemalto|thales|yubi|nitrokey|feitian|utimaco|cloudhsm|fortanix|entrust|hsm`)

// buildPKIPolicy: providers, enrolment, EFS, PKCS#11 modules, trust store files, as records.
func (b *configBuilder) buildPKIPolicy(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		list := groups[sig]
		var props []cdx.Property
		var sources []string
		var providers, files []string
		for _, it := range list {
			switch it.Kind {
			case "registry":
				if len(it.Fields) < 3 {
					continue
				}
				sources = append(sources, registryLeaf(it.Fields[0]))
				if it.Fields[1] == "" { // a sub-key listing: the name is the value
					providers = append(providers, it.Fields[2])
					continue
				}
				props = append(props, prop("setting:"+it.Fields[1], registryWord(sig, it.Fields[1], it.Fields[2])))
			case "file":
				if len(it.Fields) >= 1 {
					files = append(files, it.Fields[0])
					sources = append(sources, path.Dir(strings.ReplaceAll(it.Fields[0], `\`, "/")))
				}
			case "line":
				if len(it.Fields) < 2 {
					continue
				}
				sources = append(sources, it.Fields[0])
				k, v := settingOf(it.Fields[1])
				props = append(props, prop("setting:"+k+" ("+path.Base(strings.ReplaceAll(it.Fields[0], `\`, "/"))+")", v))
			}
		}
		if len(providers) > 0 {
			sort.Strings(providers)
			var hw []string
			for _, p := range providers {
				props = append(props, prop("provider", p))
				if hardwareProvider.MatchString(p) {
					hw = append(hw, p)
				}
			}
			if len(hw) > 0 {
				props = append([]cdx.Property{prop("hardware-providers", strings.Join(hw, ", "))}, props...)
			}
		}
		for _, f := range files {
			props = append(props, prop("file", f))
		}
		if len(props) == 0 {
			continue
		}
		b.add(dataComponent("config/pki/"+refSafe(sig), titleOf(b.db, sig), b.areaOf(sig), "pki-policy", strings.Join(dedupe(sources), ", "), props))
	}
}

// buildKeyProviders reads certutil -store output: for each personal certificate, its subject,
// SHA-1 hash and the provider that holds its private key.
func (b *configBuilder) buildKeyProviders(items []Item) {
	if len(items) == 0 {
		return
	}
	type entry struct{ subject, hash, container, provider string }
	var entries []entry
	var cur *entry
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		l := strings.TrimSpace(it.Fields[1])
		switch {
		case strings.HasPrefix(l, "=") && strings.Contains(l, "Certificate"):
			entries = append(entries, entry{})
			cur = &entries[len(entries)-1]
		case cur == nil:
			continue
		case strings.HasPrefix(l, "Subject:"):
			cur.subject = strings.TrimSpace(strings.TrimPrefix(l, "Subject:"))
		case strings.HasPrefix(l, "Cert Hash(sha1):"):
			cur.hash = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(l, "Cert Hash(sha1):")), " ", ""))
		case strings.HasPrefix(l, "Key Container ="):
			cur.container = strings.TrimSpace(strings.TrimPrefix(l, "Key Container ="))
		case strings.HasPrefix(l, "Provider ="):
			cur.provider = strings.TrimSpace(strings.TrimPrefix(l, "Provider ="))
		}
	}
	var props []cdx.Property
	byProvider := map[string]int{}
	hardware := 0
	for _, e := range entries {
		if e.provider == "" {
			continue
		}
		byProvider[e.provider]++
		if hardwareProvider.MatchString(e.provider) {
			hardware++
		}
		cn := e.subject
		if m := regexp.MustCompile(`CN=([^,]+)`).FindStringSubmatch(e.subject); m != nil {
			cn = m[1]
		}
		props = append(props, prop("key", cn+" → "+e.provider+" (sha1 "+e.hash+")"))
		b.keyProviders = append(b.keyProviders, [2]string{cn, e.provider})
	}
	if len(props) == 0 {
		return
	}
	names := make([]string, 0, len(byProvider))
	for p := range byProvider {
		names = append(names, p)
	}
	sort.Strings(names)
	var head []cdx.Property
	for _, p := range names {
		head = append(head, prop("provider-count", fmt.Sprintf("%s: %d", p, byProvider[p])))
	}
	head = append(head, prop("hardware-bound-keys", strconv.Itoa(hardware)))
	b.add(dataComponent("config/pki/key-providers", "Private keys of personal certificates, by provider", "pki", "key-providers", "certutil -store My, certutil -user -store My", append(head, props...)))
}

// buildTLSBindings: netsh http show sslcert blocks, IIS bindings and WinRM listeners, as one
// protocol component of bindings (port → certificate → store).
func (b *configBuilder) buildTLSBindings(items []Item) {
	if len(items) == 0 {
		return
	}
	var props []cdx.Property
	var sources []string
	cur := map[string]string{}
	flush := func() {
		if ep, ok := cur["endpoint"]; ok {
			s := ep + " → certificate " + cur["hash"]
			if st := cur["store"]; st != "" {
				s += " (store " + st + ")"
			}
			if app := cur["app"]; app != "" {
				s += " app " + app
			}
			props = append(props, prop("binding", s))
		}
		cur = map[string]string{}
	}
	site := ""
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		l := strings.TrimSpace(it.Fields[1])
		switch {
		case it.Kind == "query" && it.Fields[0] == "http.sslcert":
			sources = append(sources, "netsh http show sslcert")
			k, v, ok := strings.Cut(l, " : ")
			if !ok {
				k, v = settingOf(l)
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch {
			case strings.HasPrefix(k, "IP"), strings.HasPrefix(k, "Hostname"), strings.HasPrefix(k, "Central"):
				flush()
				cur["endpoint"] = v
			case strings.HasPrefix(k, "Certificate Hash"):
				cur["hash"] = v
			case strings.HasPrefix(k, "Application ID"):
				cur["app"] = v
			case strings.HasPrefix(k, "Certificate Store Name"):
				cur["store"] = v
			}
		case it.Kind == "query" && it.Fields[0] == "winrm.listeners":
			sources = append(sources, "WSMan:\\localhost\\Listener")
			props = append(props, prop("winrm-listener", l))
		case it.Kind == "line":
			sources = append(sources, it.Fields[0])
			switch {
			case strings.HasPrefix(l, "<site "):
				if m := regexp.MustCompile(`name="([^"]+)"`).FindStringSubmatch(l); m != nil {
					site = m[1]
				}
			case strings.Contains(l, `protocol="https"`):
				info := ""
				if m := regexp.MustCompile(`bindingInformation="([^"]+)"`).FindStringSubmatch(l); m != nil {
					info = m[1]
				}
				props = append(props, prop("iis-binding", site+": https "+info))
			case strings.Contains(l, "certificateHash="):
				props = append(props, prop("iis-certificate", site+": "+l))
			}
		}
	}
	flush()
	if len(props) == 0 {
		return
	}
	b.add(protocolConfig("config/tls/bindings", "TLS bindings: which certificate each listening endpoint presents", "bound", cdx.CryptoProtocolTypeTLS, strings.Join(dedupe(sources), ", "), props))
}

// cryptoStackOf names the TLS or crypto stack a process's loaded libraries imply.
func cryptoStackOf(libs []string) string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, l := range libs {
		ll := strings.ToLower(l)
		switch {
		case strings.HasPrefix(ll, "schannel"):
			add("Schannel (Windows TLS)")
		case strings.HasPrefix(ll, "ncrypt"):
			add("CNG key storage")
		case strings.HasPrefix(ll, "rsaenh"), strings.HasPrefix(ll, "dssenh"):
			add("CAPI (legacy)")
		case strings.Contains(ll, "libeay32"), strings.Contains(ll, "ssleay32"):
			add("OpenSSL 1.0 (libeay32)")
		case strings.Contains(ll, "libssl-1_1"), strings.Contains(ll, "libcrypto-1_1"), strings.Contains(ll, "libssl.so.1.1"), strings.Contains(ll, "libcrypto.so.1.1"):
			add("OpenSSL 1.1")
		case strings.Contains(ll, "libssl-3"), strings.Contains(ll, "libcrypto-3"), strings.Contains(ll, "libssl.so.3"), strings.Contains(ll, "libcrypto.so.3"):
			add("OpenSSL 3")
		case strings.Contains(ll, "libssl"), strings.Contains(ll, "libcrypto"):
			add("OpenSSL")
		case strings.Contains(ll, "gnutls"):
			add("GnuTLS")
		case strings.Contains(ll, "nss3"), strings.Contains(ll, "smime3"), strings.Contains(ll, "nspr4"):
			add("NSS")
		case strings.Contains(ll, "sodium"):
			add("libsodium")
		case strings.Contains(ll, "gcrypt"):
			add("libgcrypt")
		case strings.Contains(ll, "mbed"):
			add("mbedTLS")
		case strings.Contains(ll, "wolfssl"):
			add("wolfSSL")
		case strings.Contains(ll, "botan"):
			add("Botan")
		case strings.Contains(ll, "libssh"):
			add("libssh")
		case strings.Contains(ll, "k5crypto"), strings.Contains(ll, "krb5"):
			add("Kerberos (MIT)")
		case strings.Contains(ll, "nettle"), strings.Contains(ll, "hogweed"):
			add("Nettle")
		case strings.Contains(ll, "tss2"):
			add("TPM 2.0 (tss2)")
		case strings.Contains(ll, "p11-kit"), strings.Contains(ll, "softhsm"):
			add("PKCS#11")
		case strings.Contains(ll, "sunec"), strings.Contains(ll, "sunmscapi"):
			add("Java providers")
		case strings.Contains(ll, "oqs"):
			add("liboqs (post-quantum)")
		}
	}
	return strings.Join(out, ", ")
}

// buildListeners: one application component per listening process, with its sockets and the
// cryptographic libraries loaded into it. Processes the run could not see keep their socket.
func (b *configBuilder) buildListeners(items []Item) {
	if len(items) == 0 {
		return
	}
	// One component per program (name and executable), its processes merged: a browser with
	// fifteen listening renderer processes is one row, not fifteen.
	type proc struct {
		name, exe string
		pids      []string
		libs      map[string]bool
		sockets   []string
		readable  bool // at least one process let the run read its executable or modules
	}
	procs := map[string]*proc{}
	var order []string
	for _, it := range items {
		if len(it.Fields) < 3 {
			continue
		}
		// Trailing empty fields (no process, no libraries) may be cut off by an editor or a copy.
		fields := append(append([]string{}, it.Fields...), make([]string, 7)...)[:7]
		proto, addr, port, pid, name, exe, libs := fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6]
		key := strings.ToLower(name + "|" + exe)
		if pid == "" || pid == "0" {
			key = "unknown"
		}
		p, ok := procs[key]
		if !ok {
			p = &proc{name: name, exe: exe, libs: map[string]bool{}}
			procs[key] = p
			order = append(order, key)
		}
		if pid != "" && key != "unknown" && !containsString(p.pids, pid) {
			p.pids = append(p.pids, pid)
		}
		if exe != "" || libs != "" {
			p.readable = true
		}
		for _, l := range strings.Split(libs, ",") {
			if l = strings.TrimSpace(l); l != "" {
				p.libs[l] = true
			}
		}
		sock := proto + " " + addr + ":" + port
		if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
			sock = proto + " [" + addr + "]:" + port
		}
		p.sockets = append(p.sockets, sock)
	}
	sort.SliceStable(order, func(i, j int) bool {
		if (order[i] == "unknown") != (order[j] == "unknown") {
			return order[j] == "unknown"
		}
		a, c := procs[order[i]], procs[order[j]]
		if !strings.EqualFold(a.name, c.name) {
			return strings.ToLower(a.name) < strings.ToLower(c.name)
		}
		return a.exe < c.exe
	})
	for _, key := range order {
		p := procs[key]
		exeBase := ""
		if p.exe != "" {
			exeBase = strings.TrimSuffix(path.Base(strings.ReplaceAll(p.exe, `\`, "/")), ".exe")
		}
		name := p.name
		if name == "" && p.exe != "" {
			name = exeBase
		}
		props := []cdx.Property{prop("config-area", "bound"), prop("config-kind", "listener")}
		if key == "unknown" {
			name = "Processes this run could not identify"
			props = append(props, prop("note", "Run the script as root or Administrator to see which process owns these sockets."))
		} else {
			sort.Strings(p.pids)
			props = append(props, prop("pid", strings.Join(p.pids, ", ")), prop("process-count", strconv.Itoa(len(p.pids))))
		}
		if p.exe != "" {
			props = append(props, prop("executable", p.exe))
		}
		sort.Strings(p.sockets)
		props = append(props, prop("listens", strings.Join(dedupe(p.sockets), ", ")))
		libs := make([]string, 0, len(p.libs))
		for l := range p.libs {
			libs = append(libs, l)
		}
		sort.Strings(libs)
		switch {
		case len(libs) > 0:
			props = append(props, prop("loaded-libraries", strings.Join(libs, ", ")))
			if st := cryptoStackOf(libs); st != "" {
				props = append(props, prop("crypto-stack", st))
			}
		case key == "unknown":
		case !p.readable:
			props = append(props, prop("crypto-stack", "not readable: another account's process (run as Administrator or root)"))
		default:
			props = append(props, prop("crypto-stack", "none seen (statically linked, or no cryptography)"))
		}
		ref := "service/" + refSafe(name)
		if exeBase != "" {
			ref += "-" + refSafe(exeBase)
		}
		if key == "unknown" {
			ref = "service/unidentified"
		}
		b.add(collector.CryptoAsset{Component: cdx.Component{BOMRef: ref, Type: cdx.ComponentTypeApplication, Name: name, Properties: &props}})
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// buildKernelCrypto: the kernel's registered algorithms and loaded crypto modules, as one record
// providing the algorithms the catalogue knows.
func (b *configBuilder) buildKernelCrypto(items []Item) {
	if len(items) == 0 {
		return
	}
	var names, modules []string
	var refs []string
	for _, it := range items {
		if len(it.Fields) < 2 {
			continue
		}
		if strings.HasSuffix(it.Fields[0], "/proc/modules") {
			f := strings.Fields(it.Fields[1])
			if len(f) > 0 {
				modules = append(modules, f[0])
			}
			continue
		}
		_, v := settingOf(it.Fields[1])
		if v == "" {
			continue
		}
		names = append(names, v)
		if r, ok := b.algoNamed(v, "kernel", "/proc/crypto"); ok {
			refs = append(refs, r)
		}
	}
	names = dedupe(names)
	sort.Strings(names)
	modules = dedupe(modules)
	sort.Strings(modules)
	var props []cdx.Property
	if len(names) > 0 {
		props = append(props, prop("algorithms", strings.Join(names, ", ")), prop("algorithm-count", strconv.Itoa(len(names))))
	}
	if len(modules) > 0 {
		props = append(props, prop("modules", strings.Join(modules, ", ")))
	}
	if len(props) == 0 {
		return
	}
	a := dataComponent("config/platform/kernel-crypto", "Linux kernel cryptography", "platform", "kernel-crypto", "/proc/crypto, /proc/modules", props)
	a.Provides = dedupe(refs)
	b.add(a)
}

// buildGenericConfig: a signature interpreted as plain configuration becomes a record of its
// settings, so a new signature reaches the page without code (REQ-SG-5).
func (b *configBuilder) buildGenericConfig(items []Item) {
	order, groups := bySig(items)
	for _, sig := range order {
		if _, known := b.db.ByID(sig); !known {
			continue // an unknown signature stays observed configuration only (see build)
		}
		var props []cdx.Property
		var sources []string
		for _, it := range groups[sig] {
			switch it.Kind {
			case "registry":
				if len(it.Fields) >= 3 {
					sources = append(sources, registryLeaf(it.Fields[0]))
					props = append(props, prop("setting:"+it.Fields[1], it.Fields[2]))
				}
			case "line", "query":
				if len(it.Fields) >= 2 {
					if it.Kind == "query" {
						sources = append(sources, titleOf(b.db, sig))
					} else {
						sources = append(sources, it.Fields[0])
					}
					k, v := settingOf(it.Fields[1])
					if k != "" {
						props = append(props, prop("setting:"+k, v))
					}
				}
			case "file", "program":
				if len(it.Fields) >= 1 {
					props = append(props, prop("file", it.Fields[0]))
				}
			}
		}
		if len(props) == 0 {
			continue
		}
		b.add(dataComponent("config/"+refSafe(sig), titleOf(b.db, sig), b.areaOf(sig), "config", strings.Join(dedupe(sources), ", "), props))
	}
}
