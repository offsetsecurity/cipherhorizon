// Package registry describes the SSH algorithm names a server may advertise: what each one is,
// which standard defines it, and the facts the evaluation judges it by (hash, group size, cipher
// mode, post-quantum). It is hand-written from the cited RFCs and drafts, not from a download:
// every entry names its source, and a test keeps every entry sourced.
//
// It states facts, not verdicts. Whether SHA-1 key exchange is acceptable is the evaluation's call
// (internal/eval), citing RFC 9142; this package only says the method uses SHA-1.
package registry

import "strings"

// Kinds of algorithm name.
const (
	KindKex         = "kex"
	KindHostKey     = "host-key"
	KindCipher      = "cipher"
	KindMAC         = "mac"
	KindCompression = "compression"
	KindPseudo      = "pseudo" // ext-info-*, kex-strict-*: signals carried in the kex list
)

// Algorithm is one SSH algorithm name.
type Algorithm struct {
	Name    string
	Kind    string
	Display string // for people: "ML-KEM-768 + X25519", "AES-256 in CTR mode"

	// Key exchange.
	PQ        bool   // a post-quantum (hybrid) key exchange or signature
	Hybrid    bool   // combines a post-quantum and a classical algorithm
	FIPS      bool   // its post-quantum part is a NIST standard (ML-KEM, FIPS 203; ML-DSA, FIPS 204)
	Hash      string // "SHA-1", "SHA-256" ...: the exchange hash, or the signature or MAC hash
	GroupBits int    // finite-field group size; 0 when not fixed by the name (group exchange)
	Exchange  string // "MODP", "ECDH", "X25519", "X448", "RSA", "GEX", "Hybrid", "GSS"

	// Host keys.
	Key  string // "Ed25519", "ECDSA", "RSA", "DSA", "ML-DSA-65", "ML-DSA-44+Ed25519"
	Cert bool   // an OpenSSH certificate type
	SK   bool   // a security-key (FIDO) type

	// Ciphers and MACs.
	Cipher    string // "AES", "ChaCha20-Poly1305", "3DES", "RC4", "Blowfish", "CAST-128", "DES", "none" ...
	KeyBits   int
	BlockBits int
	Mode      string // "CTR", "CBC", "GCM", "AEAD", "STREAM", "none"
	AEAD      bool   // integrity is part of the cipher: no MAC is negotiated
	ETM       bool   // MAC: encrypt-then-MAC
	TagBits   int    // MAC output length

	// Catalogue is the internal/algo catalogue ID for the CBOM, when there is one.
	Catalogue string
	Source    string
}

var byName = map[string]Algorithm{}

func add(as ...Algorithm) {
	for _, a := range as {
		byName[a.Name] = a
	}
}

const (
	srcRFC4253 = "RFC 4253"
	srcRFC4344 = "RFC 4344"
	srcRFC4419 = "RFC 4419"
	srcRFC4432 = "RFC 4432"
	srcRFC5647 = "RFC 5647"
	srcRFC5656 = "RFC 5656"
	srcRFC6668 = "RFC 6668"
	srcRFC8268 = "RFC 8268"
	srcRFC8308 = "RFC 8308"
	srcRFC8332 = "RFC 8332"
	srcRFC8709 = "RFC 8709"
	srcRFC8731 = "RFC 8731"
	srcRFC8758 = "RFC 8758"
	srcOpenSSH = "OpenSSH PROTOCOL"
	srcCertkey = "OpenSSH PROTOCOL.certkeys"
	srcStrict  = "OpenSSH PROTOCOL (strict key exchange, CVE-2023-48795)"
	srcMLKEM   = "RFC 10042; FIPS 203"
	srcSntrup  = "RFC 9941"
	srcMLDSA   = "draft-sfluhrer-ssh-mldsa; FIPS 204"
	srcComp    = "draft-miller-sshm-composite-sigs; FIPS 204"
	srcUMAC    = "OpenSSH PROTOCOL; RFC 4418"
)

func init() {
	// Key exchange.
	add(
		Algorithm{Name: "mlkem768x25519-sha256", Kind: KindKex, Display: "ML-KEM-768 + X25519 hybrid", PQ: true, Hybrid: true, FIPS: true, Hash: "SHA-256", Exchange: "Hybrid", Catalogue: "mlkem768x25519-sha256", Source: srcMLKEM},
		Algorithm{Name: "mlkem768nistp256-sha256", Kind: KindKex, Display: "ML-KEM-768 + ECDH P-256 hybrid", PQ: true, Hybrid: true, FIPS: true, Hash: "SHA-256", Exchange: "Hybrid", Catalogue: "mlkem768nistp256-sha256", Source: srcMLKEM},
		Algorithm{Name: "mlkem1024nistp384-sha384", Kind: KindKex, Display: "ML-KEM-1024 + ECDH P-384 hybrid", PQ: true, Hybrid: true, FIPS: true, Hash: "SHA-384", Exchange: "Hybrid", Catalogue: "mlkem1024nistp384-sha384", Source: srcMLKEM},
		Algorithm{Name: "sntrup761x25519-sha512", Kind: KindKex, Display: "Streamlined NTRU Prime 761 + X25519 hybrid", PQ: true, Hybrid: true, Hash: "SHA-512", Exchange: "Hybrid", Catalogue: "sntrup761x25519-sha512", Source: srcSntrup},
		Algorithm{Name: "sntrup761x25519-sha512@openssh.com", Kind: KindKex, Display: "Streamlined NTRU Prime 761 + X25519 hybrid (OpenSSH name)", PQ: true, Hybrid: true, Hash: "SHA-512", Exchange: "Hybrid", Catalogue: "sntrup761x25519-sha512", Source: srcSntrup},
		Algorithm{Name: "curve25519-sha256", Kind: KindKex, Display: "X25519", Hash: "SHA-256", Exchange: "X25519", Catalogue: "X25519", Source: srcRFC8731},
		Algorithm{Name: "curve25519-sha256@libssh.org", Kind: KindKex, Display: "X25519 (libssh name)", Hash: "SHA-256", Exchange: "X25519", Catalogue: "X25519", Source: srcRFC8731},
		Algorithm{Name: "curve448-sha512", Kind: KindKex, Display: "X448", Hash: "SHA-512", Exchange: "X448", Source: srcRFC8731},
		Algorithm{Name: "ecdh-sha2-nistp256", Kind: KindKex, Display: "ECDH P-256", Hash: "SHA-256", Exchange: "ECDH", Catalogue: "ECDH", Source: srcRFC5656},
		Algorithm{Name: "ecdh-sha2-nistp384", Kind: KindKex, Display: "ECDH P-384", Hash: "SHA-384", Exchange: "ECDH", Catalogue: "ECDH", Source: srcRFC5656},
		Algorithm{Name: "ecdh-sha2-nistp521", Kind: KindKex, Display: "ECDH P-521", Hash: "SHA-512", Exchange: "ECDH", Catalogue: "ECDH", Source: srcRFC5656},
		Algorithm{Name: "diffie-hellman-group1-sha1", Kind: KindKex, Display: "1024-bit MODP group (Oakley 2), SHA-1", Hash: "SHA-1", GroupBits: 1024, Exchange: "MODP", Catalogue: "DH", Source: srcRFC4253},
		Algorithm{Name: "diffie-hellman-group14-sha1", Kind: KindKex, Display: "2048-bit MODP group 14, SHA-1", Hash: "SHA-1", GroupBits: 2048, Exchange: "MODP", Catalogue: "DH", Source: srcRFC4253},
		Algorithm{Name: "diffie-hellman-group14-sha256", Kind: KindKex, Display: "2048-bit MODP group 14, SHA-256", Hash: "SHA-256", GroupBits: 2048, Exchange: "MODP", Catalogue: "DH", Source: srcRFC8268},
		Algorithm{Name: "diffie-hellman-group15-sha512", Kind: KindKex, Display: "3072-bit MODP group 15, SHA-512", Hash: "SHA-512", GroupBits: 3072, Exchange: "MODP", Catalogue: "DH", Source: srcRFC8268},
		Algorithm{Name: "diffie-hellman-group16-sha512", Kind: KindKex, Display: "4096-bit MODP group 16, SHA-512", Hash: "SHA-512", GroupBits: 4096, Exchange: "MODP", Catalogue: "DH", Source: srcRFC8268},
		Algorithm{Name: "diffie-hellman-group17-sha512", Kind: KindKex, Display: "6144-bit MODP group 17, SHA-512", Hash: "SHA-512", GroupBits: 6144, Exchange: "MODP", Catalogue: "DH", Source: srcRFC8268},
		Algorithm{Name: "diffie-hellman-group18-sha512", Kind: KindKex, Display: "8192-bit MODP group 18, SHA-512", Hash: "SHA-512", GroupBits: 8192, Exchange: "MODP", Catalogue: "DH", Source: srcRFC8268},
		Algorithm{Name: "diffie-hellman-group-exchange-sha1", Kind: KindKex, Display: "server-chosen MODP group, SHA-1", Hash: "SHA-1", Exchange: "GEX", Catalogue: "DH", Source: srcRFC4419},
		Algorithm{Name: "diffie-hellman-group-exchange-sha256", Kind: KindKex, Display: "server-chosen MODP group, SHA-256", Hash: "SHA-256", Exchange: "GEX", Catalogue: "DH", Source: srcRFC4419},
		Algorithm{Name: "rsa1024-sha1", Kind: KindKex, Display: "RSA-1024 key transport, SHA-1", Hash: "SHA-1", GroupBits: 1024, Exchange: "RSA", Catalogue: "RSA", Source: srcRFC4432},
		Algorithm{Name: "rsa2048-sha256", Kind: KindKex, Display: "RSA-2048 key transport, SHA-256", Hash: "SHA-256", GroupBits: 2048, Exchange: "RSA", Catalogue: "RSA", Source: srcRFC4432},
		Algorithm{Name: "ext-info-s", Kind: KindPseudo, Display: "extension negotiation", Source: srcRFC8308},
		Algorithm{Name: "ext-info-c", Kind: KindPseudo, Display: "extension negotiation", Source: srcRFC8308},
		Algorithm{Name: "kex-strict-s-v00@openssh.com", Kind: KindPseudo, Display: "strict key exchange", Source: srcStrict},
		Algorithm{Name: "kex-strict-c-v00@openssh.com", Kind: KindPseudo, Display: "strict key exchange", Source: srcStrict},
	)

	// Host keys.
	add(
		Algorithm{Name: "ssh-ed25519", Kind: KindHostKey, Display: "Ed25519", Key: "Ed25519", Catalogue: "Ed25519", Source: srcRFC8709},
		Algorithm{Name: "ssh-ed448", Kind: KindHostKey, Display: "Ed448", Key: "Ed448", Source: srcRFC8709},
		Algorithm{Name: "ecdsa-sha2-nistp256", Kind: KindHostKey, Display: "ECDSA P-256, SHA-256", Key: "ECDSA", Hash: "SHA-256", Catalogue: "ECDSA", Source: srcRFC5656},
		Algorithm{Name: "ecdsa-sha2-nistp384", Kind: KindHostKey, Display: "ECDSA P-384, SHA-384", Key: "ECDSA", Hash: "SHA-384", Catalogue: "ECDSA", Source: srcRFC5656},
		Algorithm{Name: "ecdsa-sha2-nistp521", Kind: KindHostKey, Display: "ECDSA P-521, SHA-512", Key: "ECDSA", Hash: "SHA-512", Catalogue: "ECDSA", Source: srcRFC5656},
		Algorithm{Name: "rsa-sha2-256", Kind: KindHostKey, Display: "RSA, SHA-256 signatures", Key: "RSA", Hash: "SHA-256", Catalogue: "RSA", Source: srcRFC8332},
		Algorithm{Name: "rsa-sha2-512", Kind: KindHostKey, Display: "RSA, SHA-512 signatures", Key: "RSA", Hash: "SHA-512", Catalogue: "RSA", Source: srcRFC8332},
		Algorithm{Name: "ssh-rsa", Kind: KindHostKey, Display: "RSA, SHA-1 signatures", Key: "RSA", Hash: "SHA-1", Catalogue: "RSA", Source: srcRFC4253},
		Algorithm{Name: "ssh-dss", Kind: KindHostKey, Display: "DSA, SHA-1 signatures", Key: "DSA", Hash: "SHA-1", Catalogue: "DSA", Source: srcRFC4253},
		Algorithm{Name: "sk-ssh-ed25519@openssh.com", Kind: KindHostKey, Display: "Ed25519 on a security key", Key: "Ed25519", SK: true, Catalogue: "Ed25519", Source: srcOpenSSH},
		Algorithm{Name: "sk-ecdsa-sha2-nistp256@openssh.com", Kind: KindHostKey, Display: "ECDSA P-256 on a security key", Key: "ECDSA", Hash: "SHA-256", SK: true, Catalogue: "ECDSA", Source: srcOpenSSH},
		Algorithm{Name: "webauthn-sk-ecdsa-sha2-nistp256@openssh.com", Kind: KindHostKey, Display: "ECDSA P-256, WebAuthn", Key: "ECDSA", Hash: "SHA-256", SK: true, Catalogue: "ECDSA", Source: srcOpenSSH},
		Algorithm{Name: "ssh-mldsa-44", Kind: KindHostKey, Display: "ML-DSA-44", Key: "ML-DSA-44", PQ: true, FIPS: true, Catalogue: "ML-DSA-44", Source: srcMLDSA},
		Algorithm{Name: "ssh-mldsa-65", Kind: KindHostKey, Display: "ML-DSA-65", Key: "ML-DSA-65", PQ: true, FIPS: true, Catalogue: "ML-DSA-65", Source: srcMLDSA},
		Algorithm{Name: "ssh-mldsa-87", Kind: KindHostKey, Display: "ML-DSA-87", Key: "ML-DSA-87", PQ: true, FIPS: true, Catalogue: "ML-DSA-87", Source: srcMLDSA},
		Algorithm{Name: "ssh-mldsa44-ed25519", Kind: KindHostKey, Display: "ML-DSA-44 + Ed25519 composite", Key: "ML-DSA-44+Ed25519", PQ: true, Hybrid: true, FIPS: true, Catalogue: "ML-DSA-44", Source: srcComp},
		Algorithm{Name: "ssh-mldsa87-p384", Kind: KindHostKey, Display: "ML-DSA-87 + ECDSA P-384 composite", Key: "ML-DSA-87+ECDSA-P384", PQ: true, Hybrid: true, FIPS: true, Catalogue: "ML-DSA-87", Source: srcComp},
	)
	// Certificate forms of each host key (OpenSSH PROTOCOL.certkeys).
	for _, base := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-256", "rsa-sha2-512",
		"ssh-rsa", "ssh-dss", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
		"ssh-mldsa44-ed25519"} {
		a := byName[base]
		name := strings.TrimSuffix(base, "@openssh.com") + "-cert-v01@openssh.com"
		if base == "ssh-mldsa44-ed25519" {
			name = "ssh-mldsa44-ed25519-cert"
		}
		a.Name, a.Cert, a.Display, a.Source = name, true, a.Display+", OpenSSH certificate", srcCertkey
		add(a)
	}

	// Ciphers.
	add(
		Algorithm{Name: "chacha20-poly1305@openssh.com", Kind: KindCipher, Display: "ChaCha20-Poly1305", Cipher: "ChaCha20-Poly1305", KeyBits: 256, Mode: "AEAD", AEAD: true, Catalogue: "ChaCha20-Poly1305", Source: srcOpenSSH},
		Algorithm{Name: "aes128-gcm@openssh.com", Kind: KindCipher, Display: "AES-128 in GCM", Cipher: "AES", KeyBits: 128, BlockBits: 128, Mode: "GCM", AEAD: true, Catalogue: "AES-128-GCM", Source: srcOpenSSH},
		Algorithm{Name: "aes256-gcm@openssh.com", Kind: KindCipher, Display: "AES-256 in GCM", Cipher: "AES", KeyBits: 256, BlockBits: 128, Mode: "GCM", AEAD: true, Catalogue: "AES-256-GCM", Source: srcOpenSSH},
		Algorithm{Name: "AEAD_AES_128_GCM", Kind: KindCipher, Display: "AES-128 in GCM", Cipher: "AES", KeyBits: 128, BlockBits: 128, Mode: "GCM", AEAD: true, Catalogue: "AES-128-GCM", Source: srcRFC5647},
		Algorithm{Name: "AEAD_AES_256_GCM", Kind: KindCipher, Display: "AES-256 in GCM", Cipher: "AES", KeyBits: 256, BlockBits: 128, Mode: "GCM", AEAD: true, Catalogue: "AES-256-GCM", Source: srcRFC5647},
		Algorithm{Name: "aes128-ctr", Kind: KindCipher, Display: "AES-128 in CTR", Cipher: "AES", KeyBits: 128, BlockBits: 128, Mode: "CTR", Catalogue: "AES-128-CTR", Source: srcRFC4344},
		Algorithm{Name: "aes192-ctr", Kind: KindCipher, Display: "AES-192 in CTR", Cipher: "AES", KeyBits: 192, BlockBits: 128, Mode: "CTR", Catalogue: "AES-192-CTR", Source: srcRFC4344},
		Algorithm{Name: "aes256-ctr", Kind: KindCipher, Display: "AES-256 in CTR", Cipher: "AES", KeyBits: 256, BlockBits: 128, Mode: "CTR", Catalogue: "AES-256-CTR", Source: srcRFC4344},
		Algorithm{Name: "aes128-cbc", Kind: KindCipher, Display: "AES-128 in CBC", Cipher: "AES", KeyBits: 128, BlockBits: 128, Mode: "CBC", Catalogue: "AES-128-CBC", Source: srcRFC4253},
		Algorithm{Name: "aes192-cbc", Kind: KindCipher, Display: "AES-192 in CBC", Cipher: "AES", KeyBits: 192, BlockBits: 128, Mode: "CBC", Catalogue: "AES-192-CBC", Source: srcRFC4253},
		Algorithm{Name: "aes256-cbc", Kind: KindCipher, Display: "AES-256 in CBC", Cipher: "AES", KeyBits: 256, BlockBits: 128, Mode: "CBC", Catalogue: "AES-256-CBC", Source: srcRFC4253},
		Algorithm{Name: "rijndael-cbc@lysator.liu.se", Kind: KindCipher, Display: "AES-256 in CBC (old name)", Cipher: "AES", KeyBits: 256, BlockBits: 128, Mode: "CBC", Catalogue: "AES-256-CBC", Source: srcOpenSSH},
		Algorithm{Name: "3des-cbc", Kind: KindCipher, Display: "3DES in CBC", Cipher: "3DES", KeyBits: 168, BlockBits: 64, Mode: "CBC", Catalogue: "3DES", Source: srcRFC4253},
		Algorithm{Name: "3des-ctr", Kind: KindCipher, Display: "3DES in CTR", Cipher: "3DES", KeyBits: 168, BlockBits: 64, Mode: "CTR", Catalogue: "3DES", Source: srcRFC4344},
		Algorithm{Name: "des-cbc", Kind: KindCipher, Display: "DES in CBC", Cipher: "DES", KeyBits: 56, BlockBits: 64, Mode: "CBC", Catalogue: "DES", Source: srcRFC4253},
		Algorithm{Name: "blowfish-cbc", Kind: KindCipher, Display: "Blowfish in CBC", Cipher: "Blowfish", KeyBits: 128, BlockBits: 64, Mode: "CBC", Catalogue: "Blowfish", Source: srcRFC4253},
		Algorithm{Name: "blowfish-ctr", Kind: KindCipher, Display: "Blowfish in CTR", Cipher: "Blowfish", KeyBits: 256, BlockBits: 64, Mode: "CTR", Catalogue: "Blowfish", Source: srcRFC4344},
		Algorithm{Name: "cast128-cbc", Kind: KindCipher, Display: "CAST-128 in CBC", Cipher: "CAST-128", KeyBits: 128, BlockBits: 64, Mode: "CBC", Catalogue: "CAST-128", Source: srcRFC4253},
		Algorithm{Name: "cast128-ctr", Kind: KindCipher, Display: "CAST-128 in CTR", Cipher: "CAST-128", KeyBits: 128, BlockBits: 64, Mode: "CTR", Catalogue: "CAST-128", Source: srcRFC4344},
		Algorithm{Name: "idea-cbc", Kind: KindCipher, Display: "IDEA in CBC", Cipher: "IDEA", KeyBits: 128, BlockBits: 64, Mode: "CBC", Source: srcRFC4253},
		Algorithm{Name: "twofish-cbc", Kind: KindCipher, Display: "Twofish-256 in CBC", Cipher: "Twofish", KeyBits: 256, BlockBits: 128, Mode: "CBC", Source: srcRFC4253},
		Algorithm{Name: "twofish256-cbc", Kind: KindCipher, Display: "Twofish-256 in CBC", Cipher: "Twofish", KeyBits: 256, BlockBits: 128, Mode: "CBC", Source: srcRFC4253},
		Algorithm{Name: "serpent256-cbc", Kind: KindCipher, Display: "Serpent-256 in CBC", Cipher: "Serpent", KeyBits: 256, BlockBits: 128, Mode: "CBC", Source: srcRFC4253},
		Algorithm{Name: "arcfour", Kind: KindCipher, Display: "RC4", Cipher: "RC4", KeyBits: 128, Mode: "STREAM", Catalogue: "RC4", Source: srcRFC8758},
		Algorithm{Name: "arcfour128", Kind: KindCipher, Display: "RC4-128", Cipher: "RC4", KeyBits: 128, Mode: "STREAM", Catalogue: "RC4", Source: srcRFC8758},
		Algorithm{Name: "arcfour256", Kind: KindCipher, Display: "RC4-256", Cipher: "RC4", KeyBits: 256, Mode: "STREAM", Catalogue: "RC4", Source: srcRFC8758},
		Algorithm{Name: "none", Kind: KindCipher, Display: "no encryption", Cipher: "none", Mode: "none", Source: srcRFC4253},
	)

	// MACs, each with its encrypt-then-MAC variant (OpenSSH PROTOCOL 1.7).
	for _, m := range []Algorithm{
		{Name: "hmac-sha2-256", Display: "HMAC-SHA-256", Hash: "SHA-256", TagBits: 256, Catalogue: "HMAC-SHA-256", Source: srcRFC6668},
		{Name: "hmac-sha2-512", Display: "HMAC-SHA-512", Hash: "SHA-512", TagBits: 512, Catalogue: "HMAC-SHA-512", Source: srcRFC6668},
		{Name: "hmac-sha1", Display: "HMAC-SHA-1", Hash: "SHA-1", TagBits: 160, Catalogue: "HMAC-SHA-1", Source: srcRFC4253},
		{Name: "hmac-sha1-96", Display: "HMAC-SHA-1 truncated to 96 bits", Hash: "SHA-1", TagBits: 96, Catalogue: "HMAC-SHA-1", Source: srcRFC4253},
		{Name: "hmac-md5", Display: "HMAC-MD5", Hash: "MD5", TagBits: 128, Catalogue: "HMAC-MD5", Source: srcRFC4253},
		{Name: "hmac-md5-96", Display: "HMAC-MD5 truncated to 96 bits", Hash: "MD5", TagBits: 96, Catalogue: "HMAC-MD5", Source: srcRFC4253},
		{Name: "hmac-ripemd160@openssh.com", Display: "HMAC-RIPEMD-160", Hash: "RIPEMD-160", TagBits: 160, Source: srcOpenSSH},
		{Name: "umac-64@openssh.com", Display: "UMAC, 64-bit tag", Hash: "UMAC", TagBits: 64, Catalogue: "UMAC", Source: srcUMAC},
		{Name: "umac-128@openssh.com", Display: "UMAC, 128-bit tag", Hash: "UMAC", TagBits: 128, Catalogue: "UMAC", Source: srcUMAC},
	} {
		m.Kind = KindMAC
		add(m)
		etm := m
		etm.Name = strings.TrimSuffix(m.Name, "@openssh.com") + "-etm@openssh.com"
		etm.Display, etm.ETM = m.Display+", encrypt-then-MAC", true
		add(etm)
	}
	// "none" as a MAC is answered by Lookup: the name is also a cipher, and the table is by name.

	// Compression.
	add(
		Algorithm{Name: "zlib", Kind: KindCompression, Display: "zlib, from the start of the connection", Source: srcRFC4253},
		Algorithm{Name: "zlib@openssh.com", Kind: KindCompression, Display: "zlib, after authentication", Source: srcOpenSSH},
	)
}

// Lookup finds a name of the given kind. "none" is both a cipher and a MAC, so lookups are by kind.
func Lookup(kind, name string) (Algorithm, bool) {
	if kind == KindMAC && name == "none" {
		return Algorithm{Name: "none", Kind: KindMAC, Display: "no integrity protection", Hash: "none", Source: srcRFC4253}, true
	}
	if kind == KindCompression && name == "none" {
		return Algorithm{Name: "none", Kind: KindCompression, Display: "no compression", Source: srcRFC4253}, true
	}
	a, ok := byName[name]
	if !ok || a.Kind != kind && (kind != KindKex || a.Kind != KindPseudo) {
		return Algorithm{Name: name, Kind: kind, Display: "not in this program's registry"}, false
	}
	return a, true
}

// IsPseudo reports whether a kex-list entry is a signal rather than a key exchange.
func IsPseudo(name string) bool {
	a, ok := byName[name]
	return ok && a.Kind == KindPseudo || strings.HasPrefix(name, "ext-info-") || strings.HasPrefix(name, "kex-strict-")
}

// All returns every entry (for tests).
func All() []Algorithm {
	out := make([]Algorithm, 0, len(byName))
	for _, a := range byName {
		out = append(out, a)
	}
	return out
}
