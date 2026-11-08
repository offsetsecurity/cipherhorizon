package eval

import (
	"fmt"
	"sort"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Client simulation (PRD-018). For each of a set of named clients, the evaluation works out what
// a handshake with this server would negotiate, from two things it already has: what the server
// accepts (every version, suite and group the scan enumerated, with the server's preference) and
// what the client offers (its profile below). Nothing is sent: the simulation is a computation over
// the scan, so it costs nothing and can be redone on a stored result.
//
// The profiles are the clients' published defaults, transcribed with their source and date; where
// a default depends on an update or a setting, the profile's note says so. The outcome answers the
// operational question first: who connects, with what, and who fails and why.

// ClientProfile is what one client offers in its ClientHello.
type ClientProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Family   string `json:"family"` // browser | mobile | runtime | library | legacy
	Released string `json:"released"`
	Source   string `json:"source"`
	Note     string `json:"note,omitempty"`
	// Versions the client offers, highest first; suites per version class (TLS 1.3 names and
	// TLS 1.2-and-earlier names, each in the client's preference order); groups in preference
	// order, with the first KeyShares groups carrying a key share in the first flight.
	Versions  []string `json:"versions"`
	Suites13  []string `json:"suites13,omitempty"`
	Suites12  []string `json:"suites12"`
	Groups    []string `json:"groups"`
	KeyShares int      `json:"keyShares"`
	// SigAlgs are the TLS 1.3 signature schemes offered (by family: "ecdsa", "rsa_pss", "rsa_pkcs1",
	// "ed25519", "mldsa"), used to decide which certificate the client can authenticate.
	SigAlgs []string `json:"sigAlgs"`
	// MaxDHBits caps the finite-field DH prime the client accepts; 0 means no cap.
	MaxDHBits int `json:"maxDhBits,omitempty"`
	// MinRSABits is the smallest RSA certificate key the client accepts.
	MinRSABits int `json:"minRsaBits,omitempty"`
	// RejectsSHA1 says the client refuses a certificate signed with SHA-1.
	RejectsSHA1 bool `json:"rejectsSha1"`
	// NoSNI says the client sends no server_name: it gets the server's default certificate.
	NoSNI bool `json:"noSni,omitempty"`
}

// ClientSim is the simulated outcome for one client.
type ClientSim struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Family   string `json:"family"`
	Released string `json:"released"`
	Connects bool   `json:"connects"`
	// Why says why the handshake fails, in words.
	Why string `json:"why,omitempty"`
	// What was negotiated.
	Version        string `json:"version,omitempty"`
	Suite          string `json:"suite,omitempty"`
	Group          string `json:"group,omitempty"`
	ForwardSecrecy bool   `json:"forwardSecrecy"`
	PQ             bool   `json:"pq"`
	// HelloRetry: TLS 1.3 needed a second flight because no key share matched.
	HelloRetry bool `json:"helloRetry,omitempty"`
	// DefaultCertificate: the client sends no SNI and gets the server's default certificate,
	// which may not be the one a named client gets.
	DefaultCertificate bool `json:"defaultCertificate,omitempty"`
	// Decided says who chose the suite: "server" or "client".
	Decided string `json:"decided,omitempty"`
	Note    string `json:"note,omitempty"`
}

// ClientSummary is the fleet-friendly tally stored beside a scan.
type ClientSummary struct {
	Connect int `json:"connect"`
	Fail    int `json:"fail"`
	PQ      int `json:"pq"`
	NoFS    int `json:"noFs"`
}

// Clients lists the client profiles in display order.
func Clients() []ClientProfile { return append([]ClientProfile(nil), clientProfiles...) }

// ClientByID finds a profile.
func ClientByID(id string) (ClientProfile, bool) {
	for _, c := range clientProfiles {
		if c.ID == id {
			return c, true
		}
	}
	return ClientProfile{}, false
}

// SummariseClients tallies the simulated outcomes.
func SummariseClients(sims []ClientSim) *ClientSummary {
	if len(sims) == 0 {
		return nil
	}
	s := &ClientSummary{}
	for _, c := range sims {
		if !c.Connects {
			s.Fail++
			continue
		}
		s.Connect++
		if c.PQ {
			s.PQ++
		}
		if !c.ForwardSecrecy {
			s.NoFS++
		}
	}
	return s
}

// The suite and group names, once, so a typo is a compile error of sorts (tests check each
// profile's names against the IANA registry).
const (
	s13AES128  = "TLS_AES_128_GCM_SHA256"
	s13AES256  = "TLS_AES_256_GCM_SHA384"
	s13CHACHA  = "TLS_CHACHA20_POLY1305_SHA256"
	eeGCM128   = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	eeGCM256   = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	eeCHACHA   = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	eeCBC128   = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	eeCBC256   = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	eeCBC128s  = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	eeCBC256s  = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
	erGCM128   = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	erGCM256   = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	erCHACHA   = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	erCBC128   = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	erCBC256   = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	erCBC128s  = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	erCBC256s  = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
	er3DES     = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	ee3DES     = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
	erRC4      = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	eeRC4      = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	dheGCM128  = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	dheGCM256  = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
	dheCHACHA  = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	dheCBC128  = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	dheCBC256  = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	dheCBC128s = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
	dheCBC256s = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
	dhe3DES    = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
	rsaGCM128  = "TLS_RSA_WITH_AES_128_GCM_SHA256"
	rsaGCM256  = "TLS_RSA_WITH_AES_256_GCM_SHA384"
	rsaCBC128  = "TLS_RSA_WITH_AES_128_CBC_SHA"
	rsaCBC256  = "TLS_RSA_WITH_AES_256_CBC_SHA"
	rsaCBC128s = "TLS_RSA_WITH_AES_128_CBC_SHA256"
	rsaCBC256s = "TLS_RSA_WITH_AES_256_CBC_SHA256"
	rsa3DES    = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	rsaRC4     = "TLS_RSA_WITH_RC4_128_SHA"
	rsaRC4MD5  = "TLS_RSA_WITH_RC4_128_MD5"

	gX25519MLKEM = "X25519MLKEM768"
	gP256MLKEM   = "SecP256r1MLKEM768"
	gX25519      = "x25519"
	gX448        = "x448"
	gP256        = "secp256r1"
	gP384        = "secp384r1"
	gP521        = "secp521r1"
	gFF2048      = "ffdhe2048"
	gFF3072      = "ffdhe3072"
	gFF4096      = "ffdhe4096"
)

var (
	sigModern = []string{"ecdsa", "rsa_pss", "rsa_pkcs1", "ed25519"}
	sigNoEd   = []string{"ecdsa", "rsa_pss", "rsa_pkcs1"}
	sigPKCS1  = []string{"ecdsa", "rsa_pkcs1"}
	sigRSA1   = []string{"rsa_pkcs1"}

	chromeSuites12 = []string{eeGCM128, erGCM128, eeGCM256, erGCM256, eeCHACHA, erCHACHA, erCBC128, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256}
	modern13       = []string{s13AES128, s13AES256, s13CHACHA}
	javaSuites12   = []string{eeGCM256, eeGCM128, erGCM256, erGCM128, dheGCM256, dheGCM128, eeCBC256s, eeCBC128s, erCBC256s, erCBC128s, dheCBC256s, dheCBC128s,
		eeCBC256, eeCBC128, erCBC256, erCBC128, dheCBC256, dheCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128}
	opensslSuites12 = []string{eeGCM256, erGCM256, dheGCM256, eeCHACHA, erCHACHA, dheCHACHA, eeGCM128, erGCM128, dheGCM128, eeCBC256s, erCBC256s, dheCBC256s,
		eeCBC128s, erCBC128s, dheCBC128s, eeCBC256, erCBC256, dheCBC256, eeCBC128, erCBC128, dheCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128}
)

// clientProfiles are the clients, newest families first. Sources are the vendors' own defaults as
// documented for the named version (the Chromium and Mozilla source trees, Apple's and Oracle's
// release notes, OpenSSL's and Go's defaults, Microsoft's Schannel documentation), transcribed
// 2026-11-09. A row is a simulation of those defaults, never a capture of a particular device.
var clientProfiles = []ClientProfile{
	{ID: "chrome-131", Name: "Chrome 131+", Family: "browser", Released: "2024-11", Source: "Chromium (BoringSSL defaults; X25519MLKEM768 shipped in 131)",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: chromeSuites12, Groups: []string{gX25519MLKEM, gX25519, gP256, gP384}, KeyShares: 2,
		SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "edge-131", Name: "Edge 131+", Family: "browser", Released: "2024-11", Source: "Chromium-based: the Chrome 131 defaults",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: chromeSuites12, Groups: []string{gX25519MLKEM, gX25519, gP256, gP384}, KeyShares: 2,
		SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "firefox-132", Name: "Firefox 132+", Family: "browser", Released: "2024-10", Source: "Mozilla NSS defaults; X25519MLKEM768 enabled in 132",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM128, erGCM128, eeCHACHA, erCHACHA, eeGCM256, erGCM256, eeCBC256, eeCBC128, erCBC128, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256},
		Groups:   []string{gX25519MLKEM, gX25519, gP256, gP384, gP521, gFF2048, gFF3072}, KeyShares: 2, SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "safari-26", Name: "Safari 26 / iOS 26", Family: "browser", Released: "2025-09", Source: "Apple Network framework defaults; hybrid post-quantum key exchange from iOS 26 and macOS 26",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM256, eeGCM128, eeCHACHA, erGCM256, erGCM128, erCHACHA, eeCBC256s, eeCBC128s, eeCBC256, eeCBC128, erCBC256s, erCBC128s, erCBC256, erCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128},
		Groups:   []string{gX25519MLKEM, gX25519, gP256, gP384, gP521}, KeyShares: 2, SigAlgs: sigNoEd, MinRSABits: 2048, RejectsSHA1: true,
		Note: "Apple requires RSA keys of at least 2048 bits and SHA-2 signatures for trusted certificates."},
	{ID: "safari-17", Name: "Safari 17 / iOS 17", Family: "browser", Released: "2023-09", Source: "Apple Network framework defaults (no post-quantum group)",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM256, eeGCM128, eeCHACHA, erGCM256, erGCM128, erCHACHA, eeCBC256s, eeCBC128s, eeCBC256, eeCBC128, erCBC256s, erCBC128s, erCBC256, erCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128},
		Groups:   []string{gX25519, gP256, gP384, gP521}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 2048, RejectsSHA1: true},
	{ID: "safari-12", Name: "Safari 12 / iOS 12.1", Family: "legacy", Released: "2018-09", Source: "Apple Secure Transport defaults before TLS 1.3 (added in 12.2)",
		Versions: []string{v12, v11, v10},
		Suites12: []string{eeGCM256, eeGCM128, eeCHACHA, erGCM256, erGCM128, erCHACHA, eeCBC256s, eeCBC128s, eeCBC256, eeCBC128, erCBC256s, erCBC128s, erCBC256, erCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128, rsa3DES},
		Groups:   []string{gX25519, gP256, gP384, gP521}, SigAlgs: sigPKCS1, MinRSABits: 2048, RejectsSHA1: true},
	{ID: "android-14", Name: "Android 14 (Conscrypt)", Family: "mobile", Released: "2023-10", Source: "Conscrypt / BoringSSL defaults in the platform TLS stack (apps using OkHttp or Chrome's stack may differ)",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM128, eeGCM256, eeCHACHA, erGCM128, erGCM256, erCHACHA, eeCBC128, eeCBC256, erCBC128, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256},
		Groups:   []string{gX25519, gP256, gP384}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "android-10", Name: "Android 10", Family: "mobile", Released: "2019-09", Source: "Conscrypt defaults; TLS 1.3 on by default from Android 10",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM128, eeGCM256, eeCHACHA, erGCM128, erGCM256, erCHACHA, eeCBC128, eeCBC256, erCBC128, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256},
		Groups:   []string{gX25519, gP256, gP384}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "android-7", Name: "Android 7.0", Family: "mobile", Released: "2016-08", Source: "Conscrypt defaults; no TLS 1.3",
		Versions: []string{v12, v11, v10},
		Suites12: []string{eeGCM128, eeGCM256, eeCHACHA, erGCM128, erGCM256, erCHACHA, eeCBC128, eeCBC256, erCBC128, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256},
		Groups:   []string{gX25519, gP256, gP384}, SigAlgs: sigPKCS1, MinRSABits: 1024},
	{ID: "android-4.4", Name: "Android 4.4", Family: "legacy", Released: "2013-10", Source: "Platform defaults: TLS 1.1 and 1.2 present but not enabled by default before Android 5.0",
		Versions: []string{v10},
		Suites12: []string{eeCBC128, eeCBC256, erCBC128, erCBC256, eeRC4, erRC4, rsaCBC128, rsaCBC256, rsaRC4, rsa3DES, ee3DES, er3DES},
		Groups:   []string{gP256, gP384, gP521}, SigAlgs: sigPKCS1, MinRSABits: 1024,
		Note: "Some apps enable TLS 1.2 themselves; this row is the platform default."},
	{ID: "java-21", Name: "Java 21 (OpenJDK)", Family: "runtime", Released: "2023-09", Source: "JDK SunJSSE defaults; TLS 1.3 suites AES-GCM and ChaCha20-Poly1305; no post-quantum group",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: javaSuites12,
		Groups: []string{gX25519, gP256, gP384, gP521, gX448, gFF2048, gFF3072, gFF4096}, KeyShares: 1, SigAlgs: sigModern, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "java-11", Name: "Java 11 (OpenJDK)", Family: "runtime", Released: "2018-09", Source: "JDK 11 SunJSSE defaults; ChaCha20 suites arrive in JDK 12",
		Versions: []string{v13, v12}, Suites13: []string{s13AES256, s13AES128}, Suites12: javaSuites12,
		Groups: []string{gX25519, gP256, gP384, gP521, gX448, gFF2048, gFF3072, gFF4096}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 1024},
	{ID: "java-8", Name: "Java 8u261+", Family: "runtime", Released: "2020-07", Source: "JDK 8 SunJSSE defaults after TLS 1.3 was backported in 8u261; earlier updates stop at TLS 1.2",
		Versions: []string{v13, v12}, Suites13: []string{s13AES256, s13AES128}, Suites12: javaSuites12,
		Groups: []string{gP256, gP384, gP521, gFF2048, gFF3072, gFF4096}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 1024,
		Note: "Updates before 8u261 offer TLS 1.2 at most; before 8u51 a DH prime over 1024 bits fails."},
	{ID: "java-7", Name: "Java 7", Family: "legacy", Released: "2011-07", Source: "JDK 7 SunJSSE client defaults: TLS 1.0 unless the application enables 1.1 or 1.2; DH primes over 1024 bits refused",
		Versions: []string{v10},
		Suites12: []string{eeCBC128, eeCBC256, erCBC128, erCBC256, dheCBC128, dheCBC256, rsaCBC128, rsaCBC256, rsa3DES, rsaRC4},
		Groups:   []string{gP256, gP384, gP521}, SigAlgs: sigPKCS1, MaxDHBits: 1024, MinRSABits: 1024},
	{ID: "openssl-3.5", Name: "OpenSSL 3.5+", Family: "library", Released: "2025-04", Source: "OpenSSL 3.5 defaults: X25519MLKEM768 and SecP256r1MLKEM768 in the default group list",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: opensslSuites12,
		Groups: []string{gX25519MLKEM, gX25519, gP256MLKEM, gP256, gX448, gP384, gP521, gFF2048, gFF3072, gFF4096}, KeyShares: 2, SigAlgs: sigModern, MinRSABits: 1024},
	{ID: "openssl-3.0", Name: "OpenSSL 3.0 to 3.4", Family: "library", Released: "2021-09", Source: "OpenSSL 3.0 defaults (curl, Python, Ubuntu 22.04 and 24.04, RHEL 9 link against it)",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: opensslSuites12,
		Groups: []string{gX25519, gP256, gX448, gP521, gP384, gFF2048, gFF3072, gFF4096}, KeyShares: 1, SigAlgs: sigModern, MinRSABits: 1024},
	{ID: "openssl-1.1.1", Name: "OpenSSL 1.1.1", Family: "library", Released: "2018-09", Source: "OpenSSL 1.1.1 defaults (Ubuntu 20.04, RHEL 8)",
		Versions: []string{v13, v12}, Suites13: modern13, Suites12: opensslSuites12,
		Groups: []string{gX25519, gP256, gX448, gP521, gP384}, KeyShares: 1, SigAlgs: sigModern, MinRSABits: 1024},
	{ID: "openssl-1.0.2", Name: "OpenSSL 1.0.2", Family: "legacy", Released: "2015-01", Source: "OpenSSL 1.0.2 defaults (RHEL 7, CentOS 7): TLS 1.2 at most, no X25519",
		Versions: []string{v12, v11, v10},
		Suites12: []string{eeGCM256, erGCM256, dheGCM256, eeGCM128, erGCM128, dheGCM128, eeCBC256s, erCBC256s, dheCBC256s, eeCBC128s, erCBC128s, dheCBC128s,
			eeCBC256, erCBC256, dheCBC256, eeCBC128, erCBC128, dheCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128, rsa3DES},
		Groups: []string{gP256, gP521, gP384}, SigAlgs: sigPKCS1, MinRSABits: 1024},
	{ID: "go-1.24", Name: "Go 1.24+ (crypto/tls)", Family: "library", Released: "2025-02", Source: "Go crypto/tls defaults: X25519MLKEM768 first; this scanner's own certificate client",
		Versions: []string{v13, v12}, Suites13: modern13,
		Suites12: []string{eeGCM128, erGCM128, eeGCM256, erGCM256, eeCHACHA, erCHACHA, eeCBC128, erCBC128, eeCBC256, erCBC256, rsaGCM128, rsaGCM256, rsaCBC128, rsaCBC256},
		Groups:   []string{gX25519MLKEM, gX25519, gP256, gP384, gP521}, KeyShares: 2, SigAlgs: sigModern, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "schannel-win11", Name: "Windows 11 / Server 2022 (Schannel)", Family: "runtime", Released: "2021-10", Source: "Schannel defaults: TLS 1.3 on by default from Windows 11 and Server 2022 (.NET, PowerShell, IIS clients)",
		Versions: []string{v13, v12}, Suites13: []string{s13AES256, s13AES128, s13CHACHA},
		Suites12: []string{eeGCM256, eeGCM128, erGCM256, erGCM128, eeCBC256s, eeCBC128s, erCBC256s, erCBC128s, eeCBC256, eeCBC128, erCBC256, erCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128},
		Groups:   []string{gX25519, gP256, gP384}, KeyShares: 1, SigAlgs: sigNoEd, MinRSABits: 1024, RejectsSHA1: true},
	{ID: "schannel-win10", Name: "Windows 10 (Schannel)", Family: "runtime", Released: "2015-07", Source: "Schannel defaults on Windows 10: TLS 1.2 at most; x25519 from version 1903",
		Versions: []string{v12, v11, v10},
		Suites12: []string{eeGCM256, eeGCM128, erGCM256, erGCM128, eeCBC256s, eeCBC128s, erCBC256s, erCBC128s, eeCBC256, eeCBC128, erCBC256, erCBC128, rsaGCM256, rsaGCM128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128, rsa3DES},
		Groups:   []string{gX25519, gP256, gP384}, SigAlgs: sigNoEd, MinRSABits: 1024},
	{ID: "ie11-win7", Name: "IE 11 on Windows 7", Family: "legacy", Released: "2013-10", Source: "Schannel on Windows 7 with IE 11: TLS 1.2 enabled by the browser; no AES-GCM with ECDHE_RSA",
		Versions: []string{v12, v11, v10},
		Suites12: []string{eeGCM256, eeGCM128, eeCBC256s, eeCBC128s, erCBC256s, erCBC128s, eeCBC256, eeCBC128, erCBC256, erCBC128, rsaCBC256s, rsaCBC128s, rsaCBC256, rsaCBC128, rsa3DES, rsaRC4},
		Groups:   []string{gP256, gP384}, SigAlgs: sigPKCS1, MinRSABits: 1024},
	{ID: "java-6", Name: "Java 6", Family: "legacy", Released: "2006-12", Source: "JDK 6 SunJSSE: TLS 1.0, RSA key exchange and DHE, no elliptic curves, no server_name",
		Versions: []string{v10, ssl3},
		Suites12: []string{rsaCBC128, rsaCBC256, dheCBC128, dheCBC256, rsa3DES, dhe3DES, rsaRC4, rsaRC4MD5},
		Groups:   nil, SigAlgs: sigRSA1, MaxDHBits: 1024, MinRSABits: 512, NoSNI: true},
	{ID: "ie8-xp", Name: "IE 8 on Windows XP", Family: "legacy", Released: "2009-03", Source: "Schannel on Windows XP: SSL 3.0 and TLS 1.0, RSA key exchange, RC4 and 3DES, no server_name",
		Versions: []string{v10, ssl3},
		Suites12: []string{rsaRC4, rsaRC4MD5, rsa3DES, rsaCBC128, rsaCBC256},
		Groups:   nil, SigAlgs: sigRSA1, MinRSABits: 512, NoSNI: true},
}

// ---- the simulation --------------------------------------------------------------------------------

type certKinds struct {
	rsa, ecdsa, ed25519, pq bool
	anyServed               bool
	sha1                    bool // the leaf a named client gets is signed with SHA-1
	rsaBits                 int  // the RSA leaf's modulus, when there is one
}

func (c *ctx) servedCertKinds() certKinds {
	var k certKinds
	for _, cr := range c.rep.Certificates {
		if cr.NoSNI || len(cr.Chain) == 0 {
			continue
		}
		k.anyServed = true
		leaf := cr.Chain[0]
		switch {
		case leaf.PublicKey.Algorithm == "RSA":
			k.rsa = true
			if k.rsaBits == 0 || leaf.PublicKey.Bits < k.rsaBits {
				k.rsaBits = leaf.PublicKey.Bits
			}
		case leaf.PublicKey.Algorithm == "ECDSA":
			k.ecdsa = true
		case leaf.PublicKey.Algorithm == "Ed25519":
			k.ed25519 = true
		case strings.HasPrefix(leaf.PublicKey.Algorithm, "ML-DSA"), strings.HasPrefix(leaf.PublicKey.Algorithm, "SLH-DSA"):
			k.pq = true
		}
		if sigHash(leaf.SignatureAlg.Name) == "weak" {
			k.sha1 = true
		}
	}
	return k
}

// canAuthenticate says whether the client can verify any certificate the server serves to a
// named client, given its signature algorithms and limits. It returns the reason when not.
func (p ClientProfile) canAuthenticate(k certKinds) (bool, string) {
	if !k.anyServed {
		return true, "" // nothing read: do not invent a failure
	}
	has := func(fam string) bool { return contains(p.SigAlgs, fam) }
	switch {
	case k.ecdsa && has("ecdsa"), k.rsa && (has("rsa_pss") || has("rsa_pkcs1")), k.ed25519 && has("ed25519"), k.pq && has("mldsa"):
	default:
		if k.pq && !k.rsa && !k.ecdsa && !k.ed25519 {
			return false, "the server presents only a post-quantum (ML-DSA) certificate, which this client cannot verify"
		}
		return false, "no served certificate matches a signature algorithm the client offers"
	}
	if k.rsa && !k.ecdsa && p.MinRSABits > 0 && k.rsaBits > 0 && k.rsaBits < p.MinRSABits {
		return false, fmt.Sprintf("the RSA certificate key is %d bits; the client requires %d", k.rsaBits, p.MinRSABits)
	}
	if k.sha1 && p.RejectsSHA1 {
		return false, "the certificate is signed with SHA-1, which the client refuses"
	}
	return true, ""
}

// simulateClients runs every profile against the scan.
func simulateClients(c *ctx) []ClientSim {
	if !c.stageDone(tlsprobe.StageProtocols) || !c.stageDone(tlsprobe.StageSuites) {
		return nil
	}
	kinds := c.servedCertKinds()
	var out []ClientSim
	for _, p := range clientProfiles {
		out = append(out, simulateClient(c, p, kinds))
	}
	return out
}

// stageDone is stageRan for the evaluation context.
func (c *ctx) stageDone(name string) bool { return (&tlsCheck{ctx: c}).stageRan(name) }

func simulateClient(c *ctx, p ClientProfile, kinds certKinds) ClientSim {
	sim := ClientSim{ID: p.ID, Name: p.Name, Family: p.Family, Released: p.Released, DefaultCertificate: p.NoSNI && c.rep.NoSNI != ""}
	// 1. The version: the highest the client offers that the server supports.
	var version string
	for _, v := range p.Versions {
		if c.supported[v] {
			version = v
			break
		}
	}
	if version == "" {
		sim.Why = "no common protocol version: the client offers " + strings.Join(p.Versions, ", ") + " and the server accepts " + strings.Join(supportedList(c), ", ")
		return sim
	}
	sim.Version = version
	// 2. The certificate: can the client authenticate the server at all.
	if ok, why := p.canAuthenticate(kinds); !ok {
		sim.Why = why
		return sim
	}
	// 3. The suite, in the order of whoever decides.
	accepted := c.byVersion[version]
	if len(accepted) == 0 {
		sim.Why = "no cipher suite was enumerated for " + version
		return sim
	}
	offered := p.Suites12
	if version == v13 {
		offered = p.Suites13
	}
	serverDecides := pref(c.rep, version, "suites") == "server"
	var chosen *tlsprobe.SuiteResult
	if serverDecides {
		ranked := append([]tlsprobe.SuiteResult(nil), accepted...)
		sort.SliceStable(ranked, func(i, j int) bool {
			if ranked[i].Rank == 0 || ranked[j].Rank == 0 {
				return ranked[i].Rank != 0
			}
			return ranked[i].Rank < ranked[j].Rank
		})
		for i := range ranked {
			if contains(offered, ranked[i].Name) && c.kexWorks(p, ranked[i], version) {
				chosen = &ranked[i]
				break
			}
		}
	} else {
		for _, name := range offered {
			for i := range accepted {
				if accepted[i].Name == name && c.kexWorks(p, accepted[i], version) {
					chosen = &accepted[i]
					break
				}
			}
			if chosen != nil {
				break
			}
		}
	}
	if chosen == nil {
		// Say which it was: no suite in common, or a suite whose key exchange the client cannot do.
		common := 0
		for _, s := range accepted {
			if contains(offered, s.Name) {
				common++
			}
		}
		if common == 0 {
			sim.Why = "no common cipher suite on " + version
		} else {
			sim.Why = c.kexFailure(p, version)
		}
		return sim
	}
	sim.Connects = true
	sim.Suite = chosen.Name
	sim.Decided = map[bool]string{true: "server", false: "client"}[serverDecides]
	switch {
	case version == v13:
		sim.ForwardSecrecy = true
		g, retry := c.pickGroup13(p)
		sim.Group, sim.HelloRetry = g.Name, retry
		sim.PQ = g.PQ && !g.Obsolete
	case chosen.Kx == "ECDHE":
		sim.ForwardSecrecy = true
		if g, ok := c.pickCurve12(p); ok {
			sim.Group = g.Name
		}
	case chosen.Kx == "DHE":
		sim.ForwardSecrecy = true
		if c.rep.DH != nil {
			sim.Group = fmt.Sprintf("DHE %d bits", c.rep.DH.PrimeBits)
		}
	}
	if sim.DefaultCertificate {
		sim.Note = "sends no server name: gets the default certificate, " + c.rep.NoSNI
	}
	return sim
}

func supportedList(c *ctx) []string {
	var out []string
	for _, v := range []string{v13, v12, v11, v10, ssl3, ssl2} {
		if c.supported[v] {
			out = append(out, v)
		}
	}
	return out
}

// kexWorks says whether the client can complete the key exchange of a suite: a common curve for
// ECDHE, a DH prime within its limit for DHE; TLS 1.3 needs a common group.
func (c *ctx) kexWorks(p ClientProfile, s tlsprobe.SuiteResult, version string) bool {
	switch {
	case version == v13:
		_, ok := c.commonGroup13(p)
		return ok
	case s.Kx == "ECDHE", s.Kx == "ECDHE_PSK":
		_, ok := c.pickCurve12(p)
		return ok || len(c.groups12()) == 0 // curves not enumerated: do not invent a failure
	case s.Kx == "DHE", s.Kx == "DHE_PSK":
		return p.MaxDHBits == 0 || c.rep.DH == nil || c.rep.DH.PrimeBits <= p.MaxDHBits
	}
	return true
}

func (c *ctx) kexFailure(p ClientProfile, version string) string {
	if version == v13 {
		return "no common key-exchange group: the client offers " + strings.Join(p.Groups, ", ") + " and the server accepts " + groupNameList(c.groups13())
	}
	if c.rep.DH != nil && p.MaxDHBits > 0 && c.rep.DH.PrimeBits > p.MaxDHBits {
		return fmt.Sprintf("the server's DHE prime is %d bits; the client accepts at most %d", c.rep.DH.PrimeBits, p.MaxDHBits)
	}
	return "no common elliptic curve: the client offers " + strings.Join(p.Groups, ", ") + " and the server accepts " + groupNameList(c.groups12())
}

func (c *ctx) groups13() []tlsprobe.GroupResult { return c.groupsFor(v13) }

// groups12 are the curves for TLS 1.2 and earlier (probed once, at TLS 1.2).
func (c *ctx) groups12() []tlsprobe.GroupResult { return c.groupsFor(v12) }

func (c *ctx) groupsFor(version string) []tlsprobe.GroupResult {
	var out []tlsprobe.GroupResult
	for _, g := range c.rep.Groups {
		if g.Version == version {
			out = append(out, g)
		}
	}
	return out
}

func (c *ctx) commonGroup13(p ClientProfile) (tlsprobe.GroupResult, bool) {
	server := c.groups13()
	if len(server) == 0 {
		// Groups not enumerated (no HelloRetryRequest): fall back to what the real client got.
		if n := c.rep.Negotiated; n != nil && n.Version == v13 && n.Group != "" {
			for _, g := range p.Groups {
				if strings.EqualFold(g, n.Group) {
					return tlsprobe.GroupResult{Version: v13, Name: n.Group, PQ: n.PQ}, true
				}
			}
		}
		return tlsprobe.GroupResult{}, len(p.Groups) > 0
	}
	for _, name := range p.Groups {
		for _, g := range server {
			if strings.EqualFold(g.Name, name) {
				return g, true
			}
		}
	}
	return tlsprobe.GroupResult{}, false
}

// pickGroup13 chooses the TLS 1.3 group the way the server would: when the server ranks groups,
// its favourite among the client's offers, with a HelloRetryRequest if that group was not in the
// client's first key shares; otherwise the client's first shared group.
func (c *ctx) pickGroup13(p ClientProfile) (tlsprobe.GroupResult, bool) {
	server := c.groups13()
	offered := map[string]int{}
	for i, g := range p.Groups {
		offered[strings.ToLower(g)] = i
	}
	var pick *tlsprobe.GroupResult
	if pref(c.rep, v13, "groups") == "server" {
		ranked := append([]tlsprobe.GroupResult(nil), server...)
		sort.SliceStable(ranked, func(i, j int) bool {
			if ranked[i].Rank == 0 || ranked[j].Rank == 0 {
				return ranked[i].Rank != 0
			}
			return ranked[i].Rank < ranked[j].Rank
		})
		for i := range ranked {
			if _, ok := offered[strings.ToLower(ranked[i].Name)]; ok {
				pick = &ranked[i]
				break
			}
		}
	}
	if pick == nil {
		g, ok := c.commonGroup13(p)
		if !ok {
			return tlsprobe.GroupResult{}, false
		}
		pick = &g
	}
	idx := offered[strings.ToLower(pick.Name)]
	return *pick, p.KeyShares > 0 && idx >= p.KeyShares
}

func (c *ctx) pickCurve12(p ClientProfile) (tlsprobe.GroupResult, bool) {
	server := c.groups12()
	for _, name := range p.Groups {
		for _, g := range server {
			if strings.EqualFold(g.Name, name) {
				return g, true
			}
		}
	}
	return tlsprobe.GroupResult{}, false
}
