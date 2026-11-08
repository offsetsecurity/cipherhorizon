// Package signatures is the database of what the machine inventory scripts collect
// (PRD-006 D4). A signature is data: which read-only capability of the script
// engine to run, with which parameters, why, and how the server interprets what
// comes back. Adding something to collect means adding a signature; the engines,
// which implement the capabilities once, do not change.
package signatures

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed signatures.json
var raw []byte

// Signature is one thing the scripts collect.
type Signature struct {
	ID         string            `json:"id"`
	Platform   string            `json:"platform"` // windows | linux
	Title      string            `json:"title"`
	Why        string            `json:"why"`
	Capability string            `json:"capability"`
	Params     map[string]string `json:"params"`
	Interpret  string            `json:"interpret"`
	// Area groups signatures on the Inventory page and the machine page (PRD-019): one of Areas.
	Area string `json:"area"`
	// Needs is "admin" when the full result needs Administrator or root; "" when a standard
	// user sees all of it.
	Needs string `json:"needs,omitempty"`
	// How says, in words, how the engine pulls it (filled in from the capability).
	How string `json:"how,omitempty"`
}

// Areas are the groups a signature belongs to, in display order.
var Areas = []string{"platform", "software", "tls", "ssh", "servers", "vpn", "auth", "pki", "bound"}

// AreaTitles are the areas' names on screen.
var AreaTitles = map[string]string{
	"platform": "Platform and policy", "software": "Software and runtimes", "tls": "TLS stacks", "ssh": "SSH",
	"servers": "Servers", "vpn": "VPN and tunnels", "auth": "Authentication", "pki": "Keys and certificates", "bound": "Services and bindings",
}

// DB is the whole database.
type DB struct {
	Version    string                       `json:"version"`
	About      string                       `json:"about"`
	Maps       map[string]map[string]string `json:"maps"`
	Signatures []Signature                  `json:"signatures"`
}

// Capability is one read-only primitive an engine implements.
type Capability struct {
	Platforms []string
	Params    []string // required parameters
	Optional  []string
	How       string // template: what the engine does, in words
}

// Capabilities are the only things an engine can do. No signature can name a command (PRD-006
// D5): the "query" capability only selects, by id, one of the fixed read-only queries written in
// the engine itself (PRD-019 D1), listed in Queries.
var Capabilities = map[string]Capability{
	"registry": {Platforms: []string{"windows"}, Params: []string{"key"}, Optional: []string{"values", "depth", "subkeys"},
		How: "reads the named values of a registry key (and of its sub-keys to the given depth), and with subkeys=yes the names of its sub-keys; nothing is written"},
	"certstore": {Platforms: []string{"windows"}, Params: []string{"locations", "stores"},
		How: "lists the certificates in the named stores, with whether a private key is associated; no key is opened"},
	"file": {Platforms: []string{"windows", "linux"}, Params: []string{"roots", "names"}, Optional: []string{"depth", "max"},
		How: "finds files with these names under these folders and reports path, size, version and SHA-256; their content is not sent"},
	"program": {Platforms: []string{"windows"}, Params: []string{"match"},
		How: "lists installed programs (Windows' uninstall list) whose name matches"},
	"lines": {Platforms: []string{"windows", "linux"}, Params: []string{"paths", "match"}, Optional: []string{"max", "join"},
		How: "reads these text files and reports only the lines that match (joining backslash continuations when asked); files named like keys are never opened, and a line holding key material is dropped"},
	"query": {Platforms: []string{"windows", "linux"}, Params: []string{"query"}, Optional: []string{"match", "max"},
		How: "runs one of the engine's own fixed read-only queries (a version or algorithm listing, a settings cmdlet, the effective SSH server policy) and reports the lines that match; the signature names the query, never a command"},
	"listeners": {Platforms: []string{"windows", "linux"}, Optional: []string{"max"},
		How: "lists listening sockets with the owning process, its executable and the names of the cryptographic libraries that process has loaded; nothing is read from the processes but names"},
	"package": {Platforms: []string{"linux"}, Params: []string{"match"},
		How: "lists installed packages (dpkg, rpm or apk) whose name matches, with version and architecture"},
	"certfiles": {Platforms: []string{"linux"}, Params: []string{"dirs"}, Optional: []string{"depth", "max"},
		How: "copies the CERTIFICATE blocks of .crt, .cer and .pem files in these folders; key folders and key files are never entered or opened"},
}

// Queries are the fixed read-only queries each engine implements (PRD-019 D1). The ids here
// must match the engines' tables; a test checks both ways.
var Queries = map[string][]string{
	"linux": {"os.kernel", "cpu.crypto-flags", "openssl.version", "openssl.providers", "openssl.ciphers", "openssl.kem-algorithms",
		"openssl.signature-algorithms", "gnutls.version", "gpg.version", "curl.version", "wget.version", "ssh.version", "ssh.algorithms",
		"sshd.effective", "ssh.host-keys", "crypto-policies", "java.version", "python.ssl", "node.versions", "go.version", "ruby.openssl",
		"php.openssl", "dotnet.runtimes", "nginx.build", "apache.build", "haproxy.build", "postfix.tls", "dovecot.ssl", "samba.effective",
		"bind.build", "openvpn.version", "ipsec.version", "wireguard.interfaces", "stunnel.version", "cryptsetup.version", "disk.encryption",
		"secure-boot"},
	"windows": {"tls.cipher-suites", "tls.curves", "tpm", "bitlocker", "deviceguard", "http.sslcert", "certstore.providers", "smb.server",
		"winrm.listeners", "dotnet.runtimes", "host.role", "ssh.algorithms", "windows.features"},
}

// Interpretations the server knows.
var Interpretations = map[string]string{
	"certificate":          "certificates, through the collector's certificate sensors",
	"package":              "packages, through the collector's knowledge base (which algorithms each version can use)",
	"library-file":         "library files, through the collector's knowledge base",
	"software":             "installed programs, listed as software",
	"schannel-protocols":   "Windows TLS/SSL versions, as protocol components",
	"schannel-ciphers":     "Windows cipher and hash settings",
	"schannel-suite-order": "Windows cipher suite order, as a protocol component",
	"ssh-config":           "SSH server algorithms, as algorithm components",
	"ssh-host-key":         "SSH host key types, as algorithm and key components",
	"openssl-config":       "OpenSSL defaults, as a protocol component",
	"crypto-policy":        "the system crypto policy",
	"config":               "configuration values, recorded as observed",
	// PRD-019
	"platform":          "platform state (FIPS, TPM, disk encryption, Secure Boot, kernel, policy), as facts of the machine",
	"runtime":           "a language runtime or tool with its version and the cryptographic library it runs with",
	"openssl-build":     "the installed OpenSSL: version, providers, and the algorithms it can use",
	"ssh-supported":     "the algorithms the installed OpenSSH can use",
	"ssh-effective":     "the SSH server's effective policy, as sshd reports it",
	"ssh-client-config": "SSH client algorithms, as a protocol component",
	"ssh-host-key-info": "SSH host key sizes and fingerprints",
	"tls-config":        "a server's or stack's TLS settings, as a protocol component",
	"tls-cipher-suites": "the cipher suites and curves Windows negotiates with, in effective order",
	"java-security":     "the Java security policy (disabled algorithms, providers, key store type)",
	"auth-policy":       "authentication settings (Kerberos, NTLM, SMB, LDAP, RDP, password hashing)",
	"vpn-config":        "VPN and tunnel settings, as a protocol component",
	"pki-policy":        "key and certificate policy and infrastructure (providers, enrolment, PKCS#11, trust stores)",
	"key-providers":     "which provider holds each personal certificate's private key (hardware or software)",
	"tls-bindings":      "which certificate each listening TLS endpoint presents",
	"listeners":         "listening services with the cryptographic libraries they loaded",
	"kernel-crypto":     "the kernel's cryptographic algorithms and modules",
}

var (
	idRE = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9-]+)+$`)
	// A parameter may never point at private keys: key folders, key files or key stores
	// (a .pub file is public and allowed).
	keyPath = regexp.MustCompile(`(?i)(^|[\\/|*_.-])(private|privkey|secrets?|keystore|[a-z]*\.key|[a-z]*\.p12|[a-z]*\.pfx|[a-z]*\.jks)([\\/|*_.-]|$)`)
)

// Load parses and validates the embedded database.
func Load() (*DB, error) { return Parse(raw) }

// Parse parses and validates a database.
func Parse(b []byte) (*DB, error) {
	var db DB
	if err := json.Unmarshal(b, &db); err != nil {
		return nil, fmt.Errorf("signatures: %w", err)
	}
	if err := db.Validate(); err != nil {
		return nil, err
	}
	for i := range db.Signatures {
		db.Signatures[i].How = Capabilities[db.Signatures[i].Capability].How
	}
	return &db, nil
}

// MustLoad is Load for the embedded database, which tests keep valid.
func MustLoad() *DB {
	db, err := Load()
	if err != nil {
		panic(err)
	}
	return db
}

// Validate checks every signature (REQ-SG-2).
func (db *DB) Validate() error {
	if db.Version == "" {
		return fmt.Errorf("signatures: no version")
	}
	seen := map[string]bool{}
	for _, s := range db.Signatures {
		if !idRE.MatchString(s.ID) {
			return fmt.Errorf("signature %q: id must look like platform.thing", s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("signature %q: duplicate id", s.ID)
		}
		seen[s.ID] = true
		c, ok := Capabilities[s.Capability]
		if !ok {
			return fmt.Errorf("signature %q: unknown capability %q", s.ID, s.Capability)
		}
		if !contains(c.Platforms, s.Platform) {
			return fmt.Errorf("signature %q: capability %q does not exist on %q", s.ID, s.Capability, s.Platform)
		}
		if _, ok := Interpretations[s.Interpret]; !ok {
			return fmt.Errorf("signature %q: unknown interpretation %q", s.ID, s.Interpret)
		}
		if s.Title == "" || s.Why == "" {
			return fmt.Errorf("signature %q: title and why are required", s.ID)
		}
		if !contains(Areas, s.Area) {
			return fmt.Errorf("signature %q: area %q is not one of %v", s.ID, s.Area, Areas)
		}
		if s.Needs != "" && s.Needs != "admin" {
			return fmt.Errorf("signature %q: needs must be empty or \"admin\"", s.ID)
		}
		if q, ok := s.Params["query"]; ok && !contains(Queries[s.Platform], q) {
			return fmt.Errorf("signature %q: query %q is not one the %s engine implements", s.ID, q, s.Platform)
		}
		if s.Capability == "registry" && strings.TrimSpace(s.Params["values"]) == "" && s.Params["subkeys"] != "yes" {
			return fmt.Errorf("signature %q: a registry signature names values or asks for subkeys=yes", s.ID)
		}
		for _, p := range c.Params {
			if strings.TrimSpace(s.Params[p]) == "" {
				return fmt.Errorf("signature %q: parameter %q is required", s.ID, p)
			}
		}
		for k, v := range s.Params {
			if !contains(c.Params, k) && !contains(c.Optional, k) {
				return fmt.Errorf("signature %q: capability %q takes no parameter %q", s.ID, s.Capability, k)
			}
			if strings.ContainsAny(v, "\t\r\n") {
				return fmt.Errorf("signature %q: parameter %q holds a tab or line break", s.ID, k)
			}
			if k == "match" {
				if _, err := regexp.Compile(v); err != nil {
					return fmt.Errorf("signature %q: match does not compile: %w", s.ID, err)
				}
			}
			if (k == "paths" || k == "roots" || k == "dirs" || k == "names") && keyPath.MatchString(strings.ReplaceAll(v, ".pub", "")) {
				return fmt.Errorf("signature %q: parameter %q points at key material", s.ID, k)
			}
			// WireGuard configuration folders hold private keys next to everything else (PRD-019 §4.3).
			if (k == "paths" || k == "roots" || k == "dirs") && strings.Contains(strings.ToLower(v), "wireguard") {
				return fmt.Errorf("signature %q: parameter %q reads a WireGuard folder, which holds keys", s.ID, k)
			}
		}
	}
	return nil
}

// For returns the signatures of one platform, in database order.
func (db *DB) For(platform string) []Signature {
	var out []Signature
	for _, s := range db.Signatures {
		if s.Platform == platform {
			out = append(out, s)
		}
	}
	return out
}

// ByID finds a signature.
func (db *DB) ByID(id string) (Signature, bool) {
	for _, s := range db.Signatures {
		if s.ID == id {
			return s, true
		}
	}
	return Signature{}, false
}

// Engine renders a platform's signatures in the line format the engines read: one
// "sig <id> <capability> key=value ..." line each, tab separated, after a version line.
func (db *DB) Engine(platform string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "signatures\t%s\n", db.Version)
	for _, s := range db.For(platform) {
		keys := make([]string, 0, len(s.Params))
		for k := range s.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("sig\t" + s.ID + "\t" + s.Capability)
		for _, k := range keys {
			b.WriteString("\t" + k + "=" + s.Params[k])
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
