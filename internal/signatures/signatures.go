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
	// How says, in words, how the engine pulls it (filled in from the capability).
	How string `json:"how,omitempty"`
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

// Capabilities are the only things an engine can do. There is deliberately no capability
// that runs a command or a program (PRD-006 D5).
var Capabilities = map[string]Capability{
	"registry": {Platforms: []string{"windows"}, Params: []string{"key", "values"}, Optional: []string{"depth"},
		How: "reads the named values of a registry key (and of its sub-keys to the given depth); nothing is written"},
	"certstore": {Platforms: []string{"windows"}, Params: []string{"locations", "stores"},
		How: "lists the certificates in the named stores, with whether a private key is associated; no key is opened"},
	"file": {Platforms: []string{"windows", "linux"}, Params: []string{"roots", "names"}, Optional: []string{"depth", "max"},
		How: "finds files with these names under these folders and reports path, size, version and SHA-256; their content is not sent"},
	"program": {Platforms: []string{"windows"}, Params: []string{"match"},
		How: "lists installed programs (Windows' uninstall list) whose name matches"},
	"lines": {Platforms: []string{"windows", "linux"}, Params: []string{"paths", "match"}, Optional: []string{"max"},
		How: "reads these text files and reports only the lines that match; files named like keys are never opened, and a line holding key material is dropped"},
	"package": {Platforms: []string{"linux"}, Params: []string{"match"},
		How: "lists installed packages (dpkg, rpm or apk) whose name matches, with version and architecture"},
	"certfiles": {Platforms: []string{"linux"}, Params: []string{"dirs"}, Optional: []string{"depth", "max"},
		How: "copies the CERTIFICATE blocks of .crt, .cer and .pem files in these folders; key folders and key files are never entered or opened"},
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
