// Package machinefacts turns the plain-text facts file written by the inventory
// scripts (cipherhorizon-inventory.ps1 and cipherhorizon-inventory.sh) into a
// CycloneDX CBOM.
//
// The scripts only gather facts a person can read before uploading: the host's
// name, operating system and privilege, the crypto-relevant packages installed,
// and public certificates. The judgement (what a package can do, what a
// certificate's algorithms mean) is made here, by the same sensors, knowledge
// base and CBOM builder the Go collector uses, so a script inventory and a
// collector inventory say the same thing about the same machine.
//
// The format is one fact per line, fields separated by tabs:
//
//	cipherhorizon-machine-facts	1
//	script	<name>	<version>
//	host	name|os|os-version|privilege|collected	<value>
//	os-release	<base64 of /etc/os-release>
//	package-manager	dpkg|rpm|apk
//	package	dpkg|rpm|apk	<name>	<version>	<arch>
//	cert-file	<absolute path>	<base64 of the file>
//	store-cert	LocalMachine|CurrentUser	<store>	yes|no|unknown	<base64 DER>
//	note	<text>
//
// Everything in the file came from the machine and is treated as untrusted:
// sizes are bounded, and nothing that looks like private key material is kept.
package machinefacts

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Header is the first line of every facts file.
const Header = "cipherhorizon-machine-facts"

// Limits on one facts file.
const (
	MaxBytes     = 32 << 20
	maxLines     = 200_000
	maxPackages  = 20_000
	maxCerts     = 20_000
	maxCertBytes = 256 << 10
	maxField     = 512
	maxNotes     = 50
)

// Package is one installed package.
type Package struct {
	Manager, Name, Version, Arch string
}

// CertFile is one certificate file found on a Linux host.
type CertFile struct {
	Path string // host-relative, without the leading slash
	Data []byte
}

// StoreCert is one certificate from a Windows certificate store.
type StoreCert struct {
	Location, Store, PrivateKey string
	DER                         []byte
}

// Facts is a parsed facts file.
type Facts struct {
	Script, ScriptVersion string
	Name, OS, OSVersion   string
	Privilege             string // user | admin
	Collected             string
	OSRelease             []byte
	Managers              []string // the package managers the script asked, even when they listed nothing
	Packages              []Package
	CertFiles             []CertFile
	StoreCerts            []StoreCert
	Notes                 []string
	// Dropped counts entries refused while parsing (private key material, bad encoding, limits).
	Dropped int

	// Version 2 (signature-driven engines): what each signature returned beyond packages and
	// certificates, how many facts each produced, and the ones that could not run.
	Items       []Item
	Ran         map[string]int
	Skipped     map[string]string
	SignatureDB string
}

// Item is one registry value, file, installed program or configuration line a signature returned.
type Item struct {
	Sig    string   // the signature id
	Kind   string   // registry | file | program | line
	Fields []string // registry: key, name, value; file: path, size, sha256, version, product; program: name, version, publisher; line: path, text
}

const maxItems = 20_000

// IsFacts reports whether b starts like a facts file.
func IsFacts(b []byte) bool {
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // a UTF-8 byte-order mark, as PowerShell may write
	return bytes.HasPrefix(b, []byte(Header+"\t"))
}

func clean(s string) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if utf8.RuneCountInString(s) > maxField {
		s = string([]rune(s)[:maxField])
	}
	return s
}

// privateKey reports whether data holds key material: such a file is never kept.
func privateKey(data []byte) bool {
	return bytes.Contains(data, []byte("PRIVATE KEY")) || bytes.Contains(data, []byte("ENCRYPTED KEY"))
}

// Parse reads a facts file.
func Parse(b []byte) (*Facts, error) {
	if len(b) > MaxBytes {
		return nil, fmt.Errorf("facts file larger than %d MiB", MaxBytes>>20)
	}
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 2*maxCertBytes)
	f := &Facts{}
	n := 0
	for sc.Scan() {
		n++
		if n > maxLines {
			return nil, errors.New("facts file has too many lines")
		}
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		fl := strings.Split(line, "\t")
		if n == 1 {
			if fl[0] != Header || len(fl) < 2 || (fl[1] != "1" && fl[1] != "2") {
				return nil, errors.New("not a version 1 or 2 CipherHorizon facts file")
			}
			continue
		}
		// Version 2: "fact <signature> <kind> ...". Packages and certificates read as in version 1;
		// everything else is kept with its signature for the server to interpret.
		if fl[0] == "fact" && len(fl) >= 3 {
			sig, kind, rest := clean(fl[1]), fl[2], fl[3:]
			switch kind {
			case "certstore":
				fl = append([]string{"store-cert"}, rest...)
			case "package", "package-manager", "cert-file":
				fl = append([]string{kind}, rest...)
			case "registry", "file", "program", "line":
				if len(f.Items) >= maxItems || strings.Contains(strings.Join(rest, " "), "PRIVATE KEY") {
					f.Dropped++
					continue
				}
				it := Item{Sig: sig, Kind: kind}
				for _, x := range rest {
					it.Fields = append(it.Fields, clean(x))
				}
				f.Items = append(f.Items, it)
				continue
			default:
				f.Dropped++
				continue
			}
		}
		switch fl[0] {
		case "signatures":
			if len(fl) >= 2 {
				f.SignatureDB = clean(fl[1])
			}
		case "ran":
			if len(fl) >= 3 {
				if f.Ran == nil {
					f.Ran = map[string]int{}
				}
				n, _ := strconv.Atoi(fl[2])
				f.Ran[clean(fl[1])] = n
			}
		case "skip":
			if len(fl) >= 3 {
				if f.Skipped == nil {
					f.Skipped = map[string]string{}
				}
				f.Skipped[clean(fl[1])] = clean(fl[2])
			}
		case "script":
			if len(fl) >= 3 {
				f.Script, f.ScriptVersion = clean(fl[1]), clean(fl[2])
			}
		case "host":
			if len(fl) < 3 {
				continue
			}
			v := clean(fl[2])
			switch fl[1] {
			case "name":
				f.Name = v
			case "os":
				f.OS = strings.ToLower(v)
			case "os-version":
				f.OSVersion = v
			case "privilege":
				f.Privilege = strings.ToLower(v)
			case "collected":
				f.Collected = v
			}
		case "os-release":
			if len(fl) >= 2 {
				if data, err := base64.StdEncoding.DecodeString(fl[1]); err == nil && len(data) < 64<<10 {
					f.OSRelease = data
				}
			}
		case "package-manager":
			if len(fl) >= 2 && (fl[1] == "dpkg" || fl[1] == "rpm" || fl[1] == "apk") {
				f.Managers = append(f.Managers, fl[1])
			}
		case "package":
			if len(fl) < 4 || len(f.Packages) >= maxPackages {
				f.Dropped++
				continue
			}
			p := Package{Manager: clean(fl[1]), Name: clean(fl[2]), Version: clean(fl[3])}
			if len(fl) >= 5 {
				p.Arch = clean(fl[4])
			}
			if p.Name == "" || (p.Manager != "dpkg" && p.Manager != "rpm" && p.Manager != "apk") {
				f.Dropped++
				continue
			}
			f.Packages = append(f.Packages, p)
		case "cert-file":
			if len(fl) < 3 || len(f.CertFiles)+len(f.StoreCerts) >= maxCerts {
				f.Dropped++
				continue
			}
			data, err := base64.StdEncoding.DecodeString(fl[2])
			p := path.Clean("/" + strings.ReplaceAll(fl[1], "\\", "/"))
			if err != nil || len(data) > maxCertBytes || privateKey(data) || strings.Contains(p, "..") || len(p) > 1024 {
				f.Dropped++
				continue
			}
			f.CertFiles = append(f.CertFiles, CertFile{Path: strings.TrimPrefix(p, "/"), Data: data})
		case "store-cert":
			if len(fl) < 5 || len(f.CertFiles)+len(f.StoreCerts) >= maxCerts {
				f.Dropped++
				continue
			}
			der, err := base64.StdEncoding.DecodeString(fl[4])
			if err != nil || len(der) == 0 || len(der) > 64<<10 || privateKey(der) {
				f.Dropped++
				continue
			}
			pk := clean(fl[3])
			if pk != "yes" && pk != "no" {
				pk = "unknown"
			}
			f.StoreCerts = append(f.StoreCerts, StoreCert{Location: clean(fl[1]), Store: clean(fl[2]), PrivateKey: pk, DER: der})
		case "note":
			if len(fl) >= 2 && len(f.Notes) < maxNotes {
				f.Notes = append(f.Notes, clean(strings.Join(fl[1:], " ")))
			}
		default:
			f.Dropped++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading the facts file: %w", err)
	}
	if n == 0 {
		return nil, errors.New("empty facts file")
	}
	if f.OS != "linux" && f.OS != "windows" {
		return nil, errors.New(`the facts file names no operating system ("host	os	linux" or "windows")`)
	}
	if f.Privilege != "admin" {
		f.Privilege = "user"
	}
	return f, nil
}
