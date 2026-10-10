// Command gen turns downloaded reference sources into the Go tables in the
// parent package. See the refdata package documentation for how to run it.
//
// It is strict on purpose: an unexpected status, a fingerprint that does not
// match its certificate, a date it cannot read, or a prime that is not prime or
// not the size its heading says is an error, never a guess.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"go/format"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	mozillaURL = "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MozillaTLSServerAuthenticationCSV"
	chromeURL  = "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=ChromeTLSServerAuthenticationCSV"
	ctURL      = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	rfcURL     = "https://www.rfc-editor.org/rfc/rfc%s.txt"
)

func main() {
	mozilla := flag.String("mozilla", "", "CCADB MozillaTLSServerAuthenticationCSV")
	chrome := flag.String("chrome", "", "CCADB ChromeTLSServerAuthenticationCSV")
	ct := flag.String("ctlogs", "", "Chrome CT log list (log_list.json, v3)")
	rfcDir := flag.String("rfcs", "", "directory holding rfc2409.txt, rfc3526.txt, rfc5114.txt and rfc7919.txt")
	retrieved := flag.String("retrieved", "", "date the sources were retrieved, YYYY-MM-DD (recorded in the output)")
	outDir := flag.String("out", ".", "directory to write the *_gen.go files into")
	flag.Parse()
	if *mozilla == "" || *chrome == "" || *ct == "" || *rfcDir == "" || *retrieved == "" {
		fmt.Fprintln(os.Stderr, "gen: -mozilla, -chrome, -ctlogs, -rfcs and -retrieved are required")
		os.Exit(2)
	}
	if _, err := time.Parse("2006-01-02", *retrieved); err != nil {
		fmt.Fprintln(os.Stderr, "gen: -retrieved:", err)
		os.Exit(2)
	}
	if err := run(*mozilla, *chrome, *ct, *rfcDir, *retrieved, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(mozillaPath, chromePath, ctPath, rfcDir, retrieved, outDir string) error {
	der := map[string][]byte{}
	moz, mozSum, err := parseRoots(mozillaPath, "Mozilla Status", "Distrust for TLS After Date", "Mozilla Applied Constraints", der)
	if err != nil {
		return fmt.Errorf("%s: %w", mozillaPath, err)
	}
	chr, chrSum, err := parseRoots(chromePath, "Google Chrome Status", "sct_not_after_sec", "permitted_dns_names", der)
	if err != nil {
		return fmt.Errorf("%s: %w", chromePath, err)
	}
	if err := write(filepath.Join(outDir, "roots_gen.go"), renderRoots(der, moz, mozSum, chr, chrSum, retrieved)); err != nil {
		return err
	}
	logs, ctSum, ctVersion, err := parseCT(ctPath)
	if err != nil {
		return fmt.Errorf("%s: %w", ctPath, err)
	}
	if err := write(filepath.Join(outDir, "ctlogs_gen.go"), renderCT(logs, ctSum, ctVersion, retrieved)); err != nil {
		return err
	}
	primes, sums, err := parsePrimes(rfcDir)
	if err != nil {
		return err
	}
	return write(filepath.Join(outDir, "dhprimes_gen.go"), renderPrimes(primes, sums, retrieved))
}

func write(path string, src []byte) error {
	out, err := format.Source(src)
	if err != nil {
		return fmt.Errorf("format %s: %w", path, err)
	}
	return os.WriteFile(path, out, 0o600)
}

func fileSHA(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// ---- root stores ---------------------------------------------------------------

type root struct {
	sha, name, owner string
	distrustAfter    string // YYYY-MM-DD
	sctNotAfter      int64  // unix seconds
	permitted        []string
}

func parseRoots(path, statusCol, constraintCol, namesCol string, der map[string][]byte) ([]root, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	r := csv.NewReader(bytes.NewReader(data))
	rows, err := r.ReadAll()
	if err != nil {
		return nil, "", err
	}
	if len(rows) < 2 {
		return nil, "", fmt.Errorf("no rows")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimPrefix(h, "\xef\xbb\xbf")] = i
	}
	for _, need := range []string{"CA Owner", "Certificate Name", "SHA-256 Fingerprint", "X.509 Certificate (PEM)", statusCol, constraintCol, namesCol} {
		if _, ok := col[need]; !ok {
			return nil, "", fmt.Errorf("missing column %q", need)
		}
	}
	var out []root
	for n, row := range rows[1:] {
		line := n + 2
		if st := row[col[statusCol]]; st != "Included" {
			return nil, "", fmt.Errorf("row %d: unexpected status %q", line, st)
		}
		blk, rest := pem.Decode([]byte(row[col["X.509 Certificate (PEM)"]]))
		if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, "", fmt.Errorf("row %d: PEM is not exactly one certificate", line)
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return nil, "", fmt.Errorf("row %d: %w", line, err)
		}
		sha := fileSHA(blk.Bytes)
		if want := strings.ToLower(row[col["SHA-256 Fingerprint"]]); want != sha {
			return nil, "", fmt.Errorf("row %d: fingerprint %s does not match the certificate (%s)", line, want, sha)
		}
		der[sha] = blk.Bytes
		rt := root{sha: sha, name: row[col["Certificate Name"]], owner: row[col["CA Owner"]]}
		if v := strings.TrimSpace(row[col[constraintCol]]); v != "" {
			if strings.HasPrefix(constraintCol, "sct") {
				sec, err := strconv.ParseInt(v, 10, 64)
				if err != nil || sec <= 0 {
					return nil, "", fmt.Errorf("row %d: %s %q", line, constraintCol, v)
				}
				rt.sctNotAfter = sec
			} else {
				t, err := time.Parse("1/2/2006", v)
				if err != nil {
					return nil, "", fmt.Errorf("row %d: %s %q: %w", line, constraintCol, v, err)
				}
				rt.distrustAfter = t.Format("2006-01-02")
			}
		}
		for _, f := range strings.FieldsFunc(row[col[namesCol]], func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
			f = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(f), "*"), ".")
			if f == "" || strings.ContainsAny(f, "*/:") {
				return nil, "", fmt.Errorf("row %d: unreadable name constraint %q", line, row[col[namesCol]])
			}
			rt.permitted = append(rt.permitted, f)
		}
		out = append(out, rt)
	}
	return out, fileSHA(data), nil
}

func renderRoots(der map[string][]byte, moz []root, mozSum string, chr []root, chrSum, retrieved string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by internal/refdata/gen from the CCADB reports MozillaTLSServerAuthenticationCSV and\n")
	fmt.Fprintf(&b, "// ChromeTLSServerAuthenticationCSV (retrieved %s; CDLA-Permissive-2.0, see docs/reference-data.md). DO NOT EDIT.\n\n", retrieved)
	b.WriteString("package refdata\n\n")
	fmt.Fprintf(&b, "var mozillaSource = Source{Name: %q, URL: %q, Retrieved: %q, SHA256: %q, Licence: licenceCCADB}\n\n", "Mozilla root store", mozillaURL, retrieved, mozSum)
	fmt.Fprintf(&b, "var chromeSource = Source{Name: %q, URL: %q, Retrieved: %q, SHA256: %q, Licence: licenceCCADB}\n\n", "Chrome Root Store", chromeURL, retrieved, chrSum)
	keys := make([]string, 0, len(der))
	for k := range der {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteString("// rootDER is every root's DER, base64, by SHA-256. Each store refers to it.\nvar rootDER = map[string]string{\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "\t%q: %q,\n", k, base64.StdEncoding.EncodeToString(der[k]))
	}
	b.WriteString("}\n\n")
	emit := func(name string, rs []root) {
		fmt.Fprintf(&b, "var %s = []rootEntry{\n", name)
		for _, r := range rs {
			fmt.Fprintf(&b, "\t{SHA256: %q, Name: %q, Owner: %q", r.sha, r.name, r.owner)
			if r.distrustAfter != "" {
				fmt.Fprintf(&b, ", DistrustAfter: %q", r.distrustAfter)
			}
			if r.sctNotAfter != 0 {
				fmt.Fprintf(&b, ", SCTNotAfter: %d", r.sctNotAfter)
			}
			if len(r.permitted) > 0 {
				fmt.Fprintf(&b, ", PermittedDNS: %#v", r.permitted)
			}
			b.WriteString("},\n")
		}
		b.WriteString("}\n\n")
	}
	emit("mozillaRoots", moz)
	emit("chromeRoots", chr)
	return b.Bytes()
}

// ---- CT logs -------------------------------------------------------------------

type ctLog struct {
	id, name, operator, state, url string
}

func parseCT(path string) ([]ctLog, string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", "", err
	}
	var doc struct {
		Version   string `json:"version"`
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				Description string                     `json:"description"`
				LogID       string                     `json:"log_id"`
				URL         string                     `json:"url"`
				SubmitURL   string                     `json:"submission_url"`
				State       map[string]json.RawMessage `json:"state"`
			} `json:"logs"`
			Tiled []struct {
				Description string                     `json:"description"`
				LogID       string                     `json:"log_id"`
				URL         string                     `json:"monitoring_url"`
				SubmitURL   string                     `json:"submission_url"`
				State       map[string]json.RawMessage `json:"state"`
			} `json:"tiled_logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, "", "", err
	}
	known := map[string]bool{"pending": true, "qualified": true, "usable": true, "readonly": true, "retired": true, "rejected": true}
	seen := map[string]bool{}
	var out []ctLog
	add := func(op, desc, id, url string, st map[string]json.RawMessage) error {
		raw, err := base64.StdEncoding.DecodeString(id)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("log %q: log_id is not 32 bytes of base64", desc)
		}
		if seen[id] {
			return fmt.Errorf("log %q: duplicate log_id", desc)
		}
		seen[id] = true
		state := ""
		for k := range st {
			if !known[k] || state != "" {
				return fmt.Errorf("log %q: unexpected state %v", desc, st)
			}
			state = k
		}
		out = append(out, ctLog{id: id, name: desc, operator: op, state: state, url: url})
		return nil
	}
	for _, op := range doc.Operators {
		for _, l := range op.Logs {
			if err := add(op.Name, l.Description, l.LogID, l.URL, l.State); err != nil {
				return nil, "", "", err
			}
		}
		for _, l := range op.Tiled {
			if err := add(op.Name, l.Description, l.LogID, l.URL, l.State); err != nil {
				return nil, "", "", err
			}
		}
	}
	if len(out) == 0 {
		return nil, "", "", fmt.Errorf("no logs")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, fileSHA(data), doc.Version, nil
}

func renderCT(logs []ctLog, sum, version, retrieved string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by internal/refdata/gen from Chrome's CT log list v3 (version %s, retrieved %s). DO NOT EDIT.\n\n", version, retrieved)
	b.WriteString("package refdata\n\n")
	fmt.Fprintf(&b, "var ctSource = Source{Name: %q, URL: %q, Retrieved: %q, SHA256: %q, Licence: licenceCTList}\n\n", "CT log list", ctURL, retrieved, sum)
	b.WriteString("var ctLogs = []CTLog{\n")
	for _, l := range logs {
		fmt.Fprintf(&b, "\t{ID: %q, Name: %q, Operator: %q, State: %q, URL: %q},\n", l.id, l.name, l.operator, l.state, l.url)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// ---- DH primes -----------------------------------------------------------------

// primeSection says where a prime is printed: the RFC, the exact section
// heading, the name we give it, and the size the heading promises.
type primeSection struct {
	rfc, heading, section, name string
	bits                        int
}

var primeSections = []primeSection{
	{"2409", "6.1 First Oakley Default Group", "6.1", "Oakley Group 1 (768-bit MODP)", 768},
	{"2409", "6.2 Second Oakley Group", "6.2", "Oakley Group 2 (1024-bit MODP)", 1024},
	{"3526", "2.  1536-bit MODP Group", "2", "MODP group 5 (1536-bit)", 1536},
	{"3526", "3.  2048-bit MODP Group", "3", "MODP group 14 (2048-bit)", 2048},
	{"3526", "4.  3072-bit MODP Group", "4", "MODP group 15 (3072-bit)", 3072},
	{"3526", "5.  4096-bit MODP Group", "5", "MODP group 16 (4096-bit)", 4096},
	{"3526", "6.  6144-bit MODP Group", "6", "MODP group 17 (6144-bit)", 6144},
	{"3526", "7.  8192-bit MODP Group", "7", "MODP group 18 (8192-bit)", 8192},
	{"5114", "2.1.  1024-bit MODP Group with 160-bit Prime Order Subgroup", "2.1", "RFC 5114 group 22 (1024-bit, 160-bit subgroup)", 1024},
	{"5114", "2.2.  2048-bit MODP Group with 224-bit Prime Order Subgroup", "2.2", "RFC 5114 group 23 (2048-bit, 224-bit subgroup)", 2048},
	{"5114", "2.3.  2048-bit MODP Group with 256-bit Prime Order Subgroup", "2.3", "RFC 5114 group 24 (2048-bit, 256-bit subgroup)", 2048},
	{"7919", "A.1.  ffdhe2048", "A.1", "ffdhe2048", 2048},
	{"7919", "A.2.  ffdhe3072", "A.2", "ffdhe3072", 3072},
	{"7919", "A.3.  ffdhe4096", "A.3", "ffdhe4096", 4096},
	{"7919", "A.4.  ffdhe6144", "A.4", "ffdhe6144", 6144},
	{"7919", "A.5.  ffdhe8192", "A.5", "ffdhe8192", 8192},
}

type prime struct {
	sec primeSection
	sha string
}

var (
	hexLine  = regexp.MustCompile(`^(?:p\s*=\s*)?((?:[0-9A-F]{2,8}\s*)+)$`)
	pageLine = regexp.MustCompile(`^(RFC \d+ .*\d{4}|.*\[Page \d+\])$`)
)

func parsePrimes(dir string) ([]prime, map[string]string, error) {
	texts := map[string][]string{}
	sums := map[string]string{}
	var out []prime
	for _, s := range primeSections {
		lines, ok := texts[s.rfc]
		if !ok {
			data, err := os.ReadFile(filepath.Join(dir, "rfc"+s.rfc+".txt"))
			if err != nil {
				return nil, nil, err
			}
			sums[s.rfc] = fileSHA(data)
			sc := bufio.NewScanner(bytes.NewReader(data))
			for sc.Scan() {
				lines = append(lines, strings.TrimRight(strings.Trim(sc.Text(), "\f"), " \t\r"))
			}
			texts[s.rfc] = lines
		}
		p, err := extractPrime(lines, s)
		if err != nil {
			return nil, nil, fmt.Errorf("RFC %s §%s: %w", s.rfc, s.section, err)
		}
		out = append(out, prime{sec: s, sha: fileSHA(p.Bytes())})
	}
	return out, sums, nil
}

// extractPrime finds the heading (it must occur exactly once), then the first
// "hexadecimal" sentence after it, then reads hex lines across page breaks
// until the first line of prose.
func extractPrime(lines []string, s primeSection) (*big.Int, error) {
	at := -1
	for i, l := range lines {
		if l == s.heading {
			if at >= 0 {
				return nil, fmt.Errorf("heading %q occurs twice", s.heading)
			}
			at = i
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("heading %q not found", s.heading)
	}
	i := at + 1
	for ; i < len(lines) && !strings.Contains(lines[i], "hexadecimal"); i++ {
	}
	if i == len(lines) {
		return nil, fmt.Errorf("no hexadecimal value after the heading")
	}
	var digits strings.Builder
	started := false
	for i++; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if l == "" || pageLine.MatchString(l) {
			continue
		}
		m := hexLine.FindStringSubmatch(l)
		if m == nil {
			if started {
				break
			}
			return nil, fmt.Errorf("prose %q before the value", l)
		}
		started = true
		digits.WriteString(strings.Join(strings.Fields(m[1]), ""))
	}
	p, ok := new(big.Int).SetString(digits.String(), 16)
	if !ok {
		return nil, fmt.Errorf("value is not hexadecimal")
	}
	if p.BitLen() != s.bits {
		return nil, fmt.Errorf("value has %d bits, heading says %d", p.BitLen(), s.bits)
	}
	if !p.ProbablyPrime(32) {
		return nil, fmt.Errorf("value is not prime")
	}
	return p, nil
}

func renderPrimes(primes []prime, sums map[string]string, retrieved string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by internal/refdata/gen from the texts of RFC 2409, 3526, 5114 and 7919 (retrieved %s). DO NOT EDIT.\n\n", retrieved)
	b.WriteString("package refdata\n\n")
	rfcs := make([]string, 0, len(sums))
	for k := range sums {
		rfcs = append(rfcs, k)
	}
	sort.Strings(rfcs)
	var urls, shas []string
	for _, r := range rfcs {
		urls = append(urls, fmt.Sprintf(rfcURL, r))
		shas = append(shas, "rfc"+r+".txt="+sums[r])
	}
	fmt.Fprintf(&b, "var dhSource = Source{Name: %q, URL: %q, Retrieved: %q, SHA256: %q, Licence: licenceRFC}\n\n",
		"Published DH groups", strings.Join(urls, " "), retrieved, strings.Join(shas, " "))
	b.WriteString("// dhPrimes is keyed by the SHA-256 of the prime's big-endian bytes, leading zeros trimmed.\nvar dhPrimes = []DHPrime{\n")
	for _, p := range primes {
		fmt.Fprintf(&b, "\t{SHA256: %q, Name: %q, Bits: %d, Source: %q, Negotiated: %t},\n",
			p.sha, p.sec.name, p.sec.bits, "RFC "+p.sec.rfc+" §"+p.sec.section, p.sec.rfc == "7919")
	}
	b.WriteString("}\n")
	return b.Bytes()
}
