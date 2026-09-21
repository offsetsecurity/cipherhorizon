// Command gen turns IANA's TLS registry CSVs into the Go tables in the parent
// package. See the registry package documentation for how to run it.
//
// It is strict on purpose: a cipher-suite name it cannot decompose with its
// grammar is an error, never a guess, so a new IANA entry forces a conscious
// decision here instead of silently getting wrong properties.
package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	suitesPath := flag.String("suites", "", "IANA tls-parameters-4.csv (TLS Cipher Suites)")
	groupsPath := flag.String("groups", "", "IANA tls-parameters-8.csv (TLS Supported Groups)")
	retrieved := flag.String("retrieved", "", "date the CSVs were retrieved, YYYY-MM-DD (recorded in the output)")
	outDir := flag.String("out", ".", "directory to write suites_gen.go and groups_gen.go into")
	flag.Parse()
	if *suitesPath == "" || *groupsPath == "" || *retrieved == "" {
		fmt.Fprintln(os.Stderr, "gen: -suites, -groups and -retrieved are required")
		os.Exit(2)
	}
	if err := run(*suitesPath, *groupsPath, *retrieved, *outDir); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(suitesPath, groupsPath, retrieved, outDir string) error {
	suites, err := parseSuites(suitesPath)
	if err != nil {
		return fmt.Errorf("%s: %w", suitesPath, err)
	}
	groups, err := parseGroups(groupsPath)
	if err != nil {
		return fmt.Errorf("%s: %w", groupsPath, err)
	}
	if err := write(filepath.Join(outDir, "suites_gen.go"), renderSuites(suites, retrieved)); err != nil {
		return err
	}
	return write(filepath.Join(outDir, "groups_gen.go"), renderGroups(groups, retrieved))
}

// ---- cipher suites -----------------------------------------------------------

type suite struct {
	id                          uint16
	name, recommended, ref      string
	dtls                        bool
	class                       string // ClassLegacy | ClassTLS13 | ClassSignalling
	kx, auth                    string
	cipher, mode, mac, hash     string
	keyBits, blockBits          int
	aead, export, anon, ephemer bool
}

var valueRE = regexp.MustCompile(`^0x([0-9A-Fa-f]{2}),0x([0-9A-Fa-f]{2})$`)

func parseSuites(path string) ([]suite, error) {
	rows, err := readCSV(path)
	if err != nil {
		return nil, err
	}
	var out []suite
	for _, r := range rows {
		desc := r["Description"]
		if !strings.HasPrefix(desc, "TLS_") && !strings.HasPrefix(desc, "SSL_") {
			continue // Unassigned, Reserved, GREASE, private use
		}
		m := valueRE.FindStringSubmatch(r["Value"])
		if m == nil {
			return nil, fmt.Errorf("suite %s: unparseable value %q", desc, r["Value"])
		}
		id, err := parseID(m[1] + m[2])
		if err != nil {
			return nil, fmt.Errorf("suite %s: %w", desc, err)
		}
		s := suite{
			id: id, name: desc,
			recommended: r["Recommended"], ref: r["Reference"], dtls: r["DTLS-OK"] == "Y",
		}
		if err := decompose(&s); err != nil {
			return nil, fmt.Errorf("suite %s (%s): %w", desc, r["Value"], err)
		}
		out = append(out, s)
	}
	if len(out) < 300 {
		return nil, fmt.Errorf("only %d suites parsed; the CSV looks wrong", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	for i := 1; i < len(out); i++ {
		if out[i].id == out[i-1].id {
			return nil, fmt.Errorf("duplicate suite id 0x%04X", out[i].id)
		}
	}
	return out, nil
}

// kxInfo is what a key-exchange/authentication prefix of a legacy suite name means.
type kxInfo struct {
	kx, auth              string
	export, anon, ephemer bool
}

// The prefixes IANA uses before "_WITH_". Anything else is an error.
var kxTable = map[string]kxInfo{
	"RSA":           {kx: "RSA", auth: "RSA"},
	"RSA_EXPORT":    {kx: "RSA", auth: "RSA", export: true},
	"DH_DSS":        {kx: "DH", auth: "DSS"},
	"DH_RSA":        {kx: "DH", auth: "RSA"},
	"DH_DSS_EXPORT": {kx: "DH", auth: "DSS", export: true},
	"DH_RSA_EXPORT": {kx: "DH", auth: "RSA", export: true},
	"DHE_DSS":       {kx: "DHE", auth: "DSS", ephemer: true},
	"DHE_RSA":       {kx: "DHE", auth: "RSA", ephemer: true},
	"DHE_DSS_EXPORT": {kx: "DHE", auth: "DSS", ephemer: true,
		export: true},
	"DHE_RSA_EXPORT":  {kx: "DHE", auth: "RSA", ephemer: true, export: true},
	"DH_anon":         {kx: "DHE", auth: "anon", ephemer: true, anon: true},
	"DH_anon_EXPORT":  {kx: "DHE", auth: "anon", ephemer: true, anon: true, export: true},
	"ECDH_ECDSA":      {kx: "ECDH", auth: "ECDSA"},
	"ECDH_RSA":        {kx: "ECDH", auth: "RSA"},
	"ECDHE_ECDSA":     {kx: "ECDHE", auth: "ECDSA", ephemer: true},
	"ECDHE_RSA":       {kx: "ECDHE", auth: "RSA", ephemer: true},
	"ECDH_anon":       {kx: "ECDHE", auth: "anon", ephemer: true, anon: true},
	"PSK":             {kx: "PSK", auth: "PSK"},
	"DHE_PSK":         {kx: "DHE_PSK", auth: "PSK", ephemer: true},
	"PSK_DHE":         {kx: "DHE_PSK", auth: "PSK", ephemer: true},
	"ECDHE_PSK":       {kx: "ECDHE_PSK", auth: "PSK", ephemer: true},
	"RSA_PSK":         {kx: "RSA_PSK", auth: "PSK"},
	"SRP_SHA":         {kx: "SRP", auth: "SRP"},
	"SRP_SHA_RSA":     {kx: "SRP", auth: "RSA"},
	"SRP_SHA_DSS":     {kx: "SRP", auth: "DSS"},
	"KRB5":            {kx: "KRB5", auth: "KRB5"},
	"KRB5_EXPORT":     {kx: "KRB5", auth: "KRB5", export: true},
	"ECCPWD":          {kx: "ECCPWD", auth: "ECCPWD"},
	"GOSTR341112_256": {kx: "GOST", auth: "GOST"},
	"NULL":            {kx: "NULL", auth: "NULL"},
}

// cipherInfo describes an encryption/AEAD spelling in a suite name. CURATED:
// these are properties of the ciphers (key size, block size), not IANA data.
type cipherInfo struct {
	cipher, mode        string
	keyBits, blockBits  int
	aead, export, plain bool // plain: integrity-only, no encryption
}

var cipherTable = map[string]cipherInfo{
	"AES_128_CBC":       {cipher: "AES", mode: "CBC", keyBits: 128, blockBits: 128},
	"AES_256_CBC":       {cipher: "AES", mode: "CBC", keyBits: 256, blockBits: 128},
	"AES_128_GCM":       {cipher: "AES", mode: "GCM", keyBits: 128, blockBits: 128, aead: true},
	"AES_256_GCM":       {cipher: "AES", mode: "GCM", keyBits: 256, blockBits: 128, aead: true},
	"AES_128_CCM":       {cipher: "AES", mode: "CCM", keyBits: 128, blockBits: 128, aead: true},
	"AES_256_CCM":       {cipher: "AES", mode: "CCM", keyBits: 256, blockBits: 128, aead: true},
	"AES_128_CCM_8":     {cipher: "AES", mode: "CCM8", keyBits: 128, blockBits: 128, aead: true},
	"AES_256_CCM_8":     {cipher: "AES", mode: "CCM8", keyBits: 256, blockBits: 128, aead: true},
	"ARIA_128_CBC":      {cipher: "ARIA", mode: "CBC", keyBits: 128, blockBits: 128},
	"ARIA_256_CBC":      {cipher: "ARIA", mode: "CBC", keyBits: 256, blockBits: 128},
	"ARIA_128_GCM":      {cipher: "ARIA", mode: "GCM", keyBits: 128, blockBits: 128, aead: true},
	"ARIA_256_GCM":      {cipher: "ARIA", mode: "GCM", keyBits: 256, blockBits: 128, aead: true},
	"CAMELLIA_128_CBC":  {cipher: "CAMELLIA", mode: "CBC", keyBits: 128, blockBits: 128},
	"CAMELLIA_256_CBC":  {cipher: "CAMELLIA", mode: "CBC", keyBits: 256, blockBits: 128},
	"CAMELLIA_128_GCM":  {cipher: "CAMELLIA", mode: "GCM", keyBits: 128, blockBits: 128, aead: true},
	"CAMELLIA_256_GCM":  {cipher: "CAMELLIA", mode: "GCM", keyBits: 256, blockBits: 128, aead: true},
	"CHACHA20_POLY1305": {cipher: "CHACHA20", mode: "POLY1305", keyBits: 256, aead: true},
	"3DES_EDE_CBC":      {cipher: "3DES", mode: "CBC", keyBits: 168, blockBits: 64},
	"DES_CBC":           {cipher: "DES", mode: "CBC", keyBits: 56, blockBits: 64},
	"DES40_CBC":         {cipher: "DES", mode: "CBC", keyBits: 40, blockBits: 64, export: true},
	"DES_CBC_40":        {cipher: "DES", mode: "CBC", keyBits: 40, blockBits: 64, export: true},
	"RC2_CBC_40":        {cipher: "RC2", mode: "CBC", keyBits: 40, blockBits: 64, export: true},
	"RC4_128":           {cipher: "RC4", mode: "STREAM", keyBits: 128},
	"RC4_40":            {cipher: "RC4", mode: "STREAM", keyBits: 40, export: true},
	"IDEA_CBC":          {cipher: "IDEA", mode: "CBC", keyBits: 128, blockBits: 64},
	"SEED_CBC":          {cipher: "SEED", mode: "CBC", keyBits: 128, blockBits: 128},
	"NULL":              {cipher: "NULL", mode: "NONE", plain: true},
	"28147_CNT":         {cipher: "GOST28147", mode: "CNT", keyBits: 256, blockBits: 64},
	"KUZNYECHIK_CTR":    {cipher: "KUZNYECHIK", mode: "CTR", keyBits: 256, blockBits: 128},
	"KUZNYECHIK_MGM_L":  {cipher: "KUZNYECHIK", mode: "MGM", keyBits: 256, blockBits: 128, aead: true},
	"KUZNYECHIK_MGM_S":  {cipher: "KUZNYECHIK", mode: "MGM", keyBits: 256, blockBits: 128, aead: true},
	"MAGMA_CTR":         {cipher: "MAGMA", mode: "CTR", keyBits: 256, blockBits: 64},
	"MAGMA_MGM_L":       {cipher: "MAGMA", mode: "MGM", keyBits: 256, blockBits: 64, aead: true},
	"MAGMA_MGM_S":       {cipher: "MAGMA", mode: "MGM", keyBits: 256, blockBits: 64, aead: true},
	"SM4_GCM":           {cipher: "SM4", mode: "GCM", keyBits: 128, blockBits: 128, aead: true},
	"SM4_CCM":           {cipher: "SM4", mode: "CCM", keyBits: 128, blockBits: 128, aead: true},
	"AEGIS_256":         {cipher: "AEGIS", mode: "AEGIS", keyBits: 256, aead: true},
	"AEGIS_128L":        {cipher: "AEGIS", mode: "AEGIS", keyBits: 128, aead: true},
	"ASCONAEAD128":      {cipher: "ASCON", mode: "ASCONAEAD", keyBits: 128, aead: true},
	// Integrity-only TLS 1.3-style suites (TLS_SHA256_SHA256, TLS_SHA384_SHA384).
	"SHA256": {cipher: "NULL", mode: "NONE", plain: true},
	"SHA384": {cipher: "NULL", mode: "NONE", plain: true},
}

// macTable maps the trailing token of a non-AEAD suite to a canonical MAC name.
var macTable = map[string]string{
	"SHA": "SHA1", "SHA256": "SHA256", "SHA384": "SHA384", "MD5": "MD5",
	"NULL": "NONE", "OMAC": "OMAC", "IMIT": "IMIT",
}

// hashTable lists the hashes that may follow an AEAD cipher.
var hashTable = map[string]bool{
	"SHA256": true, "SHA384": true, "SHA512": true, "SM3": true, "ASCONHASH256": true,
}

func decompose(s *suite) error {
	name := s.name
	switch {
	case strings.HasSuffix(name, "_SCSV"):
		s.class = "ClassSignalling"
		return nil
	case strings.Contains(name, "_WITH_"):
		s.class = "ClassLegacy"
		kx, enc, _ := strings.Cut(strings.TrimPrefix(name, "TLS_"), "_WITH_")
		info, ok := kxTable[kx]
		if !ok {
			return fmt.Errorf("unknown key-exchange prefix %q", kx)
		}
		s.kx, s.auth, s.export, s.anon, s.ephemer = info.kx, info.auth, info.export, info.anon, info.ephemer
		return decomposeEnc(s, enc, false)
	default:
		s.class = "ClassTLS13"
		return decomposeEnc(s, strings.TrimPrefix(name, "TLS_"), true)
	}
}

// decomposeEnc splits "<cipher>[_<mac-or-hash>]" using the longest cipher spelling
// in cipherTable that is a prefix of enc.
func decomposeEnc(s *suite, enc string, tls13 bool) error {
	best := ""
	for key := range cipherTable {
		if (enc == key || strings.HasPrefix(enc, key+"_")) && len(key) > len(best) {
			best = key
		}
	}
	if best == "" {
		return fmt.Errorf("unknown cipher in %q", enc)
	}
	c := cipherTable[best]
	rest := strings.TrimPrefix(strings.TrimPrefix(enc, best), "_")

	s.cipher, s.mode, s.keyBits, s.blockBits = c.cipher, c.mode, c.keyBits, c.blockBits
	s.aead = c.aead
	if c.export {
		s.export = true
	}

	switch {
	case c.plain && tls13:
		// TLS_SHA256_SHA256: integrity only, the trailing token is the hash.
		if rest == "" {
			return fmt.Errorf("integrity-only suite %q has no hash", enc)
		}
		s.mac, s.hash = "NONE", rest
	case c.aead:
		s.mac = "AEAD"
		if rest != "" {
			if !hashTable[rest] {
				return fmt.Errorf("unknown hash %q after AEAD cipher", rest)
			}
			s.hash = rest
		}
	default:
		if rest == "" {
			return fmt.Errorf("non-AEAD cipher %q has no MAC token", best)
		}
		mac, ok := macTable[rest]
		if !ok {
			return fmt.Errorf("unknown MAC token %q", rest)
		}
		s.mac = mac
	}
	if tls13 && s.mac != "AEAD" && best != "SHA256" && best != "SHA384" {
		return fmt.Errorf("TLS 1.3-style suite with non-AEAD cipher %q", best)
	}
	return nil
}

func renderSuites(ss []suite, retrieved string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by internal/tlsprobe/registry/gen from the IANA TLS Cipher Suites registry\n")
	fmt.Fprintf(&b, "// (https://www.iana.org/assignments/tls-parameters/, retrieved %s). DO NOT EDIT.\n\n", retrieved)
	fmt.Fprintf(&b, "package registry\n\n")
	fmt.Fprintf(&b, "// SuitesRetrieved is the date the IANA cipher-suite registry was fetched.\nconst SuitesRetrieved = %q\n\n", retrieved)
	fmt.Fprintf(&b, "var suites = []Suite{\n")
	for _, s := range ss {
		fmt.Fprintf(&b, "\t{ID: 0x%04X, Name: %q, Recommended: '%s', DTLSOK: %t, Reference: %q, Class: %s,",
			s.id, s.name, rec(s.recommended), s.dtls, s.ref, s.class)
		if s.class != "ClassSignalling" {
			fmt.Fprintf(&b, " Kx: %q, Auth: %q, Cipher: %q, KeyBits: %d, Mode: %q, BlockBits: %d, MAC: %q, Hash: %q,"+
				" AEAD: %t, Export: %t, Anon: %t, Ephemeral: %t,",
				s.kx, s.auth, s.cipher, s.keyBits, s.mode, s.blockBits, s.mac, s.hash, s.aead, s.export, s.anon, s.ephemer)
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// rec renders IANA's Recommended letter as a byte literal for the Recommended type.
func rec(v string) string {
	if v == "Y" || v == "N" || v == "D" {
		return v
	}
	return "N"
}

// ---- groups ---------------------------------------------------------------------

type group struct {
	id                     uint16
	name, recommended, ref string
	comment                string
	dtls                   bool
	pq, hybrid, obsolete   bool
}

var pureMLKEM = regexp.MustCompile(`^MLKEM(512|768|1024)$`)

func parseGroups(path string) ([]group, error) {
	rows, err := readCSV(path)
	if err != nil {
		return nil, err
	}
	var out []group
	for _, r := range rows {
		v, err := strconv.ParseUint(r["Value"], 10, 16)
		if err != nil {
			continue // ranges (private use, reserved blocks)
		}
		desc := strings.TrimSpace(r["Description"])
		low := strings.ToLower(desc)
		if desc == "" || low == "reserved" || low == "unassigned" || strings.HasPrefix(low, "unassigned") ||
			strings.HasPrefix(low, "reserved") || strings.HasPrefix(low, "unallocated") {
			continue
		}
		gid, err := toU16(v)
		if err != nil {
			continue
		}
		g := group{id: gid, name: desc, recommended: r["Recommended"], ref: r["Reference"],
			comment: r["Comment"], dtls: r["DTLS-OK"] == "Y"}
		if strings.HasSuffix(g.name, " (OBSOLETE)") {
			g.name = strings.TrimSuffix(g.name, " (OBSOLETE)")
			g.obsolete = true
		}
		l := strings.ToLower(g.name)
		g.pq = strings.Contains(l, "mlkem") || strings.Contains(l, "kyber")
		g.hybrid = g.pq && !pureMLKEM.MatchString(g.name)
		out = append(out, g)
	}
	if len(out) < 40 {
		return nil, fmt.Errorf("only %d groups parsed; the CSV looks wrong", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	for i := 1; i < len(out); i++ {
		if out[i].id == out[i-1].id {
			return nil, fmt.Errorf("duplicate group id %d", out[i].id)
		}
	}
	return out, nil
}

func renderGroups(gs []group, retrieved string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by internal/tlsprobe/registry/gen from the IANA TLS Supported Groups registry\n")
	fmt.Fprintf(&b, "// (https://www.iana.org/assignments/tls-parameters/, retrieved %s). DO NOT EDIT.\n\n", retrieved)
	fmt.Fprintf(&b, "package registry\n\n")
	fmt.Fprintf(&b, "// GroupsRetrieved is the date the IANA supported-groups registry was fetched.\nconst GroupsRetrieved = %q\n\n", retrieved)
	fmt.Fprintf(&b, "var groups = []Group{\n")
	for _, g := range gs {
		fmt.Fprintf(&b, "\t{ID: %d, Name: %q, Recommended: '%s', DTLSOK: %t, Reference: %q, Comment: %q, PQ: %t, Hybrid: %t, Obsolete: %t},\n",
			g.id, g.name, rec(g.recommended), g.dtls, g.ref, g.comment, g.pq, g.hybrid, g.obsolete)
	}
	b.WriteString("}\n")
	return b.Bytes()
}

// ---- helpers ----------------------------------------------------------------------

// parseID parses four hex digits as a 16-bit code point.
func parseID(hex4 string) (uint16, error) {
	v, err := strconv.ParseUint(hex4, 16, 16)
	if err != nil {
		return 0, err
	}
	return toU16(v)
}

// toU16 narrows a parsed number, refusing anything out of range.
func toU16(v uint64) (uint16, error) {
	if v > 0xFFFF {
		return 0, fmt.Errorf("%d does not fit in 16 bits", v)
	}
	return uint16(v), nil
}

func readCSV(path string) ([]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only
	rd := csv.NewReader(f)
	rd.FieldsPerRecord = -1
	header, err := rd.Read()
	if err != nil {
		return nil, err
	}
	var rows []map[string]string
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		row := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(rec) {
				row[h] = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func write(path string, src []byte) error {
	out, err := format.Source(src)
	if err != nil {
		return fmt.Errorf("formatting %s: %w", path, err)
	}
	return os.WriteFile(path, out, 0o600)
}
