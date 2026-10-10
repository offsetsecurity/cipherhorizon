package refdata

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDHPrimesMatchOpenSSL pins the generated fingerprints to an independent
// producer: OpenSSL 3.5's built-in named groups, exported with
//
//	openssl genpkey -genparam -algorithm DH -pkeyopt group:NAME | openssl asn1parse
//
// and hashed over the prime's bytes. OpenSSL has no Oakley group 1 or 2; those
// two rest on the generator's primality and size checks.
func TestDHPrimesMatchOpenSSL(t *testing.T) {
	oracle := map[string]string{
		"ffdhe2048":                "9cd3b7f336872f46c09428d1bbc19877a4d440512cda8d1c1cf0cd6e33698966",
		"ffdhe3072":                "0eaf67db3a839156d5013494a5318a772b5697d270d721f37f092efc69ea5a17",
		"ffdhe4096":                "4648414224ac881b3d0dc59b466f96d06a558278776807797ecf1f66ff397b3e",
		"ffdhe6144":                "227ac9066b3ddd9e193670cda2388fa884f65ba0cf98b742d1fe77a6687c79c7",
		"ffdhe8192":                "770b14efaf6f049929c523113b3fa99a8d11dab1b18af3609590122075d19833",
		"MODP group 5 (1536-bit)":  "64fcc83ec403930bf18393dbc883ccaa1fbb08ac876f77f7aa99748ca945019b",
		"MODP group 14 (2048-bit)": "d66436f79bbd6b2e38c0ffbd079be904d2641415e2e67140e09448be9a60890e",
		"MODP group 15 (3072-bit)": "48cf8b092fbce4359d9871abf74f98e25b6163379eaa15cd9087e800c6d1c55c",
		"MODP group 16 (4096-bit)": "4ee95187682bcb230ad26a95205f6920e84708f6251b3894329b09ec23919e33",
		"MODP group 17 (6144-bit)": "d1bfe6d0925ce7e4da262b62861514a7755e35831e429f343e7b864848657efd",
		"MODP group 18 (8192-bit)": "39ab4feab950a3128fb71accb9fc3965d857012e081998a85996e3ea8b3c3bcf",
		"RFC 5114 group 22 (1024-bit, 160-bit subgroup)": "44c55cfee5c075927cf682da5b681bdecbd5c3eb0784c14f5dce7610f0ef133d",
		"RFC 5114 group 23 (2048-bit, 224-bit subgroup)": "bfe545862ca102ad1eeddb5fbfa5bf855ac4995c56a8b408ce3fe099dce93a9d",
		"RFC 5114 group 24 (2048-bit, 256-bit subgroup)": "0b7835722cb619827610c2549fdda5587421686c4409a13865e76225522ddcc9",
	}
	for name, sha := range oracle {
		p, ok := LookupDHPrime(sha)
		if !ok || p.Name != name {
			t.Errorf("%s: lookup by the OpenSSL fingerprint gave %+v, %v", name, p, ok)
		}
	}
	if len(dhPrimes) != len(oracle)+2 {
		t.Errorf("dhPrimes has %d entries, want %d", len(dhPrimes), len(oracle)+2)
	}
	for _, p := range dhPrimes {
		if p.Negotiated != (p.Name[:5] == "ffdhe") {
			t.Errorf("%s: Negotiated=%v", p.Name, p.Negotiated)
		}
	}
	if p, _ := LookupDHPrime("3f35a3f5f6c4376a744acad409bb22f8d897f949d2311d885adaa890981b67a0"); p.Bits != 1024 {
		t.Errorf("Oakley group 2 = %+v", p)
	}
}

func TestStoresLoad(t *testing.T) {
	st := Stores()
	if len(st) != 2 || st[0].Name != "Mozilla" || st[1].Name != "Chrome" {
		t.Fatalf("stores = %v", st)
	}
	if st[0].Len() != len(mozillaRoots) || st[1].Len() != len(chromeRoots) {
		t.Errorf("distinct roots %d/%d, entries %d/%d", st[0].Len(), st[1].Len(), len(mozillaRoots), len(chromeRoots))
	}
	if st[0].Len() < 100 || st[1].Len() < 80 {
		t.Errorf("implausibly small stores: %d, %d", st[0].Len(), st[1].Len())
	}
	if !st[0].Constrained || st[0].Snapshot == "" {
		t.Errorf("Mozilla store metadata: %+v", st[0])
	}
	// Every DER is referenced by at least one store; nothing is orphaned.
	used := map[string]bool{}
	for _, l := range [][]rootEntry{mozillaRoots, chromeRoots} {
		for _, e := range l {
			used[e.SHA256] = true
		}
	}
	for k := range rootDER {
		if !used[k] {
			t.Errorf("root %s is in rootDER but in no store", k)
		}
	}
}

// TestRootConstraintsCarried checks that the constraints in the CCADB reports
// survive generation: a distrust-after date, an sct_not_after, and a name
// constraint.
func TestRootConstraintsCarried(t *testing.T) {
	var distrust, sct, names int
	for _, e := range mozillaRoots {
		if e.DistrustAfter != "" {
			distrust++
		}
		if len(e.PermittedDNS) > 0 {
			names++
		}
	}
	for _, e := range chromeRoots {
		if e.SCTNotAfter != 0 {
			sct++
		}
	}
	if distrust == 0 || sct == 0 || names == 0 {
		t.Fatalf("constraints lost: distrust=%d sct=%d names=%d", distrust, sct, names)
	}
	moz := Stores()[0]
	for _, e := range mozillaRoots {
		if e.DistrustAfter == "" {
			continue
		}
		r, ok := moz.Root(e.SHA256)
		if !ok || r.DistrustAfter.IsZero() {
			t.Fatalf("%s: distrust date not on the store root", e.Name)
		}
		// Issued on the date itself: still trusted; the next day: not.
		day, _ := time.Parse("2006-01-02", e.DistrustAfter)
		if !day.Add(23*time.Hour).Before(r.DistrustAfter) || !day.Add(24*time.Hour).After(r.DistrustAfter) {
			t.Errorf("%s: DistrustAfter %v does not cover the whole day %s", e.Name, r.DistrustAfter, e.DistrustAfter)
		}
	}
}

// TestLifetimeTablePinned pins the hand-transcribed SC-081v3 schedule. Change
// it only together with lifetime.go, from the ballot text.
func TestLifetimeTablePinned(t *testing.T) {
	want := []struct {
		from string
		days int
	}{{"2020-09-01", 398}, {"2026-03-15", 200}, {"2027-03-15", 100}, {"2029-03-15", 47}}
	got := LifetimeTable()
	if len(got) != len(want) {
		t.Fatalf("table has %d rows", len(got))
	}
	for i, w := range want {
		if got[i].From.Format("2006-01-02") != w.from || got[i].Days != w.days {
			t.Errorf("row %d = %v %d, want %s %d", i, got[i].From, got[i].Days, w.from, w.days)
		}
	}
	cases := []struct {
		at   string
		days int
		ok   bool
	}{
		{"2019-01-01", 0, false},
		{"2026-03-14", 398, true},
		{"2026-03-15", 200, true},
		{"2027-03-14", 200, true},
		{"2027-03-15", 100, true},
		{"2029-03-15", 47, true},
		{"2035-01-01", 47, true},
	}
	for _, c := range cases {
		at, _ := time.Parse("2006-01-02", c.at)
		d, ok := MaxLifetime(at)
		if d != c.days || ok != c.ok {
			t.Errorf("MaxLifetime(%s) = %d, %v; want %d, %v", c.at, d, ok, c.days, c.ok)
		}
	}
}

func TestCTLookup(t *testing.T) {
	if len(ctLogs) < 20 {
		t.Fatalf("only %d CT logs", len(ctLogs))
	}
	id, _ := base64.StdEncoding.DecodeString(ctLogs[0].ID)
	if l, ok := LookupCTLog(id); !ok || l.Name == "" || l.Operator == "" {
		t.Errorf("lookup of the first log: %+v %v", l, ok)
	}
	if _, ok := LookupCTLog(make([]byte, 32)); ok {
		t.Error("an all-zero log ID matched")
	}
}

func TestSourcesRecorded(t *testing.T) {
	src := Sources()
	if len(src) != 5 {
		t.Fatalf("%d sources", len(src))
	}
	for _, s := range src {
		if s.Name == "" || s.URL == "" || s.Licence == "" || s.Count == 0 {
			t.Errorf("source incomplete: %+v", s)
		}
		if _, err := time.Parse("2006-01-02", s.Retrieved); err != nil {
			t.Errorf("%s: retrieved %q", s.Name, s.Retrieved)
		}
	}
	at, _ := time.Parse("2006-01-02", src[0].Retrieved)
	if src[0].Age(at.AddDate(0, 0, StaleAfterDays+1)) <= StaleAfterDays {
		t.Error("Age does not pass the stale threshold")
	}
}

// TestGeneratedTablesAreSelfConsistent is SECARCH-001 SR-22: a hand edit of a generated
// list breaks a checksum. Every root's DER must hash to the key it is filed under, every
// store entry must point at a root that exists, every CT log ID must be 32 bytes, and the
// generated files must still say they are generated.
func TestGeneratedTablesAreSelfConsistent(t *testing.T) {
	for sha, b64 := range rootDER {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("%s: %v", sha, err)
		}
		sum := sha256.Sum256(der)
		if hex.EncodeToString(sum[:]) != sha {
			t.Errorf("root %s: its DER hashes to %x (edited by hand?)", sha, sum)
		}
	}
	for _, l := range [][]rootEntry{mozillaRoots, chromeRoots} {
		for _, e := range l {
			if _, ok := rootDER[e.SHA256]; !ok {
				t.Errorf("store entry %s (%s) has no certificate", e.SHA256, e.Name)
			}
		}
	}
	for _, l := range ctLogs {
		if id, err := base64.StdEncoding.DecodeString(l.ID); err != nil || len(id) != 32 {
			t.Errorf("CT log %q: ID is not 32 bytes", l.Name)
		}
	}
	for _, f := range []string{"roots_gen.go", "ctlogs_gen.go", "dhprimes_gen.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b[:min(len(b), 400)]), "Code generated by internal/refdata/gen") || !strings.Contains(string(b[:min(len(b), 400)]), "DO NOT EDIT") {
			t.Errorf("%s lost its generated-code header", f)
		}
	}
}
