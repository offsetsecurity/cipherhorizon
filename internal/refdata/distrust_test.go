package refdata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/pki"
)

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// TestDistrustListIsWellFormed: every incident is dated, typed and cited, and
// every value is a lower-case SHA-256 listed once.
func TestDistrustListIsWellFormed(t *testing.T) {
	f := DistrustData()
	if _, err := time.Parse("2006-01-02", f.Version); err != nil {
		t.Errorf("version %q", f.Version)
	}
	seen := map[string]string{}
	ids := map[string]bool{}
	for _, in := range f.Incidents {
		if in.ID == "" || ids[in.ID] || in.Title == "" || in.Summary == "" || len(in.Entries) == 0 {
			t.Errorf("incident %q incomplete or duplicated", in.ID)
		}
		ids[in.ID] = true
		if in.Kind != pki.KindKeyCompromise && in.Kind != pki.KindCADistrust {
			t.Errorf("%s: kind %q", in.ID, in.Kind)
		}
		if _, err := time.Parse("2006-01-02", in.Since); err != nil {
			t.Errorf("%s: since %q", in.ID, in.Since)
		}
		if len(in.Sources) == 0 {
			t.Errorf("%s: no sources", in.ID)
		}
		for _, s := range in.Sources {
			if !strings.HasPrefix(s, "https://") {
				t.Errorf("%s: source %q", in.ID, s)
			}
		}
		for _, e := range in.Entries {
			if e.Name == "" || (e.SPKISHA256 == "" && len(e.CertSHA256) == 0) {
				t.Errorf("%s: entry %+v", in.ID, e)
			}
			vals := append([]string{}, e.CertSHA256...)
			if e.SPKISHA256 != "" {
				vals = append(vals, e.SPKISHA256)
			}
			for _, v := range vals {
				if !isHex64(v) {
					t.Errorf("%s/%s: %q is not a lower-case SHA-256", in.ID, e.Name, v)
				}
				if prev, dup := seen[v]; dup {
					t.Errorf("%s listed twice (%s, %s)", v, prev, e.Name)
				}
				seen[v] = e.Name
			}
		}
	}
	if Distrust().Len() != len(seen) {
		t.Errorf("loaded %d values, file has %d", Distrust().Len(), len(seen))
	}
}

// TestEmudhraKeysAreSmallScalars checks the eMudhra entries cryptographically,
// not by copying: each listed key must be d·G on P-384 for the private value
// published for that CA, and every published value must be listed.
func TestEmudhraKeysAreSmallScalars(t *testing.T) {
	want := map[string]int64{
		"EM DV TLS CA - G3B": 156, "EM OV TLS CA - G3B": 155, "EM EV TLS CA - G3B": 115, "EM OV CS CA - G3B": 66,
		"EM DV TLS CA - G3C": 230, "EM OV TLS CA - G3C": 4, "EM EV TLS CA - G3C": 56, "EM OV CS CA - G3C": 237,
	}
	found := 0
	for _, in := range DistrustData().Incidents {
		if in.ID != "emudhra-2026-10" {
			continue
		}
		for _, e := range in.Entries {
			d, ok := want[e.Name]
			if !ok {
				t.Errorf("unexpected entry %q", e.Name)
				continue
			}
			b := make([]byte, 48)
			big.NewInt(d).FillBytes(b)
			k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), b)
			if err != nil {
				t.Fatal(err)
			}
			spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(spki)
			if got := hex.EncodeToString(sum[:]); got != e.SPKISHA256 {
				t.Errorf("%s: d=%d gives SPKI %s, list says %s", e.Name, d, got, e.SPKISHA256)
			}
			if len(e.CertSHA256) != 2 {
				t.Errorf("%s: want the eMudhra certificate and the Sectigo cross-sign, have %d", e.Name, len(e.CertSHA256))
			}
			found++
		}
	}
	if found != len(want) {
		t.Errorf("%d eMudhra entries, want %d", found, len(want))
	}
}
