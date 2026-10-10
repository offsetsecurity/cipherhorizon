package server

import (
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

func certObs(key, alg, bits, ca string) store.ObservationRow {
	return store.ObservationRow{Current: true, Class: "scanner", SourceID: 1, Entity: store.Entity{Kind: "certificate", Key: key, Name: key,
		Attrs: map[string]string{"keyAlg": alg, "keyBits": bits, "isCA": ca}}}
}

// Only end-entity certificates whose key algorithm has a cited quantum-vulnerable verdict are item 4
// rows: a post-quantum key, an algorithm with no verdict, and a CA certificate are not.
func TestItem4ListsOnlyCitedQuantumVulnerableEndEntityKeys(t *testing.T) {
	obs := []store.ObservationRow{
		certObs("cert:a", "RSA", "2048", ""),
		certObs("cert:b", "ML-DSA-65", "", ""),
		certObs("cert:c", "Some-Unknown-Alg", "1", ""),
		certObs("cert:d", "RSA", "4096", "true"),
		certObs("cert:a", "RSA", "2048", ""), // the same certificate seen twice is one row
	}
	doc := buildM2302(store.System{ID: 1, Name: "s"}, obs, nil, time.Unix(0, 0))
	rows := doc.Items[3].Rows
	if len(rows) != 1 || rows[0].Algorithm != "RSA" || rows[0].KeyLength == nil || *rows[0].KeyLength != 2048 {
		t.Fatalf("rows = %+v", rows)
	}
	// A vulnerable key with no recorded size says so instead of guessing.
	doc = buildM2302(store.System{ID: 1, Name: "s"}, []store.ObservationRow{certObs("cert:e", "ECDSA", "", "")}, nil, time.Unix(0, 0))
	if r := doc.Items[3].Rows; len(r) != 1 || r[0].KeyLength != nil || r[0].KeyLengthNote == "" {
		t.Errorf("rows = %+v", r)
	}
}

// Item 6 is the operating system each machine reported, and is not provided when none did.
func TestItem6IsTheOperatingSystemMachinesReported(t *testing.T) {
	sys := store.System{ID: 1, Name: "s"}
	if it := buildM2302(sys, nil, nil, time.Unix(0, 0)).Items[5]; it.Status != "not provided" || it.Reason == "" {
		t.Errorf("no machine: %+v", it)
	}
	if it := buildM2302(sys, nil, []string{"linux 6.1", "windows 10.0.26200"}, time.Unix(0, 0)).Items[5]; it.Status != "provided" || it.Source != "evidence" || it.Value != "linux 6.1; windows 10.0.26200" {
		t.Errorf("two machines: %+v", it)
	}
}
