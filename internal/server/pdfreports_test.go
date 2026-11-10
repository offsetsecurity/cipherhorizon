package server_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/pdf/pdfcheck"
)

// TestDownloadsAreGeneratedPDFs: the report and inventory downloads are PDF documents the server
// makes from the stored scan and the merged inventory, not a print of the page.
func TestDownloadsAreGeneratedPDFs(t *testing.T) {
	e := newEnv(t)
	hy := e.addAsset(hybridServer(t).Addr)
	cl := e.addAsset(classicalServer(t).Addr)
	var scanID int64
	for _, a := range []assetJSON{hy, cl} {
		sc := e.scanAndWait(a.ID)
		if sc.Status != "done" {
			t.Fatalf("scan %+v", sc)
		}
		if a.ID == cl.ID {
			scanID = sc.ID
		}
	}

	for kind, want := range map[string][]string{
		"full": {"TLS SECURITY REPORT", "Fix first", "Key exchange & post-quantum", "Certificates & trust", "About this report"},
		"tls":  {"TLS CONFIGURATION REPORT", "Cipher suites", "Key-exchange groups accepted"},
		"cert": {"CERTIFICATE REPORT", "Every certificate, field by field", "SHA-256"},
	} {
		status, body, hdr := e.req("GET", fmt.Sprintf("/api/v1/scans/%d/report.pdf?kind=%s", scanID, kind), nil, nil)
		if status != 200 || hdr.Get("Content-Type") != "application/pdf" || !strings.Contains(hdr.Get("Content-Disposition"), ".pdf") {
			t.Fatalf("%s: %d %q %q", kind, status, hdr.Get("Content-Type"), hdr.Get("Content-Disposition"))
		}
		info, err := pdfcheck.Check(body)
		if err != nil {
			t.Fatalf("%s: not a well-formed PDF: %v", kind, err)
		}
		for _, w := range want {
			if !strings.Contains(info.Text, w) {
				t.Errorf("%s report lacks %q", kind, w)
			}
		}
	}
	if s, _ := e.do("GET", fmt.Sprintf("/api/v1/scans/%d/report.pdf?kind=print", scanID), nil); s != 400 {
		t.Errorf("an unknown kind is refused: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/scans/999999/report.pdf", nil); s != 404 {
		t.Errorf("an unknown scan is 404: %d", s)
	}

	var d struct {
		Totals       map[string]int `json:"totals"`
		Quantum      map[string]int `json:"quantum"`
		ReplaceFirst []struct {
			Name     string `json:"name"`
			Kind     string `json:"kind"`
			Places   int    `json:"places"`
			Fallback int    `json:"fallback"`
		} `json:"replaceFirst"`
		Protocols []struct {
			Name   string `json:"name"`
			Places int    `json:"places"`
		} `json:"protocols"`
		ByPurpose []struct {
			Purpose string `json:"purpose"`
		} `json:"byPurpose"`
		Sources []struct {
			Kind  string `json:"kind"`
			Items int    `json:"items"`
		} `json:"sources"`
	}
	if s := e.call("GET", "/api/v1/inventory/dashboard", nil, &d); s != 200 {
		t.Fatalf("dashboard: %d", s)
	}
	if d.Totals["endpoints"] != 2 || d.Quantum["vulnerable"] == 0 || d.Quantum["safe"] == 0 || len(d.ReplaceFirst) == 0 || len(d.ByPurpose) == 0 {
		t.Errorf("dashboard figures: %+v", d)
	}
	for i := 1; i < len(d.ReplaceFirst); i++ {
		if d.ReplaceFirst[i].Places > d.ReplaceFirst[i-1].Places {
			t.Errorf("replace first is ordered by how widely used: %+v", d.ReplaceFirst)
		}
	}
	// Replace first names algorithms only (a key is named by its certificate), and an endpoint that
	// also accepts a hybrid group does not count against the classical group it keeps as a fallback.
	sawX25519 := false
	for _, r := range d.ReplaceFirst {
		if r.Kind != "algorithm" {
			t.Errorf("replace first lists algorithms only: %+v", r)
		}
		if r.Name == "X25519" {
			sawX25519 = true
			if r.Places != 1 || r.Fallback != 1 {
				t.Errorf("X25519 counts the classical-only endpoint, and is a fallback on the hybrid one: %+v", r)
			}
		}
	}
	if !sawX25519 {
		t.Errorf("X25519 is still to replace where nothing quantum-safe is accepted: %+v", d.ReplaceFirst)
	}
	if len(d.Sources) != 2 || d.Sources[0].Kind != "endpoint" || d.Sources[0].Items == 0 {
		t.Errorf("sources: %+v", d.Sources)
	}
	// The dashboard agrees with the lists it summarises.
	if algs := e.inventoryRows("kind=algorithm&imported=1"); len(algs) != d.Totals["algorithm"] {
		t.Errorf("dashboard says %d algorithms, the list has %d", d.Totals["algorithm"], len(algs))
	}

	status, body, hdr := e.req("GET", "/api/v1/inventory/report.pdf", nil, nil)
	if status != 200 || hdr.Get("Content-Type") != "application/pdf" {
		t.Fatalf("inventory report: %d %q", status, hdr.Get("Content-Type"))
	}
	info, err := pdfcheck.Check(body)
	if err != nil {
		t.Fatalf("inventory report: %v", err)
	}
	for _, w := range []string{"Cryptographic inventory", "Post-quantum status", "Replace first", "X25519MLKEM768", "Sources"} {
		if !strings.Contains(info.Text, w) {
			t.Errorf("inventory report lacks %q", w)
		}
	}
}
