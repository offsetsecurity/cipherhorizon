package server_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

type x509JSON struct {
	DER    bool   `json:"der"`
	Reason string `json:"reason"`
	X509   *struct {
		SHA256     string `json:"sha256"`
		PEM        string `json:"pem"`
		Extensions []struct {
			Name string `json:"name"`
		} `json:"extensions"`
		PublicKey struct {
			Strength struct {
				Bits int `json:"bits"`
			} `json:"strength"`
		} `json:"publicKey"`
	} `json:"x509"`
	Source *struct {
		ScanID   int64 `json:"scanId"`
		AssetID  int64 `json:"assetId"`
		Position int   `json:"position"`
	} `json:"source"`
}

// PRD-012 REQ-XV-1, REQ-XV-4: a certificate a scan saw decodes from that scan's DER, as served.
func TestX509EndpointDecodesTheServedCertificate(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	sum := sha256.Sum256(ec.Certificate[0])
	fp := hex.EncodeToString(sum[:])
	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)
	sc := e.scanAndWait(a.ID)
	if sc.Status != "done" {
		t.Fatalf("scan: %+v", sc)
	}
	for _, path := range []string{"/api/v1/certificates/" + fp + "/x509", fmt.Sprintf("/api/v1/certificates/%s/x509?scan=%d", strings.ToUpper(fp), sc.ID)} {
		var out x509JSON
		if s := e.call("GET", path, nil, &out); s != 200 {
			t.Fatalf("%s: %d", path, s)
		}
		if !out.DER || out.X509 == nil || out.X509.SHA256 != fp || out.Source == nil || out.Source.ScanID != sc.ID || out.Source.AssetID != a.ID || out.Source.Position != 0 {
			t.Fatalf("%s: %+v", path, out)
		}
		if len(out.X509.Extensions) == 0 || out.X509.PublicKey.Strength.Bits == 0 {
			t.Errorf("%s: no extensions or no key strength: %+v", path, out.X509)
		}
		b, _ := pem.Decode([]byte(out.X509.PEM))
		if b == nil {
			t.Fatalf("%s: no PEM", path)
		}
		if c, err := x509.ParseCertificate(b.Bytes); err != nil || sha256.Sum256(c.Raw) != sum {
			t.Errorf("%s: the PEM is not the certificate (%v)", path, err)
		}
	}
	for path, want := range map[string]int{
		"/api/v1/certificates/" + fp + "/x509?scan=abc":             400,
		"/api/v1/certificates/" + fp[:10] + "/x509":                 400,
		"/api/v1/certificates/" + strings.Repeat("0", 64) + "/x509": 404,
	} {
		if s, _ := e.do("GET", path, nil); s != want {
			t.Errorf("%s answered %d, want %d", path, s, want)
		}
	}
}

// PRD-012 REQ-XV-3: a certificate known only from a source that kept no DER says so.
func TestX509WithoutDERSaysSo(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	leaf, err := x509.ParseCertificate(ec.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := hostCBOMWithCertificates(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	if s := e.call("POST", "/api/v1/hosts/ingest", string(doc), nil); s != 201 {
		t.Fatalf("ingest: %d", s)
	}
	sum := sha256.Sum256(leaf.Raw)
	var out x509JSON
	if s := e.call("GET", "/api/v1/certificates/"+hex.EncodeToString(sum[:])+"/x509", nil, &out); s != 200 {
		t.Fatalf("x509: %d", s)
	}
	if out.DER || out.X509 != nil || !strings.Contains(out.Reason, "raw bytes") {
		t.Errorf("a certificate with no DER: %+v", out)
	}
}
