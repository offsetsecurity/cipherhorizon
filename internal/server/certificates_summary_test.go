package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/example/cipherhorizon/internal/cbom"
	"github.com/example/cipherhorizon/internal/discover"
	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/schematest"
	"github.com/example/cipherhorizon/internal/sense"
)

type pkiCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// pki makes a certificate signed by parent (or self-signed when parent is nil).
func pki(t *testing.T, cn string, ca bool, notAfter time.Time, parent *pkiCert) pkiCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().AddDate(-1, 0, 0), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: ca,
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pkiCert{cert: c, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func hostDoc(t *testing.T, name string, files map[string][]byte) []byte {
	t.Helper()
	m := fstest.MapFS{}
	for p, b := range files {
		m[p] = &fstest.MapFile{Data: b}
	}
	res, err := discover.Run(context.Background(), sense.Default, discover.Options{FS: m, OS: "linux", Tier: "user", HostName: name})
	if err != nil {
		t.Fatal(err)
	}
	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{})
	if err != nil {
		t.Fatal(err)
	}
	bom, _ := cbom.Build(assets, cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon-collector", Version: "test"}, HostName: name, MetadataProperties: props})
	pqc.Annotate(bom, pqc.Analyze(bom))
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	schematest.Validate(t, buf.Bytes())
	return buf.Bytes()
}

// REQ-CERT-5 / REQ-CERT-7: end-entity certificates are itemised with their findings; roots
// and intermediates are summarised, not listed; a change to a host's set of roots is reported.
func TestEndEntityCertificatesAreListedAndAnchorsAreSummarised(t *testing.T) {
	e := newEnv(t)
	soon := time.Now().Add(5 * 24 * time.Hour)
	longLived := time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)

	root1 := pki(t, "Root One", true, longLived, nil)
	root2 := pki(t, "Root Two", true, time.Now().Add(-48*time.Hour), nil) // already expired
	root3 := pki(t, "Root Three", true, longLived, nil)
	inter := pki(t, "Intermediate", true, time.Now().Add(400*24*time.Hour), &root1)
	leafSoon := pki(t, "soon.example.test", false, soon, &inter)
	leafFine := pki(t, "fine.example.test", false, time.Now().Add(300*24*time.Hour), &inter)

	first := hostDoc(t, "web-01", map[string][]byte{
		"etc/ssl/certs/root1.crt": root1.pem, "etc/ssl/certs/root2.crt": root2.pem, "etc/ssl/certs/inter.crt": inter.pem,
		"etc/nginx/ssl/soon.crt": leafSoon.pem, "etc/nginx/ssl/fine.crt": leafFine.pem,
	})
	if s, b, _ := e.req("POST", "/api/v1/hosts/ingest", string(first), nil); s != 201 {
		t.Fatalf("first upload: %d %s", s, b)
	}
	// Second upload: Root Two is gone, Root Three has appeared.
	second := hostDoc(t, "web-01", map[string][]byte{
		"etc/ssl/certs/root1.crt": root1.pem, "etc/ssl/certs/root3.crt": root3.pem, "etc/ssl/certs/inter.crt": inter.pem,
		"etc/nginx/ssl/soon.crt": leafSoon.pem, "etc/nginx/ssl/fine.crt": leafFine.pem,
	})
	if s, b, _ := e.req("POST", "/api/v1/hosts/ingest", string(second), nil); s != 200 {
		t.Fatalf("second upload: %d %s", s, b)
	}

	var list struct {
		Certificates []struct {
			Subject  string `json:"subject"`
			Role     string `json:"role"`
			DaysLeft *int   `json:"daysLeft"`
			Current  bool   `json:"current"`
			Findings []struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			} `json:"findings"`
		} `json:"certificates"`
		TrustAnchors map[string]struct {
			Count          int `json:"count"`
			Current        int `json:"current"`
			Expired        int `json:"expired"`
			Expiring90Days int `json:"expiring90Days"`
			OutlivesPQC    int `json:"outlivesPqcDeprecation"`
		} `json:"trustAnchors"`
		RootSetChanges []struct {
			AssetName  string   `json:"assetName"`
			AddedNames []string `json:"addedNames"`
			Removed    []string `json:"removedNames"`
		} `json:"rootSetChanges"`
	}
	if s := e.call("GET", "/api/v1/certificates", nil, &list); s != 200 {
		t.Fatalf("list: %d", s)
	}
	// Only the two end-entity certificates are itemised.
	if len(list.Certificates) != 2 {
		t.Fatalf("%d certificates listed, want the 2 end-entity ones: %+v", len(list.Certificates), list.Certificates)
	}
	for _, c := range list.Certificates {
		if c.Role != "end-entity" {
			t.Errorf("%s listed with role %s", c.Subject, c.Role)
		}
	}
	// The one expiring in five days is ranked first and carries the cited finding.
	first0 := list.Certificates[0]
	if !strings.Contains(first0.Subject, "soon.example.test") || len(first0.Findings) == 0 || first0.Findings[0].ID != "CERT.EXPIRING" || first0.Findings[0].Severity != "high" {
		t.Errorf("first certificate = %+v", first0)
	}
	if len(list.Certificates[1].Findings) != 0 {
		t.Errorf("a healthy certificate has findings: %+v", list.Certificates[1].Findings)
	}
	// Roots: Root One, Root Two (expired) and Root Three in total; two are still current. One intermediate.
	roots, inters := list.TrustAnchors["root"], list.TrustAnchors["intermediate"]
	if roots.Count != 3 || roots.Current != 2 || roots.Expired != 1 || roots.OutlivesPQC != 2 || inters.Count != 1 {
		t.Errorf("trust anchors: roots %+v intermediates %+v", roots, inters)
	}
	// The change to the set of roots is reported by name.
	if len(list.RootSetChanges) != 1 || list.RootSetChanges[0].AssetName != "web-01" ||
		strings.Join(list.RootSetChanges[0].AddedNames, "|") != "CN=Root Three" || strings.Join(list.RootSetChanges[0].Removed, "|") != "CN=Root Two" {
		t.Errorf("root set changes = %+v", list.RootSetChanges)
	}

	// include=all lists the CA certificates too, and marks the removed root as no longer current.
	var all struct {
		Certificates []struct {
			Subject string `json:"subject"`
			Role    string `json:"role"`
			Current bool   `json:"current"`
		} `json:"certificates"`
	}
	e.call("GET", "/api/v1/certificates?include=all", nil, &all)
	if len(all.Certificates) != 6 {
		t.Errorf("include=all lists %d certificates, want 6", len(all.Certificates))
	}
	for _, c := range all.Certificates {
		if strings.Contains(c.Subject, "Root Two") && c.Current {
			t.Error("a root no longer present is still marked current")
		}
	}
}

func TestCertificateDetailRefusesBadFingerprints(t *testing.T) {
	e := newEnv(t)
	for _, fp := range []string{"nothex", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65), "..%2F..%2Fetc"} {
		if s, _ := e.do("GET", "/api/v1/certificates/"+fp, nil); s != http.StatusBadRequest && s != http.StatusNotFound {
			t.Errorf("fingerprint %q: %d, want 400 or 404", fp, s)
		}
	}
	if s, _ := e.do("GET", "/api/v1/certificates/"+strings.Repeat("a", 64), nil); s != http.StatusNotFound {
		t.Errorf("an unknown certificate: %d, want 404", s)
	}
	if s, _ := e.do("GET", "/api/v1/certificates/"+strings.Repeat("A", 63), nil); s != http.StatusBadRequest {
		t.Errorf("a short fingerprint: %d, want 400", s)
	}
}

// A system's certificates: the same view, scoped to one system.
func TestASystemListsItsOwnCertificates(t *testing.T) {
	e := newEnv(t)
	root := pki(t, "Some Root", true, time.Now().Add(3000*24*time.Hour), nil)
	leaf := pki(t, "leaf.example.test", false, time.Now().Add(200*24*time.Hour), &root)
	other := pki(t, "other.example.test", false, time.Now().Add(200*24*time.Hour), &root)
	var ing struct {
		Asset struct {
			SystemID int64 `json:"systemId"`
		} `json:"asset"`
	}
	e.call("POST", "/api/v1/hosts/ingest", string(hostDoc(t, "web-01", map[string][]byte{"etc/ssl/certs/root.crt": root.pem, "etc/nginx/ssl/leaf.crt": leaf.pem})), &ing)
	e.call("POST", "/api/v1/hosts/ingest", string(hostDoc(t, "db-01", map[string][]byte{"etc/ssl/certs/other.crt": other.pem})), nil)

	var got struct {
		Certificates []struct {
			Subject string `json:"subject"`
		} `json:"certificates"`
		TrustAnchors map[string]struct {
			Count int `json:"count"`
		} `json:"trustAnchors"`
	}
	if s := e.call("GET", "/api/v1/systems/"+itoa(ing.Asset.SystemID)+"/certificates", nil, &got); s != 200 {
		t.Fatalf("status %d", s)
	}
	if len(got.Certificates) != 1 || !strings.Contains(got.Certificates[0].Subject, "leaf.example.test") || got.TrustAnchors["root"].Count != 1 {
		t.Errorf("system certificates = %+v", got)
	}
	if s, _ := e.do("GET", "/api/v1/systems/999999/certificates", nil); s != 404 {
		t.Errorf("unknown system: %d", s)
	}
}
