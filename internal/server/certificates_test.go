package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/discover"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/sense"
	_ "github.com/offsetsecurity/cipherhorizon/internal/sense/all"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// hostCBOMWithCertificates runs the real collector pipeline over a Linux-shaped filesystem
// and returns the CBOM it would upload, plus the canary key text planted beside it.
func hostCBOMWithCertificates(t *testing.T, certPEM []byte) (doc []byte, canary string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	canary = base64.StdEncoding.EncodeToString(keyDER)

	var fsys fs.FS = fstest.MapFS{
		"etc/nginx/ssl/site.crt":     {Data: certPEM},
		"etc/nginx/ssl/site.key":     {Data: keyPEM},
		"etc/ssl/certs/combined.pem": {Data: append(append([]byte{}, certPEM...), keyPEM...)},
		"etc/hostname":               {Data: []byte("web-01\n")},
	}
	res, err := discover.Run(context.Background(), sense.Default, discover.Options{FS: fsys, OS: "linux", Tier: "user", HostName: "web-01"})
	if err != nil {
		t.Fatal(err)
	}
	assets, props, err := cbom.FromHostGraph(res.Graph, cbom.HostOptions{PrivilegeNote: res.PrivilegeNote})
	if err != nil {
		t.Fatal(err)
	}
	bom, warnings := cbom.Build(assets, cbom.Options{Tool: cbom.Tool{Name: "cipherhorizon-collector", Version: "test"}, HostName: "web-01", MetadataProperties: props})
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	pqc.Annotate(bom, pqc.Analyze(bom))
	var buf bytes.Buffer
	if err := cbom.Encode(&buf, bom, true); err != nil {
		t.Fatal(err)
	}
	schematest.Validate(t, buf.Bytes()) // the document is valid CycloneDX 1.6
	return buf.Bytes(), canary
}

type certListJSON struct {
	Certificates []struct {
		Fingerprint string `json:"fingerprint"`
		Role        string `json:"role"`
		Subject     string `json:"subject"`
		KeyAlg      string `json:"keyAlgorithm"`
		KeyBits     *int   `json:"keyBits"`
		Curve       string `json:"curve"`
		Current     bool   `json:"current"`
		Places      int    `json:"places"`
		Systems     int    `json:"systems"`
		Findings    []struct {
			ID string `json:"id"`
		} `json:"findings"`
	} `json:"certificates"`
	TrustAnchors map[string]struct {
		Count int `json:"count"`
	} `json:"trustAnchors"`
}

// REQ-CERT-3, -4, -6, -8 end to end: a certificate a scan sees on the wire and the same
// certificate a host holds are one entity with two places; its key size and curve are
// there; a private key planted beside it appears nowhere the API can show.
func TestOneCertificateSeenByAScanAndByAHostIsOneEntity(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	leaf, err := x509.ParseCertificate(ec.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	// The network stream: scan a server that presents that certificate.
	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)
	sc := e.startScan(a.ID)
	if done := e.wait(sc.ID); done.Status != "done" {
		t.Fatalf("scan: %+v", done)
	}

	// The host stream: upload what the collector found on a machine that holds the same certificate.
	doc, canary := hostCBOMWithCertificates(t, certPEM)
	var ing struct {
		SourceClass string `json:"sourceClass"`
		SnapshotID  int64  `json:"snapshotId"`
		Asset       struct {
			ID       int64 `json:"id"`
			SystemID int64 `json:"systemId"`
		} `json:"asset"`
	}
	if s := e.call("POST", "/api/v1/hosts/ingest", string(doc), &ing); s != 201 || ing.SourceClass != "collector" {
		t.Fatalf("ingest: %d %+v", s, ing)
	}

	var list certListJSON
	if s := e.call("GET", "/api/v1/certificates", nil, &list); s != 200 {
		t.Fatalf("certificates: %d", s)
	}
	var mine *struct {
		Fingerprint string `json:"fingerprint"`
		Role        string `json:"role"`
		Subject     string `json:"subject"`
		KeyAlg      string `json:"keyAlgorithm"`
		KeyBits     *int   `json:"keyBits"`
		Curve       string `json:"curve"`
		Current     bool   `json:"current"`
		Places      int    `json:"places"`
		Systems     int    `json:"systems"`
		Findings    []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	for i := range list.Certificates {
		if list.Certificates[i].Subject == leaf.Subject.String() {
			mine = &list.Certificates[i]
		}
	}
	if mine == nil {
		t.Fatalf("the certificate is not listed: %+v", list.Certificates)
	}
	if mine.KeyAlg != "ECDSA" || mine.KeyBits == nil || *mine.KeyBits != 256 || mine.Curve != "P-256" {
		t.Errorf("key facts = %s %v %s, want ECDSA 256 P-256", mine.KeyAlg, mine.KeyBits, mine.Curve)
	}
	// Seen by the scan (one place) and by the host in two files (two places): one entity, three places.
	// It is held by exactly one first-party host and presented by exactly one first-party scan, so
	// correlation joined the endpoint to the host: one system, not two (see the correlation tests).
	if mine.Places != 3 || mine.Systems != 1 {
		t.Errorf("places=%d systems=%d, want 3 and 1", mine.Places, mine.Systems)
	}
	if strings.Count(fmt.Sprint(list.Certificates), leaf.Subject.String()) != 1 {
		t.Error("the certificate is listed more than once")
	}

	// The detail names every place, with the stream, the source class and where the host holds it.
	var detail struct {
		Places []struct {
			Stream      string `json:"stream"`
			SourceClass string `json:"sourceClass"`
			Location    string `json:"location"`
			PrivateKey  string `json:"privateKey"`
			Rung        string `json:"rung"`
		} `json:"places"`
	}
	if s := e.call("GET", "/api/v1/certificates/"+mine.Fingerprint, nil, &detail); s != 200 {
		t.Fatalf("detail: %d", s)
	}
	streams := map[string]int{}
	keys := map[string]string{}
	for _, p := range detail.Places {
		streams[p.Stream+"/"+p.SourceClass+"/"+p.Rung]++
		if p.Location != "" {
			keys[p.Location] = p.PrivateKey
		}
	}
	if streams["network/scanner/exercised"] != 1 || streams["host/collector/provisioned"] != 2 {
		t.Errorf("places by stream/class/rung = %v", streams)
	}
	// site.crt is a bare certificate (unknown); combined.pem holds a key beside it (yes).
	if keys["/etc/nginx/ssl/site.crt"] != "unknown" || keys["/etc/ssl/certs/combined.pem"] != "yes" {
		t.Errorf("private-key flags by location = %v", keys)
	}

	// SR-06/SR-17: the canary key appears in nothing the API returns.
	for _, path := range []string{
		"/api/v1/certificates", "/api/v1/certificates?include=all", "/api/v1/certificates/" + mine.Fingerprint,
		"/api/v1/systems", "/api/v1/systems/" + itoa(ing.Asset.SystemID) + "/observations", "/api/v1/systems/" + itoa(ing.Asset.SystemID) + "/certificates",
		"/api/v1/entities", "/api/v1/entities?kind=certificate", "/api/v1/hosts", "/api/v1/hosts/" + itoa(ing.Asset.ID),
		"/api/v1/hosts/" + itoa(ing.Asset.ID) + "/snapshots/" + itoa(ing.SnapshotID) + "/cbom",
		"/api/v1/systems/" + itoa(ing.Asset.SystemID) + "/m2302.json", "/api/v1/systems/" + itoa(ing.Asset.SystemID) + "/m2302.csv",
		"/api/v1/systems/export.csv", "/api/v1/estate", "/api/v1/links?state=all", "/api/v1/graph/stats", "/api/v1/openapi.json",
	} {
		_, body, _ := e.req("GET", path, nil, nil)
		if strings.Contains(string(body), canary) || strings.Contains(string(body), canary[10:40]) || strings.Contains(string(body), "PRIVATE KEY") {
			t.Errorf("GET %s leaked key material", path)
		}
	}
	if bytes.Contains(doc, []byte(canary)) || bytes.Contains(doc, []byte(canary[10:40])) {
		t.Error("the uploaded CBOM itself contains the planted key")
	}
	// M4: nor does the database file (and its write-ahead log) that holds everything the server stored.
	for _, suffix := range []string{"", "-wal"} {
		raw, err := os.ReadFile(e.dbPath + suffix)
		if err != nil {
			continue
		}
		if bytes.Contains(raw, []byte(canary)) || bytes.Contains(raw, []byte(canary[10:40])) || bytes.Contains(raw, []byte("BEGIN PRIVATE KEY")) {
			t.Errorf("the database file%s contains key material", suffix)
		}
	}

	// The host CBOM states key size in the standard's place (a public-key component with a size).
	if !bytes.Contains(doc, []byte(`"size": 256`)) && !bytes.Contains(doc, []byte(`"size":256`)) {
		t.Error("the CBOM carries no key size for the certificate")
	}
}
