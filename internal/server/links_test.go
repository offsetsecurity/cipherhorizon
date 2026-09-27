package server_test

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/example/cipherhorizon/internal/tlsprobe/testserver"
)

type linkJSON struct {
	ID         int64  `json:"id"`
	AssetID    int64  `json:"assetId"`
	AssetName  string `json:"assetName"`
	SystemID   int64  `json:"systemId"`
	SystemName string `json:"systemName"`
	State      string `json:"state"`
	Strength   string `json:"strength"`
	Ambiguous  bool   `json:"ambiguous"`
	Note       string `json:"note"`
	Stale      bool   `json:"stale"`
	DecidedBy  string `json:"decidedBy"`
	Rules      []struct {
		ID     string `json:"id"`
		Detail string `json:"detail"`
	} `json:"rules"`
	Competes int `json:"competingProposals"`
}

func links(e *env, state string) []linkJSON {
	e.t.Helper()
	var out []linkJSON
	if s := e.call("GET", "/api/v1/links?state="+state, nil, &out); s != 200 {
		e.t.Fatalf("links: %d", s)
	}
	return out
}

// corr is a scanned endpoint (presenting the test server's certificate) and helpers to make hosts
// that hold that same certificate, so correlation has something real to join.
type corr struct {
	e        *env
	endpoint assetJSON
	certPEM  []byte
}

func newCorr(t *testing.T) *corr {
	t.Helper()
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	leaf, err := x509.ParseCertificate(ec.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)
	e.wait(e.startScan(a.ID).ID)
	return &corr{e: e, endpoint: a, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}
}

// uploadHost uploads a collector-made document for a host; withCert says whether it holds the endpoint's certificate.
func (c *corr) uploadHost(name string, withCert bool) int64 {
	c.e.t.Helper()
	files := map[string][]byte{"etc/hostname": []byte(name)}
	if withCert {
		files["etc/nginx/ssl/site.crt"] = c.certPEM
	}
	var ing struct {
		Asset struct {
			ID       int64 `json:"id"`
			SystemID int64 `json:"systemId"`
		} `json:"asset"`
	}
	if s := c.e.call("POST", "/api/v1/hosts/ingest?name="+name, string(hostDoc(c.e.t, name, files)), &ing); s != 200 && s != 201 {
		c.e.t.Fatalf("upload %s: %d", name, s)
	}
	return ing.Asset.ID
}

func (c *corr) endpointSystem() int64 {
	var a struct {
		SystemID int64 `json:"systemId"`
	}
	c.e.call("GET", "/api/v1/assets/"+itoa(c.endpoint.ID), nil, &a)
	return a.SystemID
}

// AC-COR-1: a unique first-party match joins on its own, with the values that matched on the record.
func TestAUniqueFirstPartyMatchAutoConfirmsWithItsExplanation(t *testing.T) {
	c := newCorr(t)
	host := c.uploadHost("web-01", true)
	got := links(c.e, "confirmed")
	if len(got) != 1 || got[0].AssetID != c.endpoint.ID || got[0].Strength != "strong" || got[0].DecidedBy != "auto" || got[0].Ambiguous || got[0].Stale {
		t.Fatalf("confirmed links = %+v", got)
	}
	l := got[0]
	if len(l.Rules) != 1 || l.Rules[0].ID != "J1-certificate-fingerprint" || !strings.Contains(l.Rules[0].Detail, "web-01") || !strings.Contains(l.Rules[0].Detail, "/etc/nginx/ssl/site.crt") {
		t.Errorf("the explanation does not say what matched: %+v", l.Rules)
	}
	// The join is real: the endpoint and the host are one system.
	var hostAsset struct {
		SystemID int64 `json:"systemId"`
	}
	c.e.call("GET", "/api/v1/assets/"+itoa(host), nil, &hostAsset)
	if c.endpointSystem() != hostAsset.SystemID || len(c.e.systems()) != 1 {
		t.Errorf("endpoint system %d, host system %d, %d systems", c.endpointSystem(), hostAsset.SystemID, len(c.e.systems()))
	}
	// And the merge is on the audit trail with the reason.
	var log []struct {
		Action, Actor, Reason string
	}
	c.e.call("GET", "/api/v1/systems/"+itoa(hostAsset.SystemID)+"/audit", nil, &log)
	seen := map[string]bool{}
	for _, x := range log {
		seen[x.Action] = true
	}
	if !seen["merge"] || !seen["link-confirm"] {
		t.Errorf("audit = %+v", log)
	}
}

// REQ-COR-3, -5, -7: the same certificate on two hosts is ambiguous and joins neither; a person
// confirms one; the other stays a proposal until rejected; a rejection is never proposed again.
func TestAmbiguousMatchesAreProposedAndNeverAutomatic(t *testing.T) {
	e := newEnv(t)
	ec, _ := testserver.Certificates(t)
	leaf, _ := x509.ParseCertificate(ec.Certificate[0])
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	// Two hosts hold the certificate BEFORE the endpoint is scanned: the evidence is ambiguous from the start.
	for _, name := range []string{"web-01", "web-02"} {
		e.call("POST", "/api/v1/hosts/ingest?name="+name, string(hostDoc(t, name, map[string][]byte{"etc/nginx/ssl/site.crt": certPEM})), nil)
	}
	srv := hybridServer(t)
	a := e.addAsset(srv.Addr)
	e.wait(e.startScan(a.ID).ID)

	if got := links(e, "confirmed"); len(got) != 0 {
		t.Fatalf("an ambiguous match joined on its own: %+v", got)
	}
	proposed := links(e, "proposed")
	if len(proposed) != 2 {
		t.Fatalf("%d proposals, want one per holder: %+v", len(proposed), proposed)
	}
	for _, l := range proposed {
		if !l.Ambiguous || l.Strength != "medium" || !strings.Contains(l.Note, "2 systems") || l.Competes != 1 {
			t.Errorf("proposal = %+v", l)
		}
	}
	if len(e.systems()) != 3 {
		t.Errorf("%d systems, want the endpoint and two hosts kept apart", len(e.systems()))
	}

	// A person confirms one: the endpoint joins that host.
	var confirmed linkJSON
	if s := e.call("POST", "/api/v1/links/"+itoa(proposed[0].ID)+"/confirm?reason=verified+with+ops", nil, &confirmed); s != 200 || confirmed.State != "confirmed" || confirmed.DecidedBy != "local" {
		t.Fatalf("confirm: %d %+v", s, confirmed)
	}
	if len(e.systems()) != 2 {
		t.Errorf("%d systems after confirming, want 2", len(e.systems()))
	}
	// Reject the other proposal: it is never proposed again, even after a rescan.
	others := links(e, "proposed")
	var other linkJSON
	for _, l := range others {
		if l.ID != proposed[0].ID {
			other = l
		}
	}
	if other.ID == 0 {
		t.Fatalf("the second proposal disappeared: %+v", others)
	}
	if s := e.call("POST", "/api/v1/links/"+itoa(other.ID)+"/reject?reason=different+machine", nil, &other); s != 200 || other.State != "rejected" {
		t.Fatalf("reject: %d %+v", s, other)
	}
	e.wait(e.startScan(a.ID).ID)
	e.call("POST", "/api/v1/hosts/ingest?name=web-02", string(hostDoc(t, "web-02", map[string][]byte{"etc/nginx/ssl/site.crt": certPEM})), nil)
	if got := links(e, "proposed"); len(got) != 0 {
		t.Errorf("a rejected link came back: %+v", got)
	}
	rej := links(e, "rejected")
	if len(rej) != 1 || rej[0].ID != other.ID {
		t.Errorf("rejected = %+v", rej)
	}
	// Deciding an unknown or already-decided link is handled.
	if s, _ := e.do("POST", "/api/v1/links/999999/confirm", nil); s != 404 {
		t.Errorf("unknown link: %d", s)
	}
}

// REQ-COR-5: a confirmed join whose evidence has gone is flagged for review, not silently removed.
func TestAConfirmedLinkThatLosesItsEvidenceIsFlaggedNotRemoved(t *testing.T) {
	c := newCorr(t)
	c.uploadHost("web-01", true)
	if got := links(c.e, "confirmed"); len(got) != 1 || got[0].Stale {
		t.Fatalf("setup: %+v", got)
	}
	c.uploadHost("web-01", false) // the certificate is gone from the host
	got := links(c.e, "confirmed")
	if len(got) != 1 || !got[0].Stale {
		t.Errorf("confirmed links = %+v, want the one, flagged stale", got)
	}
	if len(c.e.systems()) != 1 {
		t.Error("the systems were split by the loss of evidence: a confirmed join is a person's or the product's decision, to be reviewed, not undone")
	}
	// The certificate comes back: no longer stale.
	c.uploadHost("web-01", true)
	if got := links(c.e, "confirmed"); len(got) != 1 || got[0].Stale {
		t.Errorf("after the evidence returned: %+v", got)
	}
}

// DN-1, REQ-COR-7: a join that would overwrite different operator-set values is not made
// automatically; the proposal says why, and confirming it is refused with the fields named.
func TestAJoinThatWouldOverwriteOperatorValuesIsBlockedAndExplained(t *testing.T) {
	c := newCorr(t)
	hostID := c.uploadHost("web-01", false) // the host exists first, without the certificate
	var hostAsset struct {
		SystemID int64 `json:"systemId"`
	}
	c.e.call("GET", "/api/v1/assets/"+itoa(hostID), nil, &hostAsset)
	c.e.call("PATCH", "/api/v1/systems/"+itoa(hostAsset.SystemID), map[string]any{"owner": "web team"}, nil)
	c.e.call("PATCH", "/api/v1/systems/"+itoa(c.endpointSystem()), map[string]any{"owner": "shop team"}, nil)

	c.uploadHost("web-01", true) // now the certificate appears: a strong, unambiguous, first-party match
	if got := links(c.e, "confirmed"); len(got) != 0 {
		t.Fatalf("a conflicting join was made: %+v", got)
	}
	prop := links(c.e, "proposed")
	if len(prop) != 1 || prop[0].Strength != "strong" || !strings.Contains(prop[0].Note, "owner") {
		t.Fatalf("proposals = %+v", prop)
	}
	var conflict struct {
		Error  string   `json:"error"`
		Fields []string `json:"fields"`
	}
	if s := c.e.call("POST", "/api/v1/links/"+itoa(prop[0].ID)+"/confirm", nil, &conflict); s != 409 || len(conflict.Fields) != 1 || conflict.Fields[0] != "owner" {
		t.Fatalf("confirm: %d %+v", s, conflict)
	}
	// The person resolves the disagreement, and the confirmation goes through.
	c.e.call("PATCH", "/api/v1/systems/"+itoa(c.endpointSystem()), map[string]any{"owner": "web team"}, nil)
	var ok linkJSON
	if s := c.e.call("POST", "/api/v1/links/"+itoa(prop[0].ID)+"/confirm", nil, &ok); s != 200 || ok.State != "confirmed" {
		t.Errorf("confirm after resolving: %d %+v", s, ok)
	}
}

// SR-05 / T-05: a forged import carrying the real certificate's fingerprint gets a proposal of its
// own and changes nothing about the real join.
func TestAForgedImportGetsAProposalAndTheRealJoinStands(t *testing.T) {
	c := newCorr(t)
	c.uploadHost("web-01", true)
	sum := c.fingerprint(t)
	doc := strings.ReplaceAll(interop(t, "cbomlens-like-1.7.json"), strings.Repeat("ab", 32), sum)
	if s, _, raw := upload(c.e, doc, "newSystem=forger"); s != 201 {
		t.Fatalf("%d %s", s, raw)
	}
	confirmed := links(c.e, "confirmed")
	if len(confirmed) != 1 || confirmed[0].DecidedBy != "auto" {
		t.Errorf("confirmed = %+v: the forgery disturbed the real join", confirmed)
	}
	prop := links(c.e, "proposed")
	if len(prop) != 1 || prop[0].SystemName != "forger" || prop[0].Strength != "strong" {
		t.Fatalf("proposed = %+v", prop)
	}
	// Confirming the forged proposal is a person's act, and it is an act on the record.
	if s := c.e.call("POST", "/api/v1/links/"+itoa(prop[0].ID)+"/reject", nil, nil); s != 200 {
		t.Errorf("reject: %d", s)
	}
}

func (c *corr) fingerprint(t *testing.T) string {
	t.Helper()
	var list certListJSON
	c.e.call("GET", "/api/v1/certificates", nil, &list)
	for _, x := range list.Certificates {
		return x.Fingerprint
	}
	t.Fatal("no certificate")
	return ""
}

// The manual link of 0.1.0 is a confirmed link with source operator; removing it is a rejection
// that correlation respects.
func TestManualLinksAreConfirmedLinksAndUnlinkingIsARejection(t *testing.T) {
	e := newEnv(t)
	ep := e.addAsset("shop.example.test:443")
	var host struct {
		Asset struct {
			ID int64 `json:"id"`
		} `json:"asset"`
	}
	e.call("POST", "/api/v1/hosts/ingest", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"device","name":"web-01"}}}`, &host)
	if s, _ := e.do("PUT", "/api/v1/assets/"+itoa(ep.ID)+"/links/"+itoa(host.Asset.ID), nil); s != 200 && s != 204 {
		t.Fatalf("link: %d", s)
	}
	got := links(e, "confirmed")
	if len(got) != 1 || len(got[0].Rules) != 1 || got[0].Rules[0].ID != "manual" || got[0].AssetID != ep.ID || got[0].DecidedBy != "local" {
		t.Fatalf("confirmed = %+v", got)
	}
	if s, _ := e.do("DELETE", "/api/v1/assets/"+itoa(ep.ID)+"/links/"+itoa(host.Asset.ID), nil); s != 200 && s != 204 {
		t.Fatalf("unlink: %d", s)
	}
	rej := links(e, "rejected")
	if len(rej) == 0 {
		t.Errorf("unlinking left no rejection: %+v", links(e, "all"))
	}
	if got := links(e, "proposed"); len(got) != 0 {
		t.Errorf("a removed link was proposed again: %+v", got)
	}
}

func TestLinkRoutesValidateInput(t *testing.T) {
	e := newEnv(t)
	if s, _ := e.do("GET", "/api/v1/links?state=bogus", nil); s != 400 {
		t.Errorf("bad state: %d", s)
	}
	for _, st := range []string{"", "proposed", "confirmed", "rejected", "all"} {
		if s, _ := e.do("GET", "/api/v1/links?state="+st, nil); s != 200 {
			t.Errorf("state %q: %d", st, s)
		}
	}
	if s, _ := e.do("POST", "/api/v1/links/abc/confirm", nil); s != 400 {
		t.Errorf("bad id: %d", s)
	}
	if s, _ := e.do("POST", "/api/v1/links/1/confirm?reason="+strings.Repeat("r", 201), nil); s != 400 {
		t.Errorf("long reason: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/systems/999999/links", nil); s != 404 {
		t.Errorf("unknown system: %d", s)
	}
}

// A manual link that would overwrite different operator values is refused with the fields named.
func TestManualLinkConflictIsRefusedWithTheFields(t *testing.T) {
	e := newEnv(t)
	ep := e.addAsset("shop.example.test:443")
	var host struct {
		Asset struct {
			ID       int64 `json:"id"`
			SystemID int64 `json:"systemId"`
		} `json:"asset"`
	}
	e.call("POST", "/api/v1/hosts/ingest", `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"device","name":"web-01"}}}`, &host)
	e.call("PATCH", "/api/v1/systems/"+itoa(host.Asset.SystemID), map[string]any{"owner": "a"}, nil)
	var ea struct {
		SystemID int64 `json:"systemId"`
	}
	e.call("GET", "/api/v1/assets/"+itoa(ep.ID), nil, &ea)
	e.call("PATCH", "/api/v1/systems/"+itoa(ea.SystemID), map[string]any{"owner": "b"}, nil)
	var out struct {
		Fields []string `json:"fields"`
	}
	_, raw, _ := e.req("PUT", "/api/v1/assets/"+itoa(ep.ID)+"/links/"+itoa(host.Asset.ID), nil, nil)
	mustJSON(t, raw, &out)
	if len(out.Fields) != 1 || out.Fields[0] != "owner" {
		t.Errorf("reply = %s", raw)
	}
}
