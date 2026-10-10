package server_test

import (
	"encoding/csv"
	"strings"
	"testing"
)

type m2302JSON struct {
	Format    string `json:"format"`
	Statement string `json:"statement"`
	System    string `json:"system"`
	Items     []struct {
		Number int    `json:"number"`
		Status string `json:"status"`
		Source string `json:"source"`
		Value  string `json:"value"`
		Reason string `json:"reason"`
		Rows   []struct {
			Algorithm     string `json:"algorithm"`
			Service       string `json:"service"`
			KeyLength     *int   `json:"keyLength"`
			KeyLengthNote string `json:"keyLengthNote"`
			Where         string `json:"where"`
		} `json:"rows"`
	} `json:"items"`
}

// AC-EXP-3: the export for a system has all nine items, each marked provided or not provided with
// the right source, item 4 rows carry algorithm, service and key length (or say why not), and the
// wording supports a structure without claiming compliance.
func TestTheM2302ExportHasNineItemsMarkedProvidedOrNot(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(classicalServer(t).Addr)
	e.wait(e.startScan(a.ID).ID)
	id := e.systems()[0].ID
	path := "/api/v1/systems/" + itoa(id) + "/m2302.json"

	// Before anyone enters anything: the manual items are "not provided" and say who can supply them.
	var doc m2302JSON
	if s := e.call("GET", path, nil, &doc); s != 200 {
		t.Fatalf("m2302: %d", s)
	}
	if doc.Format != "cipherhorizon-m2302/1" || len(doc.Items) != 9 {
		t.Fatalf("doc = %+v", doc)
	}
	for i, it := range doc.Items {
		if it.Number != i+1 {
			t.Errorf("item %d is numbered %d", i+1, it.Number)
		}
		switch it.Number {
		case 1, 2, 3, 7, 8, 9:
			if it.Status != "not provided" || !strings.Contains(it.Reason, "no tool can observe it") {
				t.Errorf("item %d before entry: %+v", it.Number, it)
			}
		}
	}
	if strings.Contains(strings.ToLower(doc.Statement), "is compliant") || !strings.Contains(doc.Statement, "not a statement that the system complies") {
		t.Errorf("statement = %q", doc.Statement)
	}
	four := doc.Items[3]
	if four.Status != "provided" || four.Source != "evidence" || len(four.Rows) == 0 {
		t.Fatalf("item 4 = %+v", four)
	}
	var sawCert, sawGroup bool
	for _, r := range four.Rows {
		if r.Service == "" || r.Where == "" || (r.KeyLength == nil && !strings.HasPrefix(r.KeyLengthNote, "unknown(")) {
			t.Errorf("item 4 row lacks its facts: %+v", r)
		}
		if strings.HasPrefix(r.Where, "certificate ") {
			sawCert = true
			if r.KeyLength == nil {
				t.Errorf("a scanned certificate has a key size: %+v", r)
			}
		}
		if strings.HasPrefix(r.Where, "TLS key-exchange group") {
			sawGroup = true
		}
	}
	if !sawCert || !sawGroup {
		t.Errorf("item 4 rows = %+v", four.Rows)
	}
	if doc.Items[5].Status != "not provided" || doc.Items[5].Reason == "" {
		t.Errorf("item 6 = %+v", doc.Items[5])
	}

	// A person fills the manual items: they become "provided", from the operator.
	if s := e.call("PATCH", "/api/v1/systems/"+itoa(id), map[string]any{
		"fismaId": "FISMA-1234", "fips199": "high", "hvaId": "HVA-9", "hosting": "commercial-cloud", "hostingProvider": "ExampleCloud",
		"dataLifetimeYears": 25, "notes": "=HYPERLINK(\"http://evil.example\")",
	}, nil); s != 200 {
		t.Fatalf("patch: %d", s)
	}
	doc = m2302JSON{}
	e.call("GET", path, nil, &doc)
	want := map[int]string{1: "FISMA-1234", 2: "high", 3: "HVA-9", 7: "commercial-cloud (ExampleCloud)", 8: "25 years"}
	for _, it := range doc.Items {
		if v, ok := want[it.Number]; ok && (it.Status != "provided" || it.Source != "operator" || it.Value != v) {
			t.Errorf("item %d after entry: %+v", it.Number, it)
		}
	}

	// The CSV has the same items, one line per item 4 row, and a hostile note cannot become a formula.
	s, raw := e.do("GET", "/api/v1/systems/"+itoa(id)+"/m2302.csv", nil)
	if s != 200 {
		t.Fatalf("csv: %d", s)
	}
	recs, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse: %v\n%s", err, raw)
	}
	items, item4 := map[string]bool{}, 0
	for _, r := range recs[1:] {
		if r[2] != "" {
			items[r[2]] = true
		}
		if r[2] == "4" {
			item4++
		}
		if strings.HasPrefix(r[6], "=") || strings.HasPrefix(r[14], "=") {
			t.Errorf("a cell starts with =: %v", r)
		}
	}
	if len(items) != 9 || item4 != len(four.Rows) {
		t.Errorf("csv has %d items and %d item-4 lines; want 9 and %d", len(items), item4, len(four.Rows))
	}
	if !strings.Contains(string(raw), "'=HYPERLINK") {
		t.Errorf("the note was not made safe:\n%s", raw)
	}
}

func TestTheM2302ExportSaysWhenNothingWasObserved(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(deadPort(t))
	_ = a
	id := e.systems()[0].ID
	var doc m2302JSON
	if s := e.call("GET", "/api/v1/systems/"+itoa(id)+"/m2302.json", nil, &doc); s != 200 {
		t.Fatal(s)
	}
	if four := doc.Items[3]; four.Status != "not provided" || !strings.Contains(four.Reason, "no scanner or collector") {
		t.Errorf("item 4 = %+v", four)
	}
	if s, _ := e.do("GET", "/api/v1/systems/999999/m2302.json", nil); s != 404 {
		t.Errorf("unknown system: %d", s)
	}
	if s, _ := e.do("GET", "/api/v1/systems/abc/m2302.csv", nil); s != 400 {
		t.Errorf("bad id: %d", s)
	}
}

func TestTheM2302ExportRequiresTheToken(t *testing.T) {
	e := newEnv(t, withToken("s3cret-token-0123456789"))
	e.token = ""
	for _, p := range []string{"/api/v1/systems/1/m2302.json", "/api/v1/systems/1/m2302.csv"} {
		if s, _, _ := e.req("GET", p, nil, nil); s != 401 {
			t.Errorf("%s without a token: %d", p, s)
		}
	}
}

// A hybrid post-quantum group is not a quantum-vulnerable element and is not listed as one.
func TestTheM2302ExportDoesNotListAPostQuantumGroup(t *testing.T) {
	e := newEnv(t)
	a := e.addAsset(hybridServer(t).Addr)
	e.wait(e.startScan(a.ID).ID)
	var doc m2302JSON
	e.call("GET", "/api/v1/systems/"+itoa(e.systems()[0].ID)+"/m2302.json", nil, &doc)
	for _, r := range doc.Items[3].Rows {
		if strings.Contains(strings.ToLower(r.Algorithm), "mlkem") {
			t.Errorf("a post-quantum group was listed as quantum-vulnerable: %+v", r)
		}
	}
	if len(doc.Items[3].Rows) == 0 {
		t.Error("the certificate is still quantum-vulnerable and should be listed")
	}
}
