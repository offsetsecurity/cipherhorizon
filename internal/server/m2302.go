package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/algo"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// M-23-02 structured export (PRD-003 REQ-EXP-3).
//
// OMB M-23-02 Section II asks for nine data items per cryptographic system; the CISA automated-discovery
// strategy says only items 4, 5 and 6 can be collected by a tool and the rest are manual (RESEARCH-003
// section 3.3). The export therefore takes items 1, 2, 3, 7, 8 and 9 from what a person entered and
// says so, takes item 4 from evidence, and marks every item provided or not provided with the reason.
// It "supports the structure"; it is never a statement of compliance, and the document says that.

const m2302Statement = "This export follows the nine-item structure that OMB memorandum M-23-02 Section II describes, as read " +
	"from the CISA Strategy for Migrating to Automated PQC Discovery and Inventory Tools. It supports that structure. " +
	"It is not a statement that the system complies with the memorandum."

type m2302Item struct {
	Number int    `json:"number"`
	Name   string `json:"name"`
	// Status is "provided" or "not provided": a value is never defaulted in.
	Status string `json:"status"`
	// Source says how the value is known: "operator" (a person entered it), "evidence" (a sensor
	// observed it) or "" when there is no value.
	Source string `json:"source,omitempty"`
	Value  string `json:"value,omitempty"`
	// Reason says why an item is not provided, or what a provided one does not cover.
	Reason string `json:"reason,omitempty"`
	// Rows are the item 4 elements and the item 5 software entries.
	Rows []m2302Row `json:"rows,omitempty"`
}

// m2302Row is one quantum-vulnerable element (item 4) or one software entry (item 5).
type m2302Row struct {
	Algorithm string `json:"algorithm,omitempty"`
	// Service is what the element provides: key establishment, digital signatures.
	Service string `json:"service,omitempty"`
	// KeyLength is the key size in bits. Absent means unknown, and KeyLengthNote says why.
	KeyLength     *int   `json:"keyLength,omitempty"`
	KeyLengthNote string `json:"keyLengthNote,omitempty"`
	Where         string `json:"where"`
	Basis         string `json:"basis,omitempty"`
	Software      string `json:"software,omitempty"`
	Version       string `json:"version,omitempty"`
	Vendor        string `json:"vendor,omitempty"`
}

type m2302Doc struct {
	Format      string      `json:"format"`
	Statement   string      `json:"statement"`
	GeneratedAt string      `json:"generatedAt"`
	SystemID    int64       `json:"systemId"`
	System      string      `json:"system"`
	Items       []m2302Item `json:"items"`
}

func provided(n int, name, source, value string) m2302Item {
	return m2302Item{Number: n, Name: name, Status: "provided", Source: source, Value: value}
}

func notProvided(n int, name, reason string) m2302Item {
	return m2302Item{Number: n, Name: name, Status: "not provided", Reason: reason}
}

// operatorItem builds an item that only a person can supply.
func operatorItem(n int, name, value, field string) m2302Item {
	if value == "" {
		return notProvided(n, name, "no one has entered it (system field "+field+"); no tool can observe it")
	}
	return provided(n, name, "operator", value)
}

// operatingSystem is item 6, from what each of the system's machines reported about itself.
func operatingSystem(hostOS []string) m2302Item {
	if len(hostOS) == 0 {
		return notProvided(6, "Operating system and version", "no collector run on a machine of this system recorded its operating system")
	}
	return provided(6, "Operating system and version", "evidence", strings.Join(hostOS, "; "))
}

// certService names what a certificate's public key is used for, from its algorithm.
func certService(keyAlg string) string {
	if a, ok := algo.Lookup(keyAlg); ok {
		switch string(a.Primitive) {
		case "signature":
			return "digital signatures"
		case "key-agree", "kem":
			return "key establishment"
		}
	}
	switch strings.ToUpper(keyAlg) {
	case "RSA":
		return "digital signatures and key establishment"
	case "ECDSA", "ED25519", "DSA":
		return "digital signatures"
	}
	return "not stated by the certificate"
}

// buildM2302 assembles the nine items for one system from what a person entered and the system's
// current observations.
func buildM2302(sys store.System, obs []store.ObservationRow, hostOS []string, now time.Time) m2302Doc {
	doc := m2302Doc{Format: "cipherhorizon-m2302/1", Statement: m2302Statement, GeneratedAt: now.UTC().Format(time.RFC3339), SystemID: sys.ID, System: sys.Name}

	hosting := sys.Hosting
	if hosting != "" && sys.HostingProvider != "" {
		hosting += " (" + sys.HostingProvider + ")"
	}
	life := ""
	if sys.DataLifetimeYears != nil {
		life = strconv.Itoa(*sys.DataLifetimeYears) + " years"
	}

	var item4, item5 []m2302Row
	seen4, seen5 := map[string]bool{}, map[string]bool{}
	firstParty := 0
	for _, o := range obs {
		if !o.Current {
			continue
		}
		if o.Class == "scanner" || o.Class == "collector" {
			firstParty++
		}
		e := o.Entity
		switch e.Kind {
		case "certificate":
			alg := e.Attrs["keyAlg"]
			if e.Attrs["isCA"] == "true" || alg == "" || seen4[e.Key] {
				continue
			}
			if c, ok := pqc.ClassOf(alg, ""); !ok || c != pqc.Vulnerable {
				continue
			}
			seen4[e.Key] = true
			row := m2302Row{Algorithm: alg, Service: certService(alg), Where: "certificate " + strings.TrimPrefix(e.Key, "cert:") + " (" + e.Name + ")",
				Basis: "certificate public key; quantum-vulnerable under the cited rule"}
			if c := e.Attrs["curve"]; c != "" {
				row.Algorithm += " " + c
			}
			if n, err := strconv.Atoi(e.Attrs["keyBits"]); err == nil && n > 0 {
				row.KeyLength = &n
			} else {
				row.KeyLengthNote = "unknown(no source recorded a key size for this certificate)"
			}
			item4 = append(item4, row)
		case "group":
			if e.Attrs["pq"] == "true" || seen4[e.Key] {
				continue
			}
			seen4[e.Key] = true
			item4 = append(item4, m2302Row{Algorithm: e.Name, Service: "key establishment (encrypted connections)", Where: "TLS key-exchange group offered by a scanned endpoint",
				KeyLengthNote: "unknown(a TLS group fixes its own parameters; no key size is recorded)", Basis: "observed in a handshake; not post-quantum"})
		case "software":
			if seen5[e.Key] {
				continue
			}
			seen5[e.Key] = true
			item5 = append(item5, m2302Row{Software: e.Name, Version: e.Attrs["version"], Where: "software observed on the system",
				Vendor: "unknown(the sensors do not record the supplier)"})
		}
	}
	sort.Slice(item4, func(i, j int) bool { return item4[i].Where < item4[j].Where })
	sort.Slice(item5, func(i, j int) bool { return item5[i].Software < item5[j].Software })

	const name4 = "Quantum-vulnerable elements: algorithm, service provided, key length"
	i4 := m2302Item{Number: 4, Name: name4, Rows: item4}
	switch {
	case len(item4) > 0:
		i4.Status, i4.Source = "provided", "evidence"
	case firstParty > 0:
		i4.Status, i4.Source = "provided", "evidence"
		i4.Reason = "no quantum-vulnerable element was observed by the sources this system has; that says nothing about what they could not see (see coverage)"
	default:
		i4 = notProvided(4, name4, "no scanner or collector has observed this system")
	}
	const name5 = "Software package: type and supplier"
	i5 := m2302Item{Number: 5, Name: name5, Rows: item5}
	if len(item5) > 0 {
		i5.Status, i5.Source = "provided", "evidence"
		i5.Reason = "the supplier of a package is not recorded by the sensors; confirm it with the supplier"
	} else {
		i5 = notProvided(5, name5, "no software was observed for this system; embedded and custom software may not be discoverable by tools")
	}

	doc.Items = []m2302Item{
		operatorItem(1, "FISMA system identifier", sys.FISMAID, "fismaId"),
		operatorItem(2, "FIPS 199 categorisation", sys.FIPS199, "fips199"),
		operatorItem(3, "High value asset identifier", sys.HVAID, "hvaId"),
		i4, i5,
		operatingSystem(hostOS),
		operatorItem(7, "Hosting", hosting, "hosting"),
		operatorItem(8, "Data lifecycle: how long the data must stay protected", life, "dataLifetimeYears"),
		operatorItem(9, "Notes", sys.Notes, "notes"),
	}
	return doc
}

func (s *Server) m2302For(w http.ResponseWriter, r *http.Request) (m2302Doc, bool) {
	id, ok := idParam(w, r)
	if !ok {
		return m2302Doc{}, false
	}
	sys, err := s.cfg.Store.GetSystem(id)
	if err != nil {
		storeErr(w, err)
		return m2302Doc{}, false
	}
	obs, err := s.cfg.Store.SystemObservations(id, true)
	if err != nil {
		storeErr(w, err)
		return m2302Doc{}, false
	}
	var hostOS []string
	seen := map[string]bool{}
	for _, a := range sys.Assets {
		if a.Kind != store.KindHost {
			continue
		}
		snaps, err := s.cfg.Store.HostSnapshots(a.ID, 1)
		if err != nil || len(snaps) == 0 {
			continue
		}
		var sum HostSummary
		if json.Unmarshal(snaps[0].Summary, &sum) == nil && sum.Coverage != nil && sum.Coverage.OS != "" && !seen[sum.Coverage.OS] {
			seen[sum.Coverage.OS] = true
			hostOS = append(hostOS, sum.Coverage.OS)
		}
	}
	return buildM2302(sys, obs, hostOS, s.cfg.Now()), true
}

func (s *Server) m2302JSON(w http.ResponseWriter, r *http.Request) {
	if doc, ok := s.m2302For(w, r); ok {
		w.Header().Set("Content-Disposition", `attachment; filename="m-23-02.json"`)
		writeJSON(w, 200, doc)
	}
}

func (s *Server) m2302CSV(w http.ResponseWriter, r *http.Request) {
	doc, ok := s.m2302For(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="m-23-02.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"system_id", "system", "item", "item_name", "status", "source", "value", "algorithm", "service", "key_length", "software", "version", "vendor", "where", "note"})
	base := func(it m2302Item) []string {
		return []string{strconv.FormatInt(doc.SystemID, 10), csvSafe(doc.System), strconv.Itoa(it.Number), it.Name, it.Status, it.Source, csvSafe(it.Value)}
	}
	for _, it := range doc.Items {
		if len(it.Rows) == 0 {
			_ = cw.Write(append(base(it), "", "", "", "", "", "", "", csvSafe(it.Reason)))
			continue
		}
		for _, row := range it.Rows {
			kl, note := "", row.KeyLengthNote
			if row.KeyLength != nil {
				kl = strconv.Itoa(*row.KeyLength)
			}
			if note == "" {
				note = it.Reason
			}
			_ = cw.Write(append(base(it), csvSafe(row.Algorithm), row.Service, kl, csvSafe(row.Software), csvSafe(row.Version), row.Vendor, csvSafe(row.Where), csvSafe(note)))
		}
	}
	_ = cw.Write([]string{"", "", "", "", "", "", "", "", "", "", "", "", "", "", doc.Statement})
	cw.Flush()
}
