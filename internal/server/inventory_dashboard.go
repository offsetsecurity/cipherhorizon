package server

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The inventory dashboard: every figure the Inventory page and the inventory
// PDF show, computed once from the merged CBOM and the certificate store so
// the two never disagree.

type dashRow struct {
	Name      string     `json:"name"`
	Kind      string     `json:"kind"` // algorithm, key, protocol or software
	Detail    string     `json:"detail,omitempty"`
	Purpose   string     `json:"purpose,omitempty"`
	Quantum   string     `json:"quantum"`
	Places    int        `json:"places"`
	Endpoints int        `json:"endpoints"`
	Machines  int        `json:"machines"`
	Imports   int        `json:"imports"`
	Legacy    bool       `json:"legacy,omitempty"` // a protocol version that is deprecated
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

type purposeRow struct {
	Purpose    string `json:"purpose"`
	Vulnerable int    `json:"vulnerable"`
	Safe       int    `json:"safe"`
	Unknown    int    `json:"unknown"`
}

type certBrief struct {
	Fingerprint string `json:"fingerprint"`
	Name        string `json:"name"`
	Issuer      string `json:"issuer"`
	Key         string `json:"key"`
	NotAfter    string `json:"notAfter,omitempty"`
	DaysLeft    *int   `json:"daysLeft"`
	Places      int    `json:"places"`
}

type labelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type certDashboard struct {
	Total    int          `json:"total"`
	Expired  int          `json:"expired"`
	Within30 int          `json:"within30"`
	Within90 int          `json:"within90"`
	Later    int          `json:"later"`
	Keys     []labelCount `json:"keys"`
	Soonest  []certBrief  `json:"soonest"`
}

type sourceRow struct {
	Label string    `json:"label"`
	Kind  string    `json:"kind"`
	ID    int64     `json:"id"`
	When  time.Time `json:"when"`
	Items int       `json:"items"` // inventory rows it contributed to
}

type inventoryDashboard struct {
	GeneratedAt  time.Time      `json:"generatedAt"`
	Totals       map[string]int `json:"totals"`
	Quantum      map[string]int `json:"quantum"` // over algorithms and keys: vulnerable, safe, unknown
	ReplaceFirst []dashRow      `json:"replaceFirst"`
	ByPurpose    []purposeRow   `json:"byPurpose"`
	Protocols    []dashRow      `json:"protocols"`
	Software     []dashRow      `json:"software"`
	Certificates certDashboard  `json:"certificates"`
	Sources      []sourceRow    `json:"sources"`
}

// purposeOf names what an algorithm is for, from its CycloneDX primitive.
func purposeOf(detail string) string {
	prim := strings.TrimSpace(strings.Split(detail, " · ")[0])
	switch prim {
	case "key-agree", "kem", "combiner":
		return "Key exchange"
	case "signature":
		return "Signatures"
	case "pke":
		return "Public-key encryption"
	case "ae", "block-cipher", "stream-cipher":
		return "Symmetric encryption"
	case "hash", "xof":
		return "Hashing"
	case "mac":
		return "Message authentication"
	case "kdf":
		return "Key derivation"
	case "drbg":
		return "Random generation"
	}
	return "Other"
}

var purposeOrder = []string{"Key exchange", "Signatures", "Public-key encryption", "Symmetric encryption", "Hashing", "Message authentication", "Key derivation", "Random generation", "Other"}

func legacyProtocol(name string) bool {
	switch name {
	case "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1":
		return true
	}
	return false
}

func toDash(r inventoryRow, kind string) dashRow {
	d := dashRow{Name: r.Name, Kind: kind, Detail: r.Detail, Quantum: r.Quantum, Places: len(r.Places), LastSeen: r.Seen}
	for _, p := range r.Places {
		switch p.Kind {
		case "endpoint":
			d.Endpoints++
		case "machine":
			d.Machines++
		case "import":
			d.Imports++
		}
	}
	if kind == "algorithm" {
		d.Purpose = purposeOf(r.Detail)
	}
	if kind == "protocol" {
		d.Legacy = legacyProtocol(r.Name)
	}
	return d
}

// buildDashboard computes the dashboard. Imported CBOMs are included: the
// inventory shows everything it knows, marking where each item came from.
func (s *Server) buildDashboard() (*inventoryDashboard, error) {
	inv, err := s.mergeInventory(true)
	if err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	d := &inventoryDashboard{GeneratedAt: now.UTC(), Totals: map[string]int{}, Quantum: map[string]int{"vulnerable": 0, "safe": 0, "unknown": 0},
		ReplaceFirst: []dashRow{}, ByPurpose: []purposeRow{}, Protocols: []dashRow{}, Software: []dashRow{}, Sources: []sourceRow{}}
	sources := map[string]*sourceRow{}
	purposes := map[string]*purposeRow{}
	var vulnerable []dashRow
	for _, kind := range []string{"algorithm", "key", "protocol", "software"} {
		rows := inventoryRows(inv, kind)
		d.Totals[kind] = len(rows)
		for _, r := range rows {
			dr := toDash(r, kind)
			for _, p := range r.Places {
				k := p.String()
				src := sources[k]
				if src == nil {
					id := p.AssetID
					if p.Kind == "import" {
						id = p.ImportID
					}
					src = &sourceRow{Label: p.Label, Kind: p.Kind, ID: id, When: p.When}
					sources[k] = src
				}
				src.Items++
			}
			if kind == "algorithm" || kind == "key" {
				switch r.Quantum {
				case "quantum-vulnerable":
					d.Quantum["vulnerable"]++
					vulnerable = append(vulnerable, dr)
				case "quantum-safe":
					d.Quantum["safe"]++
				default:
					d.Quantum["unknown"]++
				}
			}
			switch kind {
			case "algorithm":
				pr := purposes[dr.Purpose]
				if pr == nil {
					pr = &purposeRow{Purpose: dr.Purpose}
					purposes[dr.Purpose] = pr
				}
				switch r.Quantum {
				case "quantum-vulnerable":
					pr.Vulnerable++
				case "quantum-safe":
					pr.Safe++
				default:
					pr.Unknown++
				}
			case "protocol":
				d.Protocols = append(d.Protocols, dr)
			case "software":
				d.Software = append(d.Software, dr)
			}
		}
	}
	sort.SliceStable(vulnerable, func(i, j int) bool {
		if vulnerable[i].Places != vulnerable[j].Places {
			return vulnerable[i].Places > vulnerable[j].Places
		}
		return vulnerable[i].Name < vulnerable[j].Name
	})
	if len(vulnerable) > 8 {
		vulnerable = vulnerable[:8]
	}
	d.ReplaceFirst = append(d.ReplaceFirst, vulnerable...)
	for _, p := range purposeOrder {
		if pr := purposes[p]; pr != nil {
			d.ByPurpose = append(d.ByPurpose, *pr)
		}
	}
	// Newest protocol first.
	sort.SliceStable(d.Protocols, func(i, j int) bool { return d.Protocols[i].Name > d.Protocols[j].Name })
	sort.SliceStable(d.Software, func(i, j int) bool { return d.Software[i].Places > d.Software[j].Places })
	if len(d.Software) > 8 {
		d.Software = d.Software[:8]
	}
	for _, src := range sources {
		d.Sources = append(d.Sources, *src)
	}
	sort.Slice(d.Sources, func(i, j int) bool {
		if !d.Sources[i].When.Equal(d.Sources[j].When) {
			return d.Sources[i].When.After(d.Sources[j].When)
		}
		return d.Sources[i].Label < d.Sources[j].Label
	})
	d.Totals["endpoints"], d.Totals["machines"] = inv.endpoints, inv.machines
	imps, err := s.cfg.Store.Imports()
	if err != nil {
		return nil, err
	}
	for _, imp := range imps {
		if imp.Status == "active" {
			d.Totals["imports"]++
		}
	}

	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		return nil, err
	}
	keys := map[string]int{}
	var briefs []certBrief
	for _, c := range certs {
		v, _ := viewCert(c, now)
		if !v.Current || v.Role == "root" || v.Role == "intermediate" {
			continue
		}
		cd := &d.Certificates
		cd.Total++
		switch {
		case v.DaysLeft == nil:
		case *v.DaysLeft < 0:
			cd.Expired++
		case *v.DaysLeft <= 30:
			cd.Within30++
		case *v.DaysLeft <= 90:
			cd.Within90++
		default:
			cd.Later++
		}
		key := v.KeyAlg
		if v.KeyBits != nil {
			key += " " + strconv.Itoa(*v.KeyBits)
		}
		if v.Curve != "" {
			key += " " + v.Curve
		}
		keys[strings.TrimSpace(key)]++
		na := ""
		if v.NotAfter != nil {
			na = *v.NotAfter
		}
		briefs = append(briefs, certBrief{Fingerprint: v.Fingerprint, Name: v.Name, Issuer: v.Issuer, Key: strings.TrimSpace(key), NotAfter: na, DaysLeft: v.DaysLeft, Places: v.Places})
	}
	d.Totals["certificates"] = d.Certificates.Total
	for k, n := range keys {
		d.Certificates.Keys = append(d.Certificates.Keys, labelCount{k, n})
	}
	sort.Slice(d.Certificates.Keys, func(i, j int) bool {
		if d.Certificates.Keys[i].Count != d.Certificates.Keys[j].Count {
			return d.Certificates.Keys[i].Count > d.Certificates.Keys[j].Count
		}
		return d.Certificates.Keys[i].Label < d.Certificates.Keys[j].Label
	})
	sort.SliceStable(briefs, func(i, j int) bool {
		di, dj := 1<<30, 1<<30
		if briefs[i].DaysLeft != nil {
			di = *briefs[i].DaysLeft
		}
		if briefs[j].DaysLeft != nil {
			dj = *briefs[j].DaysLeft
		}
		return di < dj
	})
	if len(briefs) > 5 {
		briefs = briefs[:5]
	}
	d.Certificates.Soonest = append([]certBrief{}, briefs...)
	if d.Certificates.Keys == nil {
		d.Certificates.Keys = []labelCount{}
	}
	return d, nil
}

func (s *Server) inventoryDashboard(w http.ResponseWriter, _ *http.Request) {
	d, err := s.buildDashboard()
	if errors.Is(err, errInventoryTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, d)
}
