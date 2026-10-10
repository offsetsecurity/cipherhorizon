package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"

	"github.com/offsetsecurity/cipherhorizon/internal/eval"
	"github.com/offsetsecurity/cipherhorizon/internal/reportpdf"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// fileStem makes a name safe to use in a download's file name.
func fileStem(s string) string {
	s = unsafeFileChars.ReplaceAllString(s, "_")
	if len(s) > 60 {
		s = s[:60]
	}
	if s == "" || s == "_" {
		return "endpoint"
	}
	return s
}

func writePDF(w http.ResponseWriter, b []byte, filename string) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	_, _ = w.Write(b)
}

// scanPDF renders a completed scan as a PDF report: kind=full (default), tls or cert.
func (s *Server) scanPDF(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = reportpdf.KindFull
	}
	if !reportpdf.ValidKind(kind) {
		writeErr(w, http.StatusBadRequest, "kind must be full, tls or cert")
		return
	}
	sc, err := s.cfg.Store.GetScan(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	a, err := s.cfg.Store.GetAsset(sc.AssetID)
	if err != nil {
		storeErr(w, err)
		return
	}
	rb, err := s.cfg.Store.Report(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	eb, err := s.cfg.Store.Evaluation(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	var rep tlsprobe.Report
	var ev eval.Evaluation
	if json.Unmarshal(rb, &rep) != nil || json.Unmarshal(eb, &ev) != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	b, err := reportpdf.Endpoint(reportpdf.EndpointInput{
		Name: a.Name, Address: a.Address(), ScanID: id, Report: &rep, Eval: &ev, Kind: kind,
		Version: s.cfg.Version, Generated: s.cfg.Now(),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	suffix := map[string]string{reportpdf.KindFull: "security-report", reportpdf.KindTLS: "tls-report", reportpdf.KindCert: "certificate-report"}[kind]
	writePDF(w, b, fmt.Sprintf("%s-%s.pdf", fileStem(a.Name), suffix))
}

// inventoryPDF renders the whole inventory as a PDF report.
func (s *Server) inventoryPDF(w http.ResponseWriter, _ *http.Request) {
	d, err := s.buildDashboard()
	if errors.Is(err, errInventoryTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	inv, err := s.mergeInventory(true)
	if err != nil {
		storeErr(w, err)
		return
	}
	items := func(kind string) []reportpdf.InvItem {
		var out []reportpdf.InvItem
		for _, r := range inventoryRows(inv, kind) {
			out = append(out, invItem(toDash(r, kind), r))
		}
		return out
	}
	in := reportpdf.InventoryInput{Version: s.cfg.Version, Generated: d.GeneratedAt, Totals: d.Totals, Quantum: d.Quantum,
		Algorithms: items("algorithm"), Keys: items("key"), Protocols: items("protocol"), Software: items("software")}
	byName := map[string]reportpdf.InvItem{}
	for _, it := range append(append([]reportpdf.InvItem{}, in.Algorithms...), in.Keys...) {
		byName[it.Kind+"\x00"+it.Name] = it
	}
	for _, r := range d.ReplaceFirst {
		in.Replace = append(in.Replace, byName[r.Kind+"\x00"+r.Name])
	}
	for _, p := range d.ByPurpose {
		in.ByPurpose = append(in.ByPurpose, reportpdf.InvPurpose{Purpose: p.Purpose, Vulnerable: p.Vulnerable, Safe: p.Safe, Unknown: p.Unknown})
	}
	c := d.Certificates
	in.CertCounts.Total, in.CertCounts.Expired, in.CertCounts.Within30, in.CertCounts.Within90, in.CertCounts.Later = c.Total, c.Expired, c.Within30, c.Within90, c.Later
	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	var all []reportpdf.InvCert
	for _, cr := range certs {
		v, _ := viewCert(cr, now)
		if !v.Current || v.Role == "root" || v.Role == "intermediate" {
			continue
		}
		key := v.KeyAlg
		if v.KeyBits != nil {
			key += fmt.Sprintf(" %d", *v.KeyBits)
		}
		if v.Curve != "" {
			key += " " + v.Curve
		}
		na := ""
		if v.NotAfter != nil {
			na = *v.NotAfter
		}
		all = append(all, reportpdf.InvCert{Name: v.Name, Issuer: v.Issuer, Key: key, NotAfter: na, DaysLeft: v.DaysLeft, Places: v.Places})
	}
	sort.SliceStable(all, func(i, j int) bool {
		di, dj := 1<<30, 1<<30
		if all[i].DaysLeft != nil {
			di = *all[i].DaysLeft
		}
		if all[j].DaysLeft != nil {
			dj = *all[j].DaysLeft
		}
		return di < dj
	})
	in.Certs = all
	for _, src := range d.Sources {
		in.Sources = append(in.Sources, reportpdf.InvSource{Label: src.Label, Kind: src.Kind, When: src.When, Items: src.Items})
	}
	b, err := reportpdf.Inventory(in)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writePDF(w, b, "cipherhorizon-inventory-report.pdf")
}

func invItem(d dashRow, r inventoryRow) reportpdf.InvItem {
	it := reportpdf.InvItem{Name: d.Name, Kind: d.Kind, Detail: d.Detail, Purpose: d.Purpose, Quantum: d.Quantum,
		Endpoints: d.Endpoints, Machines: d.Machines, Imports: d.Imports, Legacy: d.Legacy}
	if d.LastSeen != nil {
		it.LastSeen = *d.LastSeen
	}
	for _, p := range r.Places {
		it.Places = append(it.Places, p.Label)
	}
	return it
}
