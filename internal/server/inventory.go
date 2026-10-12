package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// The cryptographic inventory (PRD-005 REQ-INV, ENG-HANDOFF-004 E-4..E-6). The inventory IS the
// merged CBOM: the latest CBOM of every endpoint and every machine (and, on request, every
// imported CBOM) merged by bom-ref. The rows the page shows are read from that document, so
// what you see is exactly what you download.

// inventoryTabs maps a page tab to the CycloneDX component it lists.
var inventoryTabs = map[string]func(c cdx.Component) bool{
	"algorithm": func(c cdx.Component) bool { return assetType(c) == cdx.CryptoAssetTypeAlgorithm },
	"key":       func(c cdx.Component) bool { return assetType(c) == cdx.CryptoAssetTypeRelatedCryptoMaterial },
	"protocol":  func(c cdx.Component) bool { return assetType(c) == cdx.CryptoAssetTypeProtocol },
	"software": func(c cdx.Component) bool {
		return c.CryptoProperties == nil && (c.Type == cdx.ComponentTypeLibrary || c.Type == cdx.ComponentTypeApplication || c.Type == cdx.ComponentTypeFramework)
	},
}

func assetType(c cdx.Component) cdx.CryptoAssetType {
	if c.CryptoProperties == nil {
		return ""
	}
	return c.CryptoProperties.AssetType
}

// inventoryRow is one named thing in the inventory and every place it was seen.
type inventoryRow struct {
	Name    string        `json:"name"`
	Kind    string        `json:"kind"`
	Detail  string        `json:"detail,omitempty"` // e.g. the primitive, the key size, the protocol version
	Quantum string        `json:"quantum"`          // quantum-vulnerable, quantum-safe, not-applicable, unknown
	Places  []sourceLabel `json:"places"`
	Refs    []string      `json:"refs"`               // bom-refs merged into this row
	Seen    *time.Time    `json:"lastSeen,omitempty"` // when the most recent of its places last reported
}

func property(c cdx.Component, name string) string {
	if c.Properties == nil {
		return ""
	}
	for _, p := range *c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func detailOf(c cdx.Component) string {
	cp := c.CryptoProperties
	if cp == nil {
		return c.Version
	}
	switch cp.AssetType {
	case cdx.CryptoAssetTypeAlgorithm:
		if ap := cp.AlgorithmProperties; ap != nil {
			parts := []string{}
			if ap.Primitive != "" {
				parts = append(parts, string(ap.Primitive))
			}
			if ap.ParameterSetIdentifier != "" {
				parts = append(parts, ap.ParameterSetIdentifier)
			}
			if ap.Curve != "" {
				parts = append(parts, ap.Curve)
			}
			return strings.Join(parts, " · ")
		}
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
		if rp := cp.RelatedCryptoMaterialProperties; rp != nil {
			d := string(rp.Type)
			if rp.Size != nil {
				d += fmt.Sprintf(" · %d bits", *rp.Size)
			}
			return d
		}
	case cdx.CryptoAssetTypeProtocol:
		if pp := cp.ProtocolProperties; pp != nil {
			return strings.TrimSpace(string(pp.Type) + " " + pp.Version)
		}
	}
	return ""
}

// inventoryRows reads the rows of one tab from a merged inventory.
func inventoryRows(inv *mergedInventory, tab string) []inventoryRow {
	keep := inventoryTabs[tab]
	status := map[string]string{}
	for _, c := range inv.bom.compsOrEmpty() {
		if st := property(c, "cipherhorizon:pqc:status"); st != "" {
			status[c.BOMRef] = st
		}
	}
	byName := map[string]int{}
	var out []inventoryRow
	for _, c := range inv.bom.compsOrEmpty() {
		if !keep(c) {
			continue
		}
		q := "not-applicable"
		switch assetType(c) {
		case cdx.CryptoAssetTypeAlgorithm:
			q = "unknown"
			if st := status[c.BOMRef]; st != "" {
				q = st
			}
		case cdx.CryptoAssetTypeRelatedCryptoMaterial:
			q = "unknown"
			for _, d := range inv.deps[c.BOMRef] { // a key takes the status of its algorithm
				if st := status[d]; st != "" {
					q = st
				}
			}
		}
		key := string(assetType(c)) + "\x00" + c.Name
		i, ok := byName[key]
		if !ok {
			i = len(out)
			byName[key] = i
			out = append(out, inventoryRow{Name: c.Name, Kind: tab, Detail: detailOf(c), Quantum: q, Places: []sourceLabel{}})
		}
		row := &out[i]
		row.Refs = append(row.Refs, c.BOMRef)
		if row.Quantum == "unknown" && q != "unknown" {
			row.Quantum = q
		}
		for _, p := range inv.seenIn[c.BOMRef] {
			if !containsLabel(row.Places, p) {
				row.Places = append(row.Places, p)
			}
			if row.Seen == nil || p.When.After(*row.Seen) {
				w := p.When
				row.Seen = &w
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := quantumRank(out[i].Quantum), quantumRank(out[j].Quantum)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	if out == nil {
		out = []inventoryRow{}
	}
	return out
}

func quantumRank(q string) int {
	switch q {
	case "quantum-vulnerable":
		return 0
	case "unknown":
		return 1
	case "quantum-safe":
		return 2
	}
	return 3
}

func containsLabel(ls []sourceLabel, l sourceLabel) bool {
	for _, x := range ls {
		if x == l {
			return true
		}
	}
	return false
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tab := q.Get("kind")
	if tab == "" {
		tab = "algorithm"
	}
	if inventoryTabs[tab] == nil {
		writeErr(w, http.StatusBadRequest, "kind must be algorithm, key, protocol or software")
		return
	}
	source := q.Get("source")
	if source != "" && source != "endpoint" && source != "machine" && source != "import" {
		writeErr(w, http.StatusBadRequest, "source must be endpoint, machine or import")
		return
	}
	inv, err := s.mergeInventory(q.Get("imported") == "1" || source == "import")
	if errors.Is(err, errInventoryTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	text := strings.ToLower(strings.TrimSpace(q.Get("q")))
	vulnerable := q.Get("vulnerable") == "1"
	rows := inventoryRows(inv, tab)
	filtered := make([]inventoryRow, 0, len(rows))
	for _, row := range rows {
		if text != "" && !strings.Contains(strings.ToLower(row.Name), text) && !strings.Contains(strings.ToLower(row.Detail), text) {
			continue
		}
		if vulnerable && row.Quantum != "quantum-vulnerable" {
			continue
		}
		if source != "" {
			found := false
			for _, p := range row.Places {
				found = found || p.Kind == source
			}
			if !found {
				continue
			}
		}
		filtered = append(filtered, row)
	}
	writeJSON(w, 200, map[string]any{"kind": tab, "rows": filtered})
}

func (s *Server) inventorySummary(w http.ResponseWriter, _ *http.Request) {
	inv, err := s.mergeInventory(false)
	if err != nil && !errors.Is(err, errInventoryTooLarge) {
		storeErr(w, err)
		return
	}
	out := map[string]int{}
	if inv != nil {
		for tab := range inventoryTabs {
			rows := inventoryRows(inv, tab)
			out[tab] = len(rows)
			if tab == "algorithm" {
				for _, r := range rows {
					switch r.Quantum {
					case "quantum-vulnerable":
						out["quantumVulnerable"]++
					case "quantum-safe":
						out["quantumSafe"]++
					}
				}
			}
		}
		out["endpoints"], out["machines"] = inv.endpoints, inv.machines
	}
	certs, err := s.cfg.Store.Certificates()
	if err != nil {
		storeErr(w, err)
		return
	}
	now := s.cfg.Now()
	for _, c := range certs {
		if !c.Current {
			continue
		}
		out["certificates"]++
		if na, err := time.Parse("2006-01-02T15:04:05Z", c.Attrs["notAfter"]); err == nil && na.After(now) && na.Sub(now) <= 30*24*time.Hour {
			out["certificatesExpiring30"]++
		}
	}
	imps, err := s.cfg.Store.Imports()
	if err != nil {
		storeErr(w, err)
		return
	}
	for _, imp := range imps {
		if imp.Status == "active" {
			out["imports"]++
		}
	}
	writeJSON(w, 200, out)
}

// maxInventoryComponents bounds the whole-inventory CBOM.
const maxInventoryComponents = 20000

var errInventoryTooLarge = errors.New("the inventory has more than 20,000 components; download per endpoint or machine instead")

// sourceLabel is one place a component was seen.
type sourceLabel struct {
	Label    string    `json:"label"`
	Kind     string    `json:"kind"` // endpoint, machine or import
	AssetID  int64     `json:"assetId,omitempty"`
	ImportID int64     `json:"importId,omitempty"`
	When     time.Time `json:"when"` // the scan's end, the snapshot's upload or the import's receipt
}

func (l sourceLabel) String() string { return l.Label + " (" + l.Kind + ")" }

// mergedInventory is the merged document and what the merge learned.
type mergedInventory struct {
	bom                 bomView
	seenIn              map[string][]sourceLabel
	deps                map[string][]string
	endpoints, machines int
}

type bomView struct{ *cdx.BOM }

func (b bomView) compsOrEmpty() []cdx.Component {
	if b.BOM == nil || b.Components == nil {
		return nil
	}
	return *b.Components
}

func (s *Server) inventoryBOM(includeImported bool) (*cdx.BOM, error) {
	inv, err := s.mergeInventory(includeImported)
	if err != nil {
		return nil, err
	}
	return inv.bom.BOM, nil
}

// mergeInventory merges the latest CBOM of every endpoint and every machine (and, when asked,
// every active imported CBOM) into one document (ENG-HANDOFF-004 E-5).
func (s *Server) mergeInventory(includeImported bool) (*mergedInventory, error) {
	m := newBOMMerger()
	inv := &mergedInventory{}

	latest, err := s.cfg.Store.LatestDoneScans(0)
	if err != nil {
		return nil, err
	}
	for assetID, scanID := range latest {
		a, err := s.cfg.Store.GetAsset(assetID)
		if err != nil || !store.IsEndpoint(a.Kind) {
			continue
		}
		raw, err := s.cfg.Store.Report(scanID)
		if err != nil {
			continue
		}
		dec, err := decodeReport(raw)
		if err != nil {
			continue
		}
		assets, _ := endpointAssets(dec)
		bom, _ := cbom.Build(assets, cbom.Options{
			Tool: cbom.Tool{Name: "cipherhorizon", Version: s.cfg.Version}, Endpoint: a.Address(),
		})
		var when time.Time
		if sc, err := s.cfg.Store.GetScan(scanID); err == nil && sc.FinishedAt != nil {
			when = *sc.FinishedAt
		}
		if err := m.add(bom, sourceLabel{Label: a.Name, Kind: "endpoint", AssetID: a.ID, When: when}, ""); err != nil {
			return nil, err
		}
		inv.endpoints++
	}

	snaps, err := s.cfg.Store.LatestHostSnapshots()
	if err != nil {
		return nil, err
	}
	for assetID, snap := range snaps {
		a, err := s.cfg.Store.GetAsset(assetID)
		if err != nil {
			continue
		}
		raw, err := s.cfg.Store.HostCBOM(snap.ID)
		if err != nil {
			continue
		}
		var bom cdx.BOM
		if cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom) != nil {
			continue
		}
		if err := m.add(&bom, sourceLabel{Label: a.Name, Kind: "machine", AssetID: a.ID, When: snap.At}, ""); err != nil {
			return nil, err
		}
		inv.machines++
	}

	if includeImported {
		imps, err := s.cfg.Store.Imports()
		if err != nil {
			return nil, err
		}
		for _, imp := range imps {
			if imp.Status != "active" {
				continue
			}
			raw, err := s.cfg.Store.ImportDocument(imp.ID)
			if err != nil {
				continue
			}
			var bom cdx.BOM
			if cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom) != nil {
				continue
			}
			name := imp.ToolName
			if name == "" {
				name = "CBOM"
			}
			if err := m.add(&bom, sourceLabel{Label: fmt.Sprintf("%s #%d", name, imp.ID), Kind: "import", ImportID: imp.ID, When: imp.ReceivedAt}, fmt.Sprintf("import-%d/", imp.ID)); err != nil {
				return nil, err
			}
		}
	}

	out := m.result(s.cfg.Version, s.cfg.Now())
	pqc.Annotate(out, pqc.Analyze(out))
	inv.bom, inv.seenIn = bomView{out}, m.seenIn
	inv.deps = map[string][]string{}
	for r, set := range m.deps {
		for x := range set {
			inv.deps[r] = append(inv.deps[r], x)
		}
	}
	return inv, nil
}

// bomMerger unions components by bom-ref and dependencies by ref, remembering where each
// cryptographic component was seen.
type bomMerger struct {
	comps   []cdx.Component
	index   map[string]int
	deps    map[string]map[string]bool
	order   []string
	seenIn  map[string][]sourceLabel
	subject []string
}

func newBOMMerger() *bomMerger {
	return &bomMerger{index: map[string]int{}, deps: map[string]map[string]bool{}, seenIn: map[string][]sourceLabel{}}
}

func (m *bomMerger) add(bom *cdx.BOM, label sourceLabel, prefix string) error {
	ref := func(r string) string {
		if r == "" {
			return ""
		}
		return prefix + r
	}
	var subjectRef string
	if bom.Metadata != nil && bom.Metadata.Component != nil {
		sc := *bom.Metadata.Component
		sc.Components = nil
		if sc.BOMRef == "" {
			sc.BOMRef = "source/" + label.String()
		}
		sc.BOMRef = ref(sc.BOMRef)
		subjectRef = sc.BOMRef
		m.put(sc, label)
		m.subject = append(m.subject, subjectRef)
	}
	if bom.Components != nil {
		var walk func(cs []cdx.Component) error
		walk = func(cs []cdx.Component) error {
			for _, c := range cs {
				nested := c.Components
				c.Components = nil
				c.BOMRef = ref(c.BOMRef)
				if c.BOMRef == "" {
					continue
				}
				m.put(c, label)
				if len(m.comps) > maxInventoryComponents {
					return errInventoryTooLarge
				}
				if nested != nil {
					if err := walk(*nested); err != nil {
						return err
					}
				}
			}
			return nil
		}
		if err := walk(*bom.Components); err != nil {
			return err
		}
	}
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			r := ref(d.Ref)
			if r == "" {
				continue
			}
			set := m.deps[r]
			if set == nil {
				set = map[string]bool{}
				m.deps[r] = set
				m.order = append(m.order, r)
			}
			if d.Dependencies != nil {
				for _, x := range *d.Dependencies {
					set[ref(x)] = true
				}
			}
		}
	}
	return nil
}

func (m *bomMerger) put(c cdx.Component, label sourceLabel) {
	if _, ok := m.index[c.BOMRef]; !ok {
		m.index[c.BOMRef] = len(m.comps)
		m.comps = append(m.comps, c)
	}
	if !containsLabel(m.seenIn[c.BOMRef], label) {
		m.seenIn[c.BOMRef] = append(m.seenIn[c.BOMRef], label)
	}
}

const maxSeenIn = 20

func (m *bomMerger) result(version string, now time.Time) *cdx.BOM {
	for i := range m.comps {
		c := &m.comps[i]
		if c.CryptoProperties == nil {
			continue
		}
		var v []string
		for i, l := range m.seenIn[c.BOMRef] {
			if i == maxSeenIn {
				v = append(v, fmt.Sprintf("and %d more", len(m.seenIn[c.BOMRef])-maxSeenIn))
				break
			}
			v = append(v, l.String())
		}
		props := []cdx.Property{}
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if p.Name != "cipherhorizon:seen-in" {
					props = append(props, p)
				}
			}
		}
		props = append(props, cbom.Property("seen-in", strings.Join(v, "; ")))
		c.Properties = &props
	}
	deps := []cdx.Dependency{}
	root := "cipherhorizon-inventory"
	subjects := append([]string(nil), m.subject...)
	deps = append(deps, cdx.Dependency{Ref: root, Dependencies: &subjects})
	for _, r := range m.order {
		var list []string
		for x := range m.deps[r] {
			if x != "" {
				list = append(list, x)
			}
		}
		sort.Strings(list)
		deps = append(deps, cdx.Dependency{Ref: r, Dependencies: &list})
	}
	comps := m.comps
	bom := cdx.NewBOM()
	bom.SerialNumber = cbom.RandomSerial()
	bom.Metadata = &cdx.Metadata{
		Timestamp: now.UTC().Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "cipherhorizon", Version: version}}},
		Component: &cdx.Component{BOMRef: root, Type: cdx.ComponentTypeApplication, Name: "CipherHorizon cryptographic inventory"},
	}
	bom.Components = &comps
	bom.Dependencies = &deps
	return bom
}

func (s *Server) inventoryCBOM(w http.ResponseWriter, r *http.Request) {
	spec := r.URL.Query().Get("spec")
	if spec == "" {
		spec = cbom.DefaultSpec
	}
	if spec != cbom.Spec16 && spec != cbom.Spec17 {
		writeErr(w, http.StatusBadRequest, "spec must be 1.6 or 1.7")
		return
	}
	bom, err := s.inventoryBOM(r.URL.Query().Get("imported") == "1")
	if errors.Is(err, errInventoryTooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, bom, spec, true); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	extendWriteDeadline(w, s.log, downloadWriteTimeout)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="cipherhorizon-inventory-cbom-`+strconv.Itoa(int(s.cfg.Now().Unix()))+`.json"`)
	}
	_, _ = w.Write(buf.Bytes())
}
