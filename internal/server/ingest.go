package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/example/cipherhorizon/internal/pqc"
	"github.com/example/cipherhorizon/internal/store"
)

const maxCBOM = 32 << 20

// HostAlgorithm is one algorithm found in a host's CBOM with its verdict.
type HostAlgorithm struct {
	Name       string          `json:"name"`
	OID        string          `json:"oid,omitempty"`
	Class      string          `json:"class"`
	MatchedBy  string          `json:"matchedBy"`
	Rationale  string          `json:"rationale"`
	Basis      []pqc.Reference `json:"basis"`
	ProvidedBy []string        `json:"providedBy"` // package names; capability, not observed use
}

// HostSummary is the analysis of an uploaded CBOM.
type HostSummary struct {
	Name         string          `json:"name"`
	Producer     string          `json:"producer,omitempty"`
	Components   int             `json:"components"`
	Packages     int             `json:"packages"`
	Vulnerable   int             `json:"vulnerable"`
	Safe         int             `json:"safe"`
	Unclassified []string        `json:"unclassified"`
	Algorithms   []HostAlgorithm `json:"algorithms"`
	Timestamp    string          `json:"timestamp,omitempty"`
}

// summarizeCBOM analyses a CBOM with the same cited PQC rules used everywhere.
func summarizeCBOM(bom *cdx.BOM, name string) HostSummary {
	rep := pqc.Analyze(bom)
	names := map[string]string{}
	sum := HostSummary{Name: name, Unclassified: []string{}, Algorithms: []HostAlgorithm{}}
	if bom.Components != nil {
		sum.Components = len(*bom.Components)
		for _, c := range *bom.Components {
			label := c.Name
			if c.Version != "" {
				label += " " + c.Version
			}
			names[c.BOMRef] = label
			if c.Type == cdx.ComponentTypeLibrary || c.Type == cdx.ComponentTypeApplication {
				sum.Packages++
			}
		}
	}
	for _, f := range rep.Findings {
		provided := []string{}
		for _, ref := range f.ProvidedBy {
			if n := names[ref]; n != "" {
				provided = append(provided, n)
			}
		}
		sum.Algorithms = append(sum.Algorithms, HostAlgorithm{Name: f.Name, OID: f.OID, Class: string(f.Class),
			MatchedBy: f.MatchedBy, Rationale: f.Rationale, Basis: f.Basis, ProvidedBy: provided})
	}
	sum.Vulnerable, sum.Safe = rep.Count(pqc.Vulnerable), rep.Count(pqc.Safe)
	for _, ref := range rep.Unclassified {
		n := names[ref]
		if n == "" {
			n = ref
		}
		sum.Unclassified = append(sum.Unclassified, n)
	}
	if bom.Metadata != nil {
		sum.Timestamp = bom.Metadata.Timestamp
		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil && len(*bom.Metadata.Tools.Components) > 0 {
			t := (*bom.Metadata.Tools.Components)[0]
			sum.Producer = strings.TrimSpace(t.Name + " " + t.Version)
		}
	}
	return sum
}

func (s *Server) ingestHost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCBOM)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "CBOM larger than 32 MiB")
			return
		}
		writeErr(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(strings.NewReader(string(raw)), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		writeErr(w, http.StatusBadRequest, "not a valid CycloneDX JSON document: "+err.Error())
		return
	}
	if bom.BOMFormat != "CycloneDX" {
		writeErr(w, http.StatusBadRequest, "not a CycloneDX document (bomFormat is not CycloneDX)")
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" && bom.Metadata != nil && bom.Metadata.Component != nil {
		name = strings.TrimSpace(bom.Metadata.Component.Name)
	}
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "\r\n\t") {
		writeErr(w, http.StatusBadRequest, "the CBOM names no host: set metadata.component.name, or pass ?name= (1 to 100 characters)")
		return
	}

	asset, created, err := s.cfg.Store.UpsertHostAsset(name)
	if err != nil {
		storeErr(w, err)
		return
	}
	sum := summarizeCBOM(&bom, name)
	sumJSON, _ := json.Marshal(sum)
	id, err := s.cfg.Store.AddHostSnapshot(asset.ID, raw, sumJSON)
	if err != nil {
		storeErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"asset": view(asset, nil), "snapshotId": id, "created": created, "summary": sum})
}

type hostView struct {
	assetView
	Summary   *HostSummary `json:"summary"`
	UpdatedAt *time.Time   `json:"snapshotAt"`
	Snapshots int          `json:"snapshots"`
}

func (s *Server) hostFor(a store.Asset, links map[int64][]int64) hostView {
	hv := hostView{assetView: view(a, links)}
	snaps, err := s.cfg.Store.HostSnapshots(a.ID, 50)
	if err != nil || len(snaps) == 0 {
		return hv
	}
	hv.Snapshots = len(snaps)
	at := snaps[0].At
	hv.UpdatedAt = &at
	var sum HostSummary
	if json.Unmarshal(snaps[0].Summary, &sum) == nil {
		hv.Summary = &sum
	}
	return hv
}

func (s *Server) listHosts(w http.ResponseWriter, _ *http.Request) {
	as, err := s.cfg.Store.ListAssets(store.KindHost)
	if err != nil {
		storeErr(w, err)
		return
	}
	links, err := s.cfg.Store.AllLinks()
	if err != nil {
		storeErr(w, err)
		return
	}
	out := make([]hostView, 0, len(as))
	for _, a := range as {
		out = append(out, s.hostFor(a, links))
	}
	writeJSON(w, 200, out)
}

func (s *Server) getHost(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	a, err := s.cfg.Store.GetAsset(id)
	if err != nil || a.Kind != store.KindHost {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	linked, err := s.cfg.Store.LinkedAssetIDs(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	hv := s.hostFor(a, map[int64][]int64{id: linked})
	snaps, _ := s.cfg.Store.HostSnapshots(id, 50)
	history := make([]map[string]any, 0, len(snaps))
	for _, sn := range snaps {
		var sum HostSummary
		_ = json.Unmarshal(sn.Summary, &sum)
		history = append(history, map[string]any{"id": sn.ID, "at": sn.At, "vulnerable": sum.Vulnerable, "safe": sum.Safe, "packages": sum.Packages})
	}
	writeJSON(w, 200, map[string]any{"host": hv, "history": history})
}

// hostSnapshotCBOM downloads one of a host's raw uploaded CBOMs, closing the
// asymmetry with TLS endpoints (which can already export a CBOM on demand).
func (s *Server) hostSnapshotCBOM(w http.ResponseWriter, r *http.Request) {
	hostID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	snapID, err := strconv.ParseInt(r.PathValue("snapshotId"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid snapshot id")
		return
	}
	snaps, err := s.cfg.Store.HostSnapshots(hostID, 50)
	if err != nil {
		storeErr(w, err)
		return
	}
	found := false
	for _, sn := range snaps {
		if sn.ID == snapID {
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	b, err := s.cfg.Store.HostCBOM(snapID)
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="host-%d-snapshot-%d-cbom.json"`, hostID, snapID))
	}
	_, _ = w.Write(b)
}
