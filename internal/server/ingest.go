package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/estate"
	"github.com/offsetsecurity/cipherhorizon/internal/importer"
	"github.com/offsetsecurity/cipherhorizon/internal/machinefacts"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

const maxCBOM = 32 << 20

// uploadSlots bounds how many large documents (host uploads, imports) are read and decoded at
// once: each can hold tens of MiB in memory while it is parsed.
var uploadSlots = make(chan struct{}, 2)

// uploadSlot waits for an upload slot; it answers 503 itself if the client gives up first.
func uploadSlot(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	select {
	case uploadSlots <- struct{}{}:
		return func() { <-uploadSlots }, true
	case <-r.Context().Done():
		writeErr(w, http.StatusServiceUnavailable, "the server is busy with other uploads; try again")
		return nil, false
	}
}

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
	// Coverage is how complete the inventory is; nil when the CBOM does not say.
	Coverage *HostCoverage `json:"coverage,omitempty"`
	// Legacy lists algorithms the CBOM marks as retired or broken for classical
	// reasons, each with the source it cites. This is separate from the post-quantum
	// verdict: MD5 is not "quantum-vulnerable", it is unsafe against today's computers.
	Legacy []HostLegacy `json:"legacy"`
}

// HostLegacy is one retired or broken algorithm found on a host.
type HostLegacy struct {
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	Basis      string   `json:"basis"`
	ProvidedBy []string `json:"providedBy"`
}

// summarizeCBOM analyses a CBOM with the same cited PQC rules used everywhere.
func summarizeCBOM(bom *cdx.BOM, name string) HostSummary {
	rep := pqc.Analyze(bom)
	names := map[string]string{}
	sum := HostSummary{Name: name, Unclassified: []string{}, Algorithms: []HostAlgorithm{}, Legacy: []HostLegacy{}}
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
	sum.Coverage = coverageFromBOM(bom)
	sum.Legacy = legacyFromBOM(bom, names)
	if bom.Metadata != nil {
		sum.Timestamp = bom.Metadata.Timestamp
		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil && len(*bom.Metadata.Tools.Components) > 0 {
			t := (*bom.Metadata.Tools.Components)[0]
			sum.Producer = strings.TrimSpace(t.Name + " " + t.Version)
		}
	}
	return sum
}

// validHostName accepts 1 to 100 printable characters of valid UTF-8. Control
// characters (line breaks included), format characters (which cover the
// bidirectional overrides and zero-width characters) and line or paragraph
// separators are refused, so the name is safe in logs, headers and file names
// and cannot be made to read differently from what it is.
func validHostName(name string) bool {
	if name == "" || len(name) > 100 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

func (s *Server) ingestHost(w http.ResponseWriter, r *http.Request) {
	release, ok := uploadSlot(w, r)
	if !ok {
		return
	}
	defer release()
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
	// A facts file from an inventory script is turned into a CBOM here, by the collector's own
	// sensors and knowledge, and from then on is handled like any collector upload.
	if machinefacts.IsFacts(raw) {
		facts, err := machinefacts.Parse(raw)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "not a valid inventory facts file: "+err.Error())
			return
		}
		converted, err := machinefacts.ToCBOM(r.Context(), facts, machinefacts.Options{ToolVersion: s.cfg.Version, Now: s.cfg.Now})
		if err != nil {
			writeErr(w, http.StatusBadRequest, "could not inventory the facts file: "+err.Error())
			return
		}
		var buf bytes.Buffer
		if err := cbom.EncodeSpec(&buf, converted, cbom.Spec16, true); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		raw = buf.Bytes()
	}
	// The same limits as an import: depth, value count and string length are checked on the token
	// stream before anything is decoded into memory.
	if err := importer.CheckLimits(raw, importer.DefaultLimits); err != nil {
		var ie *importer.Error
		if errors.As(err, &ie) && ie.Stage == "limits" {
			writeErr(w, http.StatusRequestEntityTooLarge, ie.Message)
			return
		}
		writeErr(w, http.StatusBadRequest, "not a valid CycloneDX JSON document: "+err.Error())
		return
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
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
	if !validHostName(name) {
		writeErr(w, http.StatusBadRequest, "the CBOM names no host: set metadata.component.name, or pass ?name= (1 to 100 printable characters)")
		return
	}

	asset, created, err := s.cfg.Store.UpsertHostAsset(name)
	if err != nil {
		storeErr(w, err)
		return
	}
	sum := summarizeCBOM(&bom, name)
	sumJSON, _ := json.Marshal(sum)
	// Trust follows the channel, not the document (SECARCH-001 T-03). Until the collector has an
	// authenticated push of its own, this token-protected upload route is what carries its output,
	// so a document that names this product as its producer is attributed to the collector and
	// anything else is imported. A token holder can still mislabel a document; that is the
	// operator-mislabel residual the threat model states, and the class is recorded per source.
	class := estate.ClassImported
	if strings.HasPrefix(strings.ToLower(sum.Producer), "cipherhorizon") {
		class = estate.ClassCollector
	}
	id, err := s.cfg.Store.AddHostSnapshotAs(asset.ID, raw, sumJSON, class, s.actor(r))
	if errors.Is(err, store.ErrQuota) {
		writeErr(w, http.StatusInsufficientStorage, err.Error()+"; ask an administrator to remove hosts that are no longer needed")
		return
	}
	if err != nil {
		storeErr(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"asset": view(asset, nil), "snapshotId": id, "created": created, "summary": sum, "sourceClass": class})
}

type hostView struct {
	assetView
	Summary   *HostSummary `json:"summary"`
	UpdatedAt *time.Time   `json:"snapshotAt"`
	Snapshots int          `json:"snapshots"`
	// SnapshotID is the latest upload, whose CBOM the Reports page offers.
	SnapshotID int64 `json:"snapshotId,omitempty"`
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
	hv.SnapshotID = snaps[0].ID
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
	snaps, err := s.cfg.Store.HostSnapshots(id, 50)
	if err != nil {
		storeErr(w, err)
		return
	}
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
	extendWriteDeadline(w, s.log, downloadWriteTimeout)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="host-%d-snapshot-%d-cbom.json"`, hostID, snapID))
	}
	_, _ = w.Write(b)
}
