package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/refdata"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// Private trust anchors, reference data and re-evaluation (PRD-004 REQ-TTRS-2,
// REQ-TDAT-3, REQ-TNFR-4).

// maxAnchorUpload bounds one anchor upload (the PEM text).
const maxAnchorUpload = 64 << 10

func (s *Server) listTrustAnchors(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetSystem(id); err != nil {
		storeErr(w, err)
		return
	}
	list, err := s.cfg.Store.TrustAnchors(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"anchors": list, "max": store.MaxAnchorsPerSystem})
}

func (s *Server) addTrustAnchors(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAnchorUpload+1024)
	var req struct {
		PEM string `json:"pem"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "the upload is larger than 64 KiB")
			return
		}
		writeErr(w, http.StatusBadRequest, `the body must be {"pem": "..."}`)
		return
	}
	if len(req.PEM) > maxAnchorUpload {
		writeErr(w, http.StatusRequestEntityTooLarge, "the upload is larger than 64 KiB")
		return
	}
	certs, err := ParseAnchors([]byte(req.PEM), store.MaxAnchorsPerSystem)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	in := make([]store.AnchorCert, 0, len(certs))
	for _, c := range certs {
		in = append(in, store.AnchorCert{SHA256: c.SHA, Subject: clip(c.Cert.Subject.String(), 300), NotAfter: c.Cert.NotAfter, DER: c.Cert.Raw})
	}
	added, err := s.cfg.Store.AddTrustAnchors(id, in, s.actor(r))
	switch {
	case errors.Is(err, store.ErrTooManyAnchors):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		storeErr(w, err)
		return
	}
	n := 0
	if len(added) > 0 {
		n = s.cfg.Runner.ReevaluateSystem(id, "trust anchors added")
	}
	list, err := s.cfg.Store.TrustAnchors(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	if added == nil {
		added = []store.TrustAnchor{}
	}
	writeJSON(w, 200, map[string]any{"added": added, "anchors": list, "reevaluated": n})
}

func (s *Server) removeTrustAnchor(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	fp := strings.ToLower(r.PathValue("fingerprint"))
	if !fingerprintRE.MatchString(fp) {
		writeErr(w, http.StatusBadRequest, "fingerprint must be 64 lower-case hex characters")
		return
	}
	if err := s.cfg.Store.RemoveTrustAnchor(id, fp, s.actor(r)); err != nil {
		storeErr(w, err)
		return
	}
	n := s.cfg.Runner.ReevaluateSystem(id, "trust anchor removed")
	writeJSON(w, 200, map[string]any{"removed": fp, "reevaluated": n})
}

// serverTrustAnchors lists the server-wide bundle (read-only; set with --ca-bundle).
func (s *Server) serverTrustAnchors(w http.ResponseWriter, _ *http.Request) {
	out := []store.TrustAnchor{}
	for _, a := range s.cfg.Runner.CABundle() {
		out = append(out, store.TrustAnchor{SHA256: a.SHA, Subject: clip(a.Cert.Subject.String(), 300), NotAfter: a.Cert.NotAfter.UTC(), AddedBy: "--ca-bundle"})
	}
	writeJSON(w, 200, map[string]any{"anchors": out})
}

type refView struct {
	refdata.Source
	AgeDays int  `json:"ageDays"`
	Stale   bool `json:"stale"`
}

func (s *Server) referenceData(w http.ResponseWriter, _ *http.Request) {
	now := s.cfg.Now()
	out := []refView{}
	for _, src := range refdata.Sources() {
		age := src.Age(now)
		out = append(out, refView{Source: src, AgeDays: age, Stale: age > refdata.StaleAfterDays})
	}
	writeJSON(w, 200, map[string]any{
		"lists": out, "staleAfterDays": refdata.StaleAfterDays,
		"attribution": "Root-store data is derived from the Common CA Database (CCADB), used under the CCADB Data Usage Terms " +
			"(CDLA-Permissive-2.0). The CCADB does not endorse this product.",
	})
}

func (s *Server) reevaluateScan(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	ev, err := s.cfg.Runner.Reevaluate(id, "requested")
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "no completed scan with that id")
			return
		}
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, ev)
}
