package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/x509view"
)

// x509Source says where the decoded certificate came from: the scan, the endpoint, and where in
// the chain it was served.
type x509Source struct {
	ScanID      int64  `json:"scanId"`
	AssetID     int64  `json:"assetId"`
	AssetName   string `json:"assetName"`
	Position    int    `json:"position"`
	ChainLength int    `json:"chainLength"`
	NoSNI       bool   `json:"noSni,omitempty"`
}

// getCertificateX509 decodes a certificate's stored DER (PRD-012 REQ-XV-1, REQ-XV-3): from the
// scan the page came from (?scan=), else from the newest endpoint scan that saw it. Nothing new is
// stored, so a scan made before this view existed shows it too. A certificate known only from a
// source that kept no DER answers der: false with the reason.
func (s *Server) getCertificateX509(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fingerprint")
	if !fingerprintRE.MatchString(fp) {
		writeErr(w, http.StatusBadRequest, "a certificate is identified by its 64-digit SHA-256 fingerprint")
		return
	}
	fp = strings.ToLower(fp)
	var scans []int64
	if v := r.URL.Query().Get("scan"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, "scan must be a scan id")
			return
		}
		scans = append(scans, id)
	}
	places, known, err := s.cfg.Store.CertificatePlaces(fp)
	if err != nil {
		storeErr(w, err)
		return
	}
	seen := map[int64]bool{}
	for _, p := range places {
		if p.AssetID == 0 || !store.IsEndpoint(p.AssetKind) || seen[p.AssetID] {
			continue
		}
		seen[p.AssetID] = true
		if a, err := s.cfg.Store.GetAsset(p.AssetID); err == nil && a.LastDone != nil {
			scans = append(scans, a.LastDone.ID)
		}
	}
	for _, id := range scans {
		src, der, issuer, ok := s.findDER(id, fp)
		if !ok {
			continue
		}
		v, err := x509view.DecodeBase64(der, issuer)
		if err != nil {
			writeJSON(w, 200, map[string]any{"der": false, "reason": "the stored certificate could not be decoded: " + err.Error(), "source": src})
			return
		}
		writeJSON(w, 200, map[string]any{"der": true, "x509": v, "source": src})
		return
	}
	if known {
		writeJSON(w, 200, map[string]any{"der": false, "reason": "No source kept this certificate's raw bytes (an imported CBOM, a machine inventory, or a scan made before tls-report/2), so only the fields above are known."})
		return
	}
	writeErr(w, http.StatusNotFound, "not found")
}

// findDER looks for the certificate in one scan's report: its DER, its issuer (the next
// certificate in the chain, when the server sent it), and where it was served.
func (s *Server) findDER(scanID int64, fp string) (x509Source, string, *x509.Certificate, bool) {
	sc, err := s.cfg.Store.GetScan(scanID)
	if err != nil {
		return x509Source{}, "", nil, false
	}
	raw, err := s.cfg.Store.Report(scanID)
	if err != nil || len(raw) == 0 {
		return x509Source{}, "", nil, false
	}
	var rep tlsprobe.Report
	if json.Unmarshal(raw, &rep) != nil {
		return x509Source{}, "", nil, false
	}
	for _, cr := range rep.Certificates {
		for i, ci := range cr.Chain {
			if !strings.EqualFold(ci.SHA256, fp) || ci.DER == "" {
				continue
			}
			var issuer *x509.Certificate
			if i+1 < len(cr.Chain) && cr.Chain[i+1].DER != "" {
				if b, err := base64.StdEncoding.DecodeString(cr.Chain[i+1].DER); err == nil {
					issuer, _ = x509.ParseCertificate(b)
				}
			}
			name := ""
			if a, err := s.cfg.Store.GetAsset(sc.AssetID); err == nil {
				name = a.Name
			}
			return x509Source{ScanID: scanID, AssetID: sc.AssetID, AssetName: name, Position: i, ChainLength: len(cr.Chain), NoSNI: cr.NoSNI}, ci.DER, issuer, true
		}
	}
	return x509Source{}, "", nil, false
}
