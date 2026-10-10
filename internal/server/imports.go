package server

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/importer"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

// importReply is what an upload returns: the record, what the producer profile made of it, and
// whether these exact bytes were already imported.
type importReply struct {
	Import       store.ImportRecord `json:"import"`
	ProfileLabel string             `json:"profileLabel"`
	Duplicate    bool               `json:"duplicate"`
}

// importDocument accepts a third-party CycloneDX CBOM (1.6 or 1.7) and attaches it to a system
// the OPERATOR names: ?system=ID for an existing one or ?newSystem=NAME. What the document says
// about its own subject is recorded and shown, and never decides where its data goes (SR-04).
func (s *Server) importDocument(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var systemID int64
	newName := strings.TrimSpace(q.Get("newSystem"))
	if v := q.Get("system"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, "system must be the id of an existing system")
			return
		}
		systemID = id
	}
	if (systemID == 0) == (newName == "") {
		writeErr(w, http.StatusBadRequest, "say which system the document describes: system=ID for an existing one, or newSystem=NAME for a new one (exactly one)")
		return
	}
	release, ok := uploadSlot(w, r)
	if !ok {
		return
	}
	defer release()
	r.Body = http.MaxBytesReader(w, r.Body, int64(importer.DefaultLimits.MaxBytes))
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, "the document is larger than 32 MiB")
			return
		}
		writeErr(w, http.StatusBadRequest, "could not read the request body")
		return
	}
	doc, err := importer.Parse(raw, importer.DefaultLimits)
	if err != nil {
		var ie *importer.Error
		if errors.As(err, &ie) {
			code := http.StatusBadRequest
			if ie.Stage == "limits" {
				code = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, code, map[string]any{"error": ie.Message, "stage": ie.Stage, "problems": ie.Problems})
			return
		}
		writeErr(w, http.StatusBadRequest, "the document could not be read")
		return
	}
	rec, dup, err := s.cfg.Store.AddImport(store.ImportInput{
		Raw: raw, SHA256: doc.SHA256, SpecVersion: doc.SpecVersion, Profile: doc.Profile.ID, Kind: doc.Profile.Kind,
		ToolName: doc.ToolName, ToolVersion: doc.ToolVersion, SubjectClaim: doc.SubjectClaim, SubmittedBy: s.actor(r),
		SystemID: systemID, NewSystemName: newName,
	})
	switch {
	case errors.Is(err, store.ErrAlreadyImported):
		writeErr(w, http.StatusConflict, "this exact document is already imported for another system; withdraw that import first")
		return
	case err != nil:
		systemErr(w, err)
		return
	}
	status := http.StatusCreated
	if dup {
		status = http.StatusOK
	}
	writeJSON(w, status, importReply{Import: rec, ProfileLabel: doc.Profile.Label, Duplicate: dup})
}

func (s *Server) listImports(w http.ResponseWriter, _ *http.Request) {
	recs, err := s.cfg.Store.Imports()
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, recs)
}

func (s *Server) getImport(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	rec, err := s.cfg.Store.GetImport(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, rec)
}

func (s *Server) withdrawImport(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	if err := s.cfg.Store.WithdrawImport(id, s.actor(r), reason); err != nil {
		storeErr(w, err)
		return
	}
	rec, err := s.cfg.Store.GetImport(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, rec)
}
