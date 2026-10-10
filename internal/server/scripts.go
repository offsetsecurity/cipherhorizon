package server

import (
	"fmt"
	"net/http"

	"github.com/offsetsecurity/cipherhorizon/internal/machinefacts"
	"github.com/offsetsecurity/cipherhorizon/internal/signatures"
)

// listInventoryScripts describes the machine inventory scripts (name, platform, command, SHA-256).
func (s *Server) listInventoryScripts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"scripts": machinefacts.Scripts()})
}

// inventoryScript serves one script as plain text, to read or to save.
func (s *Server) inventoryScript(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	for _, sc := range machinefacts.Scripts() {
		if sc.Name != name {
			continue
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.URL.Query().Get("download") == "1" {
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sc.Name))
		}
		w.Header().Set("X-Content-SHA256", sc.SHA256)
		_, _ = w.Write(sc.Body())
		return
	}
	writeErr(w, http.StatusNotFound, "no such script")
}

// listSignatures publishes the signature database: everything the inventory scripts collect,
// how and why (PRD-006 REQ-SG-4).
func (s *Server) listSignatures(w http.ResponseWriter, _ *http.Request) {
	db, err := signatures.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, 200, db)
}
