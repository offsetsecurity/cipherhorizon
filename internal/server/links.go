package server

import (
	"net/http"

	"github.com/example/cipherhorizon/internal/store"
)

func (s *Server) listLinks(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "", store.LinkProposed, store.LinkConfirmed, store.LinkRejected:
	case "all":
		state = ""
	default:
		writeErr(w, http.StatusBadRequest, "state must be proposed, confirmed, rejected or all")
		return
	}
	links, err := s.cfg.Store.Links(state)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, links)
}

func (s *Server) systemLinks(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.Store.GetSystem(id); err != nil {
		storeErr(w, err)
		return
	}
	links, err := s.cfg.Store.SystemLinks(id)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, 200, links)
}

func (s *Server) confirmLink(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	l, err := s.cfg.Store.ConfirmLink(id, s.actor(), reason)
	if err != nil {
		systemErr(w, err)
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) rejectLink(w http.ResponseWriter, r *http.Request) {
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	reason, ok := reasonOf(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "reason is over 200 characters or contains a control character")
		return
	}
	l, err := s.cfg.Store.RejectLink(id, s.actor(), reason)
	if err != nil {
		systemErr(w, err)
		return
	}
	writeJSON(w, 200, l)
}
