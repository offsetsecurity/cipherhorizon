package server

import (
	"net/http"
	"strings"

	"github.com/offsetsecurity/cipherhorizon/internal/revocation"
	"github.com/offsetsecurity/cipherhorizon/internal/store"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
)

// Scan settings (0.5.1). The command line sets the defaults when the server starts; Settings
// stores overrides; every scan reads the effective values when it starts, so a change applies to
// the next scan without a restart.

// ScanConfig is the effective scan configuration and where each value comes from.
type ScanConfig struct {
	HTTPChecks bool `json:"httpChecks"`
	CRL        bool `json:"crlLookups"`
	CRLPrivate bool `json:"crlPrivate"`
	// Defaults are the command line's values, shown so "reset" is meaningful.
	Defaults struct {
		HTTPChecks bool `json:"httpChecks"`
		CRL        bool `json:"crlLookups"`
		CRLPrivate bool `json:"crlPrivate"`
	} `json:"defaults"`
	// Overridden names the values Settings changed from the command line.
	Overridden []string `json:"overridden"`
}

// scanConfig reads the effective configuration: stored overrides over the command-line defaults.
func (r *Runner) scanConfig() ScanConfig {
	var c ScanConfig
	c.Defaults.HTTPChecks = r.opts.Scan.HTTPChecks
	c.Defaults.CRL = r.opts.Scan.CRL != nil
	c.Defaults.CRLPrivate = r.opts.CRLPrivate
	c.HTTPChecks, c.CRL, c.CRLPrivate = c.Defaults.HTTPChecks, c.Defaults.CRL, c.Defaults.CRLPrivate
	c.Overridden = []string{}
	st, err := r.st.ScanSettings()
	if err != nil {
		r.log.Error("reading the scan settings; using the command line's", "err", err)
		return c
	}
	if st.HTTPChecks != nil {
		c.HTTPChecks = *st.HTTPChecks
		c.Overridden = append(c.Overridden, "httpChecks")
	}
	if st.CRL != nil {
		c.CRL = *st.CRL
		c.Overridden = append(c.Overridden, "crlLookups")
	}
	if st.CRLPrivate != nil {
		c.CRLPrivate = *st.CRLPrivate
		c.Overridden = append(c.Overridden, "crlPrivate")
	}
	return c
}

// ScanConfig is the effective scan configuration, for the API.
func (r *Runner) ScanConfig() ScanConfig { return r.scanConfig() }

// scanOptions applies the effective configuration to a copy of the base options. One CRL fetcher
// per policy is kept for the server's life, so its cache spans scans.
func (r *Runner) scanOptions() tlsprobe.Options {
	o := r.opts.Scan
	c := r.scanConfig()
	o.HTTPChecks = c.HTTPChecks
	o.CRL = nil
	if c.CRL {
		o.CRL = r.crlFetcher(c.CRLPrivate)
	}
	return o
}

func (r *Runner) crlFetcher(private bool) tlsprobe.CRLFetcher {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fetchers == nil {
		r.fetchers = map[bool]tlsprobe.CRLFetcher{}
	}
	if f, ok := r.fetchers[private]; ok {
		return f
	}
	var f tlsprobe.CRLFetcher
	// The command line's fetcher is reused for its own policy, so its cache is kept.
	if r.opts.Scan.CRL != nil && private == r.opts.CRLPrivate {
		f = r.opts.Scan.CRL
	} else {
		f = revocation.New(revocation.Policy{AllowPrivate: private, AllowLoopback: private})
	}
	r.fetchers[private] = f
	return f
}

// putScanSettings stores the scan settings from Settings. Each field is "on", "off" or "default"
// (the command line decides again).
func (s *Server) putScanSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		HTTPChecks string `json:"httpChecks"`
		CRLLookups string `json:"crlLookups"`
		CRLPrivate string `json:"crlPrivate"`
	}
	if !decode(w, r, &in) {
		return
	}
	parse := func(name, v string) (*bool, bool) {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "on", "true":
			b := true
			return &b, true
		case "off", "false":
			b := false
			return &b, true
		case "", "default":
			return nil, true
		}
		writeErr(w, http.StatusBadRequest, name+" must be on, off or default")
		return nil, false
	}
	var v store.ScanSettings
	var ok bool
	if v.HTTPChecks, ok = parse("httpChecks", in.HTTPChecks); !ok {
		return
	}
	if v.CRL, ok = parse("crlLookups", in.CRLLookups); !ok {
		return
	}
	if v.CRLPrivate, ok = parse("crlPrivate", in.CRLPrivate); !ok {
		return
	}
	if err := s.cfg.Store.SetScanSettings(v); err != nil {
		storeErr(w, err)
		return
	}
	c := s.cfg.Runner.ScanConfig()
	s.audit(r, "scan-settings-changed", s.actor(r), "HTTP check "+word(c.HTTPChecks)+", CRL lookups "+word(c.CRL)+", private CRL servers "+word(c.CRLPrivate))
	writeJSON(w, http.StatusOK, c)
}

func word(b bool) string {
	if b {
		return "on"
	}
	return "off"
}
