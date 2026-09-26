package server

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// propPrefix is the namespace of the properties the collector writes about a run.
const propPrefix = "cipherhorizon:"

// SensorCoverage is what one sensor covered on the host, as the collector recorded it.
type SensorCoverage struct {
	Sensor string `json:"sensor"`
	Status string `json:"status"` // complete | partial | unsupported | failed
	Reason string `json:"reason,omitempty"`
	Denied int    `json:"denied,omitempty"`
	Scope  string `json:"scope,omitempty"`
}

// HostCoverage says how complete an uploaded inventory is: which privilege it
// ran with, what each sensor covered and what none of them could see. Its
// absence (an older or third-party CBOM) means "not recorded", never "complete".
type HostCoverage struct {
	OS        string           `json:"os,omitempty"`
	Privilege string           `json:"privilege,omitempty"` // user | admin | root
	Note      string           `json:"note,omitempty"`
	Sensors   []SensorCoverage `json:"sensors"`
	NotSeen   []string         `json:"notSeen"`
	Redacted  bool             `json:"redacted,omitempty"` // the host name is a stable label, not the real one
}

var coverageRE = regexp.MustCompile(`^sensor=(\S+) status=(\S+)(?: reason=(.*?))?(?: denied=(\d+))?(?: scope=(.*))?$`)

// coverageFromBOM reads the run properties; it returns nil when the document
// records none of them.
func coverageFromBOM(bom *cdx.BOM) *HostCoverage {
	if bom.Metadata == nil || bom.Metadata.Properties == nil {
		return nil
	}
	cov := &HostCoverage{Sensors: []SensorCoverage{}, NotSeen: []string{}}
	found := false
	for _, p := range *bom.Metadata.Properties {
		name, ok := strings.CutPrefix(p.Name, propPrefix)
		if !ok {
			continue
		}
		v := strings.TrimSpace(p.Value)
		switch name {
		case "privilege-tier":
			cov.Privilege, found = clip(v, 20), true
		case "host-os":
			cov.OS, found = clip(v, 80), true
		case "coverage-note":
			cov.Note, found = clip(v, 400), true
		case "host-id":
			cov.Redacted = true
		case "coverage":
			if m := coverageRE.FindStringSubmatch(v); m != nil {
				denied, _ := strconv.Atoi(m[4])
				cov.Sensors = append(cov.Sensors, SensorCoverage{Sensor: clip(m[1], 40), Status: clip(m[2], 20),
					Reason: clip(m[3], 120), Denied: denied, Scope: clip(m[5], 200)})
				found = true
			}
		case "not-seen":
			if len(cov.NotSeen) < 30 {
				cov.NotSeen = append(cov.NotSeen, clip(v, 300))
			}
			found = true
		}
	}
	if !found {
		return nil
	}
	return cov
}

// clip bounds attacker-controlled text before it is stored and shown.
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// legacyFromBOM lists the algorithm components that carry a cited classical status,
// with the components that provide them. Text is bounded: it came from a document.
func legacyFromBOM(bom *cdx.BOM, names map[string]string) []HostLegacy {
	out := []HostLegacy{}
	if bom.Components == nil {
		return out
	}
	providers := map[string][]string{} // algorithm bom-ref -> provider names
	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if d.Provides == nil {
				continue
			}
			for _, ref := range *d.Provides {
				if n := names[d.Ref]; n != "" {
					providers[ref] = append(providers[ref], n)
				}
			}
		}
	}
	for _, c := range *bom.Components {
		if c.Type != cdx.ComponentTypeCryptographicAsset || c.Properties == nil {
			continue
		}
		var status, basis string
		for _, p := range *c.Properties {
			switch p.Name {
			case propPrefix + "classical-status":
				status = clip(strings.TrimSpace(p.Value), 300)
			case propPrefix + "classical-basis":
				basis = clip(strings.TrimSpace(p.Value), 400)
			}
		}
		if status == "" {
			continue
		}
		list := providers[c.BOMRef]
		if len(list) > 30 {
			list = list[:30]
		}
		out = append(out, HostLegacy{Name: clip(c.Name, 100), Status: status, Basis: basis, ProvidedBy: uniqueSorted(list)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
