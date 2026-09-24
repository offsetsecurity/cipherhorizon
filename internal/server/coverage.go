package server

import (
	"regexp"
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
