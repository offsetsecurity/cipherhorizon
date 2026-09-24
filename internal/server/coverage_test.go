package server

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func bomWith(props ...[2]string) *cdx.BOM {
	ps := make([]cdx.Property, 0, len(props))
	for _, p := range props {
		ps = append(ps, cdx.Property{Name: p[0], Value: p[1]})
	}
	return &cdx.BOM{Metadata: &cdx.Metadata{Properties: &ps}}
}

func TestCoverageIsReadFromTheRunProperties(t *testing.T) {
	cov := coverageFromBOM(bomWith(
		[2]string{"cipherhorizon:privilege-tier", "user"},
		[2]string{"cipherhorizon:host-os", "windows 10.0.26200"},
		[2]string{"cipherhorizon:coverage-note", "129 location(s) could not be read"},
		[2]string{"cipherhorizon:coverage", "sensor=pe-files status=partial reason=permission denied=129 scope=crypto-library files under Program Files"},
		[2]string{"cipherhorizon:coverage", "sensor=dpkg status=unsupported"},
		[2]string{"cipherhorizon:not-seen", "certificates"},
		[2]string{"unrelated:thing", "ignored"},
	))
	if cov == nil {
		t.Fatal("coverage not found")
	}
	if cov.Privilege != "user" || cov.OS != "windows 10.0.26200" || cov.Note == "" || len(cov.NotSeen) != 1 {
		t.Errorf("run properties = %+v", cov)
	}
	if len(cov.Sensors) != 2 {
		t.Fatalf("sensors = %+v", cov.Sensors)
	}
	s := cov.Sensors[0]
	if s.Sensor != "pe-files" || s.Status != "partial" || s.Reason != "permission" || s.Denied != 129 || !strings.HasPrefix(s.Scope, "crypto-library files") {
		t.Errorf("first sensor = %+v", s)
	}
	if s := cov.Sensors[1]; s.Sensor != "dpkg" || s.Status != "unsupported" || s.Reason != "" || s.Denied != 0 || s.Scope != "" {
		t.Errorf("second sensor = %+v", s)
	}
}

func TestCoverageIsAbsentNotCompleteWhenTheCBOMDoesNotSay(t *testing.T) {
	if coverageFromBOM(&cdx.BOM{}) != nil || coverageFromBOM(bomWith([2]string{"other:x", "y"})) != nil {
		t.Error("a CBOM without run properties must yield no coverage, not an empty one")
	}
}

func TestCoverageBoundsHostileText(t *testing.T) {
	long := strings.Repeat("é", 5000)
	props := [][2]string{{"cipherhorizon:coverage-note", long}}
	for i := 0; i < 100; i++ {
		props = append(props, [2]string{"cipherhorizon:not-seen", long})
	}
	cov := coverageFromBOM(bomWith(props...))
	if len([]rune(cov.Note)) > 400 || len(cov.NotSeen) > 30 || len([]rune(cov.NotSeen[0])) > 300 {
		t.Errorf("unbounded: note %d, not-seen %d", len([]rune(cov.Note)), len(cov.NotSeen))
	}
}
