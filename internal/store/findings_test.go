package store_test

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/store"
)

func TestFindingStatusSetGetClear(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)

	if got, err := s.FindingStatuses(a.ID); err != nil || len(got) != 0 {
		t.Fatalf("new asset should have no triage: %v %v", got, err)
	}

	if err := s.SetFindingStatus(a.ID, "CIPHER.RC4", store.FindingAcknowledged, "seen it"); err != nil {
		t.Fatal(err)
	}
	got, err := s.FindingStatuses(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fs, ok := got["CIPHER.RC4"]; !ok || fs.Status != store.FindingAcknowledged || fs.Note != "seen it" {
		t.Errorf("status = %+v", got)
	}

	// Setting again replaces, it does not duplicate.
	if err := s.SetFindingStatus(a.ID, "CIPHER.RC4", store.FindingAcceptedRisk, "won't fix"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.FindingStatuses(a.ID)
	if len(got) != 1 || got["CIPHER.RC4"].Status != store.FindingAcceptedRisk {
		t.Errorf("status after replace = %+v", got)
	}

	if err := s.ClearFindingStatus(a.ID, "CIPHER.RC4"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.FindingStatuses(a.ID)
	if len(got) != 0 {
		t.Errorf("status after clear = %+v", got)
	}
}

func TestFindingStatusRejectsUnknownStatus(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	if err := s.SetFindingStatus(a.ID, "CIPHER.RC4", "resolved", ""); err == nil {
		t.Error("\"resolved\" must never be a settable status: it is derived, not asserted")
	}
}

func TestFindingStatusDeletedWithAsset(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	if err := s.SetFindingStatus(a.ID, "CIPHER.RC4", store.FindingAcknowledged, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(a.ID); err != nil {
		t.Fatal(err)
	}
	all, err := s.AllFindingStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all[a.ID]; ok {
		t.Error("triage should cascade-delete with its asset")
	}
}

func TestAllFindingStatusesSpansAssets(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	b := asset(t, s, "b.example", 443)
	if err := s.SetFindingStatus(a.ID, "CIPHER.RC4", store.FindingAcknowledged, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.SetFindingStatus(b.ID, "pqc:RSA", store.FindingAcceptedRisk, ""); err != nil {
		t.Fatal(err)
	}
	all, err := s.AllFindingStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[a.ID]["CIPHER.RC4"].Status != store.FindingAcknowledged || all[b.ID]["pqc:RSA"].Status != store.FindingAcceptedRisk {
		t.Errorf("all = %+v", all)
	}
}

func TestLinkAssets(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	h, _, err := s.UpsertHostAsset("a-host")
	if err != nil {
		t.Fatal(err)
	}

	if got, err := s.LinkedAssetIDs(a.ID); err != nil || len(got) != 0 {
		t.Fatalf("unlinked asset should report no links: %v %v", got, err)
	}

	if err := s.LinkAssets(a.ID, h.ID); err != nil {
		t.Fatal(err)
	}
	// Linking again must not error or duplicate (idempotent).
	if err := s.LinkAssets(a.ID, h.ID); err != nil {
		t.Fatal(err)
	}

	// The link is symmetric: visible from either side.
	got, err := s.LinkedAssetIDs(a.ID)
	if err != nil || len(got) != 1 || got[0] != h.ID {
		t.Errorf("LinkedAssetIDs(a) = %v, %v", got, err)
	}
	got, err = s.LinkedAssetIDs(h.ID)
	if err != nil || len(got) != 1 || got[0] != a.ID {
		t.Errorf("LinkedAssetIDs(h) = %v, %v", got, err)
	}

	if err := s.UnlinkAssets(h.ID, a.ID); err != nil { // reversed order on purpose
		t.Fatal(err)
	}
	got, _ = s.LinkedAssetIDs(a.ID)
	if len(got) != 0 {
		t.Errorf("still linked after unlink: %v", got)
	}
}

func TestLinkAssetsRejectsSelfAndMissing(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	if err := s.LinkAssets(a.ID, a.ID); err == nil {
		t.Error("an asset must not be linkable to itself")
	}
	if err := s.LinkAssets(a.ID, 999999); err == nil {
		t.Error("linking to a nonexistent asset must fail")
	}
}

func TestLinkedAssetsCascadeOnDelete(t *testing.T) {
	s, _ := open(t)
	a := asset(t, s, "a.example", 443)
	h, _, err := s.UpsertHostAsset("a-host")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LinkAssets(a.ID, h.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAsset(h.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.LinkedAssetIDs(a.ID)
	if err != nil || len(got) != 0 {
		t.Errorf("link should be gone once the linked asset is deleted: %v %v", got, err)
	}
}
