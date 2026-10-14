package estate_test

import (
	"testing"

	"github.com/offsetsecurity/cipherhorizon/internal/estate"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
)

// REQ-SHO-5: every observation an SSH report projects passes the estate's own validation, and the
// projection is deterministic.
func TestSSHObservationsValidate(t *testing.T) {
	rep := &sshprobe.Report{
		Algorithms: &sshprobe.Algorithms{Kex: []string{"mlkem768x25519-sha256", "curve25519-sha256", "made-up@example.com"},
			HostKey: []string{"ssh-ed25519"}, CipherC2S: []string{"aes128-ctr"}, CipherS2C: []string{"aes128-ctr"},
			MACC2S: []string{"hmac-sha2-256"}, MACS2C: []string{"hmac-sha2-256"}},
		Negotiated: &sshprobe.Negotiated{Kex: "mlkem768x25519-sha256", Cipher: "aes128-ctr", MAC: "hmac-sha2-256", Completed: true},
		HostKeys:   []sshprobe.HostKey{{Type: "ssh-ed25519", Algorithm: "Ed25519", Fingerprint: "SHA256:abc"}},
	}
	obs := estate.FromSSHReport(rep)
	if len(obs) < 7 {
		t.Fatalf("%d observations", len(obs))
	}
	for _, o := range obs {
		if err := estate.Validate(estate.StreamNetwork, o); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
	again := estate.FromSSHReport(rep)
	for i := range obs {
		if obs[i].Entity.Key != again[i].Entity.Key || obs[i].Relation != again[i].Relation {
			t.Fatalf("projection order differs at %d", i)
		}
	}
	if estate.FromSSHReport(&sshprobe.Report{}) != nil {
		t.Error("observations from a report with no lists")
	}
}
