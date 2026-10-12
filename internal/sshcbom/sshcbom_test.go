package sshcbom_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/collector"
	"github.com/offsetsecurity/cipherhorizon/internal/pqc"
	"github.com/offsetsecurity/cipherhorizon/internal/schematest"
	"github.com/offsetsecurity/cipherhorizon/internal/sshcbom"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/sshprobe/testserver"
	"golang.org/x/crypto/ssh"
)

func scan(t *testing.T, cfg testserver.Config) *sshprobe.Report {
	t.Helper()
	srv := testserver.Start(t, cfg)
	rep, err := sshprobe.Scan(context.Background(), sshprobe.Target{Host: srv.Host, Port: srv.Port}, sshprobe.Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(assets []collector.CryptoAsset, ref string) *collector.CryptoAsset {
	for i := range assets {
		if assets[i].Component.BOMRef == ref {
			return &assets[i]
		}
	}
	return nil
}

func prop(a *collector.CryptoAsset, name string) string {
	if a == nil || a.Component.Properties == nil {
		return ""
	}
	for _, p := range *a.Component.Properties {
		if p.Name == cbom.PropertyNamespace+":"+name {
			return p.Value
		}
	}
	return ""
}

func build(t *testing.T, assets []collector.CryptoAsset, spec string) []byte {
	t.Helper()
	bom, warnings := cbom.Build(assets, cbom.Options{
		Tool: cbom.Tool{Name: "cipherhorizon", Version: "test"}, Endpoint: "bastion.example:22",
		Now:       func() time.Time { return time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) },
		NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
	})
	if len(warnings) != 0 {
		t.Errorf("warnings: %v", warnings)
	}
	pqc.Annotate(bom, pqc.Analyze(bom))
	var buf bytes.Buffer
	if err := cbom.EncodeSpec(&buf, bom, spec, true); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// REQ-SHO-1: schema-valid in 1.6 and 1.7, zero warnings, every component with evidence.
func TestSSHCBOMIsSchemaValid(t *testing.T) {
	rep := scan(t, testserver.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519, ssh.InsecureKeyExchangeDH14SHA1},
		Ciphers: []string{ssh.CipherAES256GCM, ssh.CipherAES128CTR, ssh.InsecureCipherAES128CBC}, MACs: []string{ssh.HMACSHA256ETM, ssh.HMACSHA1},
		Keys: []string{testserver.KeyEd25519, testserver.KeyECDSA, testserver.KeyRSA, testserver.KeyMLDSA65}})
	assets := sshcbom.FromSSHReport(rep)
	for _, a := range assets {
		if a.Component.Evidence == nil {
			t.Errorf("%s has no evidence", a.Component.BOMRef)
		}
	}
	for _, spec := range []string{cbom.Spec16, cbom.Spec17} {
		out := build(t, assets, spec)
		if spec == cbom.Spec16 {
			schematest.Validate(t, out)
		}
		for _, want := range []string{`"type": "ssh"`, "mlkem768x25519-sha256", "ML-DSA-65", "ECDSA-P256", "RSA-3072", "AES-128-CTR", "HMAC-SHA-256"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("%s: %q missing", spec, want)
			}
		}
	}
	proto := find(assets, sshcbom.ProtocolRef)
	if proto == nil || len(proto.DependsOn) < 8 {
		t.Fatalf("protocol %+v", proto)
	}
}

// REQ-SHO-1: the choices a current client makes are marked, exactly.
func TestSSHCBOMMarksTheNegotiatedChoices(t *testing.T) {
	rep := scan(t, testserver.Config{KeyExchanges: []string{ssh.KeyExchangeMLKEM768X25519, ssh.KeyExchangeCurve25519},
		Ciphers: []string{ssh.CipherAES256GCM, ssh.CipherAES128CTR}})
	assets := sshcbom.FromSSHReport(rep)
	proto := find(assets, sshcbom.ProtocolRef)
	if prop(proto, "negotiated-kex") != "mlkem768x25519-sha256" || prop(proto, "negotiated-cipher") != "aes256-gcm@openssh.com" ||
		prop(proto, "negotiation-evidence") != "observed" || prop(proto, "strict-kex") != "true" {
		t.Errorf("protocol properties %+v", proto.Component.Properties)
	}
	var flagged []string
	for i := range assets {
		if prop(&assets[i], "negotiated") == "true" {
			flagged = append(flagged, assets[i].Component.Name)
		}
	}
	if strings.Join(flagged, ",") != "AES-256-GCM,mlkem768x25519-sha256" {
		t.Errorf("flagged %v; want exactly the negotiated kex and cipher", flagged)
	}
}

func TestNilAndSSH1ReportsGiveNothing(t *testing.T) {
	if sshcbom.FromSSHReport(nil) != nil || sshcbom.FromSSHReport(&sshprobe.Report{}) != nil {
		t.Error("components from nothing")
	}
}
