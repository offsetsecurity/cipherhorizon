package machinefacts

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// FuzzParseFacts (PRD-007 REQ-TR-6, audit L-15): a facts file is uploaded by a person and comes
// from a machine the server does not control. Whatever it holds, parsing and conversion return
// an answer or an error; they never panic, and a parsed file never carries a private key on.
func FuzzParseFacts(f *testing.F) {
	cert := "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUAA==\n-----END CERTIFICATE-----\n"
	seeds := []string{
		"",
		"cipherhorizon-machine-facts\t1\n",
		strings.Join([]string{
			"cipherhorizon-machine-facts\t2",
			"script\tlinux-sh\t2.0.1",
			"host\tname\tweb-01",
			"host\tos\tlinux",
			"host\tprivilege\tadmin",
			"os-release\t" + base64.StdEncoding.EncodeToString([]byte("ID=debian\nVERSION_ID=13\n")),
			"signatures\t2026.10.04",
			"fact\tLNX.OPENSSL\tpackage\tdpkg\topenssl\t3.5.1-1\tamd64",
			"fact\tLNX.CERTS\tcert-file\t/etc/ssl/certs/a.pem\t" + base64.StdEncoding.EncodeToString([]byte(cert)),
			"fact\tLNX.LIBS\tfile\t/usr/lib/libssl.so.3\t1234\tabcd\t\t",
			"fact\tLNX.SSHD\tline\t/etc/ssh/sshd_config\tKexAlgorithms mlkem768x25519-sha256",
			"ran\tLNX.OPENSSL\t1",
			"note\tRan without root.",
		}, "\n") + "\n",
		strings.Join([]string{
			"cipherhorizon-machine-facts\t2",
			"script\twindows-powershell\t2.0.1",
			"host\tos\twindows",
			"fact\tWIN.SCHANNEL\tregistry\tHKLM:\\SYSTEM\\x\tEnabled\t0",
			"fact\tWIN.CERTS\tcertstore\tLocalMachine\\My\t" + base64.StdEncoding.EncodeToString([]byte("not der")) + "\tTrue",
			"skip\tWIN.X\tnot present",
		}, "\r\n"),
		"\xef\xbb\xbfcipherhorizon-machine-facts\t2\nfact\tX\tcert-file\t/p\t" + base64.StdEncoding.EncodeToString([]byte("-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----\n")) + "\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	now := func() time.Time { return time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC) }
	f.Fuzz(func(t *testing.T, b []byte) {
		facts, err := Parse(b)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bom, err := ToCBOM(ctx, facts, Options{ToolVersion: "fuzz", Now: now})
		if err != nil || bom == nil {
			return
		}
		if bom.Components != nil {
			for _, c := range *bom.Components {
				if strings.Contains(c.Name, "PRIVATE KEY") {
					t.Fatalf("a component carries private key text: %q", c.Name)
				}
			}
		}
	})
}
