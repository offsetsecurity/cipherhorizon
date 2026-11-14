package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/cbom"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe"
	"github.com/offsetsecurity/cipherhorizon/internal/tlsprobe/testserver"
)

// One report, two ways to its CBOM: straight from the scan, as "tls scan --cbom" writes it, and
// through JSON, as "tls cbom --from" reads it. With the clock and serial number fixed the two
// documents are the same bytes, so nothing the CBOM needs is lost in the saved result.
func TestSavedReportGivesTheSameCBOM(t *testing.T) {
	srv := testserver.Start(t, testserver.Config{
		MinVersion: tls.VersionTLS12, Cert: testserver.CertBoth,
		Curves: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	})
	target, err := tlsprobe.ParseTarget(srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := tlsprobe.Scan(context.Background(), target, tlsprobe.Options{Concurrency: 8})
	if err != nil {
		t.Fatal(err)
	}

	env := func(out io.Writer) Env {
		return Env{
			Stdout: out, Stderr: io.Discard,
			Now:       func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
			NewSerial: func() string { return "urn:uuid:00000000-0000-4000-8000-000000000000" },
		}
	}
	var direct bytes.Buffer
	if err := writeTLSCBOM(env(&direct), rep, target, cbom.DefaultSpec); err != nil {
		t.Fatal(err)
	}

	saved, err := json.Marshal([]map[string]any{{"target": srv.Addr, "report": rep}})
	if err != nil {
		t.Fatal(err)
	}
	var fromSaved bytes.Buffer
	e := env(&fromSaved)
	e.Stdin = bytes.NewReader(saved)
	if code := tlsCBOMCmd([]string{"--from", "-"}, e); code != ExitOK {
		t.Fatalf("tls cbom --from -: exit %d", code)
	}
	if !bytes.Equal(direct.Bytes(), fromSaved.Bytes()) {
		t.Errorf("the CBOM of the saved report differs from the CBOM of the report itself (%d and %d bytes)", fromSaved.Len(), direct.Len())
	}
}
