package app_test

import (
	"context"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
)

// The container image's HEALTHCHECK: it has no shell, curl or wget, so the binary checks
// itself. It needs no token even when the server requires one for everything else.
func TestHealthcheckAgainstARunningServer(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "s3cret-token-0123456789")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errb := &lockedBuf{}
	go func() {
		_ = app.Main(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--db", filepath.Join(t.TempDir(), "x.db")},
			app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	re := regexp.MustCompile(`on http://127\.0\.0\.1:(\d+)`)
	var addr string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			addr = "127.0.0.1:" + m[1]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == "" {
		t.Fatalf("server never announced its address; stderr:\n%s", errb.String())
	}

	if code, _, out := run(t, "healthcheck", "--addr", addr); code != app.ExitOK || out != "" {
		t.Errorf("healthy server: exit %d, stderr %q", code, out)
	}
}

func TestHealthcheckFailsAgainstNothingListening(t *testing.T) {
	code, _, errOut := run(t, "healthcheck", "--addr", "127.0.0.1:1")
	if code != app.ExitFatal {
		t.Errorf("exit = %d, want fatal", code)
	}
	if !strings.Contains(errOut, "healthcheck") {
		t.Errorf("stderr = %q", errOut)
	}
}
