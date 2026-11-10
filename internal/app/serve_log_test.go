package app_test

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/offsetsecurity/cipherhorizon/internal/app"
)

// The server logs the method, path and client address of a request that fails authentication.
// Those come from the request, so the log must not let one forge a line: the path here carries a
// line break followed by what looks like a log entry. The handler serve configures quotes it, and
// this test fails if that is ever swapped for one that writes values raw (code scanning reports
// the log call as "log injection"; this is why that report is a false positive).
func TestRequestValuesCannotForgeALogLine(t *testing.T) {
	db := filepath.Join(t.TempDir(), "x.db")
	ctx, cancel := context.WithCancel(context.Background())
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, []string{"serve", "--db", db, "--addr", "127.0.0.1:0", "--token", "s3cret-token-0123456789", "--mcp"},
			app.Env{Stdout: io.Discard, Stderr: errb})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("server did not shut down")
		}
	})
	re := regexp.MustCompile(`UI and API on http://(\S+) `)
	var addr string
	for deadline := time.Now().Add(10 * time.Second); addr == "" && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			addr = m[1]
		}
	}
	if addr == "" {
		t.Fatalf("serve never announced its address: %s", errb.String())
	}

	const forged = "level=ERROR msg=forged-by-request"
	for _, path := range []string{"/api/v1/assets%0A" + strings.ReplaceAll(forged, " ", "%20"), "/mcp"} {
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer wrong-token-0123456789")
		req.Header.Set("X-Requested-With", "cipherhorizon")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s with a wrong token: %d", path, resp.StatusCode)
		}
	}

	var failures int
	for _, line := range strings.Split(errb.String(), "\n") {
		if strings.HasPrefix(line, forged) {
			t.Fatalf("a request forged a log line: %q", line)
		}
		if strings.Contains(line, `msg="authentication failed"`) {
			failures++
			if !strings.HasPrefix(line, "time=") {
				t.Errorf("an authentication failure is not one whole line: %q", line)
			}
		}
	}
	if failures != 2 {
		t.Errorf("want two authentication failures logged, one per request; got %d in:\n%s", failures, errb.String())
	}
	if !strings.Contains(errb.String(), `\n`+forged) {
		t.Errorf("the line break in the path is not shown escaped:\n%s", errb.String())
	}
}
