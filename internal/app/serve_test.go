package app_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/cipherhorizon/internal/app"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestServeRefusesNetworkBindWithoutToken(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	for _, addr := range []string{":0", "0.0.0.0:0", "192.0.2.1:0", "[::]:0"} {
		var errb bytes.Buffer
		code := app.Main(context.Background(), []string{"serve", "--addr", addr, "--db", filepath.Join(t.TempDir(), "x.db")},
			app.Env{Stdout: io.Discard, Stderr: &errb})
		if code != app.ExitFatal {
			t.Errorf("%s: exit %d, want fatal", addr, code)
		}
		if !strings.Contains(errb.String(), "without an access token") {
			t.Errorf("%s: message does not say why: %q", addr, errb.String())
		}
	}
}

func TestServeRunsAndShutsDownGracefully(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errb := &lockedBuf{}
	done := make(chan int, 1)
	go func() {
		done <- app.Main(ctx, []string{"serve", "--addr", "127.0.0.1:0", "--db", filepath.Join(t.TempDir(), "x.db")},
			app.Env{Stdout: io.Discard, Stderr: errb})
	}()

	re := regexp.MustCompile(`on http://(127\.0\.0\.1:\d+)`)
	var base string
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(errb.String()); m != nil {
			base = "http://" + m[1]
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if base == "" {
		t.Fatalf("server never announced its address; stderr:\n%s", errb.String())
	}

	for path, want := range map[string]string{"/api/v1/health": `"ok"`, "/": "<html"} {
		res, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if res.StatusCode != 200 || !strings.Contains(string(body), want) {
			t.Errorf("GET %s: %d %q", path, res.StatusCode, body)
		}
	}
	if !strings.Contains(errb.String(), "authorised to test") {
		t.Error("the authorisation notice was not printed")
	}

	cancel()
	select {
	case code := <-done:
		if code != app.ExitOK {
			t.Errorf("exit %d after shutdown; stderr:\n%s", code, errb.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not shut down")
	}
}
