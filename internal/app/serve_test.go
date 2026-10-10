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

	"github.com/offsetsecurity/cipherhorizon/internal/app"
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

// ADR-0018: on the network, passwords and session cookies need TLS (or a proxy that provides it).
func TestServeRefusesNetworkBindOverPlainHTTP(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	for _, addr := range []string{":0", "0.0.0.0:0", "192.0.2.1:0", "[::]:0"} {
		var errb bytes.Buffer
		code := app.Main(context.Background(), []string{"serve", "--addr", addr, "--db", filepath.Join(t.TempDir(), "x.db")},
			app.Env{Stdout: io.Discard, Stderr: &errb})
		if code != app.ExitFatal {
			t.Errorf("%s: exit %d, want fatal", addr, code)
		}
		if !strings.Contains(errb.String(), "over plain HTTP") || !strings.Contains(errb.String(), "--tls-cert") {
			t.Errorf("%s: message does not say why: %q", addr, errb.String())
		}
	}
}

// SEC-03: a token that can be guessed is worse than none, because it looks like protection.
func TestServeRefusesAShortToken(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	for _, args := range [][]string{{"--token", "a"}, {"--token", "0123456789abcde"}} {
		var errb bytes.Buffer
		full := append([]string{"serve", "--addr", "127.0.0.1:0", "--db", filepath.Join(t.TempDir(), "x.db")}, args...)
		if code := app.Main(context.Background(), full, app.Env{Stdout: io.Discard, Stderr: &errb}); code != app.ExitFatal {
			t.Errorf("%v: exit %d, want fatal", args, code)
		}
		if !strings.Contains(errb.String(), "too short") || !strings.Contains(errb.String(), "openssl rand") {
			t.Errorf("%v: the message should say why and how to make a token: %q", args, errb.String())
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

// UX-REVIEW-008 S3: sign-in is off by default, so a server on the network must either require it
// or say, with --open-network, that it is meant to be open.
func TestServeOnTheNetworkNeedsSignInOrOpenNetwork(t *testing.T) {
	t.Setenv("CIPHERHORIZON_TOKEN", "")
	var errb bytes.Buffer
	code := app.Main(context.Background(), []string{"serve", "--addr", "0.0.0.0:0", "--plain-http", "--db", filepath.Join(t.TempDir(), "x.db")},
		app.Env{Stdout: io.Discard, Stderr: &errb})
	if code != app.ExitFatal || !strings.Contains(errb.String(), "--sign-in on") || !strings.Contains(errb.String(), "--open-network") {
		t.Fatalf("exit %d: %q", code, errb.String())
	}
	for _, extra := range [][]string{{"--open-network"}, {"--sign-in", "on"}, {"--login"}} {
		ctx, cancel := context.WithCancel(context.Background())
		errs := &lockedBuf{}
		done := make(chan int, 1)
		go func() {
			done <- app.Main(ctx, append([]string{"serve", "--addr", "0.0.0.0:0", "--plain-http", "--db", filepath.Join(t.TempDir(), "x.db")}, extra...),
				app.Env{Stdout: io.Discard, Stderr: errs})
		}()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && !strings.Contains(errs.String(), "UI and API on") {
			time.Sleep(20 * time.Millisecond)
		}
		cancel()
		if c := <-done; c != app.ExitOK {
			t.Errorf("%v: exit %d\n%s", extra, c, errs.String())
		}
		wantCode := extra[0] != "--open-network"
		if got := strings.Contains(errs.String(), "one-time setup code"); got != wantCode {
			t.Errorf("%v: setup code printed %v, want %v\n%s", extra, got, wantCode, errs.String())
		}
	}
	if code := app.Main(context.Background(), []string{"serve", "--login", "--no-login", "--db", filepath.Join(t.TempDir(), "x.db")},
		app.Env{Stdout: io.Discard, Stderr: io.Discard}); code != app.ExitFatal {
		t.Errorf("--login with --no-login: exit %d", code)
	}
}
